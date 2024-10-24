#include <stdio.h>
#include <Windows.h>
#include <thread>
#include <iostream>
#include <filesystem>

bool LoadService(const std::string& szServiceName, const std::string& szServiceDisplayName, const std::string& szServiceFile) {
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager) {
		printf("[!] OpenSCManager failed! Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return false;
	}

	hService = CreateServiceA(hSCManager, szServiceName.c_str(), szServiceDisplayName.c_str(), SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szServiceFile.c_str(), NULL, NULL, NULL, NULL, NULL);
	if (!hService) {
		printf("[!] CreateServiceA failed! Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return false;
	}
	return true;
}

bool StartKernelService(const std::string& szServiceName) {
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager) {
		printf("[!] OpenSCManager failed! Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return false;
	}

	hService = OpenServiceA(hSCManager, szServiceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
	if (!hService) {
		printf("[!] OpenServiceA failed! Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return false;
	}

	if (StartServiceA(hService, 0, NULL) == FALSE) {
		printf("[!] StartServiceA failed! Error: %ld\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return false;
	}

	return true;

}

void HandleClientConnection(HANDLE hPipe) {
	char buffer[1024];
	DWORD bytesRead;

	while (true) {
		BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
		if (!result || bytesRead == 0) {
			// if read fails or pipe is closed, then exit the loop.
			break;
		}

		buffer[bytesRead] = '\0';
		std::cout << "Received from DLL: " << buffer << std::endl;
	}
}

void StartNamedPipeServer() {
	while (true) {

		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
		sa.bInheritHandle = TRUE;

		if (!InitializeSecurityDescriptor(sa.lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION)) {
			printf("[!] Failed to initialize security descriptor!\n");
			return;
		}

		if (!SetSecurityDescriptorDacl(sa.lpSecurityDescriptor, TRUE, (PACL)NULL, FALSE)) {
			printf("[!] Failed to set security descriptor DACL!\n");
			return;
		}
		HANDLE hPipe = CreateNamedPipe(
			TEXT("\\\\.\\pipe\\HookPipe"),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			1024, 1024, 0, &sa
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("[!] Failed to create named pipe!\n");
			return;
		}

		printf("[+] Waiting for client connection...\n");
		BOOL isConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (isConnected) {
			printf("[+] Client Connected. Spawning handler thread...\n");
			std::thread clientThread(HandleClientConnection, hPipe);
			clientThread.detach();
		}
		else {
			CloseHandle(hPipe);
		}
	}
}



int main() {
	std::string szServiceFile = "C:\\vedr\\vDriver.sys";
	std::string szServiceName = "VEDR Kernel";

	if (!std::filesystem::exists(szServiceFile)) {
		printf("[!] Driver file %s does not exist!\n", szServiceFile.c_str());
		return 0;
	}

	printf("[+] Driver: %s\n", szServiceFile.c_str());
	printf("[+] Service Name: %s\n", szServiceName.c_str());

	printf("[+] Attempting to start vEDR kernel service: %s\n", szServiceName.c_str());
	if (LoadService(szServiceName, szServiceName, szServiceFile) == FALSE) {
		printf("[!] An error occured loading kernel service!\n");
	}

	if (StartKernelService(szServiceName) == FALSE) {
		printf("[!] An error occured starting kernel service!\n");
	}
	printf("[+] vEDR Driver loaded and running!\n");

	printf("[+] Staring named pipe server...\n");

	// start named pipe server
	StartNamedPipeServer();

	return 0;
}
#include <stdio.h>
#include <Windows.h>
#include <thread>
#include <iostream>

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

		HANDLE hPipe = CreateNamedPipe(
			TEXT("\\\\.\\pipe\\HookPipe"),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			1024, 1024, 0, NULL
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("Failed to create named pipe!\n");
			return;
		}

		printf("Waiting for client connection...\n");
		BOOL isConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (isConnected) {
			printf("Client Connected. Spawning handler thread...\n");
			std::thread clientThread(HandleClientConnection, hPipe);
			clientThread.detach();
		}
		else {
			CloseHandle(hPipe);
		}
	}
}



int main() {
	printf("Staring named pipe server...\n");

	// start named pipe server
	StartNamedPipeServer();

	return 0;
}
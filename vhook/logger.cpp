#include "pch.h"
#include "logger.hpp"
#include <Windows.h>
#include <queue>
#include <string>


namespace Logger {

	HANDLE hPipe = INVALID_HANDLE_VALUE;
	std::string processName;
	DWORD processId = 0;

	void GetCurrentProcessInfo(std::string& processName, DWORD& processId) {

		processId = GetCurrentProcessId();

		char processPath[MAX_PATH];

		if (GetModuleFileNameA(NULL, processPath, MAX_PATH) > 0) {
			char* baseName = strrchr(processPath, '\\');
			if (baseName != NULL) {
				processName = std::string(baseName + 1);
			}
			else {
				processName = std::string(processPath);
			}
		}
		else {
			processName = "UnknownProcess";
		}
	}

	bool OpenPipeConnection() {
		if (hPipe == INVALID_HANDLE_VALUE) {
			hPipe = CreateFile(TEXT("\\\\.\\pipe\\HookPipe"),
				GENERIC_WRITE,
				0, NULL, OPEN_EXISTING, 0, NULL);
			if (hPipe == INVALID_HANDLE_VALUE) {
				return false;
			}
		}
		return true;
	}

	void LogMessage(const std::string& message) {
		if (processId == 0)
			GetCurrentProcessInfo(processName, processId);

		DWORD dwWritten;

		if (!OpenPipeConnection()) {
			return;
		}

		std::string logMessage = "Process Name: " + processName + " | Process ID: " + std::to_string(processId) + " | " + message;

		if (!WriteFile(hPipe, logMessage.c_str(), logMessage.length(), &dwWritten, NULL)) {
			CloseHandle(hPipe);
			hPipe = INVALID_HANDLE_VALUE;
		}
	}

	void Cleanup() {
		if (hPipe != INVALID_HANDLE_VALUE) {
			CloseHandle(hPipe);
		}
	}

}
// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include "MinHook.h"
#include "logger.hpp"
#include <unordered_map>

#if _WIN64
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif

BOOL hooked = FALSE;

// structure to keep track of process info
struct ProcessTrackingInfo {
    bool allocatedExecutableMemory = false; // used virtual alloc to allocate memory for something
    bool wroteToExecutableMemory = false; // wrote to the newly allocated memory
    PVOID allocatedBaseAddress = nullptr; // base address of the allocated memory
    SIZE_T allocatedRegionSize = 0; // size of the allocated memory
};

// Map to track multiple proccesses; keyed with the PID
static std::unordered_map<DWORD, ProcessTrackingInfo> processTrackingMap;

typedef DWORD(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef DWORD(WINAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

typedef HANDLE(WINAPI* pCreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

typedef DWORD(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

typedef HANDLE(WINAPI* pOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId);

pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = nullptr;
pNtProtectVirtualMemory pOriginalNtProtectVirutalMemory = nullptr;
pCreateRemoteThread pOriginalCreateRemoteThread = nullptr;
pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory = nullptr;
pOpenProcess pOriginalOpenProcess = nullptr;


DWORD NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {

    if (hooked) {
        if (Protect == PAGE_EXECUTE_READWRITE) {
            DWORD pid = GetProcessId(ProcessHandle);
            if (pid != 0) {
                Logger::LogMessage("NtAllocateVirtualMemory PAGE_EXECUTE_READWRITE permission detected pid=" + std::to_string(pid) + ".");
                if (pid != GetCurrentProcessId()) {
                    Logger::LogMessage("Suspicious memory allocation attempt detected pid=" + std::to_string(pid) + " with PAGE_EXECUTE_READWRITE permission.");
                    return NULL; // Dont let the api allocate the memory
                }
            }
            auto& trackingInfo = processTrackingMap[pid];
            trackingInfo.allocatedExecutableMemory = true;
        }
    }

    return pOriginalNtAllocateVirtualMemory(ProcessHandle,BaseAddress,ZeroBits,RegionSize,AllocationType,Protect);
}

DWORD NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect) {

    if (hooked) {
        if (NewProtect == PAGE_EXECUTE_READWRITE) {
            DWORD pid = GetProcessId(ProcessHandle);
            if (pid != 0) {
                Logger::LogMessage("NtProtectVirtualMemory PAGE_EXECUTE_READWRITE permission detected pid=" + std::to_string(pid) + ".");

            }
            auto& trackingInfo = processTrackingMap[pid];
            trackingInfo.allocatedExecutableMemory = true;
        }
    }

    return pOriginalNtProtectVirutalMemory(ProcessHandle,BaseAddress,RegionSize,NewProtect,OldProtect);
}

DWORD NTAPI HookedNtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten) {

    if (hooked) {
        DWORD pid = GetProcessId(ProcessHandle);
        if (pid != 0) {
            // check if we write to the previously allocated memory
            if (processTrackingMap.find(pid) != processTrackingMap.end()) {
                auto& trackingInfo = processTrackingMap[pid];
                if (trackingInfo.allocatedExecutableMemory) {
                    Logger::LogMessage("NtWriteVirtualMemory called on executable memory for PID: " + std::to_string(pid) + " Potential code injection detected!");
                    trackingInfo.wroteToExecutableMemory = true;
                }
            }
        }
    }

    return pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

HANDLE WINAPI HookedCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId) {

    if (hooked) {
        DWORD pid = GetProcessId(hProcess);
        if (pid != 0) {
            // check if we write to the previously allocated memory
            if (processTrackingMap.find(pid) != processTrackingMap.end()) {
                auto& trackingInfo = processTrackingMap[pid];
                if (trackingInfo.allocatedExecutableMemory && trackingInfo.wroteToExecutableMemory) {
                    Logger::LogMessage("CreateRemoteThread called after memory allocation and writing for PID: " + std::to_string(pid) + " Code execution detected!");
                    return NULL;
                }
            }
        }
    }

    return pOriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}
HANDLE WINAPI HookedOpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId) {

    if (hooked) {
        if (dwDesiredAccess & PROCESS_ALL_ACCESS) {
            Logger::LogMessage("Suspicious OpenProcess call with PROCESS_ALL_ACCESS to PID:" + std::to_string(dwProcessId));
        }
    }
    return pOriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

void InitializeHooks() {
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        Logger::LogMessage("Minhook init failed. Error code: " + std::to_string(status));
        return;
    }

    if (MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory", &HookedNtProtectVirtualMemory, (LPVOID*)&pOriginalNtProtectVirutalMemory) != MH_OK) {
        Logger::LogMessage("Failed to hook NtProtectVirtualMemory");
    }

    if (MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory", &HookedNtAllocateVirtualMemory, (LPVOID*)&pOriginalNtAllocateVirtualMemory) != MH_OK) {
        Logger::LogMessage("Failed to hook NtAllocateVirtualMemory");
    }

    if (MH_CreateHookApi(L"ntdll", "NtWriteVirtualMemory", &HookedNtWriteVirtualMemory, (LPVOID*)&pOriginalNtWriteVirtualMemory) != MH_OK) {
        Logger::LogMessage("Failed to hook NtNtWriteVirtualMemory");
    }

    if (MH_CreateHookApi(L"kernel32", "CreateRemoteThread", &HookedCreateRemoteThread, (LPVOID*)&pOriginalCreateRemoteThread) != MH_OK) {
        Logger::LogMessage("Failed to hook CreateRemoteThread");
    }

    if (MH_CreateHookApi(L"kernel32", "OpenProcess", &HookedOpenProcess, (LPVOID*)&pOriginalOpenProcess) != MH_OK) {
        Logger::LogMessage("Failed to hook OpenProcess");
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Logger::LogMessage("Failed to enable hooks.");
        return;
    }

    Logger::LogMessage("Hooks installed successfully!");
}


DWORD MainFunction(LPVOID lpParam) {
    InitializeHooks();
    hooked = TRUE;
    // Initialize hooks
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Logger::LogMessage("Injected into process!");
        MainFunction(NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


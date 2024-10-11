// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include "MinHook.h"
#include "logger.hpp"

#if _WIN64
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif

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

pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = nullptr;
pNtProtectVirtualMemory pOriginalNtProtectVirutalMemory = nullptr;


DWORD NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {

    // Check the protect arg for PAGE_EXECUTE_READWRITE)
    if (Protect == PAGE_EXECUTE_READWRITE) {
        Logger::LogMessage("PAGE_EXECUTE_READWRITE permission detected in NtAllocateVirtualMemory function call!");
        // if protections enabled then closethe process, prevent the call, etc.
    }

    return pOriginalNtAllocateVirtualMemory(ProcessHandle,BaseAddress,ZeroBits,RegionSize,AllocationType,Protect);
}

DWORD NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect) {

    // Check the protect arg for PAGE_EXECUTE_READWRITE)
    if (NewProtect == PAGE_EXECUTE_READWRITE) {
        Logger::LogMessage("PAGE_EXECUTE_READWRITE permission detected in NtProtectVirtualMemory function call!");
        // if protections enabled then closethe process, prevent the call, etc.
    }

    return pOriginalNtProtectVirutalMemory(ProcessHandle,BaseAddress,RegionSize,NewProtect,OldProtect);
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

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Logger::LogMessage("Failed to enable hooks.");
        return;
    }

    Logger::LogMessage("Hooks installed successfully!");
}


DWORD MainFunction(LPVOID lpParam) {
    InitializeHooks();
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


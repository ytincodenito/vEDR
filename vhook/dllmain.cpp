// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include "MinHook.h"

#if _WIN64
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// NtAllocateVirtualMemory
// NtProtectVirtualMemory
// enumerate for RWX permissions

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
        std::cout << "PAGE_EXECUTE_READWRITE permission detected in NtAllocateVirtualMemory function call!" << std::endl;
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
        std::cout << "PAGE_EXECUTE_READWRITE permission detected in NtProtectVirtualMemory function call!" << std::endl;
        // if protections enabled then closethe process, prevent the call, etc.
    }

    return pOriginalNtProtectVirutalMemory(ProcessHandle,BaseAddress,RegionSize,NewProtect,OldProtect);
}

void InitializeHooks() {
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        std::cout << "Minhook init failed. Error code: " << status << std::endl;
        return;
    }

    if (MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory", &HookedNtProtectVirtualMemory, (LPVOID*)&pOriginalNtProtectVirutalMemory) != MH_OK) {
        std::cout << "Failed to hook NtProtectVirtualMemory" << std::endl;
    }

    if (MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory", &HookedNtAllocateVirtualMemory, (LPVOID*)&pOriginalNtAllocateVirtualMemory) != MH_OK) {
        std::cout << "Failed to hook NtAllocateVirtualMemory" << std::endl;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        std::cout << "Failed to enable hooks." << std::endl;
        return;
    }

    std::cout << "Hooks installed successfully!" << std::endl;
}




void CreateConsole() {
    FreeConsole();

    if (AllocConsole()) {
        FILE* file;
        freopen_s(&file, "CONOUT$", "w", stdout);
        freopen_s(&file, "CONOUT$", "w", stderr);
        freopen_s(&file, "CONIN$", "w", stdin);

        std::cout << "Console allocated..." << std::endl;
    }
}
DWORD MainFunction(LPVOID lpParam) {
    // Create a console
    CreateConsole();
    InitializeHooks();
    Sleep(500000);
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
        CreateThread(NULL, 0, MainFunction, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        FreeConsole();
        break;
    }
    return TRUE;
}


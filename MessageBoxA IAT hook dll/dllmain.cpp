#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <Psapi.h>

// Declarations for hook
using PrototypeMessageBox = int (WINAPI*)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
static PrototypeMessageBox originalMsgBox = nullptr;

DWORD IsProcessRunning(const wchar_t* pName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry))
        do {
            if (!_wcsicmp(entry.szExeFile, pName)) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);
        return 0;
}

void printProcessModules(HANDLE pProcessHandle, DWORD pid) {

    HMODULE hModules[1024];
    DWORD cbNeeded;
    EnumProcessModules(pProcessHandle, hModules, sizeof(hModules), &cbNeeded);


    // Calculate the number of modules
    int moduleCount = cbNeeded / sizeof(HMODULE);

    // Print the module names
    LPWSTR szModuleName = new WCHAR[MAX_PATH];
    std::cout << "Module names in process " << pid << ":" << std::endl;
    for (int i = 0; i < moduleCount; i++) {
        if (GetModuleFileNameEx(pProcessHandle, hModules[i], szModuleName, MAX_PATH)) {
            std::wcout << L"Module " << i + 1 << L": " << szModuleName << std::endl;
        }
    }
}

PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(HMODULE hModule) {
    DWORD oldProtect = 0;
    VirtualProtect((LPVOID)hModule, sizeof(HMODULE), PAGE_READWRITE, &oldProtect);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeaders->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)hModule);
    return importDescriptor;
}

void iatHook(const void* hookFunction, const char* targetFunctionName, PrototypeMessageBox& originalMsgBox) {

    HMODULE hModule = GetModuleHandleA(NULL);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = getImportDescriptor(hModule);

    LPCSTR libraryName = NULL;
    HMODULE library = NULL;
    PIMAGE_IMPORT_BY_NAME functionName = NULL;

    while (importDescriptor->Name != NULL)
    {
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)hModule;
        library = LoadLibraryA(libraryName);
        if (!library) {
            continue;
        }

        PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
        originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + importDescriptor->FirstThunk);

        while (originalFirstThunk->u1.AddressOfData != NULL)
        {
            functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)hModule + originalFirstThunk->u1.AddressOfData);

            if (std::string(functionName->Name).compare(targetFunctionName) == 0)
            {
                // Hotpatches MessageBoxW jump address
                DWORD oldProtect = 0;
                VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
                originalMsgBox = (PrototypeMessageBox)firstThunk->u1.Function;
                firstThunk->u1.Function = (DWORD_PTR)hookFunction;
                return;
            }
            ++originalFirstThunk;
            ++firstThunk;
        }

        importDescriptor++;
    }
}

// Trampoline function
int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return originalMsgBox(hWnd, L"Hooked message!", L"MessageBoxW Hooked", uType);
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // Install the hook when the DLL is attached to a process
        iatHook(hookedMessageBox, "MessageBoxW", originalMsgBox);
        break;
    }
    return TRUE;
}

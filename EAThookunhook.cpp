#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <Psapi.h>

IMAGE_EXPORT_DIRECTORY* getExportDirectory(HMODULE imageBase) {

    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDataDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)imageBase + exportDataDirectory.VirtualAddress);

    return exportDirectory;
}

PDWORD getEATEntryByName(HMODULE imageBase,
    const char* targetFunctionName) {

    IMAGE_EXPORT_DIRECTORY* exportDirectory = getExportDirectory(imageBase);
    if (!exportDirectory) {
        std::cerr << "Could not get base address of imports directory" << std::endl;
        return nullptr;
    }

    DWORD numberOfNames = exportDirectory->NumberOfNames;
    PDWORD exportAddressTable = (PDWORD)((DWORD_PTR)imageBase + exportDirectory->AddressOfFunctions);
    PWORD nameOrdinalsPointer = (PWORD)((DWORD_PTR)imageBase + exportDirectory->AddressOfNameOrdinals);
    PDWORD exportNamePointerTable = (PDWORD)((DWORD_PTR)imageBase + exportDirectory->AddressOfNames);

    for (int index = 0; index < numberOfNames; index++) {

        const char* exportedFunctionName = (char*)((unsigned char*)imageBase + exportNamePointerTable[index]);

        if (!strcmp(targetFunctionName, exportedFunctionName)) {
            return &exportAddressTable[nameOrdinalsPointer[index]];
        }
    }

    return nullptr;
}

void* allocateClosestAfterAddress(HMODULE imageBase, const int size) {

    MODULEINFO moduleInfo{};
    auto result = GetModuleInformation(GetCurrentProcess(), static_cast<HMODULE>(imageBase), &moduleInfo, sizeof(MODULEINFO));
    if (!result) {
        std::cerr << "Could not get module information" << std::endl;
        return nullptr;
    }

    PDWORD freeAddress = (PDWORD)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage;

    void* allocatedAddress = NULL;
    constexpr size_t ALLOC_ALIGNMENT = 0x10000;
    do {
        allocatedAddress = VirtualAlloc(reinterpret_cast<void*>(freeAddress),
            size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        freeAddress += ALLOC_ALIGNMENT;
    } while (allocatedAddress == nullptr);

    return allocatedAddress;
}

char* createJumpBytes(void* const hookAddress) {

    char jumpBytes[12] = {
        /*mov rax, 0xCCCCCCCCCCCCCCCC*/
        0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

        /*jmp rax*/
        0xFF, 0xE0
    };

    const auto address = (intptr_t)(hookAddress);
    std::memcpy(&jumpBytes[2], &address, sizeof(void*));

    return jumpBytes;
}

template <typename OriginalFunctionPtr>
void InstallEATHook(const std::string& targetModuleName,
    const char* targetFunctionName, void* const hookAddress,
    OriginalFunctionPtr& originalFunction) {

    HMODULE imageBase = GetModuleHandleA(targetModuleName.c_str());
    if (imageBase == nullptr) {
        imageBase = LoadLibraryA(targetModuleName.c_str());
    }

    PDWORD eatEntryRva = getEATEntryByName(imageBase, targetFunctionName);
    if (eatEntryRva == nullptr) {
        std::cerr << "EAT entry not found" << std::endl;
        return;
    }

    // Jumps to original function with address as defined in EAT
    originalFunction = reinterpret_cast<OriginalFunctionPtr>((unsigned char*)imageBase + *eatEntryRva);

    // jumpStub is the pointer to the jump instructions allocated near to the EAT
    void* jumpStub = allocateClosestAfterAddress(imageBase, 12);
    if (jumpStub == nullptr) {
        std::cerr << "Hook could not be installed" << std::endl;
        return;
    }

    // Generates the assembly instructions to jump to hookAddress
    const auto jumpBytes = createJumpBytes(hookAddress);

    // Copies jump instructions from jumpBytes to jumpStub
    std::memcpy(jumpStub, jumpBytes, 12);

    // Changes EAT jump address to jumpStub
    DWORD oldProtect = 0;
    VirtualProtect(eatEntryRva, 8, PAGE_READWRITE, &oldProtect);
    *eatEntryRva = (DWORD)((DWORD_PTR)jumpStub - (DWORD_PTR)imageBase);
    VirtualProtect(eatEntryRva, 8, PAGE_READONLY, &oldProtect);

    return;
}

// General declarations
HMODULE hModule = GetModuleHandleA(NULL);

using PrototypeMessageBox = int(__stdcall*)(HWND, LPCSTR, LPCSTR, UINT);
static PrototypeMessageBox OriginalMessageBoxA = nullptr;

int HookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return OriginalMessageBoxA(NULL, "MessageBoxA hooked", "Hook", 0);
}

int main(int argc, char* argv[]) {

    MessageBoxA(nullptr, "Hello World!", nullptr, 0);

    // Stores the original MessageBoxA pointer
    static PrototypeMessageBox UnusedOriginalMessageBoxAPtr =
        reinterpret_cast<PrototypeMessageBox>(
            GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"));

    // Hooks MessageBoxA
    InstallEATHook("user32.dll", "MessageBoxA",
        HookMessageBoxA, OriginalMessageBoxA);

    // Stores the hooked MessageBoxA pointer
    PrototypeMessageBox MessageBoxAFnc =
        reinterpret_cast<PrototypeMessageBox>(
            GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"));

    if (MessageBoxAFnc == nullptr) {
        std::cerr << "Could not find MessageBoxA export"
            << std::endl;
        return -1;
    }

    MessageBoxAFnc(nullptr, "Hello World!", nullptr, 0);

    return 0;
}

#include <iostream>
#include <Windows.h>
#include <winternl.h>

// General declarations
HMODULE hModule = GetModuleHandleA(NULL);

// Declarations for hook
using PrototypeMessageBox = int (WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
PrototypeMessageBox originalMsgBox = MessageBoxA;

// Trampoline function
int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	MessageBoxW(NULL, L"MessageBoxA hooked", L"Hook", 0);
	return originalMsgBox(hWnd, lpText, lpCaption, uType);
}

// Hooks MessageBoxA
int hook() {
	// Gets module handle of current module
	LPVOID imageBase = (LPVOID)hModule;
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	// Crawls through libraries in importDescriptor to find the MessageBoxA import
	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		library = LoadLibraryA(libraryName);
		if (!library) {
			continue;
		}

		PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
		originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
		firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

		while (originalFirstThunk->u1.AddressOfData != NULL)
		{
			functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

			if (std::string(functionName->Name).compare("MessageBoxA") == 0)
			{
				// Hotpatches MessageBoxA jump address
				DWORD oldProtect = 0;
				VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
				firstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;
			}
			++originalFirstThunk;
			++firstThunk;
		}

		importDescriptor++;
	}

	return 1;
}

// Declarations for hook detector
enum HOOK_TYPE {
	NO_HOOK,
	HOOK_RELATIVE,
	HOOK_ABSOLUTE
};

HOOK_TYPE isHooked(LPCVOID lpFuncAddress) {
	LPCBYTE lpBytePtr = (LPCBYTE)lpFuncAddress;

	if (lpBytePtr[0] == 0xE9 || lpBytePtr[0] == 0xEB) {
		return HOOK_RELATIVE;    // E9 and EB jmp is relative.
	}
	else if (lpBytePtr[0] == 0x68 && lpBytePtr[5] == 0xC3) {
		return HOOK_ABSOLUTE;    // push/ret is absolute.
	}
	return NO_HOOK;            // No hook.
}

int hookJumpCheck(LPCVOID lpFuncAddress) {
	// We check if the jump address of the hook is suspicious
	LPVOID dwHookAddress = 0;
	HOOK_TYPE ht = isHooked(lpFuncAddress);

	// Finds address of hooking function
	if (ht == HOOK_ABSOLUTE) {
		dwHookAddress = (LPVOID)(*(LPDWORD)((LPBYTE)lpFuncAddress + 1));
	}
	else if (ht == HOOK_RELATIVE) {
		INT nJumpSize = (*(PINT)((LPBYTE)lpFuncAddress + 1));
		DWORD_PTR dwRelativeAddress = (DWORD_PTR)((LPBYTE)lpFuncAddress + 5);
		dwHookAddress = (LPVOID)(dwRelativeAddress + nJumpSize);
	}
	else {
		return 0;
	}

	// Checks if hook is malicious based on location of hook
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(dwHookAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	if (mbi.AllocationBase == (PVOID)hModule) {
		// Same module, assume safe
		// return 0;

		// For demonstration, we take the hook as malicious
		return 1;
	}

	// Get a handle to the hooking module
	HMODULE hModuleHook = NULL;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCTSTR)dwHookAddress, &hModuleHook);

	TCHAR path1[MAX_PATH] = { 0 }, path2[MAX_PATH] = { 0 };
	DWORD result1 = GetModuleFileName(hModule, path1, MAX_PATH);
	DWORD result2 = GetModuleFileName(hModuleHook, path2, MAX_PATH);
	if (_wcsicmp(path1, path2) == 0) {
		// Same path, assume safe.
		return 0;
	}

	// If execution reaches here then the hook could be malicious
	return 1;
}

int hookDllCheck() {
	// We check a function's jump address against the dll's EAT

	/*
	In this function we perform the following steps:
	1. Load the imageBase of the current module and get its importsDirectory
	2. Iterate over importsDirectory to get the imported libraries
		2.1. Each iteration creates the first corresponding originalFirstThunk and firstThunk instances
		2.2. Iterate over the exported function names to find the ordinals corresponding to the imported functions
			2.2.1. Compare the jump instructions of the imported and exported functions. Differing instructions indicates a hook.
			2.2.2. Overwrite the erroneous instruction
	*/

	LPVOID imageBase = (LPVOID)hModule;
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

	// Gets import directory to call library
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	while (importDescriptor->Name != NULL)
	{
		// Initialises library to compare against its EAT
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		library = LoadLibraryA(libraryName);
		if (!library) {
			continue;
		}
		
		PIMAGE_DOS_HEADER libDosHeaders = (PIMAGE_DOS_HEADER)library;
		PIMAGE_NT_HEADERS libNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)library + libDosHeaders->e_lfanew);
		IMAGE_DATA_DIRECTORY exportDataDirectory = libNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)library + exportDataDirectory.VirtualAddress);

		// Contains all the required info to check exported functions
		DWORD numberOfNames = exportDirectory->NumberOfNames;
		PDWORD exportAddressTable = (PDWORD)((DWORD_PTR)library + exportDirectory->AddressOfFunctions);
		PWORD nameOrdinalsPointer = (PWORD)((DWORD_PTR)library + exportDirectory->AddressOfNameOrdinals);
		PDWORD exportNamePointerTable = (PDWORD)((DWORD_PTR)library + exportDirectory->AddressOfNames);

		// First thunk and original first thunk of module to inspect
		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

		while (originalFirstThunk->u1.AddressOfData != NULL)
		{
			// hint contains the function names to compare against exported functions
			PIMAGE_IMPORT_BY_NAME hint = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
			LPCSTR functionName = hint->Name;
			// Ideally we can just access the correct EAT entry using hint->Hint but it doesn't work for mysterious reasons...

			for (int nameIndex = 0; nameIndex < numberOfNames; nameIndex++)
			{
				char* name = (char*)((unsigned char*)library + exportNamePointerTable[nameIndex]);
				if (strcmp(functionName, name) != 0) {
					continue;
				}
				WORD ordinal = nameOrdinalsPointer[nameIndex];
				/*
				WHY does the ordinal not match the hint? Neither ordinal nor nameIndex matches the hint
				E.g.
				hint -> Hint = 651, Name = MessageBoxW
				ordinal = 657
				Caused me so much trouble >:(
				*/
				PDWORD originalFunction = (PDWORD)((unsigned char*)library + exportAddressTable[ordinal]);

				if (memcmp((LPVOID)firstThunk->u1.Function, originalFunction, 8) != 0) {
					std::cout << "Hooked function " << functionName << " found\n";

					DWORD oldProtect = 0;
					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
					firstThunk->u1.Function = (DWORD_PTR) originalFunction;
					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READONLY, &oldProtect);

					std::cout << "Function " << functionName << " unhooked\n\n";

				}

			}
			++originalFirstThunk;
			++firstThunk;
		}

		importDescriptor++;
	}

	return 0;
}

/*
int removeHooks() {
	// For demonstration, we assume knowledge that the IAT is hooked
	TCHAR filePath[MAX_PATH] = { 0 };
	if (!GetModuleFileName(hModule, filePath, MAX_PATH)) {
		return 1;
	}

	// Get a handle to the file
	HANDLE hFile = CreateFile(
		filePath,       // Pointer to the file path.
		GENERIC_READ,       // Read access.
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,      // File must exist.
		0,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		return 1;
	}

	// Map the module
	HANDLE hFileMapping = CreateFileMapping(
		hFile,                       // Handle to the file.
		NULL,
		PAGE_READONLY | SEC_IMAGE,   // Map it as an executable image.
		0,
		0,
		NULL
	);

	if ((long)hFileMapping == ERROR_ALREADY_EXISTS || !hFileMapping) {
		return 1;
	}
	
	// Gets base address of file
	LPVOID lpMapping = MapViewOfFile(
		hFileMapping,       // From above
		FILE_MAP_READ,      // Same map permissions as above.
		0,
		0,
		0
	);

	if (!lpMapping) {
		return 1;
	}

	// Parse the PE headers.
	HMODULE imageBase = hModule;
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)lpMapping;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpMapping + dosHeaders->e_lfanew);

	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)lpMapping);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	// Replaces import descriptors with ones read from disk
	for(; (DWORD)importDescriptor < importsDirectory.Size + (DWORD_PTR)lpMapping; importDescriptor++)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)lpMapping;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA diskOriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpMapping + importDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);
			DWORD oldProtect = 0;

			VirtualProtect(originalFirstThunk, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &oldProtect);
			memcpy(originalFirstThunk, diskOriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));
			VirtualProtect(originalFirstThunk, sizeof(IMAGE_THUNK_DATA), PAGE_READONLY, &oldProtect);

			VirtualProtect(firstThunk, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &oldProtect);
			memcpy(firstThunk, diskOriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));
			VirtualProtect(firstThunk, sizeof(IMAGE_THUNK_DATA), PAGE_READONLY, &oldProtect);
		}
	}

	return 0;
}
*/

int main() {
	hook();
	MessageBoxA(NULL, "Hello World!", "Hello World", 0);
	hookDllCheck();
	MessageBoxA(NULL, "Hello World!", "Hello World", 0);

	return 0;
}
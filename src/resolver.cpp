#include <pe_structs.h>
#include <resolver.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

HMODULE WINAPI GetModule(LPCWSTR module_name) {
	PEB* peb = ((PEB*)((TEB*)((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock));
	// Return the base of calling mod
	if (module_name == nullptr) {
		return reinterpret_cast<HMODULE>(peb->ImageBaseAddress);
	}

	PEB_LDR_DATA* ldr = peb->Ldr;
	if (!ldr) return nullptr;
	LIST_ENTRY* ModuleList = &ldr->InMemoryOrderModuleList;

	for (LIST_ENTRY* pEntryList = ModuleList->Flink;  // Loop through list entries
		pEntryList != ModuleList;
		pEntryList = pEntryList->Flink)
	{
		LDR_DATA_TABLE_ENTRY* pEntry = CONTAINING_RECORD(pEntryList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks); // Table entry

		if (strcmp(reinterpret_cast<const char*>(pEntry->BaseDllName.Buffer), reinterpret_cast<const char*>(module_name))) {  //Compare the names of modules
			return reinterpret_cast<HMODULE>(pEntry->DllBase);
		}
	}

	return nullptr;
}

inline static bool PeHeaderCheck(void* baseaddr) {
	if (!baseaddr) return false;
	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(baseaddr);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

	IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<BYTE*>(baseaddr) + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

	return true;
}

static void* RvaToPtr(void* baseaddr, DWORD rva) {
	if (!baseaddr || !rva) return nullptr;
	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(baseaddr);
	IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<BYTE*>(baseaddr) + dos->e_lfanew);

	if (rva >= nt->OptionalHeader.SizeOfImage) return nullptr;
	return (BYTE*)baseaddr + rva;
}


FARPROC WINAPI GetProc(HMODULE moduleBase, const char* functionName) {
	if (!moduleBase || !functionName) {
		return nullptr;
	}
	void* baseaddr = reinterpret_cast<void*>(moduleBase);

	// Check if addresses are valid
	if(!PeHeaderCheck(baseaddr)){
		return nullptr;
	}
	// Pointers to headers 
	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(baseaddr);
	IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<BYTE*>(baseaddr) +dos->e_lfanew);
	IMAGE_OPTIONAL_HEADER64* opt = &nt->OptionalHeader;

	if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return nullptr;
	IMAGE_DATA_DIRECTORY* dir = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir->VirtualAddress) return nullptr;

	IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(RvaToPtr(baseaddr, dir->VirtualAddress));
	if (!exportDir) return nullptr; 

	// Resolve addresses to EAT, name table, and ordinal table
	DWORD* functions = reinterpret_cast<DWORD*>(RvaToPtr(baseaddr, exportDir->AddressOfFunctions));
	DWORD* names = reinterpret_cast<DWORD*>(RvaToPtr(baseaddr, exportDir->AddressOfNames));
	WORD* ordinals = reinterpret_cast<WORD*>(RvaToPtr(baseaddr, exportDir->AddressOfNameOrdinals));
	if (!functions || !names || !ordinals) return nullptr;


	for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
		char* namePtr = reinterpret_cast<char*>(RvaToPtr(baseaddr, names[i]));
		if (!namePtr) continue;

		if (_stricmp(namePtr, functionName) == 0) {
			WORD ord = ordinals[i];
			DWORD funcRVA = functions[ord];

			if (funcRVA >= dir->VirtualAddress && funcRVA < dir->VirtualAddress + dir->Size) {
				return nullptr;
			}

			return reinterpret_cast<FARPROC>(RvaToPtr(baseaddr, funcRVA));
		}
	}

	return nullptr;

}



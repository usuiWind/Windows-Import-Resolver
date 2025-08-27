#include <pe_structs.h>
#include <resolver.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

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

		if (_wcsicmp(pEntry->BaseDllName.Buffer, module_name) == 0) {  //Compare the names of modules
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


void* WINAPI GetProc(HMODULE moduleBase, const char* functionName) {
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

	// Check for ordinal and resolve 
	uintptr_t intName = reinterpret_cast<uintptr_t>(functionName);
	if ((intName >> 16) == 0) {
		WORD ordinal = static_cast<WORD>(intName);

		DWORD funcRVA = functions[ordinal - exportDir->Base];
		if (funcRVA) {
			return nullptr;
		}

		return (RvaToPtr(baseaddr, funcRVA));
	}


	for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
		char* namePtr = reinterpret_cast<char*>(RvaToPtr(baseaddr, names[i]));
		if (!namePtr) continue;

		if (_stricmp(namePtr, functionName) == 0) {
			WORD ord = ordinals[i];
			DWORD funcRVA = functions[ord];

			// If the forwarder lies in export directory 
			if (funcRVA >= dir->VirtualAddress && funcRVA < dir->VirtualAddress + dir->Size) {
				const char* forward = reinterpret_cast<const char*>(RvaToPtr(baseaddr, funcRVA));
				if (!forward) return nullptr; 
				
				const char* dot = strchr(forward, '.'); 
				if (!dot || dot == forward) return nullptr;

				// Seperate the dll part and sym part
				std::string dll(forward, static_cast<size_t>(dot - forward));
				std::string sym(dot + 1);

				// Checks if  dll is part of  name 
				if (_stricmp(dll.c_str() + dll.size() - 4, ".dll") != 0) {
					dll.append(".dll");
				}

				std::wstring wdll(dll.begin(), dll.end());
				HMODULE targetDll = GetModule(wdll.c_str());

				// Forwarder uses ordinals instead 
				if (sym[0] == '#') {
					WORD ordinal = static_cast<WORD>(strtoul(sym.c_str() + 1, nullptr, 10));
					return GetProc(targetDll, reinterpret_cast<const char*>(static_cast<uintptr_t>(ordinal)));
				}

				return GetProc(targetDll, sym.c_str());
			}

			return (RvaToPtr(baseaddr, funcRVA));
		}
	}

	return nullptr;

}



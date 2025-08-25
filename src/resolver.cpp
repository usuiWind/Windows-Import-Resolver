#include <pe_structs.h>
#include <resolver.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

HMODULE* WINAPI GetModule(LPCWSTR* module_name) {
	PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	// Return the base of calling mod
	if (module_name == nullptr) {
		return reinterpret_cast<HMODULE>(peb->ImageBaseAddress);
	}

	PEB_LDR_DATA* ldr = peb->Ldr;
	LIST_ENTRY* ModuleList = &ldr->InMemoryOrderModuleList;

	for (LIST_ENTRY* pEntryList = ModuleList->Flink;  // Loop through list entries
		pEntryList != ModuleList;
		pEntryList = pEntryList->Flink)
	{
		LDR_DATA_TABLE_ENTRY* pEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>((reinterpret_cast<BYTE*>(pListEntry) - sizeof(LIST_ENTRY))); // Table entry

		if (_wcsicmp(pEntry->BaseDllName.Buffer, module_name) == 0) {  //Compare the names of modules
			return reinterpret_cast<HMODULE>(pEntry->DllBase);
		}
	}

	return 0;
}

inline static boolean PeHeaderCheck(void* base) {
	if (!base) return false;
	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(baseaddr);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

	IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(baseaddr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	if (&nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

	return true;
}


FARPROC WINAPI GetProc(HMODULE* moduleBase, const char* functionName) {
	if (!moduleBase || !functionName) {
		return nullptr;
	}
	void* baseaddr = reinterpret_cast<void*>(moduleBase);

	if(!PeHeaderCheck(baseaddr)){
		return nullptr;
	}
	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(baseaddr);
	IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(baseaddr+dos->e_lfanew);
	IMAGE_OPTIONAL_HEADER* opt = &nt->OptionalHeader;
}



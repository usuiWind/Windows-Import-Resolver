#pragma once 
#include <Windows.h>
HMODULE WINAPI GetModule(LPCWSTR module_name);
void* WINAPI GetProc(HMODULE moduleBase, const char* functionName);
#include <resolver.h>
#include "errors.hpp"
#include <string>
#include <random>
#include <vector>
/*
A simple test behavior to mimic C2 by spawning a message box every few seconds
*/


int main() {
	HMODULE kernel32 = GetModule(L"kernel32.dll");
	if (!kernel32) {
		return error::get_kernel32;
	}

	auto sleep_ = reinterpret_cast<VOID(WINAPI*)(DWORD)>(GetProc(kernel32, "Sleep"));
	if (!sleep_) {
		return error::get_sleep;
	}

	auto LoadLibraryW_ = reinterpret_cast<HMODULE(WINAPI*)(LPCWSTR)>(GetProc(kernel32, "LoadLibraryW"));
	if (!LoadLibraryW_) {
		return error::get_loadLibraryW;
	}
	HMODULE user32 = LoadLibraryW_(L"user32.dll");
	if (!user32) {
		return error::get_user32;
	}

	auto MessageBoxW_ = reinterpret_cast<int (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT)>(GetProc(user32, "MessageBoxW"));
	if (!MessageBoxW_) {
		return error::get_messageBoxW;
	}

	std::vector<std::wstring> cmds = {L"Lateral Movement", L"Exfiltrate Data", L"Encrypt Data", L"Erase Artifacts"};

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dist(3000, 7000);

	while (true) {
		
		sleep_(dist(gen));

		int idx = dist(gen) % cmds.size();
		std::wstring cmd = cmds[idx];

		MessageBoxW_(
			NULL,
			cmd.c_str(),
			L"C2 Simulation",
			NULL
		);
	}

	return error::success;
}
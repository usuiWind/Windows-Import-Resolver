#include <resolver.h>
#include "errors.hpp"

int main() {
	HMODULE kernel32 = GetModule(L"kernel32.dll");
	if (!kernel32) {
		return error::get_kernel32;
	}

	auto sleep_ = GetProc(kernel32, "Sleep");
	if (!sleep_) {
		return error::get_sleep;
	}

	auto GetTickCount64_ = GetProc(kernel32, "GetTickCount64");
	if (!GetTickCount64_) {
		return error::get_gettickcount64;
	}

	HMODULE msvcrt = GetModule(L"msvcrt.dll");
	if (!msvcrt) {
		return error::get_msvcrt;
	}

	auto rand_ = GetProc(msvcrt, "rand");
	if (!rand_) {
		return error::get_rand;
	}

	auto srand_ = GetProc(msvcrt, "srand");
	if (!srand_) {
		return error::get_srand;
	}

	srand_();

	return error::success;
}
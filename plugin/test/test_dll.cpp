// A stand-in for a plugin that hooks the game: the self-test jumps from patched code into this DLL.
#include <windows.h>

extern "C" __declspec(dllexport) int hm_hook(int x) { return x + 1; }
extern "C" __declspec(dllexport) const char* hm_name() { return HM_TEST_NAME; }

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }

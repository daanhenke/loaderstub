#include <Windows.h>

DWORD Thread(void* unused)
{
    MessageBoxA(nullptr, "target", "original DllMain called!", MB_OK);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
    }

    return TRUE;
}
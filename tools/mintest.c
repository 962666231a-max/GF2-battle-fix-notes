
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE i, DWORD r, LPVOID x) {
    (void)i; (void)x;
    if (r == DLL_PROCESS_ATTACH) {
        HANDLE h = CreateFileA("L"."\\_mintest.txt",
                               GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { DWORD w=0; WriteFile(h, "ok", 2, &w, NULL); CloseHandle(h); }
    }
    return TRUE;
}

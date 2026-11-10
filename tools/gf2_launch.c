/*
 * gf2_launch.c —— 带 -logFile 启动 GF2_Exilium.exe，并在挂起状态注入 daiyan.dll
 *
 * 为什么需要它
 *   · 客户端重定向不是靠 hosts，而是 launcher.exe 注入 daiyan.dll 在进程内完成
 *     （hosts 里没有 GF2 条目也能看到）
 *   · 但我们要 -logFile 抓 Unity 原始日志，而 launcher.exe 不接受/不转发参数
 *   ⇒ 自己做：CreateProcess(SUSPENDED) + 远程 LoadLibraryW(daiyan.dll) + Resume
 *
 * 用法
 *   gf2_launch.exe <游戏目录> [日志文件]
 *   例：gf2_launch.exe "E:\GF2\GF2Exilium\GF2 Game\GF2 Game\GF2 Game" "E:\...\unity.log"
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

static int inject_dll(HANDLE hProc, const char *dllPath)
{
    SIZE_T len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { printf("  VirtualAllocEx 失败: %lu\n", GetLastError()); return 0; }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remote, dllPath, len, &written))
    {
        printf("  WriteProcessMemory 失败: %lu\n", GetLastError());
        return 0;
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadlib = GetProcAddress(k32, "LoadLibraryA");
    HANDLE th = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, remote, 0, NULL);
    if (!th) { printf("  CreateRemoteThread 失败: %lu\n", GetLastError()); return 0; }
    WaitForSingleObject(th, 30000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    printf("  daiyan 注入结果: %s (0x%lX)\n", code ? "成功" : "失败", code);
    return code != 0;
}

int main(int argc, char **argv)
{
    SetConsoleOutputCP(65001);
    /* 参数若被空格截断，回退到默认游戏目录 */
    const char *gamedir = "E:\\GF2\\GF2Exilium\\GF2 Game\\GF2 Game\\GF2 Game";
    if (argc > 1 && strstr(argv[1], "GF2 Game"))
        gamedir = argv[1];
    else if (argc > 1)
        printf("参数看起来被空格截断了(得到: %s)，改用默认游戏目录\n", argv[1]);
    const char *logfile = argc > 2 ? argv[2] : "E:\\残服务端破解\\03_中间产物\\GF2_lua\\unity.log";

    char exe[MAX_PATH], dll[MAX_PATH], cmd[MAX_PATH * 3];
    wsprintfA(exe, "%s\\GF2_Exilium.exe", gamedir);
    wsprintfA(dll, "%s\\daiyan.dll", gamedir);
    wsprintfA(cmd, "\"%s\" -logFile \"%s\"", exe, logfile);

    if (GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES) { printf("找不到 %s\n", exe); return 2; }
    printf("启动: %s\n", cmd);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, gamedir, &si, &pi))
    {
        printf("CreateProcess 失败: %lu\n", GetLastError());
        return 3;
    }
    printf("已挂起创建，PID=%lu\n", pi.dwProcessId);

    if (GetFileAttributesA(dll) != INVALID_FILE_ATTRIBUTES)
    {
        inject_dll(pi.hProcess, dll);
    }
    else
    {
        printf("警告：找不到 daiyan.dll，直接恢复运行（可能连官方服）\n");
    }

    ResumeThread(pi.hThread);
    printf("已恢复运行。日志: %s\n", logfile);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

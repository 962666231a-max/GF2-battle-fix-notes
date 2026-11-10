/*
 * sentry 代理 DLL（部署名 sentry.dll）—— 进程内内存扫描器（宽字符版）
 *
 * 为什么用它：GF2 不加载 xlua.dll（Lua 静态编进 GameAssembly），远程注入被 NEP2 拦；
 * 但 sentry.dll 确实会被加载，且只是崩溃上报，代理它风险最低。
 * 所有 266 个导出由 .def 转发给 sentry_real.dll，本 DLL 只做自己的事。
 *
 * 触发扫描：创建文件 <out>\_scan_now.txt（每 300ms 轮询，发现即删并扫一次）
 * 扫描：全进程可读内存，找 Lua 字节码签名 1B 4C 75 61（\x1bLua）
 *       命中处向后抓 256KB → chunk_<地址>_<序号>.lua
 *
 * 注意：路径一律用宽字符 API（CreateFileW / wsprintfW）；
 *       用 CreateFileA + UTF-8 中文字面量会被当 GBK 解释 → 写不进去（已踩过）。
 */

#include <windows.h>
#include <stdio.h>

static HINSTANCE g_self;
static HMODULE g_real;
static WCHAR g_out[MAX_PATH];
static volatile LONG g_chunk_seq = 0;

static void ensure_out(void)
{
    if (g_out[0]) return;
    WCHAR env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"GF2_LUA_OUT", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) lstrcpynW(g_out, env, MAX_PATH);
    else lstrcpynW(g_out, L"E:\\残服务端破解\\03_中间产物\\GF2_lua", MAX_PATH);

    CreateDirectoryW(g_out, NULL);
    WCHAR up[MAX_PATH];
    lstrcpynW(up, g_out, MAX_PATH);
    WCHAR *p = wcsrchr(up, L'\\');
    if (p) { *p = 0; CreateDirectoryW(up, NULL); }
}

static void write_file_w(const WCHAR *path, const void *data, DWORD len)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, data, len, &w, NULL);
    CloseHandle(h);
}

static void log_line_w(const WCHAR *fmt, ...)
{
    ensure_out();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_proxy_log.txt", g_out);
    WCHAR buf[2048];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfW(buf, fmt, ap);
    va_end(ap);

    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD w = 0;
    WriteFile(h, buf, (DWORD)(lstrlenW(buf) * sizeof(WCHAR)), &w, NULL);
    WriteFile(h, L"\r\n", 4, &w, NULL);
    CloseHandle(h);
}

static int scan_once(void)
{
    ensure_out();
    int hits = 0;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    unsigned char *addr = (unsigned char *)si.lpMinimumApplicationAddress;
    unsigned char *end = (unsigned char *)si.lpMaximumApplicationAddress;
    const SIZE_T WIN = 256 * 1024;
    const SIZE_T BLK = 512 * 1024;
    static unsigned char buf[512 * 1024];
    static unsigned char win[256 * 1024];
    HANDLE me = GetCurrentProcess();

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        unsigned char *base = (unsigned char *)mbi.BaseAddress;
        SIZE_T size = mbi.RegionSize;
        int readable = (mbi.State == MEM_COMMIT) &&
                       !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                       (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        if (readable && size >= 4)
        {
            SIZE_T off = 0;
            while (off < size)
            {
                SIZE_T want = (size - off > BLK) ? BLK : (size - off);
                SIZE_T got = 0;
                if (ReadProcessMemory(me, base + off, buf, want, &got) && got >= 4)
                {
                    for (SIZE_T i = 0; i + 4 < got; ++i)
                    {
                        if (buf[i] == 0x1B && buf[i + 1] == 0x4C && buf[i + 2] == 0x75 && buf[i + 3] == 0x61)
                        {
                            unsigned char *hit = base + off + i;
                            SIZE_T remain = (size > (off + i)) ? (size - (off + i)) : 0;
                            SIZE_T wlen = remain > WIN ? WIN : remain;
                            SIZE_T wgot = 0;
                            if (wlen && ReadProcessMemory(me, hit, win, wlen, &wgot) && wgot > 0)
                            {
                                WCHAR path[MAX_PATH * 2];
                                LONG n = InterlockedIncrement(&g_chunk_seq);
                                wsprintfW(path, L"%s\\chunk_%p_%03ld.lua", g_out, hit, n);
                                write_file_w(path, win, (DWORD)wgot);
                                hits++;
                            }
                            i += 16;
                        }
                    }
                }
                off += want;
            }
        }
        addr = base + size;
    }
    log_line_w(L"scan done, hits=%d", hits);
    return hits;
}

static DWORD WINAPI worker(LPVOID p)
{
    (void)p;
    ensure_out();

    WCHAR self[MAX_PATH];
    GetModuleFileNameW(g_self, self, MAX_PATH);
    WCHAR *slash = wcsrchr(self, L'\\');
    if (slash)
    {
        *slash = 0;
        WCHAR real[MAX_PATH * 2];
        wsprintfW(real, L"%s\\sentry_real.dll", self);
        g_real = LoadLibraryW(real);
    }
    log_line_w(L"sentry proxy attached pid=%lu real=%p", GetCurrentProcessId(), g_real);

    WCHAR trigger[MAX_PATH * 2];
    wsprintfW(trigger, L"%s\\_scan_now.txt", g_out);
    for (;;)
    {
        if (GetFileAttributesW(trigger) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteFileW(trigger);
            scan_once();
        }
        Sleep(300);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = inst;
        DisableThreadLibraryCalls(inst);
        HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}

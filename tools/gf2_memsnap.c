/*
 * gf2_memsnap.c —— 全量内存快照（一次抓完，之后离线慢慢分析）
 *
 * 为什么
 *   · 之前每次都要"触发一次 → 读结果 → 再让你重开游戏"，效率极低
 *   · 客户端运行时的关键数据（解密后的程序集镜像、proto 描述符、IL）都在内存里
 *   ⇒ 一次性把可读内存全部落盘 + 索引，之后用 python 在本地随便翻
 *
 * 产物
 *   <out>\memsnap.bin        顺序拼接的所有区域原始字节
 *   <out>\memsnap_index.txt  每个区域：基址 大小 文件偏移 保护属性 类型
 *   <out>\_memsnap_log.txt   运行日志
 *
 * 触发：<out>\_memsnap_now.txt
 */

#include <windows.h>
#include <stdio.h>

static WCHAR g_sout[MAX_PATH];

static void sp_init(void)
{
    if (g_sout[0]) return;
    WCHAR env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"GF2_LUA_OUT", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) lstrcpynW(g_sout, env, MAX_PATH);
    else lstrcpynW(g_sout, L"L"."", MAX_PATH);
    CreateDirectoryW(g_sout, NULL);
    WCHAR up[MAX_PATH];
    lstrcpynW(up, g_sout, MAX_PATH);
    WCHAR *p = wcsrchr(up, L'\\');
    if (p) { *p = 0; CreateDirectoryW(up, NULL); }
}

static void splog(const WCHAR *fmt, ...)
{
    sp_init();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_memsnap_log.txt", g_sout);
    WCHAR buf[2048];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfW(buf, fmt, ap);
    va_end(ap);
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD w = 0;
    WriteFile(h, buf, (DWORD)(lstrlenW(buf) * sizeof(WCHAR)), &w, NULL);
    WriteFile(h, L"\r\n", 4, &w, NULL);
    CloseHandle(h);
}

static const char *prot_name(DWORD p)
{
    switch (p & 0xFF)
    {
    case PAGE_READONLY: return "R";
    case PAGE_READWRITE: return "RW";
    case PAGE_WRITECOPY: return "WC";
    case PAGE_EXECUTE: return "X";
    case PAGE_EXECUTE_READ: return "XR";
    case PAGE_EXECUTE_READWRITE: return "XRW";
    case PAGE_EXECUTE_WRITECOPY: return "XWC";
    default: return "?";
    }
}

static const char *type_name(DWORD t)
{
    switch (t)
    {
    case MEM_IMAGE: return "IMAGE";
    case MEM_MAPPED: return "MAPPED";
    case MEM_PRIVATE: return "PRIVATE";
    default: return "?";
    }
}

extern "C" void gf2_memsnap_run(void)
{
    sp_init();
    WCHAR binPath[MAX_PATH * 2], idxPath[MAX_PATH * 2];
    wsprintfW(binPath, L"%s\\memsnap.bin", g_sout);
    wsprintfW(idxPath, L"%s\\memsnap_index.txt", g_sout);

    HANDLE me = GetCurrentProcess();
    HANDLE hbin = CreateFileW(binPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hbin == INVALID_HANDLE_VALUE) { splog(L"[memsnap] 建 bin 失败"); return; }
    HANDLE hidx = CreateFileW(idxPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);

    LARGE_INTEGER li0;
    li0.QuadPart = 0;
    SetFilePointerEx(hbin, li0, NULL, FILE_BEGIN);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE *addr = (BYTE *)si.lpMinimumApplicationAddress;
    BYTE *end = (BYTE *)si.lpMaximumApplicationAddress;
    static BYTE buf[1024 * 1024];
    unsigned long long total = 0, regions = 0, skipped = 0;
    DWORD t0 = GetTickCount();

    splog(L"[memsnap] 开始");
    MEMORY_BASIC_INFORMATION mbi;
    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        BYTE *base = (BYTE *)mbi.BaseAddress;
        SIZE_T size = mbi.RegionSize;
        int ok = (mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                 (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                 PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        if (ok && mbi.Type == MEM_MAPPED) ok = 0;           /* 资源映射不需要，跳过 */
        if (ok && size > 256 * 1024 * 1024) size = 256 * 1024 * 1024;  /* 单区上限 */
        if (ok && size > 0)
        {
            unsigned long long startOff = total;
            SIZE_T off = 0;
            SIZE_T good = 0;
            while (off < size)
            {
                SIZE_T want = (size - off > sizeof(buf)) ? sizeof(buf) : (size - off);
                SIZE_T got = 0;
                DWORD w = 0;
                if (ReadProcessMemory(me, base + off, buf, want, &got) && got > 0)
                {
                    WriteFile(hbin, buf, (DWORD)got, &w, NULL);
                    total += got;
                    good += got;
                }
                else
                {
                    /* 坏页：填 0 保持偏移连续 */
                    SIZE_T fill = (want > 64 * 1024) ? 64 * 1024 : want;
                    memset(buf, 0, fill);
                    WriteFile(hbin, buf, (DWORD)fill, &w, NULL);
                    total += fill;
                }
                off += want;
            }
            if (hidx != INVALID_HANDLE_VALUE)
            {
                char line[256];
                wsprintfA(line, "%p %u %u %s %s\r\n", base, (unsigned)size, (unsigned)startOff,
                          prot_name(mbi.Protect), type_name(mbi.Type));
                DWORD w = 0;
                WriteFile(hidx, line, (DWORD)lstrlenA(line), &w, NULL);
            }
            regions++;
        }
        else
        {
            skipped++;
        }
        addr = base + size;
    }

    if (hidx != INVALID_HANDLE_VALUE) CloseHandle(hidx);
    CloseHandle(hbin);
    splog(L"[memsnap] 完成：区域 %lu，跳过 %lu，写入 %.2f MB，耗时 %lu ms", regions, skipped,
          (double)total / 1048576.0, GetTickCount() - t0);
}

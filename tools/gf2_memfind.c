/*
 * gf2_memfind.c —— 进程内字符串搜索器（侧载 DLL 用）
 *
 * 为什么需要
 *   · 客户端程序集被字符串加密保护（静态文件里没有明文描述符/base64，IL 也是坏的）
 *   · 运行时这些字符串会被解密到托管堆里
 *   ⇒ 在进程内搜 UTF-16LE / UTF-8 两种编码，命中处 dump 前后若干 KB
 *
 * 用法
 *   1) 把要找的字符串写到 <out>\_memfind_target.txt（UTF-8，单行）
 *   2) 创建 <out>\_memfind_now.txt 触发
 *   3) 结果：<out>\_memfind_hits.txt（命中地址 + 附近的可读串）
 *            <out>\memdump_<addr>.bin（原始字节，方便离线解析）
 *
 * 说明
 *   · 只读本进程内存，用 ReadProcessMemory 读自己，坏页安全跳过
 *   · 每次触发扫一遍，扫完自动写入结果
 */

#include <windows.h>
#include <stdio.h>

static WCHAR g_mfout[MAX_PATH];

static void mf_init(void)
{
    if (g_mfout[0]) return;
    WCHAR env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"GF2_LUA_OUT", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) lstrcpynW(g_mfout, env, MAX_PATH);
    else lstrcpynW(g_mfout, L"L"."", MAX_PATH);
    CreateDirectoryW(g_mfout, NULL);
    WCHAR up[MAX_PATH];
    lstrcpynW(up, g_mfout, MAX_PATH);
    WCHAR *p = wcsrchr(up, L'\\');
    if (p) { *p = 0; CreateDirectoryW(up, NULL); }
}

static void mflog(const WCHAR *fmt, ...)
{
    mf_init();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_memfind_log.txt", g_mfout);
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

/* 读 UTF-8 目标文件 */
static BOOL read_target(char *buf, DWORD cap, DWORD *len)
{
    mf_init();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_memfind_target.txt", g_mfout);
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD got = 0;
    ReadFile(h, buf, cap - 1, &got, NULL);
    CloseHandle(h);
    buf[got] = 0;
    /* 去掉换行/空白 */
    while (got > 0 && (buf[got-1] == '\n' || buf[got-1] == '\r' || buf[got-1] == ' ')) buf[--got] = 0;
    *len = got;
    return got > 0;
}

static HANDLE g_hits = INVALID_HANDLE_VALUE;

static void hit_write(const char *utf8)
{
    if (g_hits == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(g_hits, utf8, (DWORD)lstrlenA(utf8), &w, NULL);
    WriteFile(g_hits, "\r\n", 2, &w, NULL);
}

extern "C" void gf2_memfind_run(void)
{
    mf_init();
    char needle[256];
    DWORD nlen = 0;
    if (!read_target(needle, sizeof(needle), &nlen))
    {
        mflog(L"[memfind] 没有 _memfind_target.txt 或为空");
        return;
    }

    /* 两种编码 */
    BYTE pat8[256]; DWORD p8len = nlen;
    BYTE pat16[512]; DWORD p16len = 0;
    for (DWORD i = 0; i < nlen; ++i) pat8[i] = (BYTE)needle[i];
    {
        WCHAR wbuf[128];
        int wn = MultiByteToWideChar(CP_UTF8, 0, needle, (int)nlen, wbuf, 128);
        if (wn > 0)
        {
            memcpy(pat16, wbuf, wn * sizeof(WCHAR));
            p16len = (DWORD)(wn * sizeof(WCHAR));
        }
    }

    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_memfind_hits.txt", g_mfout);
    g_hits = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);

    HANDLE me = GetCurrentProcess();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE *addr = (BYTE *)si.lpMinimumApplicationAddress;
    BYTE *end = (BYTE *)si.lpMaximumApplicationAddress;
    static BYTE buf[1024 * 1024];
    int hits = 0;

    mflog(L"[memfind] 开始搜索 \"%S\"（UTF-8 %lu 字节 / UTF-16 %lu 字节）", needle,
          (unsigned long)p8len, (unsigned long)p16len);

    /* 自身栈与模块范围：用于过滤"搜到自己"的假命中 */
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    BYTE *stackLo = (BYTE *)tib->StackLimit;
    BYTE *stackHi = (BYTE *)tib->StackBase;
    HMODULE selfMod = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&gf2_memfind_run, &selfMod);
    BYTE *selfBase = (BYTE *)selfMod;

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        BYTE *base = (BYTE *)mbi.BaseAddress;
        SIZE_T size = mbi.RegionSize;
        int ok = (mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                 (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                 PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        if (ok && size >= 8)
        {
            SIZE_T off = 0;
            while (off < size)
            {
                SIZE_T want = (size - off > sizeof(buf)) ? sizeof(buf) : (size - off);
                SIZE_T got = 0;
                if (ReadProcessMemory(me, base + off, buf, want, &got) && got >= 8)
                {
                    for (SIZE_T i = 0; i + p8len <= got; ++i)
                    {
                        int m8 = (i + p8len <= got) && memcmp(buf + i, pat8, p8len) == 0;
                        int m16 = (p16len && i + p16len <= got) && memcmp(buf + i, pat16, p16len) == 0;
                        if (!m8 && !m16) continue;

                        BYTE *hit = base + off + i;
                        if (hit >= stackLo && hit < stackHi) { i += 8; continue; }
                        if (selfBase && hit >= selfBase && hit < selfBase + 0x4000000) { i += 8; continue; }
                        char line[512];
                        wsprintfA(line, "HIT %p  kind=%s  region=[%p,%p)", hit, m8 ? "utf8" : "utf16",
                                  base, base + size);
                        hit_write(line);

                        /* dump 前后 8KB */
                        SIZE_T back = 8192, fwd = 8192;
                        BYTE *s = (hit > base + back) ? hit - back : base;
                        SIZE_T len = (SIZE_T)(hit - s) + fwd;
                        if (len > 65536) len = 65536;
                        static BYTE win[65536];
                        SIZE_T wgot = 0;
                        if (ReadProcessMemory(me, s, win, len, &wgot) && wgot > 0)
                        {
                            WCHAR dump[MAX_PATH * 2];
                            wsprintfW(dump, L"%s\\memdump_%p.bin", g_mfout, hit);
                            HANDLE dh = CreateFileW(dump, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                            if (dh != INVALID_HANDLE_VALUE)
                            {
                                DWORD dw = 0;
                                WriteFile(dh, win, (DWORD)wgot, &dw, NULL);
                                CloseHandle(dh);
                            }
                            /* 顺便把附近的可读串写进 hits 文件 */
                            char runs[2048];
                            int rl = 0;
                            for (SIZE_T k = 0; k < wgot && rl < 1900; ++k)
                            {
                                BYTE c = win[k];
                                runs[rl++] = (c >= 32 && c < 127) ? (char)c : ' ';
                            }
                            runs[rl] = 0;
                            hit_write("    nearby:");
                            hit_write(runs);
                        }
                        /* 自过滤：窗口里含我们自己的路径/日志标记就跳过 */
                        int self = 0;
                        for (SIZE_T k = 0; k + 8 < wgot; ++k)
                        {
                            if (memcmp(win + k, "_memfind", 8) == 0) { self = 1; break; }
                            if (memcmp(win + k, "GF2_lua", 7) == 0) { self = 1; break; }
                            if (memcmp(win + k, "HIT 0000", 8) == 0) { self = 1; break; }
                        }
                        if (self) { i += 8; continue; }

                        hits++;
                        i += 8;
                        if (hits > 400) { mflog(L"[memfind] 命中过多，提前结束"); goto done; }
                    }
                }
                off += want;
            }
        }
        addr = base + size;
    }
done:
    if (g_hits != INVALID_HANDLE_VALUE) { CloseHandle(g_hits); g_hits = INVALID_HANDLE_VALUE; }
    mflog(L"[memfind] 完成，命中 %d 处", hits);
}

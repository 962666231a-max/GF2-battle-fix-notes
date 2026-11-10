/*
 * gf2_imgdump.c —— 进程内 dump「已加载的托管程序集镜像」
 *
 * 背景
 *   · NetworkProtocol.dll 的方法体是加密的（元数据/字符串明文，IL 乱码）
 *   · 加载器会在运行时解密方法体 → 内存里一定存在明文 IL 的镜像
 *   · 所以：在进程内找到已加载的 .NET 镜像（BSJB 元数据签名 → 回溯 MZ/PE 头），
 *     整块 dump 出来，再离线反编译
 *
 * 触发：<out>\_imgdump_now.txt
 * 产物：<out>\imgdump_<基址>_<大小>.bin   （每个候选镜像一个文件）
 * 日志：<out>\_imgdump_log.txt
 */

#include <windows.h>
#include <stdio.h>

static WCHAR g_iout[MAX_PATH];

static void id_init(void)
{
    if (g_iout[0]) return;
    WCHAR env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"GF2_LUA_OUT", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) lstrcpynW(g_iout, env, MAX_PATH);
    else lstrcpynW(g_iout, L"E:\\残服务端破解\\03_中间产物\\GF2_lua", MAX_PATH);
    CreateDirectoryW(g_iout, NULL);
    WCHAR up[MAX_PATH];
    lstrcpynW(up, g_iout, MAX_PATH);
    WCHAR *p = wcsrchr(up, L'\\');
    if (p) { *p = 0; CreateDirectoryW(up, NULL); }
}

static void idlog(const WCHAR *fmt, ...)
{
    id_init();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_imgdump_log.txt", g_iout);
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

/* 校验 addr 处是否是合法 PE 头 */
static BOOL is_pe_header(BYTE *addr, SIZE_T avail, SIZE_T *imageSize)
{
    if (avail < 0x200) return FALSE;
    if (addr[0] != 'M' || addr[1] != 'Z') return FALSE;
    DWORD e_lfanew = *(DWORD *)(addr + 0x3C);
    if (e_lfanew < 0x40 || e_lfanew > 0x400) return FALSE;
    if ((SIZE_T)e_lfanew + 0x100 > avail) return FALSE;
    if (memcmp(addr + e_lfanew, "PE\0\0", 4) != 0) return FALSE;
    WORD magic = *(WORD *)(addr + e_lfanew + 24);
    if (magic != 0x10B && magic != 0x20B) return FALSE;
    DWORD sizeOfImage = *(DWORD *)(addr + e_lfanew + 24 + 56);
    if (sizeOfImage < 0x1000 || sizeOfImage > 512 * 1024 * 1024) return FALSE;
    *imageSize = sizeOfImage;
    return TRUE;
}

extern "C" void gf2_imgdump_run(void)
{
    id_init();
    HANDLE me = GetCurrentProcess();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE *addr = (BYTE *)si.lpMinimumApplicationAddress;
    BYTE *end = (BYTE *)si.lpMaximumApplicationAddress;
    static BYTE buf[1024 * 1024];
    int dumped = 0;

    /* 自身栈范围（跳过，避免把我们的缓冲当成镜像） */
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    BYTE *stackLo = (BYTE *)tib->StackLimit, *stackHi = (BYTE *)tib->StackBase;

    idlog(L"[imgdump] 开始扫描已加载镜像");

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        BYTE *base = (BYTE *)mbi.BaseAddress;
        SIZE_T size = mbi.RegionSize;
        int ok = (mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                 (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                 PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        if (ok && size >= 0x1000)
        {
            SIZE_T off = 0;
            while (off < size)
            {
                SIZE_T want = (size - off > sizeof(buf)) ? sizeof(buf) : (size - off);
                SIZE_T got = 0;
                if (ReadProcessMemory(me, base + off, buf, want, &got) && got >= 8)
                {
                    for (SIZE_T i = 0; i + 4 <= got; ++i)
                    {
                        if (!(buf[i] == 'B' && buf[i+1] == 'S' && buf[i+2] == 'J' && buf[i+3] == 'B')) continue;
                        BYTE *bsjb = base + off + i;
                        if (bsjb >= stackLo && bsjb < stackHi) continue;

                        /* 回溯找 MZ：最多往前 16MB */
                        SIZE_T back = 16 * 1024 * 1024;
                        BYTE *lowLimit = (BYTE *)si.lpMinimumApplicationAddress;
                        BYTE *scanLo = ((SIZE_T)(bsjb - lowLimit) > back) ? bsjb - back : lowLimit;
                        BYTE *p = bsjb;
                        BOOL found = FALSE;
                        SIZE_T imgSize = 0;
                        static BYTE hdr[0x400];
                        while (p > scanLo)
                        {
                            SIZE_T chunk = (p - scanLo > 0x10000) ? 0x10000 : (SIZE_T)(p - scanLo);
                            BYTE *start = p - chunk;
                            SIZE_T g = 0;
                            if (!ReadProcessMemory(me, start, buf, chunk, &g) || g < 2) break;
                            for (SIZE_T k = g - 2; k > 0; --k)
                            {
                                if (buf[k] == 'M' && buf[k+1] == 'Z')
                                {
                                    BYTE *cand = start + k;
                                    SIZE_T got2 = 0;
                                    if (ReadProcessMemory(me, cand, hdr, sizeof(hdr), &got2) && got2 == sizeof(hdr)
                                        && is_pe_header(hdr, got2, &imgSize))
                                    {
                                        p = cand; found = TRUE; break;
                                    }
                                }
                            }
                            if (found) break;
                            p = start;
                        }
                        if (!found) { i += 4; continue; }

                        /* dump 整个镜像 */
                        WCHAR path[MAX_PATH * 2];
                        wsprintfW(path, L"%s\\imgdump_%p_%lu.bin", g_iout, p, (unsigned long)imgSize);
                        HANDLE fh = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (fh != INVALID_HANDLE_VALUE)
                        {
                            DWORD w = 0;
                            SIZE_T left = imgSize;
                            BYTE *cur = p;
                            SIZE_T written = 0;
                            while (left)
                            {
                                SIZE_T ask = left > sizeof(buf) ? sizeof(buf) : left;
                                SIZE_T g3 = 0;
                                if (!ReadProcessMemory(me, cur, buf, ask, &g3) || !g3) break;
                                WriteFile(fh, buf, (DWORD)g3, &w, NULL);
                                written += g3; cur += g3; left -= g3;
                            }
                            CloseHandle(fh);
                            idlog(L"[imgdump] 镜像 base=%p size=%lu 写入 %lu 字节 → %s", p,
                                  (unsigned long)imgSize, (unsigned long)written, path);
                            dumped++;
                        }
                        i += 4;
                        if (dumped >= 12) goto done;
                    }
                }
                off += want;
            }
        }
        addr = base + size;
    }
done:
    idlog(L"[imgdump] 完成，dump 了 %d 个镜像", dumped);
}

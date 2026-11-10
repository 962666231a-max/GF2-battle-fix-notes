/*
 * gf2_readhook.c —— 钩 NEP2/GameAssembly 的文件读取与内存映射，抓解密后的 UnityFS
 *
 * 演进过程（都已实测）
 *   · AES 断点（NEP2 内联 AES-NI）在进副本时 0 命中 → AES 不是 bundle 解密用的
 *   · 钩 NEP2 的 ReadFile：装上了（patched=1）但 0 命中 → bundle 不是 ReadFile 读的
 *   · NEP2 / GameAssembly / UnityPlayer 都导入 MapViewOfFile ⇒ 走 mmap
 *
 * 本版做法
 *   1) 对 NEP2.dll 和 GameAssembly.dll 同时改导入表：
 *        KERNEL32!ReadFile        → 记录 (buf,size)
 *        KERNEL32!MapViewOfFile   → 记录 (映射基址, 0=未知)
 *        KERNEL32!CreateFileW     → 记日志（看它打开了哪些 .bundle）
 *   2) 后台线程轮询这些地址，出现真 UnityFS（且头部字段合理）就按声明长度落盘
 *
 * 输出：<out>\read_<序号>_<大小>.bundle（可直接喂 UnityPy）
 */

#include <windows.h>
#include <stdio.h>

#define RING 96

typedef BOOL(WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef LPVOID(WINAPI *fn_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef HANDLE(WINAPI *fn_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI *fn_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);

/* 映射句柄 → 文件长度（CreateFileMappingW 时记下，MapViewOfFile 时用） */
#define MAPTAB 256
static struct { HANDLE h; SIZE_T size; } g_maptab[MAPTAB];
static volatile LONG g_mapi = 0;
static fn_CreateFileMappingW g_orig_mapcreate = NULL;
static SIZE_T lookup_mapsize(HANDLE hMap);

static fn_ReadFile g_orig_read = NULL;
static fn_MapViewOfFile g_orig_map = NULL;
static fn_CreateFileW g_orig_create = NULL;
static WCHAR g_outh[MAX_PATH];

typedef struct { LPVOID buf; DWORD size; DWORD stamp; volatile LONG done; } SLOT;
static SLOT g_ring[RING];
static volatile LONG g_ri = 0;
static volatile LONG g_seq2 = 0;

static void outh_init(void)
{
    if (g_outh[0]) return;
    WCHAR env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"GF2_LUA_OUT", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) lstrcpynW(g_outh, env, MAX_PATH);
    else lstrcpynW(g_outh, L"E:\\残服务端破解\\03_中间产物\\GF2_lua", MAX_PATH);
    CreateDirectoryW(g_outh, NULL);
    WCHAR up[MAX_PATH];
    lstrcpynW(up, g_outh, MAX_PATH);
    WCHAR *p = wcsrchr(up, L'\\');
    if (p) { *p = 0; CreateDirectoryW(up, NULL); }
}

static void rhlog(const WCHAR *fmt, ...)
{
    outh_init();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_readhook_log.txt", g_outh);
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

static void record(LPVOID buf, DWORD size)
{
    LONG i = InterlockedIncrement(&g_ri) % RING;
    g_ring[i].buf = buf;
    g_ring[i].size = size;
    g_ring[i].stamp = GetTickCount();
    g_ring[i].done = 0;
}

static BOOL WINAPI hook_ReadFile(HANDLE hFile, LPVOID buf, DWORD nBytes, LPDWORD lpRead, LPOVERLAPPED ov)
{
    BOOL ok = g_orig_read ? g_orig_read(hFile, buf, nBytes, lpRead, ov) : FALSE;
    if (ok && buf && lpRead && *lpRead > 8) record(buf, *lpRead);
    return ok;
}

static LPVOID WINAPI hook_MapViewOfFile(HANDLE hMap, DWORD access, DWORD hi, DWORD lo, SIZE_T n)
{
    LPVOID p = g_orig_map ? g_orig_map(hMap, access, hi, lo, n) : NULL;
    if (p)
    {
        SIZE_T fsz = lookup_mapsize(hMap);
        if (!fsz) fsz = n;
        record(p, (DWORD)fsz);
    }
    return p;
}

static HANDLE WINAPI hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share,
                                      LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl)
{
    HANDLE h = g_orig_create ? g_orig_create(name, access, share, sa, disp, flags, tmpl) : INVALID_HANDLE_VALUE;
    if (name && wcsstr(name, L".bundle"))
        rhlog(L"[open] %s", name);
    return h;
}

static HANDLE WINAPI hook_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES sa, DWORD protect,
                                              DWORD maxHigh, DWORD maxLow, LPCWSTR name)
{
    HANDLE h = g_orig_mapcreate ? g_orig_mapcreate(hFile, sa, protect, maxHigh, maxLow, name) : NULL;
    if (h)
    {
        SIZE_T size = 0;
        if (maxHigh || maxLow)
        {
            size = ((SIZE_T)maxHigh << 32) | maxLow;
        }
        else if (hFile && hFile != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER li;
            if (GetFileSizeEx(hFile, &li)) size = (SIZE_T)li.QuadPart;
        }
        LONG i = InterlockedIncrement(&g_mapi) % MAPTAB;
        g_maptab[i].h = h;
        g_maptab[i].size = size;
    }
    return h;
}

static SIZE_T lookup_mapsize(HANDLE hMap)
{
    for (int i = 0; i < MAPTAB; ++i)
        if (g_maptab[i].h == hMap && g_maptab[i].size) return g_maptab[i].size;
    return 0;
}

/* 解析 UnityFS 头，返回声明长度；不合理返回 0 */
static long long parse_unityfs(const BYTE *b, DWORD avail, DWORD *hdr_ok)
{
    *hdr_ok = 0;
    if (avail < 32) return 0;
    if (memcmp(b, "UnityFS\x00", 8) != 0) return 0;
    int p = 12;
    int guard = 0;
    /* version 字符串 */
    while (p < (int)avail && b[p] && guard++ < 64) p++;
    if (p >= (int)avail) return 0;
    p++;
    guard = 0;
    while (p < (int)avail && b[p] && guard++ < 64) p++;
    if (p >= (int)avail) return 0;
    p++;
    if (p + 8 > (int)avail) return 0;
    long long size = 0;
    for (int k = 0; k < 8; ++k) size = (size << 8) | b[p + k];
    if (size <= 64 || size > (long long)4 * 1024 * 1024 * 1024) return 0;
    *hdr_ok = 1;
    return size;
}

static DWORD WINAPI poller(LPVOID p)
{
    (void)p;
    outh_init();
    for (;;)
    {
        for (int i = 0; i < RING; ++i)
        {
            if (g_ring[i].done || !g_ring[i].buf) continue;
            if (GetTickCount() - g_ring[i].stamp > 4000) { g_ring[i].done = 1; continue; }

            BYTE head[128];
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), g_ring[i].buf, head, sizeof(head), &got) || got < 32)
                continue;
            if (memcmp(head, "UnityFS\x00", 8) != 0) continue;

            DWORD ok = 0;
            long long declared = parse_unityfs(head, (DWORD)got, &ok);
            if (!ok)
            {
                rhlog(L"[skip] UnityFS 假头 @%p (后面: %S)", g_ring[i].buf, head + 8);
                g_ring[i].done = 1;
                continue;
            }

            /* 读取窗口上限：用 VirtualQuery 拿到所在区域剩余大小，
               否则声明长度大于缓冲时会截断（之前 32768 截断的根因） */
            SIZE_T avail = 0;
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(g_ring[i].buf, &mbi, sizeof(mbi)) == sizeof(mbi))
            {
                BYTE *regionEnd = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
                if (regionEnd > (BYTE *)g_ring[i].buf)
                    avail = (SIZE_T)(regionEnd - (BYTE *)g_ring[i].buf);
            }
            /* 取「头部声明长度 / 映射文件长度 / 区域可用大小」三者的合理最大值，
               再被区域可用大小夹住，避免又一次退回 32KB */
            /* 不再用 avail 夹长度（Windows 对映射视图的 RegionSize 只报 32KB 一段，
               会把手里的包截断）。直接按 声明长度/文件长度 取大者，读到失败为止。 */
            SIZE_T wantT = (SIZE_T)declared;
            if ((SIZE_T)g_ring[i].size > wantT) wantT = g_ring[i].size;
            if (wantT == 0 || wantT > (SIZE_T)512 * 1024 * 1024) wantT = (SIZE_T)512 * 1024 * 1024;
            DWORD want = (DWORD)wantT;
            rhlog(L"[calc] declared=%d mapsize=%d want=%d", (int)declared,
                  (int)g_ring[i].size, (int)want);

            WCHAR path[MAX_PATH * 2];
            LONG n = InterlockedIncrement(&g_seq2);
            wsprintfW(path, L"%s\\read_%03ld_%lu.bundle", g_outh, n, want);
            HANDLE fh = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (fh != INVALID_HANDLE_VALUE)
            {
                DWORD w = 0;
                static BYTE chunk[65536];
                DWORD left = want;
                BYTE *cur = (BYTE *)g_ring[i].buf;
                DWORD written = 0;
                while (left)
                {
                    DWORD ask = left > sizeof(chunk) ? sizeof(chunk) : left;
                    SIZE_T g2 = 0;
                    if (!ReadProcessMemory(GetCurrentProcess(), cur, chunk, ask, &g2) || !g2) break;
                    WriteFile(fh, chunk, (DWORD)g2, &w, NULL);
                    written += (DWORD)g2;
                    cur += g2;
                    left -= (DWORD)g2;
                }
                CloseHandle(fh);
                rhlog(L"[hit] UnityFS 落盘 %s（声明 %lld，写入 %lu）", path, declared, written);
            }
            g_ring[i].done = 1;
        }
        Sleep(30);
    }
    return 0;
}

static int patch(HMODULE mod, const char *dllname, const char *func, void *fn, void **orig)
{
    if (!mod) return 0;
    BYTE *base = (BYTE *)mod;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp.VirtualAddress) return 0;
    IMAGE_IMPORT_DESCRIPTOR *d = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp.VirtualAddress);
    for (; d->Name; ++d)
    {
        const char *dll = (const char *)(base + d->Name);
        if (_stricmp(dll, dllname) != 0) continue;
        IMAGE_THUNK_DATA *o = (IMAGE_THUNK_DATA *)(base + d->OriginalFirstThunk);
        IMAGE_THUNK_DATA *f = (IMAGE_THUNK_DATA *)(base + d->FirstThunk);
        if (!d->OriginalFirstThunk) o = f;
        for (int i = 0; o[i].u1.AddressOfData; ++i)
        {
            if (IMAGE_SNAP_BY_ORDINAL(o[i].u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + o[i].u1.AddressOfData);
            if (strcmp((const char *)ibn->Name, func) != 0) continue;
            DWORD old = 0;
            void **slot = (void **)&f[i].u1.Function;
            if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old)) return 0;
            if (orig && !*orig) *orig = *slot;
            *slot = fn;
            VirtualProtect(slot, sizeof(void *), old, &old);
            return 1;
        }
    }
    return 0;
}

extern "C" void gf2_readhook_install(void)
{
    outh_init();
    if (g_orig_read) return;
    HMODULE mods[2] = {NULL, NULL};
    for (int i = 0; i < 800; ++i)
    {
        mods[0] = GetModuleHandleA("NEP2.dll");
        mods[1] = GetModuleHandleA("GameAssembly.dll");
        if (mods[0] && mods[1]) break;
        Sleep(200);
    }
    int n = 0;
    for (int m = 0; m < 2; ++m)
    {
        HMODULE h = mods[m];
        if (!h) continue;
        n += patch(h, "KERNEL32.dll", "ReadFile", (void *)hook_ReadFile, (void **)&g_orig_read);
        n += patch(h, "KERNEL32.dll", "MapViewOfFile", (void *)hook_MapViewOfFile, (void **)&g_orig_map);
        n += patch(h, "KERNEL32.dll", "CreateFileW", (void *)hook_CreateFileW, (void **)&g_orig_create);
        n += patch(h, "KERNEL32.dll", "CreateFileMappingW", (void *)hook_CreateFileMappingW, (void **)&g_orig_mapcreate);
    }
    rhlog(L"[install] 补丁数=%d (read=%p map=%p create=%p)", n, g_orig_read, g_orig_map, g_orig_create);
    if (n)
    {
        HANDLE t = CreateThread(NULL, 0, poller, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
}

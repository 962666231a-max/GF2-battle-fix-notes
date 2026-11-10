/*
 * xinput1_3.dll —— GF2 Lua 侧载钩子（照搬崩坏3的"侧载当内鬼"套路）
 *
 * 为什么这样：GF2 有完整性校验（改 Plugins 里的 DLL 会触发 28GB 重下），
 * 但 UnityPlayer 会**优先从游戏目录**加载 xinput1_3.dll，这个文件不在它的校验清单里。
 * 放一个同名代理进去即可在进程内执行代码：
 *   · 不需要注入、不需要外部写句柄、反作弊不杀进程
 *   · 卸载 = 删掉这个 DLL
 *
 * 本 DLL 做的事：
 *   1) 代理 XInput（转发给系统的 xinput1_4.dll），保证手柄/游戏调用不炸
 *   2) 等 xlua.dll + GameAssembly.dll 就绪后，改写 GameAssembly 的导入表：
 *        xlua.dll!xluaL_loadbuffer   → 我们的钩子（★ 这是游戏真正调用的入口）
 *        xlua.dll!luaL_loadbufferx   → 我们的钩子（备用）
 *        xlua.dll!luaL_loadstring    → 我们的钩子
 *      钩子先落盘 Lua 字节码，再调原函数，游戏行为不变
 *
 * 输出目录：E:\残服务端破解\03_中间产物\GF2_lua\（宽字符 API，中文路径安全）
 * 日志：_sideload_log.txt（每次加载都写，便于确认生效）
 */

#include <windows.h>
#include <stdio.h>

typedef DWORD(WINAPI *fn_XInputGetState)(DWORD, void *);
typedef DWORD(WINAPI *fn_XInputSetState)(DWORD, void *);
typedef DWORD(WINAPI *fn_XInputGetCapabilities)(DWORD, DWORD, void *);
typedef void(WINAPI *fn_XInputEnable)(BOOL);
typedef DWORD(WINAPI *fn_XInputGetBatteryInformation)(DWORD, BYTE, void *);
typedef DWORD(WINAPI *fn_XInputGetKeystroke)(DWORD, DWORD, void *);

static fn_XInputGetState g_getstate;
static fn_XInputSetState g_setstate;
static fn_XInputGetCapabilities g_getcaps;
static fn_XInputEnable g_enable;
static fn_XInputGetBatteryInformation g_getbatt;
static fn_XInputGetKeystroke g_getkey;

typedef int (*fn_loadbuffer)(void *L, const char *buf, size_t sz, const char *name);
typedef int (*fn_loadbufferx)(void *L, const char *buf, size_t sz, const char *name, const char *mode);
typedef int (*fn_loadstring)(void *L, const char *s);

static fn_loadbuffer  g_orig_xlb = NULL;
static fn_loadbufferx g_orig_lbx = NULL;
static fn_loadstring  g_orig_ls = NULL;
static volatile LONG  g_seq = 0;

extern "C" void gf2_aesbp_arm(void);
extern "C" void gf2_readhook_install(void);
extern "C" void gf2_il2dump_run(void);
extern "C" void gf2_memfind_run(void);
extern "C" void gf2_imgdump_run(void);
extern "C" void gf2_memsnap_run(void);
static WCHAR g_out[MAX_PATH];

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

static void logw(const WCHAR *fmt, ...)
{
    ensure_out();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_sideload_log.txt", g_out);
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

static void dump_script(const char *tag, const char *name, const char *buf, size_t sz)
{
    if (!buf || sz == 0 || sz > 64 * 1024 * 1024) return;
    ensure_out();
    WCHAR safe[180];
    const char *src = (name && *name) ? name : tag;
    MultiByteToWideChar(CP_UTF8, 0, src, -1, safe, 180);
    for (WCHAR *p = safe; *p; ++p)
        if (*p < 32 || wcschr(L"\\/:*?\"<>|", *p)) *p = L'_';

    WCHAR path[MAX_PATH * 2];
    LONG n = InterlockedIncrement(&g_seq);
    wsprintfW(path, L"%s\\%04ld_%s.lua", g_out, n, safe);
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, buf, (DWORD)sz, &w, NULL);
    CloseHandle(h);
}

static int hook_xluaL_loadbuffer(void *L, const char *buf, size_t sz, const char *name)
{
    dump_script("xlb", name, buf, sz);
    return g_orig_xlb ? g_orig_xlb(L, buf, sz, name) : -1;
}

static int hook_luaL_loadbufferx(void *L, const char *buf, size_t sz, const char *name, const char *mode)
{
    dump_script("lbx", name, buf, sz);
    return g_orig_lbx ? g_orig_lbx(L, buf, sz, name, mode) : -1;
}

static int hook_luaL_loadstring(void *L, const char *s)
{
    dump_script("ls", s, s, s ? strlen(s) : 0);
    return g_orig_ls ? g_orig_ls(L, s) : -1;
}

/* 改目标模块导入表；返回补丁数 */
static int patch_iat(HMODULE mod, const char *dllname, const char *funcname, void *newfn, void **oldfn)
{
    if (!mod) return 0;
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp.VirtualAddress) return 0;

    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp.VirtualAddress);
    for (; desc->Name; ++desc)
    {
        const char *dll = (const char *)(base + desc->Name);
        if (_stricmp(dll, dllname) != 0) continue;
        IMAGE_THUNK_DATA *orig = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *first = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
        if (!desc->OriginalFirstThunk) orig = first;
        for (int i = 0; orig[i].u1.AddressOfData; ++i)
        {
            if (IMAGE_SNAP_BY_ORDINAL(orig[i].u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + orig[i].u1.AddressOfData);
            if (strcmp((const char *)ibn->Name, funcname) != 0) continue;
            DWORD oldprot = 0;
            void **slot = (void **)&first[i].u1.Function;
            if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &oldprot)) return 0;
            if (oldfn && !*oldfn) *oldfn = *slot;
            *slot = newfn;
            VirtualProtect(slot, sizeof(void *), oldprot, &oldprot);
            return 1;
        }
    }
    return 0;
}

static DWORD WINAPI worker(LPVOID p)
{
    (void)p;
    ensure_out();
    logw(L"xinput sideload attach pid=%lu", GetCurrentProcessId());

    /* 只等 GameAssembly；xlua.dll 可能根本不存在（Lua 静态链接） */
    HMODULE ga = NULL;
    for (int i = 0; i < 1500; ++i)
    {
        ga = GetModuleHandleA("GameAssembly.dll");
        if (ga) break;
        Sleep(200);
    }
    HMODULE xlua = GetModuleHandleA("xlua.dll");
    logw(L"modules: ga=%p xlua=%p", ga, xlua);
    if (!ga) return 0;

    /* 先把 GameAssembly 里 xlua.dll 的导入全部列出来（没有就说明静态链接） */
    {
        BYTE *b = (BYTE *)ga;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
        IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_IMPORT_DESCRIPTOR *d = (IMAGE_IMPORT_DESCRIPTOR *)(b + imp.VirtualAddress);
        int cnt = 0;
        for (; d && d->Name; ++d)
        {
            const char *dll = (const char *)(b + d->Name);
            if (_stricmp(dll, "xlua.dll") != 0 && _stricmp(dll, "lua54.dll") != 0) continue;
            logw(L"[import] dll=%S", dll);
            IMAGE_THUNK_DATA *o = (IMAGE_THUNK_DATA *)(b + d->OriginalFirstThunk);
            for (int i = 0; o && o[i].u1.AddressOfData; ++i)
            {
                if (IMAGE_SNAP_BY_ORDINAL(o[i].u1.Ordinal)) continue;
                IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(b + o[i].u1.AddressOfData);
                logw(L"[import]   %S", ibn->Name);
                cnt++;
            }
        }
        logw(L"[import] total xlua/lua imports=%d", cnt);
    }

    int a = 0, b = 0, c = 0;
    if (!g_orig_xlb) g_orig_xlb = (fn_loadbuffer)GetProcAddress(GetModuleHandleA("xlua.dll"), "xluaL_loadbuffer");
    if (!g_orig_lbx) g_orig_lbx = (fn_loadbufferx)GetProcAddress(GetModuleHandleA("xlua.dll"), "luaL_loadbufferx");
    if (!g_orig_ls) g_orig_ls = (fn_loadstring)GetProcAddress(GetModuleHandleA("xlua.dll"), "luaL_loadstring");

    a = patch_iat(ga, "xlua.dll", "xluaL_loadbuffer", (void *)hook_xluaL_loadbuffer, (void **)&g_orig_xlb);
    b = patch_iat(ga, "xlua.dll", "luaL_loadbufferx", (void *)hook_luaL_loadbufferx, (void **)&g_orig_lbx);
    c = patch_iat(ga, "xlua.dll", "luaL_loadstring", (void *)hook_luaL_loadstring, (void **)&g_orig_ls);
    logw(L"[iat] xluaL_loadbuffer=%d luaL_loadbufferx=%d luaL_loadstring=%d", a, b, c);

    if (!a && !b && !c)
    {
        /* 没补上：把导入表里 xlua.dll 的函数名全部列出来，便于排查 */
        BYTE *base = (BYTE *)ga;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
        IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp.VirtualAddress);
        for (; desc->Name; ++desc)
        {
            const char *dll = (const char *)(base + desc->Name);
            if (_stricmp(dll, "xlua.dll") != 0) continue;
            IMAGE_THUNK_DATA *orig = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
            for (int i = 0; orig && orig[i].u1.AddressOfData; ++i)
            {
                if (IMAGE_SNAP_BY_ORDINAL(orig[i].u1.Ordinal)) continue;
                IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + orig[i].u1.AddressOfData);
                logw(L"[import] %S", ibn->Name);
            }
        }
    }

    /* 触发式内存扫描：出现 _scan_now.txt 就扫一次，找 Lua 字节码 1B 4C 75 61 */
    WCHAR trig[MAX_PATH * 2];
    wsprintfW(trig, L"%s\\_scan_now.txt", g_out);
    gf2_readhook_install();

    WCHAR aetrig[MAX_PATH * 2];
    wsprintfW(aetrig, L"%s\\_aesbp_now.txt", g_out);

    for (;;)
    {
        WCHAR sntrig[MAX_PATH * 2];
        wsprintfW(sntrig, L"%s\\_memsnap_now.txt", g_out);
        if (GetFileAttributesW(sntrig) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteFileW(sntrig);
            gf2_memsnap_run();
        }
        WCHAR imtrig[MAX_PATH * 2];
        wsprintfW(imtrig, L"%s\\_imgdump_now.txt", g_out);
        if (GetFileAttributesW(imtrig) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteFileW(imtrig);
            gf2_imgdump_run();
        }
        WCHAR mftrig[MAX_PATH * 2];
        wsprintfW(mftrig, L"%s\\_memfind_now.txt", g_out);
        if (GetFileAttributesW(mftrig) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteFileW(mftrig);
            gf2_memfind_run();
        }
        WCHAR i3trig[MAX_PATH * 2];
        wsprintfW(i3trig, L"%s\\_il2dump_now.txt", g_out);
        if (GetFileAttributesW(i3trig) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteFileW(i3trig);
            gf2_il2dump_run();
        }
        if (GetFileAttributesW(aetrig) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteFileW(aetrig);
            gf2_aesbp_arm();
        }
        if (GetFileAttributesW(trig) != INVALID_FILE_ATTRIBUTES)
        {
            DeleteFileW(trig);
            int hits = 0;
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            unsigned char *addr = (unsigned char *)si.lpMinimumApplicationAddress;
            unsigned char *end = (unsigned char *)si.lpMaximumApplicationAddress;
            static unsigned char buf[512 * 1024];
            static unsigned char win[256 * 1024];
            HANDLE me = GetCurrentProcess();
            MEMORY_BASIC_INFORMATION mbi;
            while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi))
            {
                unsigned char *base = (unsigned char *)mbi.BaseAddress;
                SIZE_T size = mbi.RegionSize;
                int ok = (mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                         (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
                if (ok && size >= 4)
                {
                    SIZE_T off = 0;
                    while (off < size)
                    {
                        SIZE_T want = (size - off > sizeof(buf)) ? sizeof(buf) : (size - off);
                        SIZE_T got = 0;
                        if (ReadProcessMemory(me, base + off, buf, want, &got) && got >= 4)
                        {
                            for (SIZE_T i = 0; i + 4 < got; ++i)
                            {
                                if (buf[i] == 0x1B && buf[i+1] == 0x4C && buf[i+2] == 0x75 && buf[i+3] == 0x61)
                                {
                                    unsigned char *hit = base + off + i;
                                    SIZE_T remain = (size > (off + i)) ? (size - (off + i)) : 0;
                                    SIZE_T wlen = remain > sizeof(win) ? sizeof(win) : remain;
                                    SIZE_T wgot = 0;
                                    if (wlen && ReadProcessMemory(me, hit, win, wlen, &wgot) && wgot > 0)
                                    {
                                        WCHAR path[MAX_PATH * 2];
                                        LONG n = InterlockedIncrement(&g_seq);
                                        wsprintfW(path, L"%s\\chunk_%p_%03ld.lua", g_out, hit, n);
                                        HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                                        if (h != INVALID_HANDLE_VALUE)
                                        {
                                            DWORD w = 0;
                                            WriteFile(h, win, (DWORD)wgot, &w, NULL);
                                            CloseHandle(h);
                                            hits++;
                                        }
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
            logw(L"[scan] hits=%d", hits);
        }
        Sleep(300);
    }
    return 0;
}

/* ---------------- XInput 代理实现 ---------------- */
static HMODULE real_xinput(void)
{
    static HMODULE h = NULL;
    if (!h)
    {
        h = LoadLibraryA("xinput1_4.dll");
        if (!h) h = LoadLibraryA("xinput9_1_0.dll");
        if (!h) h = LoadLibraryA("xinput1_3.dll"); /* 极少见：系统自带同名 */
    }
    return h;
}

extern "C" __declspec(dllexport) DWORD WINAPI XInputGetState(DWORD idx, void *state)
{
    HMODULE h = real_xinput();
    static fn_XInputGetState f;
    if (!f && h) f = (fn_XInputGetState)GetProcAddress(h, "XInputGetState");
    return f ? f(idx, state) : 1167;
}

extern "C" __declspec(dllexport) DWORD WINAPI XInputSetState(DWORD idx, void *vib)
{
    HMODULE h = real_xinput();
    static fn_XInputSetState f;
    if (!f && h) f = (fn_XInputSetState)GetProcAddress(h, "XInputSetState");
    return f ? f(idx, vib) : 1167;
}

extern "C" __declspec(dllexport) DWORD WINAPI XInputGetCapabilities(DWORD idx, DWORD flags, void *caps)
{
    HMODULE h = real_xinput();
    static fn_XInputGetCapabilities f;
    if (!f && h) f = (fn_XInputGetCapabilities)GetProcAddress(h, "XInputGetCapabilities");
    return f ? f(idx, flags, caps) : 1167;
}

extern "C" __declspec(dllexport) void WINAPI XInputEnable(BOOL enable)
{
    HMODULE h = real_xinput();
    static fn_XInputEnable f;
    if (!f && h) f = (fn_XInputEnable)GetProcAddress(h, "XInputEnable");
    if (f) f(enable);
}

extern "C" __declspec(dllexport) DWORD WINAPI XInputGetBatteryInformation(DWORD idx, BYTE type, void *info)
{
    HMODULE h = real_xinput();
    static fn_XInputGetBatteryInformation f;
    if (!f && h) f = (fn_XInputGetBatteryInformation)GetProcAddress(h, "XInputGetBatteryInformation");
    return f ? f(idx, type, info) : 1167;
}

extern "C" __declspec(dllexport) DWORD WINAPI XInputGetKeystroke(DWORD idx, DWORD flags, void *key)
{
    HMODULE h = real_xinput();
    static fn_XInputGetKeystroke f;
    if (!f && h) f = (fn_XInputGetKeystroke)GetProcAddress(h, "XInputGetKeystroke");
    return f ? f(idx, flags, key) : 1167;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
    {
        (void)inst;
        DisableThreadLibraryCalls(inst);
        HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}

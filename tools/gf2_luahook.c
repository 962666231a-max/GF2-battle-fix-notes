/*
 * gf2_luahook.dll —— 在游戏进程内劫持 Lua 装载函数，把字节码落盘
 *
 * 原理（不打补丁、不扫特征、不改文件）：
 *   游戏的 C#（XLua）通过 P/Invoke 调 xlua.dll 的 luaL_loadbufferx / luaL_loadstring。
 *   GameAssembly.dll 的导入表里有这两项。我们在内存里把 IAT 指向自己的函数，
 *   先落盘再调用原函数，游戏行为不变。
 *
 * 输出：<输出目录>\  （可用环境变量 GF2_LUA_OUT 覆盖）
 *      每个脚本一个文件：NNN_<name>.lua（name 来自 luaL_loadbufferx 的 name 参数）
 *
 * 编译（mingw-w64）：
 *   gcc -shared -O2 -o gf2_luahook.dll gf2_luahook.c -lpsapi -lshlwapi
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#define MAXDUMP 50 * 1024 * 1024

typedef int (*fn_luaL_loadbufferx)(void *L, const char *buff, size_t sz, const char *name, const char *mode);
typedef int (*fn_luaL_loadstring)(void *L, const char *s);

static fn_luaL_loadbufferx orig_loadbufferx = NULL;
static fn_luaL_loadstring   orig_loadstring   = NULL;
static volatile LONG g_count = 0;
static char g_outdir[MAX_PATH] = {0};

static void ensure_outdir(void)
{
    if (g_outdir[0]) return;
    const char *env = getenv("GF2_LUA_OUT");
    if (env && *env) {
        lstrcpynA(g_outdir, env, MAX_PATH);
    } else {
        lstrcpynA(g_outdir, "L"."", MAX_PATH);
    }
    CreateDirectoryA(g_outdir, NULL);
    char parent[MAX_PATH];
    lstrcpynA(parent, g_outdir, MAX_PATH);
    char *p = strrchr(parent, '\\');
    if (p) { *p = 0; CreateDirectoryA(parent, NULL); }
}

static void sanitize(char *s)
{
    for (; *s; ++s) {
        if (*s == '/' || *s == '\\' || *s == ':' || *s == '*' || *s == '?' ||
            *s == '"' || *s == '<' || *s == '>' || *s == '|' || (unsigned char)*s < 32)
            *s = '_';
    }
}

static void dump_chunk(const char *name, const char *buff, size_t sz)
{
    if (!buff || sz == 0 || sz > MAXDUMP) return;
    ensure_outdir();
    LONG n = InterlockedIncrement(&g_count);

    char safe[200];
    lstrcpynA(safe, (name && *name) ? name : "noname", sizeof(safe));
    sanitize(safe);

    char path[MAX_PATH * 2];
    wsprintfA(path, "%s\\%04ld_%s.lua", g_outdir, n, safe);

    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, buff, (DWORD)sz, &written, NULL);
    CloseHandle(h);
}

static int WINAPI hook_loadbufferx(void *L, const char *buff, size_t sz, const char *name, const char *mode)
{
    dump_chunk(name, buff, sz);
    return orig_loadbufferx ? orig_loadbufferx(L, buff, sz, name, mode) : -1;
}

static int WINAPI hook_loadstring(void *L, const char *s)
{
    dump_chunk("loadstring", s, s ? strlen(s) : 0);
    return orig_loadstring ? orig_loadstring(L, s) : -1;
}

/* 在指定模块的导入表里替换函数指针 */
static int patch_iat(HMODULE mod, const char *dllname, const char *funcname, void *newfn, void **oldfn)
{
    if (!mod) return 0;
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp.VirtualAddress || !imp.Size) return 0;

    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp.VirtualAddress);
    for (; desc->Name; ++desc) {
        const char *dll = (const char *)(base + desc->Name);
        if (_stricmp(dll, dllname) != 0) continue;

        IMAGE_THUNK_DATA *orig = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *first = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
        if (!desc->OriginalFirstThunk) { orig = first; }

        for (int i = 0; orig[i].u1.AddressOfData; ++i) {
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

static DWORD WINAPI worker(LPVOID param)
{
    (void)param;
    ensure_outdir();

    /* 等 xlua.dll 和 GameAssembly.dll 加载完 */
    HMODULE xlua = NULL, ga = NULL;
    for (int i = 0; i < 600; ++i) {
        xlua = GetModuleHandleA("xlua.dll");
        ga = GetModuleHandleA("GameAssembly.dll");
        if (xlua && ga) break;
        Sleep(200);
    }
    if (!xlua || !ga) return 0;

    void *p_loadbufferx = (void *)GetProcAddress(xlua, "luaL_loadbufferx");
    void *p_loadstring = (void *)GetProcAddress(xlua, "luaL_loadstring");
    if (p_loadbufferx) orig_loadbufferx = (fn_luaL_loadbufferx)p_loadbufferx;
    if (p_loadstring) orig_loadstring = (fn_luaL_loadstring)p_loadstring;

    int a = p_loadbufferx ? patch_iat(ga, "xlua.dll", "luaL_loadbufferx", (void *)hook_loadbufferx, (void **)&orig_loadbufferx) : 0;
    int b = p_loadstring ? patch_iat(ga, "xlua.dll", "luaL_loadstring", (void *)hook_loadstring, (void **)&orig_loadstring) : 0;

    /* 写一个启动标记，便于确认注入成功 */
    char marker[MAX_PATH * 2];
    wsprintfA(marker, "%s\\_hook_installed.txt", g_outdir);
    HANDLE h = CreateFileA(marker, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[512];
        wsprintfA(buf, "xlua=%p ga=%p loadbufferx=%p patch=%d loadstring=%p patch=%d\r\n",
                  xlua, ga, p_loadbufferx, a, p_loadstring, b);
        DWORD w = 0;
        WriteFile(h, buf, lstrlenA(buf), &w, NULL);
        CloseHandle(h);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}

/*
 * xlua 代理 DLL（文件名部署为 xlua.dll）
 *
 * 目的：不注入、不改游戏，靠"同名 DLL 代理"接管 Lua 装载函数。
 *   1) 其余 200+ 个导出由 .def 转发给 xlua_real.dll（原版改名而来）
 *   2) luaL_loadbufferx / luaL_loadstring 由本 DLL 实现：
 *        先把字节码落盘，再调用 xlua_real 里的原函数
 *
 * 部署（在 GF2_Exilium_Data\Plugins\x86_64\ 下）：
 *   xlua.dll       → xlua_real.dll      （原版改名，保留）
 *   xlua_proxy.dll → xlua.dll           （本文件编译产物）
 * 卸载：把 xlua_real.dll 改回 xlua.dll 即可
 *
 * 输出：<输出目录>\   （可用 GF2_LUA_OUT 覆盖）
 */

#include <windows.h>
#include <stdio.h>

#define MAXDUMP (64 * 1024 * 1024)

typedef int (*fn_loadbufferx)(void *L, const char *buff, size_t sz, const char *name, const char *mode);
typedef int (*fn_loadstring)(void *L, const char *s);

static HMODULE g_real = NULL;
static HINSTANCE g_self = NULL;
static fn_loadbufferx g_orig_lbx = NULL;
static fn_loadstring  g_orig_ls = NULL;
static volatile LONG  g_seq = 0;
static char g_out[MAX_PATH] = {0};
static CRITICAL_SECTION g_lock;
static int g_lock_ready = 0;

static void ensure_out(void)
{
    if (g_out[0]) return;
    const char *env = getenv("GF2_LUA_OUT");
    if (env && *env) lstrcpynA(g_out, env, MAX_PATH);
    else lstrcpynA(g_out, "L"."", MAX_PATH);
    CreateDirectoryA(g_out, NULL);
    char up[MAX_PATH];
    lstrcpynA(up, g_out, MAX_PATH);
    char *p = strrchr(up, '\\');
    if (p) { *p = 0; CreateDirectoryA(up, NULL); }
}

static void sanitize(char *s)
{
    for (; *s; ++s)
        if ((unsigned char)*s < 32 || strchr("\\/:*?\"<>|", *s)) *s = '_';
}

static void dump(const char *tag, const char *name, const char *buf, size_t sz)
{
    if (!buf || sz == 0 || sz > MAXDUMP) return;
    ensure_out();
    if (g_lock_ready) EnterCriticalSection(&g_lock);
    LONG n = InterlockedIncrement(&g_seq);
    if (g_lock_ready) LeaveCriticalSection(&g_lock);

    char safe[180];
    lstrcpynA(safe, (name && *name) ? name : tag, sizeof(safe));
    sanitize(safe);

    char path[MAX_PATH * 2];
    wsprintfA(path, "%s\\%04ld_%s.lua", g_out, n, safe);

    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, buf, (DWORD)sz, &w, NULL);
    CloseHandle(h);
}

/* 供 .def 导出的两个实现 */
__declspec(dllexport) int luaL_loadbufferx(void *L, const char *buff, size_t sz, const char *name, const char *mode)
{
    dump("lbx", name, buff, sz);
    if (!g_orig_lbx) return -1;
    return g_orig_lbx(L, buff, sz, name, mode);
}

__declspec(dllexport) int luaL_loadstring(void *L, const char *s)
{
    dump("loadstring", s, s, s ? strlen(s) : 0);
    if (!g_orig_ls) return -1;
    return g_orig_ls(L, s);
}

static void load_real(void)
{
    if (g_real) return;
    char self[MAX_PATH];
    GetModuleFileNameA(g_self, self, MAX_PATH);
    char *slash = strrchr(self, '\\');
    if (!slash) return;
    *slash = 0;
    char real[MAX_PATH * 2];
    wsprintfA(real, "%s\\xlua_real.dll", self);
    g_real = LoadLibraryA(real);
    if (!g_real) return;
    g_orig_lbx = (fn_loadbufferx)GetProcAddress(g_real, "luaL_loadbufferx");
    g_orig_ls = (fn_loadstring)GetProcAddress(g_real, "luaL_loadstring");

    ensure_out();
    char marker[MAX_PATH * 2];
    wsprintfA(marker, "%s\\_proxy_installed.txt", g_out);
    HANDLE h = CreateFileA(marker, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char msg[400];
        wsprintfA(msg, "proxy loaded, real=%p lbx=%p ls=%p\r\n", g_real, g_orig_lbx, g_orig_ls);
        DWORD w = 0;
        WriteFile(h, msg, lstrlenA(msg), &w, NULL);
        CloseHandle(h);
    }
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = inst;
        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_lock);
        g_lock_ready = 1;
        load_real();
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_lock_ready) DeleteCriticalSection(&g_lock);
    }
    return TRUE;
}

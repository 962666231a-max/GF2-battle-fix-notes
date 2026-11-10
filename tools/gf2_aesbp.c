/*
 * gf2_aesbp.c —— 在 NEP2.dll 的 AES-NI 指令上下断点，命中时打印 xmm 轮密钥
 *
 * 背景（已实测）
 *   · GF2 的 bundle 解密在 NEP2.dll 里用 **内联 AES-NI** 实现，没有走 bcrypt 等系统 API
 *     证据：文件偏移 0x154555A 有 aeskeygenassist（密钥扩展），
 *           0x1545A95+ 一串 aesdec/aesdeclast（解密循环），0x1545E6C+ aesenc（加密）
 *   · NEP2.dll 只有 1 个导出 NEP_Unknown，被 GF2_Exilium.exe 动态加载
 *   · 因此"钩 API"不成立，改为**指令级断点**：在被执行到时 dump xmm0..xmm15
 *
 * 用法（配合 xinput1_3.dll 侧载）
 *   1) 游戏进到大厅/副本
 *   2) 创建 <out>\_aesbp_now.txt
 *   3) 本模块下一次轮询看到它 → 装断点 → 等 AES 执行 → 打印轮密钥
 *   4) 打满 60 次自动卸断点，避免拖慢游戏
 *
 * 输出：<out>\_aesbp_log.txt
 */

#include <windows.h>
#include <stdio.h>

#define MAX_BP 4
#define MAX_HITS 60

typedef struct
{
    volatile LONG armed;
    volatile LONG hits;
    BYTE *addr;        /* 断点地址（模块内实际 VA） */
    BYTE orig;         /* 原始首字节 */
} BP;

static BP g_bp[MAX_BP];
static int g_bp_count = 0;
static PVOID g_veh = NULL;
static WCHAR g_out2[MAX_PATH];
static volatile LONG g_in_handler = 0;

static void ensure_out2(void)
{
    if (g_out2[0]) return;
    WCHAR env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"GF2_LUA_OUT", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) lstrcpynW(g_out2, env, MAX_PATH);
    else lstrcpynW(g_out2, L"L"."", MAX_PATH);
    CreateDirectoryW(g_out2, NULL);
    WCHAR up[MAX_PATH];
    lstrcpynW(up, g_out2, MAX_PATH);
    WCHAR *p = wcsrchr(up, L'\\');
    if (p) { *p = 0; CreateDirectoryW(up, NULL); }
}

static void aeslog(const WCHAR *fmt, ...)
{
    ensure_out2();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_aesbp_log.txt", g_out2);
    WCHAR buf[4096];
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

static void hexw(WCHAR *dst, const void *src, int len, int maxch)
{
    const BYTE *b = (const BYTE *)src;
    int k = 0;
    for (int i = 0; i < len && k < maxch - 3; ++i)
        k += wsprintfW(dst + k, L"%02X ", b[i]);
    dst[k] = 0;
}

static int find_bp_index(void *addr)
{
    for (int i = 0; i < g_bp_count; ++i)
        if (g_bp[i].addr == (BYTE *)addr) return i;
    return -1;
}

static LONG CALLBACK veh(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    CONTEXT *ctx = ep->ContextRecord;

    if (code == EXCEPTION_BREAKPOINT)
    {
        int idx = find_bp_index((void *)ep->ExceptionRecord->ExceptionAddress);
        if (idx < 0) return EXCEPTION_CONTINUE_SEARCH;

        if (InterlockedCompareExchange(&g_in_handler, 1, 0) != 0)
        {
            /* 重入保护：直接放行原指令 */
            ctx->Rip = (DWORD64)g_bp[idx].addr;
            DWORD old;
            VirtualProtect(g_bp[idx].addr, 1, PAGE_EXECUTE_READWRITE, &old);
            g_bp[idx].addr[0] = g_bp[idx].orig;
            VirtualProtect(g_bp[idx].addr, 1, old, &old);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        LONG n = InterlockedIncrement(&g_bp[idx].hits);
        WCHAR hex[200];

        aeslog(L"=== AES BP hit #%ld @ %p  (bp#%d) ===", n, (void *)ctx->Rip, idx);
        aeslog(L"  rip=%p rsp=%p rcx=%p rdx=%p r8=%p r9=%p",
               (void *)ctx->Rip, (void *)ctx->Rsp, (void *)ctx->Rcx,
               (void *)ctx->Rdx, (void *)ctx->R8, (void *)ctx->R9);

        /* 轮密钥通常就在 xmm0..xmm15 里，全部打出来 */
        for (int r = 0; r < 16; r += 4)
        {
            aeslog(L"  xmm%d..%d:", r, r + 3);
            for (int j = 0; j < 4; ++j)
            {
                M128A *m = &ctx->Xmm0 + (r + j);
                hexw(hex, &m->Low, 8, 40);
                WCHAR hex2[200];
                hexw(hex2, &m->High, 8, 40);
                aeslog(L"    xmm%-2d %s%s", r + j, hex, hex2);
            }
        }

        /* 顺手把寄存器指向的内存抓一段（可能就是密文/明文缓冲） */
        PVOID ptrs[4] = {(PVOID)ctx->Rcx, (PVOID)ctx->Rdx, (PVOID)ctx->R8, (PVOID)ctx->R9};
        for (int j = 0; j < 4; ++j)
        {
            SIZE_T got = 0;
            BYTE tmp[64];
            if (ptrs[j] && ReadProcessMemory(GetCurrentProcess(), ptrs[j], tmp, 64, &got) && got == 64)
            {
                hexw(hex, tmp, 32, 200);
                aeslog(L"  [%p] %s", ptrs[j], hex);
            }
        }

        if (n >= MAX_HITS)
        {
            /* 打满了：全部卸掉 */
            for (int i = 0; i < g_bp_count; ++i)
            {
                DWORD old;
                VirtualProtect(g_bp[i].addr, 1, PAGE_EXECUTE_READWRITE, &old);
                g_bp[i].addr[0] = g_bp[i].orig;
                VirtualProtect(g_bp[i].addr, 1, old, &old);
            }
            aeslog(L"*** 已达 %d 次，全部断点已卸除 ***", MAX_HITS);
        }

        InterlockedExchange(&g_in_handler, 0);

        /* 恢复原字节 → 单步执行原指令 → 再写回 0xCC */
        ctx->Rip = (DWORD64)g_bp[idx].addr;
        DWORD old2 = 0;
        VirtualProtect(g_bp[idx].addr, 1, PAGE_EXECUTE_READWRITE, &old2);
        g_bp[idx].addr[0] = g_bp[idx].orig;
        VirtualProtect(g_bp[idx].addr, 1, old2, &old2);
        ctx->EFlags |= 0x100; /* Trap Flag */
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP)
    {
        int idx = find_bp_index((void *)(ep->ExceptionRecord->ExceptionAddress));
        if (idx < 0)
        {
            /* 不是我们的单步：把 TF 清掉免得死循环 */
            ctx->EFlags &= ~0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (g_bp[idx].hits < MAX_HITS)
        {
            DWORD old;
            VirtualProtect(g_bp[idx].addr, 1, PAGE_EXECUTE_READWRITE, &old);
            g_bp[idx].addr[0] = 0xCC;
            VirtualProtect(g_bp[idx].addr, 1, old, &old);
        }
        ctx->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* 文件偏移 → 模块内 VA */
static BYTE *off_to_va(HMODULE mod, DWORD file_off)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        DWORD start = sec[i].PointerToRawData;
        DWORD end = start + sec[i].SizeOfRawData;
        if (file_off >= start && file_off < end)
            return base + sec[i].VirtualAddress + (file_off - start);
    }
    return NULL;
}

/* 由 worker 调用：装断点 */
extern "C" void gf2_aesbp_arm(void)
{
    if (g_bp_count) return;
    HMODULE nep = NULL;
    for (int i = 0; i < 600; ++i)
    {
        nep = GetModuleHandleA("NEP2.dll");
        if (nep) break;
        Sleep(200);
    }
    if (!nep) { aeslog(L"[arm] NEP2.dll 未加载，放弃"); return; }

    /* 已验证的 AES 指令偏移（NEP2.dll 4.0.5136） */
    static const DWORD offsets[] = {
        0x1545A95, /* aesdec 循环 1 */
        0x1545C51, /* aesdec 循环 2 */
        0x1545E6C, /* aesenc 加密 */
        0x154555A, /* aeskeygenassist 密钥扩展 */
    };
    int n = (int)(sizeof(offsets) / sizeof(offsets[0]));
    if (n > MAX_BP) n = MAX_BP;

    if (!g_veh) g_veh = AddVectoredExceptionHandler(1, veh);

    for (int i = 0; i < n; ++i)
    {
        BYTE *va = off_to_va(nep, offsets[i]);
        if (!va) { aeslog(L"[arm] offset 0x%X 映射失败", offsets[i]); continue; }
        DWORD old;
        if (!VirtualProtect(va, 1, PAGE_EXECUTE_READWRITE, &old)) { aeslog(L"[arm] 改保护失败 @%p", va); continue; }
        g_bp[g_bp_count].addr = va;
        g_bp[g_bp_count].orig = *va;
        g_bp[g_bp_count].hits = 0;
        *va = 0xCC;
        VirtualProtect(va, 1, old, &old);
        aeslog(L"[arm] bp#%d @ %p (file off 0x%X, 原字节 0x%02X)", g_bp_count, va, offsets[i], g_bp[g_bp_count].orig);
        g_bp_count++;
    }
    aeslog(L"[arm] 完成，共 %d 个断点，等待 AES 执行", g_bp_count);
}

/*
 * gf2_il2dump.c —— 用 il2cpp 导出做运行时反射，把客户端所有程序集/类/字段 dump 出来
 *
 * 背景
 *   · 客户端程序集被 IL 保护（ilspycmd 反编译出的 IL 是坏的），静态拿不到 proto schema
 *   · 客户端用 HybridCLR，托管程序集在运行时注册进 il2cpp
 *   · GameAssembly.dll 导出 240 个 il2cpp_* 函数（实测），可以直接调用
 *
 * 做法
 *   1) 取 GameAssembly.dll 里的 il2cpp_* 导出
 *   2) il2cpp_domain_get → il2cpp_domain_get_assemblies → 每个 assembly 的 image
 *   3) 遍历 image 的类，输出：命名空间.类名 | 字段名:字段类型
 *   4) 结果写到 <out>\_il2dump.txt（UTF-8，宽字符路径）
 *
 * 触发：创建 <out>\_il2dump_now.txt（worker 每 300ms 轮询）
 */

#include <windows.h>
#include <stdio.h>

typedef struct Il2CppDomain Il2CppDomain;
typedef struct Il2CppAssembly Il2CppAssembly;
typedef struct Il2CppImage Il2CppImage;
typedef struct Il2CppClass Il2CppClass;
typedef struct FieldInfo FieldInfo;
typedef struct Il2CppType Il2CppType;

typedef const Il2CppDomain *(*fn_domain_get)(void);
typedef const Il2CppAssembly **(*fn_domain_get_assemblies)(const Il2CppDomain *, size_t *);
typedef const Il2CppImage *(*fn_assembly_get_image)(const Il2CppAssembly *);
typedef const char *(*fn_image_get_name)(const Il2CppImage *);
typedef size_t (*fn_image_get_class_count)(const Il2CppImage *);
typedef const Il2CppClass *(*fn_image_get_class)(const Il2CppImage *, size_t);
typedef const char *(*fn_class_get_name)(const Il2CppClass *);
typedef const char *(*fn_class_get_namespace)(const Il2CppClass *);
typedef int (*fn_class_get_field_count)(const Il2CppClass *);
typedef FieldInfo *(*fn_class_get_fields)(const Il2CppClass *, void **);
typedef const char *(*fn_field_get_name)(FieldInfo *);
typedef const Il2CppType *(*fn_field_get_type)(FieldInfo *);
typedef char *(*fn_type_get_name)(const Il2CppType *);

static WCHAR g_outd[MAX_PATH];

static void out_init(void)
{
    if (g_outd[0]) return;
    WCHAR env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"GF2_LUA_OUT", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) lstrcpynW(g_outd, env, MAX_PATH);
    else lstrcpynW(g_outd, L"L"."", MAX_PATH);
    CreateDirectoryW(g_outd, NULL);
    WCHAR up[MAX_PATH];
    lstrcpynW(up, g_outd, MAX_PATH);
    WCHAR *p = wcsrchr(up, L'\\');
    if (p) { *p = 0; CreateDirectoryW(up, NULL); }
}

static void ilog(const WCHAR *fmt, ...)
{
    out_init();
    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_il2dump_log.txt", g_outd);
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

#define RESOLVE(var, name) \
    var = (decltype(var))GetProcAddress(ga, name); \
    if (!var) { ilog(L"[missing] %S", name); }

static HANDLE g_dumpfile = INVALID_HANDLE_VALUE;

static void wdump(const WCHAR *s)
{
    if (g_dumpfile == INVALID_HANDLE_VALUE) return;
    char utf8[4096];
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, utf8, sizeof(utf8) - 1, NULL, NULL);
    if (n <= 0) return;
    DWORD w = 0;
    WriteFile(g_dumpfile, utf8, (DWORD)(n - 1), &w, NULL);
    WriteFile(g_dumpfile, "\r\n", 2, &w, NULL);
}

static void wdump2(const char *a, const char *b)
{
    WCHAR buf[2048];
    wsprintfW(buf, L"%S%s", a, b);
    wdump(buf);
}

extern "C" void gf2_il2dump_run(void)
{
    out_init();
    HMODULE ga = GetModuleHandleA("GameAssembly.dll");
    if (!ga) { ilog(L"[il2dump] GameAssembly 未加载"); return; }

    fn_domain_get p_domain_get = NULL;
    fn_domain_get_assemblies p_get_assemblies = NULL;
    fn_assembly_get_image p_get_image = NULL;
    fn_image_get_name p_image_name = NULL;
    fn_image_get_class_count p_class_count = NULL;
    fn_image_get_class p_image_class = NULL;
    fn_class_get_name p_class_name = NULL;
    fn_class_get_namespace p_class_ns = NULL;
    fn_class_get_field_count p_field_count = NULL;
    fn_class_get_fields p_fields = NULL;
    fn_field_get_name p_field_name = NULL;
    fn_field_get_type p_field_type = NULL;
    fn_type_get_name p_type_name = NULL;

    RESOLVE(p_domain_get, "il2cpp_domain_get");
    RESOLVE(p_get_assemblies, "il2cpp_domain_get_assemblies");
    RESOLVE(p_get_image, "il2cpp_assembly_get_image");
    RESOLVE(p_image_name, "il2cpp_image_get_name");
    RESOLVE(p_class_count, "il2cpp_image_get_class_count");
    p_image_class = (fn_image_get_class)GetProcAddress(ga, "il2cpp_image_get_class");
    RESOLVE(p_class_name, "il2cpp_class_get_name");
    RESOLVE(p_class_ns, "il2cpp_class_get_namespace");
    RESOLVE(p_field_count, "il2cpp_class_get_field_count");
    RESOLVE(p_fields, "il2cpp_class_get_fields");
    RESOLVE(p_field_name, "il2cpp_field_get_name");
    p_field_type = (fn_field_get_type)GetProcAddress(ga, "il2cpp_field_get_type");
    p_type_name = (fn_type_get_name)GetProcAddress(ga, "il2cpp_type_get_name");

    if (!p_domain_get || !p_get_assemblies || !p_get_image) { ilog(L"[il2dump] 关键导出缺失，放弃"); return; }

    WCHAR path[MAX_PATH * 2];
    wsprintfW(path, L"%s\\_il2dump.txt", g_outd);
    g_dumpfile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_dumpfile == INVALID_HANDLE_VALUE) { ilog(L"[il2dump] 建文件失败"); return; }

    const Il2CppDomain *dom = p_domain_get();
    size_t nass = 0;
    const Il2CppAssembly **asms = p_get_assemblies(dom, &nass);
    ilog(L"[il2dump] assemblies=%zu", nass);

    for (size_t i = 0; i < nass; ++i)
    {
        const Il2CppImage *img = p_get_image(asms[i]);
        if (!img) continue;
        const char *iname = p_image_name(img);
        WCHAR line[1024];
        wsprintfW(line, L"##### ASSEMBLY %S", iname ? iname : "?");
        wdump(line);

        size_t cnt = (p_class_count && p_image_class) ? p_class_count(img) : 0;
        if (!(p_class_count && p_image_class)) continue;

        for (size_t k = 0; k < cnt; ++k)
        {
            const Il2CppClass *klass = p_image_class(img, k);
            if (!klass) continue;
            const char *cn = p_class_name ? p_class_name(klass) : "?";
            const char *ns = p_class_ns ? p_class_ns(klass) : "";
            WCHAR cl[1024];
            wsprintfW(cl, L"%S.%S", ns, cn);
            wdump(cl);

            if (p_fields && p_field_name)
            {
                void *iter = NULL;
                FieldInfo *f = NULL;
                while ((f = p_fields(klass, &iter)) != NULL)
                {
                    const char *fn = p_field_name(f);
                    const char *tn = "";
                    if (p_field_type && p_type_name)
                    {
                        const Il2CppType *t = p_field_type(f);
                        if (t) tn = p_type_name(t);
                    }
                    WCHAR fl[1024];
                    wsprintfW(fl, L"    . %S : %S", fn ? fn : "?", tn ? tn : "?");
                    wdump(fl);
                }
            }
        }
    }
    CloseHandle(g_dumpfile);
    g_dumpfile = INVALID_HANDLE_VALUE;
    ilog(L"[il2dump] 完成");
}

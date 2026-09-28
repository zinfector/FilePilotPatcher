#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <d3d11.h>
#include <dwrite.h>
#include <intrin.h>

// Manually mapped payload: all operating-system calls are resolved at entry.
#pragma function(memset, memcpy)
extern "C" void *__cdecl memset(void *p, int v, size_t n) {
    auto b = static_cast<unsigned char *>(p); while (n--) *b++ = (unsigned char)v; return p;
}
extern "C" void *__cdecl memcpy(void *p, const void *s, size_t n) {
    auto b = static_cast<unsigned char *>(p); auto a = static_cast<const unsigned char *>(s);
    while (n--) *b++ = *a++; return p;
}
extern "C" int _fltused = 0;

struct StartupBindings {
    unsigned long long magic, version, size;
    unsigned long long loadLibraryIat, getProcAddressIat, commandLineIat;
    unsigned long long entry, configInitializer, clipboardReader, queueWindow;
    unsigned long long frameHook, platformGlobal, placementPending;
    unsigned long long unicodeMaintenance, menuMaintenance;
    unsigned long long workerLimit, standbySeconds, enabled;
    unsigned long long functionTable, functionCount, payloadBase;
    unsigned long long showWindowIat;
    unsigned long long watchQueue;
};
extern "C" __declspec(dllexport) volatile StartupBindings StartupSettings = {
    0x3154524154535046ULL, 1, sizeof(StartupBindings)
};

#define KERNEL_APIS(X) \
 X(GetModuleFileNameW) X(GetCurrentProcess) X(GetCurrentProcessId) X(GetCurrentThreadId) \
 X(GetCommandLineW) X(GetTickCount64) X(GetFileAttributesExW) X(GetCurrentDirectoryW) \
 X(SetCurrentDirectoryW) X(GetEnvironmentVariableW) X(CreateMutexW) X(ReleaseMutex) \
 X(CreateFileMappingW) X(MapViewOfFile) X(UnmapViewOfFile) X(CreateEventW) X(SetEvent) X(ResetEvent) \
 X(WaitForSingleObject) X(WaitForMultipleObjects) X(OpenProcess) X(OpenThread) X(GetProcessTimes) \
 X(CloseHandle) X(CreateProcessW) X(ExitProcess) X(VirtualAlloc) X(VirtualFree) X(VirtualProtect) \
 X(CreateMemoryResourceNotification) X(QueryMemoryResourceNotification) X(QueueUserWorkItem) \
 X(GlobalMemoryStatusEx) X(GetLastError) X(SetLastError) X(GetEnvironmentStringsW) X(FreeEnvironmentStringsW) X(RtlAddFunctionTable) X(GetStartupInfoW) \
 X(TlsAlloc) X(TlsSetValue) X(TlsGetValue) X(ReadDirectoryChangesW)
#define USER_APIS(X) \
 X(GetCursorPos) X(GetForegroundWindow) X(GetWindowThreadProcessId) X(AllowSetForegroundWindow) \
 X(SetTimer) X(KillTimer) X(SetWindowLongPtrW) X(CallWindowProcW) X(InvalidateRect) X(CreateWindowExW) \
 X(ShowWindow) X(RegisterClipboardFormatW) X(IsClipboardFormatAvailable)
#define DECL_API(n) static decltype(&n) api##n;
KERNEL_APIS(DECL_API)
USER_APIS(DECL_API)
DECL_API(OpenProcessToken)
DECL_API(GetTokenInformation)
DECL_API(CommandLineToArgvW)
DECL_API(LocalFree)
static decltype(&LoadLibraryW) apiLoadLibraryW;
static decltype(&GetProcAddress) apiGetProcAddress;
static decltype(&D3D11CreateDevice) apiD3D11CreateDevice;
static bool g_ready, g_standby, g_activated, g_visibleStarted;
static bool g_firstShow;
static wchar_t g_exe[32768], g_defaultCommand[32768], g_namespace[128];
static HANDLE g_mutex, g_mapping, g_requestEvent, g_ackEvent, g_lowMemory;
static ULONGLONG g_birth, g_nextSpawn, g_lastActivity, g_ticket;
static WNDPROC g_windowProc;
static HWND g_window;
static volatile LONG g_spawning;
static ID3D11Device *g_device;
static ID3D11DeviceContext *g_context;
static IDWriteFactory *g_fontFactory;
static IDWriteFontCollection *g_fontCollection;
static D3D_FEATURE_LEVEL g_featureLevel;
static DWORD g_watchTls = TLS_OUT_OF_INDEXES;

// Only the queue's initialization zero-fill calls this hook. Record its address
// until the first directory read, after all startup arena growth has finished.
extern "C" __declspec(dllexport) void *StartupWatchZero(void *block, int value, SIZE_T bytes) {
    memset(block, value, bytes);
    if (g_watchTls != TLS_OUT_OF_INDEXES && !value && bytes == 16 * 1024 * 1024)
        apiTlsSetValue(g_watchTls, block);
    return block;
}

extern "C" __declspec(dllexport) BOOL WINAPI StartupWatchRead(
    HANDLE directory, LPVOID buffer, DWORD length, BOOL subtree, DWORD filter,
    LPDWORD returned, LPOVERLAPPED overlapped, LPOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (g_watchTls != TLS_OUT_OF_INDEXES) {
        auto block = reinterpret_cast<ULONG_PTR>(apiTlsGetValue(g_watchTls));
        apiTlsSetValue(g_watchTls, nullptr);
        if (block) {
            // Adjacent arena objects share the boundary pages. Retain those;
            // only untouched, whole interior pages become demand committed.
            ULONG_PTR first = (block + 4095) & ~ULONG_PTR(4095);
            ULONG_PTR end = (block + 16 * 1024 * 1024) & ~ULONG_PTR(4095);
            if (end > first) apiVirtualFree(reinterpret_cast<void *>(first), end - first, MEM_DECOMMIT);
        }
    }
    return apiReadDirectoryChangesW(directory, buffer, length, subtree, filter, returned, overlapped, completion);
}

extern "C" __declspec(dllexport) void StartupWatchQueue(
    unsigned long long *arena, unsigned long long *watch, unsigned char *record) {
    // Native producer serializes a record from the scratch arena, then publishes
    // the write counter. Commit its destination before that publication. The
    // UI consumer can only read published bytes; committed pages are never
    // reclaimed while the queue is running. Preserve the native 16 MiB bound.
    ULONGLONG bytes = arena[5] + arena[4] - reinterpret_cast<ULONGLONG>(record);
    ULONGLONG capacity = watch[0x18];
    auto written = static_cast<ULONGLONG>(_InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64 *>(watch + 0x28), 0, 0));
    // Commit even when a snapshot would show a full queue: the consumer may
    // free space before the native producer repeats its capacity check.
    if (capacity && bytes <= capacity) {
        ULONGLONG offset = written % capacity;
        SIZE_T first = static_cast<SIZE_T>(bytes < capacity - offset ? bytes : capacity - offset);
        SIZE_T second = static_cast<SIZE_T>(bytes) - first;
        auto base = reinterpret_cast<unsigned char *>(watch[0x19]);
        while ((first && !apiVirtualAlloc(base + offset, first, MEM_COMMIT, PAGE_READWRITE)) ||
               (second && !apiVirtualAlloc(base, second, MEM_COMMIT, PAGE_READWRITE))) {
            // On commit exhaustion retain the pending record and retry. The
            // existing watcher cancellation event also makes shutdown bounded.
            if (apiWaitForSingleObject(reinterpret_cast<HANDLE>(watch[0x40]), 16) != WAIT_TIMEOUT)
                return;
        }
    }
    reinterpret_cast<void (*)(unsigned long long *, unsigned long long *, unsigned char *)>(
        StartupSettings.watchQueue)(arena, watch, record);
}
// The native renderer discards its 8192-instance buffer for every batch,
// including single rectangles. Append instead: previously submitted ranges
// remain untouched until WRITE_DISCARD gives the driver a new backing store.
static ID3D11DeviceContext *g_uploadContext;
static ID3D11Buffer *g_uploadBuffer;
static UINT g_uploadCursor, g_uploadCapacity;
static bool g_uploadAppend;
struct UploadCounters {
    unsigned long long draws, discards, appends, bytes, failures;
};
extern "C" __declspec(dllexport) UploadCounters RenderUploadCounters = {};

extern "C" __declspec(dllexport) void StartupUpload(
    ID3D11DeviceContext *context, ID3D11Buffer *buffer, UINT count, const void *vertices) {
    constexpr UINT stride = 0x48;
    if (!context || !buffer || !vertices || !count) return;
    if (buffer != g_uploadBuffer || context != g_uploadContext) {
        D3D11_BUFFER_DESC desc{};
        buffer->GetDesc(&desc);
        g_uploadBuffer = buffer; g_uploadContext = context;
        g_uploadCursor = 0;
        g_uploadCapacity = desc.ByteWidth / stride;
        if (g_uploadCapacity > 8192) g_uploadCapacity = 8192;
        g_uploadAppend = desc.Usage == D3D11_USAGE_DYNAMIC &&
            (desc.BindFlags & D3D11_BIND_VERTEX_BUFFER) != 0 &&
            (desc.BindFlags & D3D11_BIND_SHADER_RESOURCE) == 0 &&
            (desc.CPUAccessFlags & D3D11_CPU_ACCESS_WRITE) != 0;
    }
    // Preserve the native batch limit. The native caller already chunks large
    // batches; this also bounds every CPU write to the actual buffer size.
    if (count > g_uploadCapacity) count = g_uploadCapacity;
    if (!count) return;
    UINT first = g_uploadCursor;
    bool append = g_uploadAppend && first && count <= g_uploadCapacity - first;
    if (!append) first = 0;
    D3D11_MAPPED_SUBRESOURCE mapped{};
    HRESULT status = context->Map(buffer, 0,
        append ? D3D11_MAP_WRITE_NO_OVERWRITE : D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (FAILED(status) && append) {
        // Preserve rendering on a driver that rejects the append path.
        g_uploadAppend = false; append = false; first = 0;
        status = context->Map(buffer, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    }
    if (FAILED(status)) {
        g_uploadCursor = 0; ++RenderUploadCounters.failures; return;
    }
    memcpy(static_cast<unsigned char *>(mapped.pData) + SIZE_T(first) * stride,
        vertices, SIZE_T(count) * stride);
    context->Unmap(buffer, 0);
    // All native input elements are per-instance with step rate 1. Offset the
    // instance fetch, leaving the four SV_VertexID corner indices unchanged.
    context->DrawInstanced(4, count, 0, first);
    g_uploadCursor = first + count;
    ++RenderUploadCounters.draws;
    if (append) ++RenderUploadCounters.appends;
    else ++RenderUploadCounters.discards;
    RenderUploadCounters.bytes += SIZE_T(count) * stride;
}

static constexpr DWORD kJsonLimit = 1024 * 1024;
static constexpr DWORD kTextLimit = 32768;
static constexpr UINT_PTR kMaintenanceTimer = 0x46505354;
enum State : LONG { Empty, Starting, Ready, Pending, Taking, Taken };
enum Kind : DWORD { Command, Panel };
struct Request {
    ULONGLONG id;
    DWORD kind, flags, sender, commandChars, cwdChars, jsonBytes, showCommand;
    LONG x, y;
    DWORD placement[8];
    wchar_t command[kTextLimit], cwd[kTextLimit];
    char json[kJsonLimit + 1];
};
struct Shared {
    DWORD magic, version;
    volatile LONG state;
    DWORD pid, tid;
    ULONGLONG birth, started;
    Request request;
};
static Shared *g_shared;
static Request *g_request;
struct StringView { const char *data; unsigned long long length; };

static size_t Length(const wchar_t *s, size_t cap = kTextLimit) {
    size_t n = 0; if (s) while (n < cap && s[n]) ++n; return n;
}
static bool Equal(const wchar_t *a, const wchar_t *b) {
    if (!a || !b) return a == b;
    while (*a && *a == *b) { ++a; ++b; } return *a == *b;
}
static void Hex(wchar_t *out, ULONGLONG v) {
    for (unsigned i = 0; i < 16; ++i) out[i] = L"0123456789abcdef"[(v >> (60 - i * 4)) & 15];
    out[16] = 0;
}
static ULONGLONG ReadHex(const wchar_t *value) {
    if (Length(value, 17) != 16) return 0;
    ULONGLONG result = 0;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned digit = value[i] >= L'0' && value[i] <= L'9' ? value[i] - L'0' :
            (value[i] >= L'a' && value[i] <= L'f' ? value[i] - L'a' + 10 : 16);
        if (digit > 15) return 0; result = (result << 4) | digit;
    }
    return result;
}
static ULONGLONG Hash(const void *data, size_t size, ULONGLONG h = 1469598103934665603ULL) {
    auto bytes = static_cast<const unsigned char *>(data);
    while (size--) { h ^= *bytes++; h *= 1099511628211ULL; } return h;
}
static void Name(wchar_t *out, const wchar_t *suffix) {
    size_t n = Length(g_namespace, 100); memcpy(out, g_namespace, n * 2);
    size_t m = Length(suffix, 20); memcpy(out + n, suffix, (m + 1) * 2);
}
static bool Lock(DWORD ms = 50) {
    if (!g_mutex) return false;
    DWORD r = apiWaitForSingleObject(g_mutex, ms); return r == WAIT_OBJECT_0 || r == WAIT_ABANDONED;
}
static void Unlock() { apiReleaseMutex(g_mutex); }
static ULONGLONG Birth(HANDLE h) {
    FILETIME a{}, b{}, c{}, d{};
    if (!apiGetProcessTimes(h, &a, &b, &c, &d)) return 0;
    return (ULONGLONG(a.dwHighDateTime) << 32) | a.dwLowDateTime;
}
static HANDLE Owner() {
    HANDLE h = apiOpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_shared->pid);
    if (h && (Birth(h) != g_shared->birth || apiWaitForSingleObject(h, 0) != WAIT_TIMEOUT)) {
        apiCloseHandle(h); h = nullptr;
    }
    return h;
}
static bool MemoryAvailable() {
    BOOL low = FALSE;
    if (g_lowMemory && apiQueryMemoryResourceNotification(g_lowMemory, &low) && low) return false;
    MEMORYSTATUSEX memory{}; memory.dwLength = sizeof(memory);
    return apiGlobalMemoryStatusEx(&memory) && memory.ullAvailPhys >= 1024ULL * 1024 * 1024;
}
static bool HasNativePanelTransfer() {
    UINT format = apiRegisterClipboardFormatW(L"FilePilot-OpenWindowFormat");
    return format && apiIsClipboardFormatAvailable(format);
}
static DWORD EnvNumber(const wchar_t *name, DWORD fallback, DWORD minimum, DWORD maximum) {
    wchar_t value[24]; DWORD n = apiGetEnvironmentVariableW(name, value, 24);
    if (!n || n >= 24) return fallback;
    DWORD result = 0;
    for (DWORD i = 0; i < n; ++i) {
        if (value[i] < L'0' || value[i] > L'9' || result > maximum / 10) return fallback;
        result = result * 10 + value[i] - L'0';
    }
    return result >= minimum && result <= maximum ? result : fallback;
}
static bool Initialize() {
    apiLoadLibraryW = *reinterpret_cast<decltype(apiLoadLibraryW) *>(StartupSettings.loadLibraryIat);
    apiGetProcAddress = *reinterpret_cast<decltype(apiGetProcAddress) *>(StartupSettings.getProcAddressIat);
    HMODULE kernel = apiLoadLibraryW(L"kernel32.dll");
    HMODULE user = apiLoadLibraryW(L"user32.dll");
    HMODULE security = apiLoadLibraryW(L"advapi32.dll");
    HMODULE shell = apiLoadLibraryW(L"shell32.dll");
#define LOAD_KERNEL(n) api##n = reinterpret_cast<decltype(api##n)>(apiGetProcAddress(kernel, #n)); if (!api##n) return false;
#define LOAD_USER(n) api##n = reinterpret_cast<decltype(api##n)>(apiGetProcAddress(user, #n)); if (!api##n) return false;
    KERNEL_APIS(LOAD_KERNEL)
    USER_APIS(LOAD_USER)
    g_watchTls = apiTlsAlloc();
    if (StartupSettings.functionCount)
        apiRtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(StartupSettings.functionTable),
            static_cast<DWORD>(StartupSettings.functionCount), StartupSettings.payloadBase);
    apiLocalFree = reinterpret_cast<decltype(apiLocalFree)>(apiGetProcAddress(kernel, "LocalFree"));
    apiOpenProcessToken = reinterpret_cast<decltype(apiOpenProcessToken)>(apiGetProcAddress(security, "OpenProcessToken"));
    apiGetTokenInformation = reinterpret_cast<decltype(apiGetTokenInformation)>(apiGetProcAddress(security, "GetTokenInformation"));
    apiCommandLineToArgvW = reinterpret_cast<decltype(apiCommandLineToArgvW)>(apiGetProcAddress(shell, "CommandLineToArgvW"));
    if (!apiLocalFree || !apiOpenProcessToken || !apiGetTokenInformation || !apiCommandLineToArgvW) return false;
    DWORD n = apiGetModuleFileNameW(nullptr, g_exe, kTextLimit);
    if (!n || n + 3 >= kTextLimit) return false;
    g_defaultCommand[0] = L'"'; memcpy(g_defaultCommand + 1, g_exe, n * 2); g_defaultCommand[n + 1] = L'"';
    HANDLE token = nullptr; TOKEN_STATISTICS stats{}; DWORD used = 0;
    alignas(void *) unsigned char integrity[512]{};
    if (!apiOpenProcessToken(apiGetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    bool good = apiGetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &used) &&
        apiGetTokenInformation(token, TokenIntegrityLevel, integrity, sizeof(integrity), &used);
    apiCloseHandle(token); if (!good) return false;
    auto label = reinterpret_cast<TOKEN_MANDATORY_LABEL *>(integrity);
    auto sid = reinterpret_cast<SID *>(label->Label.Sid);
    if (!sid || !sid->SubAuthorityCount || sid->SubAuthorityCount > 15) return false;
    DWORD level = sid->SubAuthority[sid->SubAuthorityCount - 1];
    WIN32_FILE_ATTRIBUTE_DATA attrs{};
    if (!apiGetFileAttributesExW(g_exe, GetFileExInfoStandard, &attrs)) return false;
    ULONGLONG hash = Hash(g_exe, n * 2);
    hash = Hash(&attrs.ftLastWriteTime, sizeof(FILETIME), hash);
    hash = Hash(&attrs.nFileSizeHigh, sizeof(DWORD) * 2, hash);
    hash = Hash(&stats.AuthenticationId, sizeof(LUID), hash);
    hash = Hash(&level, sizeof(level), hash);
    // An already-running spare cannot safely adopt another process's loaded-DLL
    // environment. Give differing environments independent discovery scopes.
    wchar_t *environment = apiGetEnvironmentStringsW();
    if (!environment) return false;
    size_t count = 0;
    while (count < 1024 * 1024 && (environment[count] || environment[count + 1])) ++count;
    if (count >= 1024 * 1024) { apiFreeEnvironmentStringsW(environment); return false; }
    hash = Hash(environment, (count + 2) * 2, hash); apiFreeEnvironmentStringsW(environment);
    const wchar_t prefix[] = L"Local\\FPilot.Startup.v1.";
    memcpy(g_namespace, prefix, sizeof(prefix) - 2); Hex(g_namespace + (sizeof(prefix) / 2 - 1), hash);
    wchar_t name[128]; Name(name, L".lock"); g_mutex = apiCreateMutexW(nullptr, FALSE, name);
    Name(name, L".map"); g_mapping = apiCreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(Shared), name);
    if (g_mapping) g_shared = static_cast<Shared *>(apiMapViewOfFile(g_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    Name(name, L".request"); g_requestEvent = apiCreateEventW(nullptr, FALSE, FALSE, name);
    Name(name, L".ack"); g_ackEvent = apiCreateEventW(nullptr, TRUE, FALSE, name);
    g_lowMemory = apiCreateMemoryResourceNotification(LowMemoryResourceNotification);
    g_birth = Birth(apiGetCurrentProcess());
    if (!g_shared || !g_requestEvent || !g_ackEvent || !Lock()) return false;
    if (g_shared->magic != 0x31535046 || g_shared->version != 1) {
        memset(g_shared, 0, sizeof(Shared)); g_shared->magic = 0x31535046; g_shared->version = 1;
    }
    Unlock(); g_ready = true; return true;
}

static void Preload() {
    HMODULE graphics = apiLoadLibraryW(L"d3d11.dll");
    apiD3D11CreateDevice = reinterpret_cast<decltype(apiD3D11CreateDevice)>(apiGetProcAddress(graphics, "D3D11CreateDevice"));
    D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    if (apiD3D11CreateDevice)
        apiD3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, &level, 1,
            D3D11_SDK_VERSION, &g_device, &g_featureLevel, &g_context);
    HMODULE dwrite = apiLoadLibraryW(L"dwrite.dll");
    auto factory = reinterpret_cast<decltype(&DWriteCreateFactory)>(apiGetProcAddress(dwrite, "DWriteCreateFactory"));
    const GUID iid = {0xb859ee5a,0xd838,0x4b5b,{0xa2,0xe8,0x1a,0xdc,0x7d,0x93,0xdb,0x48}};
    if (factory && SUCCEEDED(factory(DWRITE_FACTORY_TYPE_SHARED, iid, reinterpret_cast<IUnknown **>(&g_fontFactory))))
        g_fontFactory->GetSystemFontCollection(&g_fontCollection, FALSE);
}

// Only the standby claims a request. The copying and state transition share the
// same mutex as cancellation; a cancelled request can never later be displayed.
static bool AwaitRequest() {
    if (!Lock(1000)) return false;
    if (!g_ticket || g_shared->started != g_ticket || g_shared->state != Starting ||
        (g_shared->pid && g_shared->pid != apiGetCurrentProcessId())) {
        Unlock(); return false;
    }
    g_shared->pid = apiGetCurrentProcessId(); g_shared->tid = apiGetCurrentThreadId();
    g_shared->birth = g_birth; Unlock();
    if (!MemoryAvailable()) {
        if (Lock()) { if (g_shared->pid == apiGetCurrentProcessId()) g_shared->state = Empty; Unlock(); }
        return false;
    }
    Preload();
    if (!Lock(1000)) return false;
    if (g_shared->pid != apiGetCurrentProcessId() || g_shared->state != Starting) { Unlock(); return false; }
    g_shared->state = Ready; Unlock();
    ULONGLONG deadline = apiGetTickCount64() + EnvNumber(L"FPILOT_STANDBY_SECONDS", (DWORD)StartupSettings.standbySeconds, 5, 600) * 1000ULL;
    HANDLE waits[2] = {g_requestEvent, g_lowMemory};
    for (;;) {
        ULONGLONG now = apiGetTickCount64();
        DWORD remaining = deadline > now ? (DWORD)(deadline - now) : 0;
        DWORD result = apiWaitForMultipleObjects(g_lowMemory ? 2 : 1, waits, FALSE, remaining);
        if (!Lock(1000)) return false;
        if (g_shared->pid != apiGetCurrentProcessId()) { Unlock(); return false; }
        if (g_shared->state == Pending) {
            Request &incoming = g_shared->request;
            if (incoming.commandChars >= kTextLimit || incoming.cwdChars >= kTextLimit ||
                incoming.jsonBytes > kJsonLimit || incoming.kind > Panel ||
                incoming.command[incoming.commandChars] || incoming.cwd[incoming.cwdChars] ||
                incoming.json[incoming.jsonBytes]) {
                g_shared->state = Ready; apiSetEvent(g_ackEvent); Unlock(); continue;
            }
            g_shared->state = Taking;
            SIZE_T requestBytes = offsetof(Request, json) + g_shared->request.jsonBytes + 1;
            g_request = g_shared->request.jsonBytes <= kJsonLimit ? static_cast<Request *>(apiVirtualAlloc(nullptr, requestBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) : nullptr;
            if (g_request) {
                memcpy(g_request, &g_shared->request, requestBytes);
                g_shared->state = Taken; apiSetEvent(g_ackEvent); Unlock();
                if (g_request->cwdChars) apiSetCurrentDirectoryW(g_request->cwd);
                if (StartupSettings.placementPending && g_request->placement[0] == 0x32545046 &&
                    g_request->placement[1] == 0x20)
                    memcpy(reinterpret_cast<void *>(StartupSettings.placementPending - 0x40), g_request->placement, 32);
                g_activated = true; return true;
            }
            g_shared->state = Ready; apiSetEvent(g_ackEvent);
        }
        if (result != WAIT_OBJECT_0 || !MemoryAvailable()) {
            g_shared->state = Empty; g_shared->pid = 0; Unlock(); return false;
        }
        Unlock();
    }
}

static bool Deliver(const wchar_t *command, const wchar_t *directory,
                    const StringView *panel, const STARTUPINFOW *startup, PROCESS_INFORMATION *pi,
                    const unsigned int *placement = nullptr) {
    if (!g_ready || !StartupSettings.enabled || !Lock()) return false;
    if (g_shared->state != Ready) { Unlock(); return false; }
    HANDLE process = Owner();
    if (!process) { g_shared->state = Empty; g_shared->pid = 0; Unlock(); return false; }
    size_t chars = Length(command), cwdChars = Length(directory);
    if (chars >= kTextLimit || cwdChars >= kTextLimit || (panel && (!panel->data || !panel->length || panel->length > kJsonLimit))) {
        apiCloseHandle(process); Unlock(); return false;
    }
    Request &r = g_shared->request;
    r.id = (apiGetTickCount64() << 20) ^ (ULONGLONG(apiGetCurrentProcessId()) << 4) ^ apiGetCurrentThreadId();
    ULONGLONG id = r.id;
    r.kind = panel ? Panel : Command; r.sender = apiGetCurrentProcessId();
    r.flags = startup ? startup->dwFlags & (STARTF_USEPOSITION | STARTF_USESHOWWINDOW) : 0;
    r.showCommand = startup ? startup->wShowWindow : SW_SHOWNORMAL;
    r.x = startup ? startup->dwX : 0; r.y = startup ? startup->dwY : 0;
    r.commandChars = (DWORD)chars; r.cwdChars = (DWORD)cwdChars;
    memset(r.placement, 0, sizeof(r.placement));
    if (placement) memcpy(r.placement, placement, sizeof(r.placement));
    r.jsonBytes = panel ? (DWORD)panel->length : 0;
    memcpy(r.command, command, (chars + 1) * 2);
    if (directory) memcpy(r.cwd, directory, (cwdChars + 1) * 2);
    else {
        r.cwdChars = apiGetCurrentDirectoryW(kTextLimit, r.cwd);
        if (!r.cwdChars || r.cwdChars >= kTextLimit) { apiCloseHandle(process); Unlock(); return false; }
    }
    if (panel) memcpy(r.json, panel->data, r.jsonBytes);
    r.json[r.jsonBytes] = 0;
    DWORD pid = g_shared->pid, tid = g_shared->tid;
    apiResetEvent(g_ackEvent); g_shared->state = Pending;
    // Windows permits the foreground process to grant its activation right.
    apiAllowSetForegroundWindow(pid); apiSetEvent(g_requestEvent); Unlock();
    apiWaitForSingleObject(g_ackEvent, 200);
    bool accepted = true;
    if (Lock(1000)) {
        if (g_shared->request.id == id && g_shared->pid == pid) {
            if (g_shared->state == Pending) { g_shared->state = Ready; accepted = false; }
            else if (g_shared->state == Ready) accepted = false;
            else if (g_shared->state == Taken) { g_shared->state = Empty; g_shared->pid = 0; }
        }
        Unlock();
    }
    if (apiWaitForSingleObject(process, 0) != WAIT_TIMEOUT) accepted = false;
    if (accepted && pi) {
        pi->hProcess = process; pi->hThread = apiOpenThread(SYNCHRONIZE, FALSE, tid);
        pi->dwProcessId = pid; pi->dwThreadId = tid;
    } else apiCloseHandle(process);
    return accepted;
}

static DWORD WINAPI SpawnStandby(void *) {
    if (!MemoryAvailable() || !Lock()) { _InterlockedExchange(&g_spawning, 0); return 0; }
    ULONGLONG now = apiGetTickCount64();
    if (g_shared->state != Empty) {
        HANDLE owner = g_shared->pid ? Owner() : nullptr;
        bool stale = !owner && now - g_shared->started > 10000;
        if (owner) apiCloseHandle(owner);
        if (!stale) { Unlock(); _InterlockedExchange(&g_spawning, 0); return 0; }
    }
    g_shared->state = Starting; g_shared->pid = 0; g_shared->started = now;
    Unlock();
    // Heap storage avoids large stack probes in this CRT-free image.
    auto cmd = static_cast<wchar_t *>(apiVirtualAlloc(nullptr, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    PROCESS_INFORMATION pi{}; STARTUPINFOW si{}; si.cb = sizeof(si);
    bool created = false;
    if (cmd) {
        size_t n = Length(g_defaultCommand); const wchar_t flag[] = L" --fp-standby-v1 ";
        if (n + sizeof(flag) / 2 + 16 < kTextLimit) {
            memcpy(cmd, g_defaultCommand, n * 2); memcpy(cmd + n, flag, sizeof(flag));
            Hex(cmd + n + sizeof(flag) / 2 - 1, now);
            created = apiCreateProcessW(g_exe, cmd, nullptr, nullptr, FALSE,
                CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE, nullptr, nullptr, &si, &pi) != FALSE;
        }
        apiVirtualFree(cmd, 0, MEM_RELEASE);
    }
    if (Lock(1000)) {
        if (g_shared->state == Starting && !g_shared->pid && g_shared->started == now) {
            if (created) { g_shared->pid = pi.dwProcessId; g_shared->tid = pi.dwThreadId; g_shared->birth = Birth(pi.hProcess); }
            else g_shared->state = Empty;
        }
        Unlock();
    }
    if (created) { apiCloseHandle(pi.hThread); apiCloseHandle(pi.hProcess); }
    _InterlockedExchange(&g_spawning, 0); return 0;
}
static void ScheduleStandby() {
    if (!g_ready || !StartupSettings.enabled || !EnvNumber(L"FPILOT_WARM", 0, 0, 1)) return;
    ULONGLONG now = apiGetTickCount64();
    if (now < g_nextSpawn) return;
    g_nextSpawn = now + 30000;
    if (_InterlockedCompareExchange(&g_spawning, 1, 0) == 0 && !apiQueueUserWorkItem(SpawnStandby, nullptr, WT_EXECUTEDEFAULT))
        _InterlockedExchange(&g_spawning, 0);
}
static void Maintenance(bool fontChange = false) {
    unsigned mode = fontChange ? 2 : (MemoryAvailable() ? 0 : 1);
    if (StartupSettings.unicodeMaintenance)
        reinterpret_cast<void (*)(unsigned)>(StartupSettings.unicodeMaintenance)(mode);
    if (StartupSettings.menuMaintenance)
        reinterpret_cast<void (*)(unsigned)>(StartupSettings.menuMaintenance)(mode);
}
static void CALLBACK Timer(HWND hwnd, UINT, UINT_PTR, DWORD) {
    apiSetTimer(hwnd, kMaintenanceTimer, 15000, Timer);
    if (apiGetTickCount64() - g_lastActivity >= 2000) Maintenance();
    if (apiGetTickCount64() - g_lastActivity < 30000) ScheduleStandby();
}
static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM w, LPARAM l) {
    if (message == WM_FONTCHANGE) Maintenance(true);
    if (message == WM_KEYDOWN || message == WM_LBUTTONDOWN || message == WM_RBUTTONDOWN ||
        (message == WM_ACTIVATE && LOWORD(w) != WA_INACTIVE)) {
        g_lastActivity = apiGetTickCount64(); ScheduleStandby();
    }
    if (message == WM_NCDESTROY) apiKillTimer(hwnd, kMaintenanceTimer);
    return apiCallWindowProcW(g_windowProc, hwnd, message, w, l);
}

extern "C" __declspec(dllexport) LPWSTR WINAPI StartupCommandLine() {
    return g_request ? g_request->command : apiGetCommandLineW();
}
extern "C" __declspec(dllexport) BOOL WINAPI StartupShowWindow(HWND hwnd, int command) {
    auto platform = *reinterpret_cast<unsigned char **>(StartupSettings.platformGlobal);
    HWND main = platform ? *reinterpret_cast<HWND *>(platform + 0x8c0) : nullptr;
    if (g_request && !g_firstShow && hwnd == main) {
        g_firstShow = true;
        if (g_request->flags & STARTF_USESHOWWINDOW) command = (int)g_request->showCommand;
    }
    return apiShowWindow(hwnd, command);
}
static bool HookImport(unsigned long long address, void *replacement) {
    DWORD old = 0; auto slot = reinterpret_cast<void **>(address);
    if (!apiVirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old)) return false;
    *slot = replacement; DWORD ignored;
    apiVirtualProtect(slot, sizeof(void *), old, &ignored); return true;
}
extern "C" __declspec(dllexport) void StartupEntry() {
    if (!Initialize()) {
        // An unavailable broker must not turn an internal standby command into
        // an ordinary visible File Pilot launch.
        HMODULE kernel = apiLoadLibraryW(L"kernel32.dll");
        auto command = reinterpret_cast<decltype(&GetCommandLineW)>(apiGetProcAddress(kernel, "GetCommandLineW"));
        auto parse = reinterpret_cast<decltype(&CommandLineToArgvW)>(apiGetProcAddress(apiLoadLibraryW(L"shell32.dll"), "CommandLineToArgvW"));
        auto leave = reinterpret_cast<decltype(&ExitProcess)>(apiGetProcAddress(kernel, "ExitProcess"));
        auto freeLocal = reinterpret_cast<decltype(&LocalFree)>(apiGetProcAddress(kernel, "LocalFree"));
        int count = 0; LPWSTR *args = command && parse ? parse(command(), &count) : nullptr;
        bool internal = args && count >= 2 && Equal(args[1], L"--fp-standby-v1");
        if (args && freeLocal) freeLocal(args);
        if (internal && leave) leave(ERROR_NOT_SUPPORTED);
        reinterpret_cast<void (*)()>(StartupSettings.entry)(); return;
    }
    int argc = 0; LPWSTR *argv = apiCommandLineToArgvW(apiGetCommandLineW(), &argc);
    g_standby = argv && argc >= 2 && Equal(argv[1], L"--fp-standby-v1");
    if (g_standby && argc == 3) g_ticket = ReadHex(argv[2]);
    bool eligible = argv && (argc == 1 || (argc == 2 && (argv[1][0] != L'-' || Equal(argv[1], L"--root"))));
    if (argv) apiLocalFree(argv);
    if (g_standby) {
        if (!AwaitRequest()) apiExitProcess(0);
    } else if (eligible && !HasNativePanelTransfer() && EnvNumber(L"FPILOT_WARM", 0, 0, 1)) {
        STARTUPINFOW info{}; info.cb = sizeof(info); apiGetStartupInfoW(&info);
        if (info.dwFlags & ~(STARTF_USEPOSITION | STARTF_USESHOWWINDOW | STARTF_FORCEONFEEDBACK | STARTF_FORCEOFFFEEDBACK))
            eligible = false;
        auto cwd = static_cast<wchar_t *>(apiVirtualAlloc(nullptr, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (cwd) {
            DWORD length = apiGetCurrentDirectoryW(kTextLimit, cwd);
            bool handed = eligible && length < kTextLimit && Deliver(apiGetCommandLineW(), cwd, nullptr, &info, nullptr);
            apiVirtualFree(cwd, 0, MEM_RELEASE); if (handed) apiExitProcess(0);
        }
    }
    // Other payloads (including Open File Location) must see the effective argv.
    if (g_request) {
        if (!HookImport(StartupSettings.commandLineIat, reinterpret_cast<void *>(StartupCommandLine)) ||
            !HookImport(StartupSettings.showWindowIat, reinterpret_cast<void *>(StartupShowWindow)))
            apiExitProcess(ERROR_ACCESS_DENIED);
    }
    reinterpret_cast<void (*)()>(StartupSettings.entry)();
}
extern "C" __declspec(dllexport) int StartupWorkers(int minimum, int logical) {
    int cap = g_ready ? (int)EnvNumber(L"FPILOT_WORKERS", (DWORD)StartupSettings.workerLimit, 2, 64) : (int)StartupSettings.workerLimit;
    if (logical < minimum) logical = minimum;
    return logical > cap ? cap : logical;
}
extern "C" __declspec(dllexport) StringView *StartupClipboard(StringView *out) {
    if (g_request) {
        out->data = g_request->kind == Panel ? g_request->json : nullptr;
        out->length = g_request->kind == Panel ? g_request->jsonBytes : 0; return out;
    }
    return reinterpret_cast<StringView *(*)(StringView *)>(StartupSettings.clipboardReader)(out);
}
extern "C" __declspec(dllexport) void StartupConfig(unsigned long long *config, void *output) {
    reinterpret_cast<void (*)(unsigned long long *, void *)>(StartupSettings.configInitializer)(config, output);
}
extern "C" __declspec(dllexport) HWND WINAPI StartupCreateWindow(DWORD extended, LPCWSTR name,
    LPCWSTR title, DWORD style, int x, int y, int width, int height, HWND parent, HMENU menu,
    HINSTANCE instance, LPVOID parameter) {
    if (!apiCreateWindowExW)
        apiCreateWindowExW = reinterpret_cast<decltype(apiCreateWindowExW)>(apiGetProcAddress(apiLoadLibraryW(L"user32.dll"), "CreateWindowExW"));
    if (g_request && (g_request->flags & STARTF_USEPOSITION)) { x = g_request->x; y = g_request->y; }
    return apiCreateWindowExW(extended, name, title, style, x, y, width, height, parent, menu, instance, parameter);
}
extern "C" __declspec(dllexport) void StartupQueue(const StringView *json, unsigned position) {
    STARTUPINFOW si{}; si.cb = sizeof(si);
    const unsigned int *placement = nullptr;
    if (position) {
        POINT point{};
        auto pending = reinterpret_cast<const unsigned int *>(StartupSettings.placementPending);
        if (pending && pending[0] == 0x32545046 && pending[1] == 0x20) {
            si.dwFlags = STARTF_USEPOSITION; si.dwX = pending[2]; si.dwY = pending[3];
            placement = pending;
        } else if (g_ready && apiGetCursorPos(&point)) {
            si.dwFlags = STARTF_USEPOSITION; si.dwX = point.x; si.dwY = point.y;
        }
    }
    if (g_ready && EnvNumber(L"FPILOT_WARM", 0, 0, 1) && Deliver(g_defaultCommand, nullptr, json, &si, nullptr, placement)) {
        if (StartupSettings.placementPending) *reinterpret_cast<unsigned int *>(StartupSettings.placementPending) = 0;
        return;
    }
    reinterpret_cast<void (*)(const StringView *, unsigned)>(StartupSettings.queueWindow)(json, position);
}
extern "C" __declspec(dllexport) BOOL WINAPI StartupCreateProcess(
    LPCWSTR app, LPWSTR command, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
    BOOL inherit, DWORD flags, LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
    LPPROCESS_INFORMATION info) {
    // These are only the two native ordinary self-launch sites, never uninstall.
    if (g_ready && !pa && !ta && !inherit && !flags && !environment &&
        (!startup || !(startup->dwFlags & ~(STARTF_USEPOSITION | STARTF_USESHOWWINDOW))) &&
        !HasNativePanelTransfer() && app && Equal(app, g_exe) &&
        EnvNumber(L"FPILOT_WARM", 0, 0, 1) && Deliver(command ? command : g_defaultCommand, directory, nullptr, startup, info)) return TRUE;
    if (!apiCreateProcessW)
        apiCreateProcessW = reinterpret_cast<decltype(apiCreateProcessW)>(apiGetProcAddress(apiLoadLibraryW(L"kernel32.dll"), "CreateProcessW"));
    return apiCreateProcessW(app, command, pa, ta, inherit, flags, environment, directory, startup, info);
}
extern "C" __declspec(dllexport) HRESULT WINAPI StartupD3D(
    IDXGIAdapter *adapter, D3D_DRIVER_TYPE type, HMODULE software, UINT flags,
    const D3D_FEATURE_LEVEL *levels, UINT count, UINT sdk, ID3D11Device **device,
    D3D_FEATURE_LEVEL *level, ID3D11DeviceContext **context) {
    // A recreated device can reuse COM pointer addresses. Never carry a write
    // cursor into a new device's uninitialized buffer.
    g_uploadContext = nullptr; g_uploadBuffer = nullptr; g_uploadCursor = 0;
    if (g_device && !adapter && type == D3D_DRIVER_TYPE_HARDWARE && !software && !flags &&
        sdk == D3D11_SDK_VERSION && count == 1 && levels && levels[0] == g_featureLevel && device && context &&
        SUCCEEDED(g_device->GetDeviceRemovedReason())) {
        *device = g_device; *context = g_context; if (level) *level = g_featureLevel;
        g_device = nullptr; g_context = nullptr; return S_OK;
    }
    if (g_context) { g_context->Release(); g_context = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
    if (!apiD3D11CreateDevice) {
        HMODULE module = apiLoadLibraryW(L"d3d11.dll");
        apiD3D11CreateDevice = reinterpret_cast<decltype(apiD3D11CreateDevice)>(apiGetProcAddress(module, "D3D11CreateDevice"));
    }
    return apiD3D11CreateDevice ? apiD3D11CreateDevice(adapter, type, software, flags, levels, count, sdk, device, level, context) : E_FAIL;
}
extern "C" __declspec(dllexport) void StartupFrame(unsigned long long app) {
    if (StartupSettings.unicodeMaintenance)
        reinterpret_cast<void (*)(unsigned)>(StartupSettings.unicodeMaintenance)(3);
    reinterpret_cast<void (*)(unsigned long long)>(StartupSettings.frameHook)(app);
    if (!g_ready || g_visibleStarted) return;
    auto platform = *reinterpret_cast<unsigned char **>(StartupSettings.platformGlobal);
    HWND hwnd = platform ? *reinterpret_cast<HWND *>(platform + 0x8c0) : nullptr;
    if (!hwnd) return;
    // Recover the mailbox even if the requester exited after adoption but
    // before observing its acknowledgement.
    if (g_activated && Lock()) {
        if (g_shared->state == Taken && g_shared->pid == apiGetCurrentProcessId()) {
            g_shared->state = Empty; g_shared->pid = 0;
        }
        Unlock();
    }
    g_visibleStarted = true; g_window = hwnd; g_lastActivity = apiGetTickCount64();
    g_windowProc = reinterpret_cast<WNDPROC>(apiSetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(WindowProc)));
    g_nextSpawn = g_lastActivity + 250;
    apiSetTimer(hwnd, kMaintenanceTimer, 500, Timer);
    // The native factories now retain their own references.
    if (g_fontCollection) { g_fontCollection->Release(); g_fontCollection = nullptr; }
    if (g_fontFactory) { g_fontFactory->Release(); g_fontFactory = nullptr; }
}
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }

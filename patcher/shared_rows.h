// Included by unicode_payload.cpp after the native row structures. Each mapping
// contains one immutable CPU raster; GPU resource descriptors remain private.
namespace SharedRows {
static constexpr DWORD kMaxPixels = 4 * 1024 * 1024;
static constexpr DWORD kMagic = 0x32525046;
struct Header {
    volatile LONG ready;
    DWORD magic, version, bytes;
    unsigned long long hash;
    float emSize, maximumWidth, layoutWidth, layoutHeight;
    DWORD family, textLength, width, height;
    RECT bounds;
    wchar_t text[kOverlayTextLimit + 1];
};
static decltype(&CreateFileMappingW) createMapping;
static decltype(&OpenFileMappingW) openMapping;
static decltype(&MapViewOfFile) mapView;
static decltype(&UnmapViewOfFile) unmapView;
static decltype(&CloseHandle) closeHandle;
static decltype(&GetLastError) lastError;
static bool attempted, available;
static wchar_t prefix[96];
static HANDLE epochMapping;
static volatile LONG *epoch;
static LONG seenEpoch;

static unsigned long long Hash(const void *p, size_t n, unsigned long long h) {
    auto b = static_cast<const unsigned char *>(p);
    while (n--) { h ^= *b++; h *= 1099511628211ULL; } return h;
}
static void Hex(wchar_t *out, unsigned long long value) {
    for (unsigned i = 0; i < 16; ++i) out[i] = L"0123456789abcdef"[(value >> (60 - 4 * i)) & 15];
    out[16] = 0;
}
static bool Init() {
    if (attempted) return available;
    attempted = true;
    HMODULE kernel = pLoadLibraryW()(L"kernel32.dll");
#define ROW_API(n, v) v = reinterpret_cast<decltype(v)>(pGetProcAddress()(kernel, #n)); if (!v) return false;
    ROW_API(CreateFileMappingW, createMapping)
    ROW_API(OpenFileMappingW, openMapping)
    ROW_API(MapViewOfFile, mapView)
    ROW_API(UnmapViewOfFile, unmapView)
    ROW_API(CloseHandle, closeHandle)
    ROW_API(GetLastError, lastError)
#undef ROW_API
    HMODULE advapi = pLoadLibraryW()(L"advapi32.dll");
    auto openToken = reinterpret_cast<decltype(&OpenProcessToken)>(pGetProcAddress()(advapi, "OpenProcessToken"));
    auto getToken = reinterpret_cast<decltype(&GetTokenInformation)>(pGetProcAddress()(advapi, "GetTokenInformation"));
    auto attributes = reinterpret_cast<decltype(&GetFileAttributesExW)>(pGetProcAddress()(kernel, "GetFileAttributesExW"));
    auto windowsDirectory = reinterpret_cast<decltype(&GetWindowsDirectoryW)>(pGetProcAddress()(kernel, "GetWindowsDirectoryW"));
    auto environment = reinterpret_cast<decltype(&GetEnvironmentVariableW)>(pGetProcAddress()(kernel, "GetEnvironmentVariableW"));
    if (!openToken || !getToken || !attributes || !windowsDirectory || !environment) return false;
    HANDLE token; TOKEN_STATISTICS stats{}; DWORD size;
    if (!openToken(reinterpret_cast<HANDLE>(-1), TOKEN_QUERY, &token)) return false;
    bool good = getToken(token, TokenStatistics, &stats, sizeof(stats), &size) != FALSE;
    closeHandle(token); if (!good) return false;
    unsigned long long hash = Hash(&stats.AuthenticationId, sizeof(LUID), 1469598103934665603ULL);
    // A new font installation changes the namespace on the next process launch;
    // WM_FONTCHANGE also advances the epoch shared by already-running processes.
    wchar_t path[1024]; WIN32_FILE_ATTRIBUTE_DATA attr{};
    UINT n = windowsDirectory(path, 900);
    const wchar_t fonts[] = L"\\Fonts";
    if (n && n < 900) {
        memcpy(path + n, fonts, sizeof(fonts));
        if (attributes(path, GetFileExInfoStandard, &attr)) hash = Hash(&attr.ftLastWriteTime, sizeof(FILETIME), hash);
    }
    n = environment(L"LOCALAPPDATA", path, 900);
    const wchar_t userFonts[] = L"\\Microsoft\\Windows\\Fonts";
    if (n && n < 900) {
        memcpy(path + n, userFonts, sizeof(userFonts));
        if (attributes(path, GetFileExInfoStandard, &attr)) hash = Hash(&attr.ftLastWriteTime, sizeof(FILETIME), hash);
    }
    const wchar_t base[] = L"Local\\FPilot.Raster.v2.";
    memcpy(prefix, base, sizeof(base) - 2); Hex(prefix + sizeof(base) / 2 - 1, hash);
    size_t end = sizeof(base) / 2 - 1 + 16;
    const wchar_t suffix[] = L".epoch"; memcpy(prefix + end, suffix, sizeof(suffix));
    epochMapping = createMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, prefix);
    if (epochMapping) epoch = static_cast<volatile LONG *>(mapView(epochMapping, FILE_MAP_ALL_ACCESS, 0, 0, 4096));
    prefix[end] = L'.'; prefix[end + 1] = 0;
    if (!epoch) return false;
    seenEpoch = _InterlockedCompareExchange(epoch, 0, 0); available = true; return true;
}
static void Name(wchar_t *name, const wchar_t *text, const OverlayPacket &packet, float width) {
    unsigned long long hash = Hash(text, packet.textLength * 2, 1469598103934665603ULL);
    hash = Hash(&packet.emSize, sizeof(float), hash);
    hash = Hash(&packet.fontFamily, sizeof(packet.fontFamily), hash);
    hash = Hash(&width, sizeof(width), hash);
    LONG generation = _InterlockedCompareExchange(epoch, 0, 0);
    hash = Hash(&generation, sizeof(generation), hash);
    size_t i = 0; while (prefix[i]) { name[i] = prefix[i]; ++i; } Hex(name + i, hash);
}
static bool Match(const Header *h, const wchar_t *text, const OverlayPacket &packet, float width) {
    if (h->ready != 1 || h->magic != kMagic || h->version != 2 ||
        h->hash != packet.textHash || h->emSize != packet.emSize || h->maximumWidth != width ||
        h->family != packet.fontFamily || h->textLength != packet.textLength ||
        !h->bytes || h->bytes > kMaxPixels || !h->width || !h->height ||
        (unsigned long long)h->width * h->height != h->bytes) return false;
    return SameText(h->text, text, packet.textLength);
}
struct View { HANDLE mapping; Header *header; };
static View Open(const wchar_t *text, const OverlayPacket &packet, float width) {
    View result{}; if (!Init()) return result;
    wchar_t name[128]; Name(name, text, packet, width);
    HANDLE mapping = openMapping(FILE_MAP_READ, FALSE, name); if (!mapping) return result;
    auto header = static_cast<Header *>(mapView(mapping, FILE_MAP_READ, 0, 0, sizeof(Header)));
    DWORD bytes = header && Match(header, text, packet, width) ? header->bytes : 0;
    if (header) unmapView(header);
    if (bytes) header = static_cast<Header *>(mapView(mapping, FILE_MAP_READ, 0, 0, sizeof(Header) + bytes));
    else header = nullptr;
    if (!header) { closeHandle(mapping); return result; }
    result.mapping = mapping; result.header = header; return result;
}
static View Publish(const wchar_t *text, const OverlayPacket &packet, float width,
                    const NativeRowCacheEntry &entry, DWORD bytes) {
    View result{}; if (!Init() || !bytes || bytes > kMaxPixels) return result;
    wchar_t name[128]; Name(name, text, packet, width);
    HANDLE mapping = createMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(Header) + bytes, name);
    if (!mapping) return result;
    DWORD error = lastError();
    if (error == ERROR_ALREADY_EXISTS) { closeHandle(mapping); return Open(text, packet, width); }
    auto header = static_cast<Header *>(mapView(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Header) + bytes));
    if (!header) { closeHandle(mapping); return result; }
    header->magic = kMagic; header->version = 2; header->bytes = bytes;
    header->hash = packet.textHash; header->emSize = packet.emSize; header->maximumWidth = width;
    header->family = packet.fontFamily; header->textLength = packet.textLength;
    header->layoutWidth = entry.layoutWidth; header->layoutHeight = entry.layoutHeight;
    header->bounds = entry.bounds; header->width = entry.resource.width; header->height = entry.resource.height;
    memcpy(header->text, text, packet.textLength * 2); header->text[packet.textLength] = 0;
    memcpy(header + 1, entry.resource.pixels, bytes);
    _InterlockedExchange(&header->ready, 1);
    unmapView(header);
    header = static_cast<Header *>(mapView(mapping, FILE_MAP_READ, 0, 0, sizeof(Header) + bytes));
    if (!header) { closeHandle(mapping); return result; }
    result.mapping = mapping; result.header = header; return result;
}
} // namespace SharedRows

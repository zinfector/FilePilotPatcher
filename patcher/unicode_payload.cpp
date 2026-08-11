#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d2d1.h>
#include <d3d11.h>
#include <dwrite.h>
#include <dxgi.h>

#include "unicode_mask_shaders.h"

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))

// File Pilot's payloads are manually mapped and intentionally have no CRT dependency.
#pragma function(memset, memcpy)
extern "C" void *__cdecl memset(void *destination, int value, size_t length) {
    auto bytes = static_cast<unsigned char *>(destination);
    for (size_t i = 0; i < length; ++i) bytes[i] = static_cast<unsigned char>(value);
    return destination;
}

extern "C" void *__cdecl memcpy(void *destination, const void *source, size_t length) {
    auto output = static_cast<unsigned char *>(destination);
    auto input = static_cast<const unsigned char *>(source);
    for (size_t i = 0; i < length; ++i) output[i] = input[i];
    return destination;
}

extern "C" int _fltused = 0;

struct UnicodeBindings {
    unsigned long long magic;
    unsigned long long version;
    unsigned long long size;
    unsigned long long iatLoadLibraryW;
    unsigned long long iatGetProcAddress;
    unsigned long long iatGetFileAttributesW;
    unsigned long long iatVirtualAlloc;
    unsigned long long iatVirtualFree;
    unsigned long long originalGlyphLookup;
    unsigned long long originalMeasureText;
    unsigned long long originalRenderText;
    unsigned long long originalFontCreateAtlas;
    unsigned long long originalFontRasterizer;
    unsigned long long originalUtf16ToUtf8;
    unsigned long long glyphRangeTable;
    unsigned long long iatD3D11CreateDevice;
    unsigned long long originalD3DRenderFrame;
    unsigned long long d3dRendererGlobal;
    unsigned long long originalNativeQuadEmitter;
    unsigned long long originalD3DDrawBatch;
    unsigned long long nativeRenderDataGlobal;
};

static constexpr unsigned long long kUnicodeBindingsMagic =
    0x53474e4942555046ULL; // "FPUBINGS"
static constexpr unsigned long long kUnicodeBindingsVersion = 6;

extern "C" __declspec(dllexport) volatile UnicodeBindings Bindings = {
    kUnicodeBindingsMagic, kUnicodeBindingsVersion, sizeof(UnicodeBindings)
};

struct NativeStringView {
    const char *data;
    unsigned long long length;
};

struct NativeWideStringView {
    const wchar_t *data;
    unsigned long long length;
};

template <typename T> static T Iat(unsigned long long slot) {
    return *reinterpret_cast<T *>(slot);
}

static auto pLoadLibraryW() {
    return Iat<decltype(&LoadLibraryW)>(Bindings.iatLoadLibraryW);
}
static auto pGetProcAddress() {
    return Iat<decltype(&GetProcAddress)>(Bindings.iatGetProcAddress);
}
static auto pGetFileAttributesW() {
    return Iat<decltype(&GetFileAttributesW)>(Bindings.iatGetFileAttributesW);
}
static auto pVirtualAlloc() {
    return Iat<decltype(&VirtualAlloc)>(Bindings.iatVirtualAlloc);
}
static auto pVirtualFree() {
    return Iat<decltype(&VirtualFree)>(Bindings.iatVirtualFree);
}

static auto pD3D11CreateDevice() {
    return Iat<decltype(&D3D11CreateDevice)>(Bindings.iatD3D11CreateDevice);
}

enum ExperimentFlags : unsigned int {
    ExperimentInitialized = 1u << 0,
    ExperimentD3DReady = 1u << 1,
    ExperimentFastRanges = 1u << 3,
    ExperimentBackendFallback = 1u << 4,
    ExperimentD3DAtlasReady = 1u << 5,
    ExperimentNativeInline = 1u << 6,
};

static constexpr unsigned int kNativeRendererShapedGlyphs = 2;
static constexpr unsigned int kNativeTransformProbe = 2;

struct UnicodeExperimentState {
    unsigned int version;
    unsigned int flags;
    unsigned long long measureCalls;
    unsigned long long renderCalls;
    unsigned long long overlayQueued;
    unsigned long long overlayDrawn;
    unsigned long long overlayDropped;
    unsigned long long backendFallbacks;
    unsigned long long glyphCacheHits;
    unsigned long long glyphCacheMisses;
    unsigned long long rangeAtlasesSuppressed;
    unsigned long long shapeMicroseconds;
    unsigned long long drawMicroseconds;
    long long lastDWriteStatus;
    unsigned long long frameCalls;
    unsigned long long atlasSuccessMask;
    unsigned long long fontMetricHits;
    unsigned long long fontMetricMisses;
    unsigned long long lastNativeFontSizeBits;
    unsigned long long lastDWriteEmSizeBits;
    unsigned long long d3dAtlasBuilds;
    unsigned long long d3dAtlasCacheHits;
    unsigned long long d3dAtlasCacheMisses;
    unsigned long long d3dAtlasFailures;
    unsigned long long d3dAtlasDrawCalls;
    unsigned long long d3dAtlasUploadBytes;
    long long lastD3DAtlasStatus;
    unsigned long long overlayCoalesced;
    unsigned long long overlayColorUpdates;
    unsigned int nativeRendererMode;
    unsigned int nativeRendererReserved;
    unsigned long long nativeMarkersSubmitted;
    unsigned long long nativeMarkersDrawn;
    unsigned long long nativeMarkersMissed;
    unsigned long long nativeBatchSplits;
    unsigned long long customCommandsSubmitted;
    unsigned long long customCommandFallbacks;
    unsigned long long shapedGlyphBuilds;
    unsigned long long shapedGlyphCacheHits;
    unsigned long long shapedGlyphDrawCalls;
    unsigned int nativeTransformMode;
    unsigned int nativeTransformReserved;
    unsigned long long nativeTransformCaptures;
    unsigned long long nativeTransformFailures;
    unsigned long long nativeAnimatedDraws;
    unsigned long long nativeProbeMarkers;
    unsigned long long nativeTransformMaxResidualBits;
};

extern "C" __declspec(dllexport) volatile UnicodeExperimentState UnicodeExperiment = {
    7, ExperimentInitialized
};

static volatile LONG g_d3dReady;

using VirtualProtectFn = BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD);

static bool WideEqualsAscii(const wchar_t *wide, const char *ascii) {
    unsigned int index = 0;
    for (; wide[index] && ascii[index]; ++index) {
        wchar_t left = wide[index];
        char right = ascii[index];
        if (L'A' <= left && left <= L'Z') left += L'a' - L'A';
        if ('A' <= right && right <= 'Z') right += 'a' - 'A';
        if (left != static_cast<wchar_t>(right)) return false;
    }
    return wide[index] == 0 && ascii[index] == 0;
}

static unsigned int FloatBits(float value) {
    return *reinterpret_cast<unsigned int *>(&value);
}

static void InstallFastGlyphRanges() {
    if (!Bindings.glyphRangeTable) return;
    static const unsigned int ranges[][2] = {
        {0x0020, 0x007f}, {0x0080, 0x00ff}, {0x0100, 0x017f},
        {0x0180, 0x024f}, {0x0370, 0x03ff}, {0x0400, 0x04ff},
        {0x0500, 0x052f}, {0x2de0, 0x2dff}, {0xa640, 0xa69f},
        {0x1c80, 0x1c8f}, {0x0300, 0x036f}, {0x2000, 0x206f},
        {0x2190, 0x2193}, {0xe000, 0xe096}, {0xe400, 0xe400},
        {0xe800, 0xe801}, {0xec00, 0xec00},
    };
    HMODULE kernel32 = pLoadLibraryW()(L"kernel32.dll");
    auto protect = kernel32 ? reinterpret_cast<VirtualProtectFn>(
        pGetProcAddress()(kernel32, "VirtualProtect")) : nullptr;
    DWORD oldProtection = 0;
    if (!protect || !protect(reinterpret_cast<void *>(Bindings.glyphRangeTable),
                             sizeof(ranges), PAGE_READWRITE, &oldProtection)) return;
    memcpy(reinterpret_cast<void *>(Bindings.glyphRangeTable), ranges, sizeof(ranges));
    DWORD ignored = 0;
    protect(reinterpret_cast<void *>(Bindings.glyphRangeTable),
            sizeof(ranges), oldProtection, &ignored);
    UnicodeExperiment.flags |= ExperimentFastRanges;
}

static volatile LONG g_pendingHighSurrogate;

struct UnicodeDebugState {
    unsigned long long ttcAtlasCalls;
    unsigned long long ttcAtlasFailures;
    unsigned long long shapedStrings;
    unsigned long long pairedSurrogates;
    unsigned long long invalidSurrogates;
    unsigned long long fontAtlasCalls;
    unsigned long long fallbackAtlasCalls;
    unsigned long long fontAtlasSuccesses;
    unsigned long long fontAtlasFailures;
    unsigned long long fontClassSuccessMask;
    unsigned long long fontClassFailureMask;
    unsigned int lastCodepoint;
    unsigned int lastRangeLow;
    unsigned int lastRangeHigh;
    unsigned int lastRangeIndex;
    unsigned int lastFontClass;
    unsigned int lastFontPathHash;
};

extern "C" __declspec(dllexport) volatile UnicodeDebugState UnicodeDebug = {};

static constexpr unsigned int kFirstFallbackRange = 3;

extern "C" __declspec(dllexport) long long __fastcall UnicodeGlyphLookupHook(
    long long font, int codepoint) {
    using OriginalFn = long long (__fastcall *)(long long, int);
    return reinterpret_cast<OriginalFn>(Bindings.originalGlyphLookup)(font, codepoint);
}

enum FontClass : unsigned int {
    FontConfigured,
    FontArabic,
    FontCjk,
    FontKorean,
    FontIndic,
    FontSymbols,
    FontEmoji,
    FontClassCount,
};

using GetWindowsDirectoryWFn = UINT (WINAPI *)(LPWSTR, UINT);
static wchar_t g_fallbackPaths[FontClassCount][32768] = {};
static volatile LONG g_fontPathStates[FontClassCount] = {};

static bool AppendWide(wchar_t *destination, unsigned int capacity, unsigned int &length,
                       const wchar_t *source) {
    for (unsigned int index = 0; source[index]; ++index) {
        if (length + 1 >= capacity) return false;
        destination[length++] = source[index];
    }
    destination[length] = 0;
    return true;
}

static const wchar_t *ResolveFallbackPath(FontClass fontClass) {
    if (fontClass == FontConfigured) return nullptr;
    LONG state = _InterlockedCompareExchange(&g_fontPathStates[fontClass], 1, 0);
    if (state == 2) return g_fallbackPaths[fontClass][0] ? g_fallbackPaths[fontClass] : nullptr;
    if (state == 1) {
        while (_InterlockedCompareExchange(&g_fontPathStates[fontClass], 0, 0) == 1)
            YieldProcessor();
        return g_fallbackPaths[fontClass][0] ? g_fallbackPaths[fontClass] : nullptr;
    }

    static const wchar_t *arabic[] = {L"segoeui.ttf", L"arial.ttf", nullptr};
    static const wchar_t *cjk[] = {
        L"msyh.ttc", L"simsun.ttc", L"YuGothM.ttc", L"meiryo.ttc", L"msgothic.ttc",
        L"simsunb.ttf",
        nullptr
    };
    static const wchar_t *korean[] = {L"malgun.ttf", L"malgunbd.ttf", L"msyh.ttc", nullptr};
    static const wchar_t *indic[] = {L"Nirmala.ttc", L"segoeui.ttf", nullptr};
    static const wchar_t *symbols[] = {L"seguisym.ttf", L"segoeui.ttf", nullptr};
    static const wchar_t *emoji[] = {L"seguiemj.ttf", L"seguisym.ttf", nullptr};
    const wchar_t **candidates = nullptr;
    switch (fontClass) {
    case FontArabic: candidates = arabic; break;
    case FontCjk: candidates = cjk; break;
    case FontKorean: candidates = korean; break;
    case FontIndic: candidates = indic; break;
    case FontSymbols: candidates = symbols; break;
    case FontEmoji: candidates = emoji; break;
    default: break;
    }

    HMODULE kernel32 = pLoadLibraryW()(L"kernel32.dll");
    auto getWindowsDirectory = kernel32 ? reinterpret_cast<GetWindowsDirectoryWFn>(
        pGetProcAddress()(kernel32, "GetWindowsDirectoryW")) : nullptr;
    wchar_t windowsDirectory[1024] = {};
    UINT windowsLength = getWindowsDirectory
        ? getWindowsDirectory(windowsDirectory, static_cast<UINT>(ARRAY_COUNT(windowsDirectory))) : 0;
    if (windowsLength && windowsLength < ARRAY_COUNT(windowsDirectory) && candidates) {
        for (unsigned int candidate = 0; candidates[candidate]; ++candidate) {
            wchar_t *path = g_fallbackPaths[fontClass];
            unsigned int length = 0;
            path[0] = 0;
            if (!AppendWide(path, 32768, length, windowsDirectory) ||
                !AppendWide(path, 32768, length, L"\\Fonts\\") ||
                !AppendWide(path, 32768, length, candidates[candidate])) continue;
            DWORD attributes = pGetFileAttributesW()(path);
            if (attributes != INVALID_FILE_ATTRIBUTES &&
                (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) break;
            path[0] = 0;
        }
    }
    _InterlockedExchange(&g_fontPathStates[fontClass], 2);
    return g_fallbackPaths[fontClass][0] ? g_fallbackPaths[fontClass] : nullptr;
}

static FontClass ClassifyRange(unsigned int low, unsigned int high) {
    if ((0x0590 <= low && low <= 0x08ff) || (0xfb50 <= low && low <= 0xfeff))
        return FontArabic;
    if ((0x3000 <= low && low <= 0x9fff) || (0xf900 <= low && low <= 0xfaff) ||
        (0x20000 <= low && low <= 0x3134f)) return FontCjk;
    if (0xac00 <= low && low <= 0xd7ff) return FontKorean;
    if ((0x0900 <= low && low <= 0x109f) || (0x1780 <= low && low <= 0x17ff))
        return FontIndic;
    if (0x1f000 <= low && high <= 0x1faff) return FontEmoji;
    if ((0x2000 <= low && low <= 0x2bff) || (0x1f000 <= low && low <= 0x1ffff))
        return FontSymbols;
    return FontConfigured;
}

static unsigned int HashWide(const wchar_t *text) {
    unsigned int hash = 2166136261u;
    if (!text) return 0;
    for (unsigned int index = 0; text[index]; ++index) {
        hash ^= static_cast<unsigned int>(text[index]);
        hash *= 16777619u;
    }
    return hash;
}

static bool IsTtcPath(const wchar_t *path) {
    if (!path) return false;
    unsigned int length = 0;
    while (path[length]) ++length;
    if (length < 4 || path[length - 4] != L'.') return false;
    wchar_t first = path[length - 3];
    wchar_t second = path[length - 2];
    wchar_t third = path[length - 1];
    if (L'A' <= first && first <= L'Z') first += L'a' - L'A';
    if (L'A' <= second && second <= L'Z') second += L'a' - L'A';
    if (L'A' <= third && third <= L'Z') third += L'a' - L'A';
    return first == L't' && second == L't' && third == L'c';
}

enum NativeFontFamily : unsigned int {
    NativeFontSegoeUI,
    NativeFontConsolas,
    NativeFontArial,
    NativeFontTahoma,
    NativeFontVerdana,
    NativeFontCalibri,
    NativeFontTimesNewRoman,
    NativeFontCourierNew,
    NativeFontSegoeUISymbol,
    NativeFontSegoeUIEmoji,
};

static const wchar_t *PathBaseName(const wchar_t *path) {
    if (!path) return L"";
    const wchar_t *base = path;
    for (const wchar_t *cursor = path; *cursor; ++cursor)
        if (*cursor == L'\\' || *cursor == L'/') base = cursor + 1;
    return base;
}

static NativeFontFamily ClassifyConfiguredFont(const wchar_t *path) {
    const wchar_t *base = PathBaseName(path);
    if (WideEqualsAscii(base, "consola.ttf")) return NativeFontConsolas;
    if (WideEqualsAscii(base, "arial.ttf")) return NativeFontArial;
    if (WideEqualsAscii(base, "tahoma.ttf")) return NativeFontTahoma;
    if (WideEqualsAscii(base, "verdana.ttf")) return NativeFontVerdana;
    if (WideEqualsAscii(base, "calibri.ttf")) return NativeFontCalibri;
    if (WideEqualsAscii(base, "times.ttf")) return NativeFontTimesNewRoman;
    if (WideEqualsAscii(base, "cour.ttf")) return NativeFontCourierNew;
    if (WideEqualsAscii(base, "seguisym.ttf")) return NativeFontSegoeUISymbol;
    if (WideEqualsAscii(base, "seguiemj.ttf")) return NativeFontSegoeUIEmoji;
    return NativeFontSegoeUI;
}

static const wchar_t *NativeFontFamilyName(NativeFontFamily family) {
    switch (family) {
    case NativeFontConsolas: return L"Consolas";
    case NativeFontArial: return L"Arial";
    case NativeFontTahoma: return L"Tahoma";
    case NativeFontVerdana: return L"Verdana";
    case NativeFontCalibri: return L"Calibri";
    case NativeFontTimesNewRoman: return L"Times New Roman";
    case NativeFontCourierNew: return L"Courier New";
    case NativeFontSegoeUISymbol: return L"Segoe UI Symbol";
    case NativeFontSegoeUIEmoji: return L"Segoe UI Emoji";
    default: return L"Segoe UI";
    }
}

struct NativeFontRecord {
    const void *volatile font;
    float emSize;
    NativeFontFamily family;
};

static constexpr unsigned int kNativeFontRecordCount = 16;
static NativeFontRecord g_nativeFontRecords[kNativeFontRecordCount];
static volatile LONG g_nativeFontRecordLock;
static unsigned int g_nativeFontRecordVictim;

static void LockNativeFontRecords() {
    while (_InterlockedExchange(&g_nativeFontRecordLock, 1) != 0) YieldProcessor();
}

static void UnlockNativeFontRecords() {
    _InterlockedExchange(&g_nativeFontRecordLock, 0);
}

static void RecordNativeFont(const void *font, float configuredSize, const wchar_t *path) {
    if (!font || configuredSize < 1.0f || configuredSize > 256.0f) return;
    // File Pilot's WinFontRasterizer.cpp converts its configured point size to
    // DirectWrite DIPs with this exact factor before requesting glyph metrics.
    float emSize = configuredSize * 1.3333333730697632f;
    LockNativeFontRecords();
    unsigned int slot = kNativeFontRecordCount;
    for (unsigned int index = 0; index < kNativeFontRecordCount; ++index) {
        if (g_nativeFontRecords[index].font == font) {
            slot = index;
            break;
        }
        if (!g_nativeFontRecords[index].font && slot == kNativeFontRecordCount) slot = index;
    }
    if (slot == kNativeFontRecordCount) {
        slot = g_nativeFontRecordVictim++ % kNativeFontRecordCount;
    }
    g_nativeFontRecords[slot].font = font;
    g_nativeFontRecords[slot].emSize = emSize;
    g_nativeFontRecords[slot].family = ClassifyConfiguredFont(path);
    UnlockNativeFontRecords();
    UnicodeExperiment.lastNativeFontSizeBits = FloatBits(configuredSize);
}

using ComReleaseFn = ULONG (__fastcall *)(void *);
using CreateFontFileReferenceFn = HRESULT (__fastcall *)(
    void *, const wchar_t *, const FILETIME *, void **);
using CreateFontFaceFn = HRESULT (__fastcall *)(
    void *, unsigned int, unsigned int, void *const *, unsigned int, unsigned int, void **);
using DWriteCreateFactoryFn = HRESULT (WINAPI *)(unsigned int, const GUID &, void **);

struct FactoryVtableProxy {
    void *methods[24];
    void *originalCreateFontFace;
};

static HRESULT __fastcall TtcCreateFontFaceProxy(
    void *factory, unsigned int, unsigned int fileCount, void *const *fontFiles,
    unsigned int faceIndex, unsigned int simulations, void **fontFace) {
    auto proxy = reinterpret_cast<FactoryVtableProxy *>(*reinterpret_cast<void ***>(factory));
    auto original = reinterpret_cast<CreateFontFaceFn>(proxy->originalCreateFontFace);
    // File Pilot hard-codes TRUETYPE (1), which makes DirectWrite reject every .ttc file.
    return original(factory, 2, fileCount, fontFiles, faceIndex, simulations, fontFace);
}

static unsigned long long CreateTtcAtlas(unsigned int *font, float size,
                                         const wchar_t *path, unsigned int rangeIndex,
                                         int renderingMode) {
    HMODULE dwrite = pLoadLibraryW()(L"dwrite.dll");
    auto createFactory = dwrite ? reinterpret_cast<DWriteCreateFactoryFn>(
        pGetProcAddress()(dwrite, "DWriteCreateFactory")) : nullptr;
    if (!createFactory) return 0;

    static const GUID idWriteFactory = {
        0xb859ee5a, 0xd838, 0x4b5b,
        {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}
    };
    void *factory = nullptr;
    // An isolated factory lets us proxy its vtable without touching File Pilot's shared factory.
    if (createFactory(1, idWriteFactory, &factory) < 0 || !factory) return 0;

    void *fontFile = nullptr;
    void **originalVtable = *reinterpret_cast<void ***>(factory);
    auto createFontFile = reinterpret_cast<CreateFontFileReferenceFn>(originalVtable[7]);
    HRESULT status = createFontFile(factory, path, nullptr, &fontFile);
    unsigned long long result = 0;
    if (status >= 0 && fontFile) {
        FactoryVtableProxy proxy = {};
        for (unsigned int index = 0; index < ARRAY_COUNT(proxy.methods); ++index)
            proxy.methods[index] = originalVtable[index];
        proxy.methods[9] = reinterpret_cast<void *>(&TtcCreateFontFaceProxy);
        proxy.originalCreateFontFace = originalVtable[9];
        *reinterpret_cast<void ***>(factory) = proxy.methods;
        using RasterizerFn = unsigned long long (__fastcall *)(
            unsigned int *, float, void *, void *, unsigned int, int);
        result = reinterpret_cast<RasterizerFn>(Bindings.originalFontRasterizer)(
            font, size, factory, fontFile, rangeIndex, renderingMode);
        *reinterpret_cast<void ***>(factory) = originalVtable;
    }
    if (fontFile) {
        void **fileVtable = *reinterpret_cast<void ***>(fontFile);
        reinterpret_cast<ComReleaseFn>(fileVtable[2])(fontFile);
    }
    reinterpret_cast<ComReleaseFn>(originalVtable[2])(factory);
    return result;
}

extern "C" __declspec(dllexport) unsigned long long __fastcall UnicodeFontCreateAtlasHook(
    unsigned int *font, float size, const wchar_t *configuredPath, unsigned int rangeIndex,
    int renderingMode) {
    RecordNativeFont(font, size, configuredPath);
    const wchar_t *path = configuredPath;
    FontClass fontClass = FontConfigured;
    UnicodeDebug.fontAtlasCalls++;
    bool d3dReady = _InterlockedCompareExchange(&g_d3dReady, 0, 0) != 0;
    if (d3dReady && kFirstFallbackRange <= rangeIndex && rangeIndex < 12)
        UnicodeExperiment.rangeAtlasesSuppressed++;
    if (!d3dReady && Bindings.glyphRangeTable &&
        kFirstFallbackRange <= rangeIndex && rangeIndex < 12) {
        unsigned long long range = reinterpret_cast<volatile unsigned long long *>(
            Bindings.glyphRangeTable)[rangeIndex];
        fontClass = ClassifyRange(static_cast<unsigned int>(range),
                                  static_cast<unsigned int>(range >> 32));
        const wchar_t *fallback = ResolveFallbackPath(fontClass);
        UnicodeDebug.lastRangeLow = static_cast<unsigned int>(range);
        UnicodeDebug.lastRangeHigh = static_cast<unsigned int>(range >> 32);
        UnicodeDebug.lastRangeIndex = rangeIndex;
        UnicodeDebug.lastFontClass = fontClass;
        if (fallback) {
            path = fallback;
            UnicodeDebug.fallbackAtlasCalls++;
        }
    }
    UnicodeDebug.lastFontPathHash = HashWide(path);
    using OriginalFn = unsigned long long (__fastcall *)(
        unsigned int *, float, const wchar_t *, unsigned int, int);
    unsigned long long result;
    if (IsTtcPath(path)) {
        UnicodeDebug.ttcAtlasCalls++;
        result = CreateTtcAtlas(font, size, path, rangeIndex, renderingMode);
        if (!result) UnicodeDebug.ttcAtlasFailures++;
    } else {
        result = reinterpret_cast<OriginalFn>(Bindings.originalFontCreateAtlas)(
            font, size, path, rangeIndex, renderingMode);
    }
    if (result) {
        UnicodeDebug.fontAtlasSuccesses++;
        UnicodeDebug.fontClassSuccessMask |= 1ULL << fontClass;
        if (rangeIndex < 64) UnicodeExperiment.atlasSuccessMask |= 1ULL << rangeIndex;
    } else {
        UnicodeDebug.fontAtlasFailures++;
        UnicodeDebug.fontClassFailureMask |= 1ULL << fontClass;
    }
    return result;
}

struct ArabicForm {
    unsigned int codepoint;
    unsigned int isolated;
    unsigned int finalForm;
    unsigned int initial;
    unsigned int medial;
    unsigned int joining; // bit 0: joins logical previous; bit 1: joins logical next
};

static const ArabicForm kArabicForms[] = {
    {0x0621,0xfe80,0,0,0,0}, {0x0622,0xfe81,0xfe82,0,0,1},
    {0x0623,0xfe83,0xfe84,0,0,1}, {0x0624,0xfe85,0xfe86,0,0,1},
    {0x0625,0xfe87,0xfe88,0,0,1}, {0x0626,0xfe89,0xfe8a,0xfe8b,0xfe8c,3},
    {0x0627,0xfe8d,0xfe8e,0,0,1}, {0x0628,0xfe8f,0xfe90,0xfe91,0xfe92,3},
    {0x0629,0xfe93,0xfe94,0,0,1}, {0x062a,0xfe95,0xfe96,0xfe97,0xfe98,3},
    {0x062b,0xfe99,0xfe9a,0xfe9b,0xfe9c,3}, {0x062c,0xfe9d,0xfe9e,0xfe9f,0xfea0,3},
    {0x062d,0xfea1,0xfea2,0xfea3,0xfea4,3}, {0x062e,0xfea5,0xfea6,0xfea7,0xfea8,3},
    {0x062f,0xfea9,0xfeaa,0,0,1}, {0x0630,0xfeab,0xfeac,0,0,1},
    {0x0631,0xfead,0xfeae,0,0,1}, {0x0632,0xfeaf,0xfeb0,0,0,1},
    {0x0633,0xfeb1,0xfeb2,0xfeb3,0xfeb4,3}, {0x0634,0xfeb5,0xfeb6,0xfeb7,0xfeb8,3},
    {0x0635,0xfeb9,0xfeba,0xfebb,0xfebc,3}, {0x0636,0xfebd,0xfebe,0xfebf,0xfec0,3},
    {0x0637,0xfec1,0xfec2,0xfec3,0xfec4,3}, {0x0638,0xfec5,0xfec6,0xfec7,0xfec8,3},
    {0x0639,0xfec9,0xfeca,0xfecb,0xfecc,3}, {0x063a,0xfecd,0xfece,0xfecf,0xfed0,3},
    {0x0640,0x0640,0x0640,0x0640,0x0640,3},
    {0x0641,0xfed1,0xfed2,0xfed3,0xfed4,3}, {0x0642,0xfed5,0xfed6,0xfed7,0xfed8,3},
    {0x0643,0xfed9,0xfeda,0xfedb,0xfedc,3}, {0x0644,0xfedd,0xfede,0xfedf,0xfee0,3},
    {0x0645,0xfee1,0xfee2,0xfee3,0xfee4,3}, {0x0646,0xfee5,0xfee6,0xfee7,0xfee8,3},
    {0x0647,0xfee9,0xfeea,0xfeeb,0xfeec,3}, {0x0648,0xfeed,0xfeee,0,0,1},
    {0x0649,0xfeef,0xfef0,0,0,1}, {0x064a,0xfef1,0xfef2,0xfef3,0xfef4,3},
    {0x0671,0xfb50,0xfb51,0,0,1}, {0x0679,0xfb66,0xfb67,0xfb68,0xfb69,3},
    {0x067a,0xfb5e,0xfb5f,0xfb60,0xfb61,3}, {0x067b,0xfb52,0xfb53,0xfb54,0xfb55,3},
    {0x067e,0xfb56,0xfb57,0xfb58,0xfb59,3}, {0x0686,0xfb7a,0xfb7b,0xfb7c,0xfb7d,3},
    {0x0688,0xfb88,0xfb89,0,0,1}, {0x0691,0xfb8c,0xfb8d,0,0,1},
    {0x0698,0xfb8a,0xfb8b,0,0,1}, {0x06a4,0xfb6a,0xfb6b,0xfb6c,0xfb6d,3},
    {0x06a9,0xfb8e,0xfb8f,0xfb90,0xfb91,3}, {0x06af,0xfb92,0xfb93,0xfb94,0xfb95,3},
    {0x06ba,0xfb9e,0xfb9f,0,0,1}, {0x06be,0xfbaa,0xfbab,0xfbac,0xfbad,3},
    {0x06c0,0xfba4,0xfba5,0,0,1}, {0x06c1,0xfba6,0xfba7,0xfba8,0xfba9,3},
    {0x06c5,0xfbe0,0xfbe1,0,0,1}, {0x06c6,0xfbd9,0xfbda,0,0,1},
    {0x06c7,0xfbd7,0xfbd8,0,0,1}, {0x06c8,0xfbdb,0xfbdc,0,0,1},
    {0x06c9,0xfbe2,0xfbe3,0,0,1}, {0x06cb,0xfbde,0xfbdf,0,0,1},
    {0x06cc,0xfbfc,0xfbfd,0xfbfe,0xfbff,3}, {0x06d0,0xfbe4,0xfbe5,0xfbe6,0xfbe7,3},
    {0x06d2,0xfbae,0xfbaf,0,0,1}, {0x06d3,0xfbb0,0xfbb1,0,0,1},
};

static const ArabicForm *FindArabicForm(unsigned int codepoint) {
    for (unsigned int index = 0; index < ARRAY_COUNT(kArabicForms); ++index)
        if (kArabicForms[index].codepoint == codepoint) return &kArabicForms[index];
    return nullptr;
}

static bool IsTransparentArabic(unsigned int codepoint) {
    return (0x0610 <= codepoint && codepoint <= 0x061a) ||
        (0x064b <= codepoint && codepoint <= 0x065f) || codepoint == 0x0670 ||
        (0x06d6 <= codepoint && codepoint <= 0x06ed) || codepoint == 0x200d;
}

static bool IsArabicRunCodepoint(unsigned int codepoint) {
    return FindArabicForm(codepoint) || IsTransparentArabic(codepoint) ||
        codepoint == 0x060c || codepoint == 0x061b || codepoint == 0x061f;
}

static unsigned int DecodeUtf8(const char *data, unsigned long long remaining,
                               unsigned int &codepoint) {
    if (!remaining) return 0;
    unsigned int first = static_cast<unsigned char>(data[0]);
    if (first < 0x80) { codepoint = first; return 1; }
    if ((first & 0xe0) == 0xc0 && remaining >= 2) {
        unsigned int second = static_cast<unsigned char>(data[1]);
        if ((second & 0xc0) == 0x80) {
            codepoint = ((first & 0x1f) << 6) | (second & 0x3f);
            return codepoint >= 0x80 ? 2 : 0;
        }
    } else if ((first & 0xf0) == 0xe0 && remaining >= 3) {
        unsigned int second = static_cast<unsigned char>(data[1]);
        unsigned int third = static_cast<unsigned char>(data[2]);
        if ((second & 0xc0) == 0x80 && (third & 0xc0) == 0x80) {
            codepoint = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
            return codepoint >= 0x800 && !(0xd800 <= codepoint && codepoint <= 0xdfff) ? 3 : 0;
        }
    } else if ((first & 0xf8) == 0xf0 && remaining >= 4) {
        unsigned int second = static_cast<unsigned char>(data[1]);
        unsigned int third = static_cast<unsigned char>(data[2]);
        unsigned int fourth = static_cast<unsigned char>(data[3]);
        if ((second & 0xc0) == 0x80 && (third & 0xc0) == 0x80 && (fourth & 0xc0) == 0x80) {
            codepoint = ((first & 7) << 18) | ((second & 0x3f) << 12) |
                ((third & 0x3f) << 6) | (fourth & 0x3f);
            return 0x10000 <= codepoint && codepoint <= 0x10ffff ? 4 : 0;
        }
    }
    codepoint = 0xfffd;
    return 1;
}

static unsigned int EncodeUtf8(unsigned int codepoint, char *output) {
    if (codepoint < 0x80) { output[0] = static_cast<char>(codepoint); return 1; }
    if (codepoint < 0x800) {
        output[0] = static_cast<char>(0xc0 | (codepoint >> 6));
        output[1] = static_cast<char>(0x80 | (codepoint & 0x3f));
        return 2;
    }
    if (codepoint < 0x10000) {
        output[0] = static_cast<char>(0xe0 | (codepoint >> 12));
        output[1] = static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f));
        output[2] = static_cast<char>(0x80 | (codepoint & 0x3f));
        return 3;
    }
    output[0] = static_cast<char>(0xf0 | (codepoint >> 18));
    output[1] = static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f));
    output[2] = static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f));
    output[3] = static_cast<char>(0x80 | (codepoint & 0x3f));
    return 4;
}

struct ShapeUnit {
    unsigned int codepoint;
    unsigned int shaped;
};

struct ShapeResult {
    NativeStringView view;
    void *allocation;
    unsigned int codepointCount;
};

static unsigned int PreviousJoinable(ShapeUnit *units, unsigned int start, unsigned int index) {
    while (index > start) {
        --index;
        if (!IsTransparentArabic(units[index].codepoint)) return index;
    }
    return 0xffffffff;
}

static unsigned int NextJoinable(ShapeUnit *units, unsigned int end, unsigned int index) {
    while (++index < end)
        if (!IsTransparentArabic(units[index].codepoint)) return index;
    return 0xffffffff;
}

static void ShapeArabicSegment(ShapeUnit *units, unsigned int start, unsigned int end) {
    for (unsigned int index = start; index < end; ++index) {
        const ArabicForm *current = FindArabicForm(units[index].codepoint);
        if (!current) continue;
        unsigned int previousIndex = PreviousJoinable(units, start, index);
        unsigned int nextIndex = NextJoinable(units, end, index);
        const ArabicForm *previous = previousIndex == 0xffffffff ? nullptr :
            FindArabicForm(units[previousIndex].codepoint);
        const ArabicForm *next = nextIndex == 0xffffffff ? nullptr :
            FindArabicForm(units[nextIndex].codepoint);
        bool joinsPrevious = previous && (previous->joining & 2) && (current->joining & 1);
        bool joinsNext = next && (current->joining & 2) && (next->joining & 1);
        if (joinsPrevious && joinsNext && current->medial) units[index].shaped = current->medial;
        else if (joinsPrevious && current->finalForm) units[index].shaped = current->finalForm;
        else if (joinsNext && current->initial) units[index].shaped = current->initial;
        else units[index].shaped = current->isolated;
    }
}

static ShapeResult ShapeArabic(const NativeStringView &input) {
    ShapeResult result = {input, nullptr, 0};
    if (!input.data || !input.length || input.length > 0x10000) return result;
    bool containsArabic = false;
    unsigned long long cursor = 0;
    unsigned int count = 0;
    while (cursor < input.length) {
        unsigned int codepoint = 0;
        unsigned int consumed = DecodeUtf8(input.data + cursor, input.length - cursor, codepoint);
        if (!consumed) return result;
        if (FindArabicForm(codepoint)) containsArabic = true;
        cursor += consumed;
        ++count;
    }
    if (!containsArabic) return result;

    unsigned long long unitBytes = static_cast<unsigned long long>(count) * sizeof(ShapeUnit);
    unsigned long long outputBytes = input.length * 2 + 4;
    auto allocation = static_cast<unsigned char *>(pVirtualAlloc()(
        nullptr, unitBytes + outputBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!allocation) return result;
    auto units = reinterpret_cast<ShapeUnit *>(allocation);
    auto output = reinterpret_cast<char *>(allocation + unitBytes);
    cursor = 0;
    for (unsigned int index = 0; index < count; ++index) {
        unsigned int codepoint = 0;
        unsigned int consumed = DecodeUtf8(input.data + cursor, input.length - cursor, codepoint);
        units[index] = {codepoint, codepoint};
        cursor += consumed;
    }

    unsigned int segment = 0;
    while (segment < count) {
        if (!IsArabicRunCodepoint(units[segment].codepoint)) { ++segment; continue; }
        unsigned int end = segment + 1;
        while (end < count && IsArabicRunCodepoint(units[end].codepoint)) ++end;
        ShapeArabicSegment(units, segment, end);
        segment = end;
    }

    unsigned long long outputLength = 0;
    unsigned int index = 0;
    while (index < count) {
        if (!IsArabicRunCodepoint(units[index].codepoint)) {
            outputLength += EncodeUtf8(units[index].shaped, output + outputLength);
            ++index;
            continue;
        }
        unsigned int end = index + 1;
        while (end < count && IsArabicRunCodepoint(units[end].codepoint)) ++end;
        unsigned int cursorIndex = end;
        while (cursorIndex > index) {
            unsigned int clusterEnd = cursorIndex;
            unsigned int clusterStart = cursorIndex - 1;
            while (clusterStart > index && IsTransparentArabic(units[clusterStart].codepoint))
                --clusterStart;
            outputLength += EncodeUtf8(units[clusterStart].shaped, output + outputLength);
            for (unsigned int mark = clusterStart + 1; mark < clusterEnd; ++mark)
                outputLength += EncodeUtf8(units[mark].shaped, output + outputLength);
            cursorIndex = clusterStart;
        }
        index = end;
    }
    result.view = {output, outputLength};
    result.allocation = allocation;
    result.codepointCount = count;
    UnicodeDebug.shapedStrings++;
    return result;
}

static void ReleaseShape(ShapeResult &result) {
    if (result.allocation) pVirtualFree()(result.allocation, 0, MEM_RELEASE);
    result.allocation = nullptr;
}

static unsigned long long ByteOffsetAfterCodepoints(const NativeStringView &text,
                                                     unsigned int count) {
    unsigned long long offset = 0;
    for (unsigned int index = 0; index < count && offset < text.length; ++index) {
        unsigned int codepoint = 0;
        unsigned int consumed = DecodeUtf8(text.data + offset, text.length - offset, codepoint);
        if (!consumed) break;
        offset += consumed;
    }
    return offset;
}

static bool IsNativeIconCodepoint(unsigned int codepoint) {
    return (0xe000 <= codepoint && codepoint <= 0xe096) || codepoint == 0xe400 ||
        (0xe800 <= codepoint && codepoint <= 0xe801) || codepoint == 0xec00 ||
        (0x2190 <= codepoint && codepoint <= 0x2193);
}

static bool ContainsExtendedText(const NativeStringView &text) {
    unsigned long long offset = 0;
    while (offset < text.length) {
        unsigned int codepoint = 0;
        unsigned int consumed = DecodeUtf8(text.data + offset, text.length - offset, codepoint);
        if (!consumed) return true;
        if (codepoint >= 0x80 && !IsNativeIconCodepoint(codepoint)) return true;
        offset += consumed;
    }
    return false;
}

struct WideConversion {
    wchar_t *data;
    unsigned int length;
    void *allocation;
};

static WideConversion ConvertUtf8ToWide(const NativeStringView &text,
                                         wchar_t *stack, unsigned int stackCapacity) {
    WideConversion converted = {stack, 0, nullptr};
    unsigned int units = 0;
    unsigned long long offset = 0;
    while (offset < text.length) {
        unsigned int codepoint = 0;
        unsigned int consumed = DecodeUtf8(text.data + offset, text.length - offset, codepoint);
        if (!consumed) return {nullptr, 0, nullptr};
        units += codepoint >= 0x10000 ? 2 : 1;
        offset += consumed;
    }
    if (units + 1 > stackCapacity) {
        converted.allocation = pVirtualAlloc()(nullptr,
            static_cast<SIZE_T>(units + 1) * sizeof(wchar_t),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        converted.data = static_cast<wchar_t *>(converted.allocation);
        if (!converted.data) return {nullptr, 0, nullptr};
    }
    offset = 0;
    while (offset < text.length) {
        unsigned int codepoint = 0;
        unsigned int consumed = DecodeUtf8(text.data + offset, text.length - offset, codepoint);
        if (codepoint < 0x10000) {
            converted.data[converted.length++] = static_cast<wchar_t>(codepoint);
        } else {
            codepoint -= 0x10000;
            converted.data[converted.length++] = static_cast<wchar_t>(0xd800 + (codepoint >> 10));
            converted.data[converted.length++] = static_cast<wchar_t>(0xdc00 + (codepoint & 0x3ff));
        }
        offset += consumed;
    }
    converted.data[converted.length] = 0;
    return converted;
}

static void ReleaseWide(WideConversion &converted) {
    if (converted.allocation) pVirtualFree()(converted.allocation, 0, MEM_RELEASE);
    converted = {};
}

using QueryPerformanceCounterFn = BOOL (WINAPI *)(LARGE_INTEGER *);
using QueryPerformanceFrequencyFn = BOOL (WINAPI *)(LARGE_INTEGER *);

static volatile LONG g_dwriteState;
static IDWriteFactory *g_dwriteFactory;

static bool EnsureDWriteFactory() {
    LONG state = _InterlockedCompareExchange(&g_dwriteState, 1, 0);
    if (state == 0) {
        HMODULE dwrite = pLoadLibraryW()(L"dwrite.dll");
        auto createFactory = dwrite ? reinterpret_cast<DWriteCreateFactoryFn>(
            pGetProcAddress()(dwrite, "DWriteCreateFactory")) : nullptr;
        static const GUID idWriteFactory = {
            0xb859ee5a, 0xd838, 0x4b5b,
            {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}
        };
        HRESULT status = createFactory ? createFactory(
            DWRITE_FACTORY_TYPE_SHARED, idWriteFactory,
            reinterpret_cast<void **>(&g_dwriteFactory)) : E_FAIL;
        UnicodeExperiment.lastDWriteStatus = status;
        _InterlockedExchange(&g_dwriteState, status >= 0 && g_dwriteFactory ? 2 : 3);
    } else if (state == 1) {
        while (_InterlockedCompareExchange(&g_dwriteState, 0, 0) == 1) YieldProcessor();
    }
    return _InterlockedCompareExchange(&g_dwriteState, 0, 0) == 2;
}

static unsigned long long PerformanceTicks() {
    static QueryPerformanceCounterFn counter;
    if (!counter) {
        HMODULE kernel32 = pLoadLibraryW()(L"kernel32.dll");
        counter = kernel32 ? reinterpret_cast<QueryPerformanceCounterFn>(
            pGetProcAddress()(kernel32, "QueryPerformanceCounter")) : nullptr;
    }
    LARGE_INTEGER value = {};
    return counter && counter(&value) ? static_cast<unsigned long long>(value.QuadPart) : 0;
}

static unsigned long long TicksToMicroseconds(unsigned long long ticks) {
    static unsigned long long frequency;
    if (!frequency) {
        HMODULE kernel32 = pLoadLibraryW()(L"kernel32.dll");
        auto queryFrequency = kernel32 ? reinterpret_cast<QueryPerformanceFrequencyFn>(
            pGetProcAddress()(kernel32, "QueryPerformanceFrequency")) : nullptr;
        LARGE_INTEGER value = {};
        if (queryFrequency && queryFrequency(&value)) frequency = value.QuadPart;
    }
    return frequency ? (ticks * 1000000ULL) / frequency : 0;
}

static float NativeFontHeight(const float *font) {
    float height = font ? font[0] + font[1] : 16.0f;
    if (height < 8.0f || height > 128.0f) height = 16.0f;
    return height;
}

struct NativeFontStyle {
    float emSize;
    NativeFontFamily family;
};

static NativeFontStyle ResolveNativeFontStyle(const float *font) {
    NativeFontStyle style = {NativeFontHeight(font) * 0.75f, NativeFontSegoeUI};
    bool found = false;
    // Atlas creation publishes these records before normal UI rendering. Reads stay
    // lock-free because text measurement is a hot path; the writer lock only protects
    // rare font creation/reconfiguration and records are never freed.
    for (unsigned int index = 0; index < kNativeFontRecordCount; ++index) {
        if (g_nativeFontRecords[index].font == font) {
            style.emSize = g_nativeFontRecords[index].emSize;
            style.family = g_nativeFontRecords[index].family;
            found = true;
            break;
        }
    }
    if (found) UnicodeExperiment.fontMetricHits++;
    else UnicodeExperiment.fontMetricMisses++;
    UnicodeExperiment.lastDWriteEmSizeBits = FloatBits(style.emSize);
    return style;
}

static FontClass ClassifyCodepoint(unsigned int codepoint) {
    if ((0x0590 <= codepoint && codepoint <= 0x08ff) ||
        (0xfb50 <= codepoint && codepoint <= 0xfeff)) return FontArabic;
    if ((0x3000 <= codepoint && codepoint <= 0x9fff) ||
        (0xf900 <= codepoint && codepoint <= 0xfaff) ||
        (0x20000 <= codepoint && codepoint <= 0x3134f)) return FontCjk;
    if (0xac00 <= codepoint && codepoint <= 0xd7ff) return FontKorean;
    if ((0x0900 <= codepoint && codepoint <= 0x109f) ||
        (0x1780 <= codepoint && codepoint <= 0x17ff)) return FontIndic;
    if (0x1f000 <= codepoint && codepoint <= 0x1faff) return FontEmoji;
    if ((0x2000 <= codepoint && codepoint <= 0x2bff) ||
        (0x1f000 <= codepoint && codepoint <= 0x1ffff)) return FontSymbols;
    return FontConfigured;
}

static const wchar_t *NativeFallbackFamilyName(FontClass fontClass) {
    switch (fontClass) {
    case FontArabic: return L"Segoe UI";
    case FontCjk: return L"Microsoft YaHei";
    case FontKorean: return L"Malgun Gothic";
    case FontIndic: return L"Nirmala UI";
    case FontSymbols: return L"Segoe UI Symbol";
    case FontEmoji: return L"Segoe UI Emoji";
    default: return nullptr;
    }
}

static void ApplyNativeFallbacks(IDWriteTextLayout *layout, const wchar_t *text,
                                 unsigned int length) {
    if (!layout || !text) return;
    unsigned int start = 0;
    while (start < length) {
        unsigned int units = 1;
        unsigned int codepoint = static_cast<unsigned short>(text[start]);
        if (0xd800 <= codepoint && codepoint <= 0xdbff && start + 1 < length) {
            unsigned int low = static_cast<unsigned short>(text[start + 1]);
            if (0xdc00 <= low && low <= 0xdfff) {
                codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
                units = 2;
            }
        }
        FontClass fontClass = ClassifyCodepoint(codepoint);
        unsigned int end = start + units;
        while (end < length) {
            unsigned int nextUnits = 1;
            unsigned int next = static_cast<unsigned short>(text[end]);
            if (0xd800 <= next && next <= 0xdbff && end + 1 < length) {
                unsigned int low = static_cast<unsigned short>(text[end + 1]);
                if (0xdc00 <= low && low <= 0xdfff) {
                    next = 0x10000 + ((next - 0xd800) << 10) + (low - 0xdc00);
                    nextUnits = 2;
                }
            }
            if (ClassifyCodepoint(next) != fontClass) break;
            end += nextUnits;
        }
        const wchar_t *fallback = NativeFallbackFamilyName(fontClass);
        if (fallback) {
            DWRITE_TEXT_RANGE range = {start, end - start};
            layout->SetFontFamilyName(fallback, range);
        }
        start = end;
    }
}

static IDWriteTextLayout *CreateTextLayout(const wchar_t *text, unsigned int length,
                                            float emSize, NativeFontFamily family,
                                            float width, float height,
                                            bool nativeFallbacks = false) {
    if (!text || !length || !EnsureDWriteFactory()) return nullptr;
    if (width < 1.0f) width = 1.0f;
    if (height < 1.0f) height = 1.0f;
    if (width > 1000000.0f) width = 1000000.0f;
    if (height > 1000000.0f) height = 1000000.0f;
    IDWriteTextFormat *format = nullptr;
    HRESULT status = g_dwriteFactory->CreateTextFormat(
        NativeFontFamilyName(family), nullptr,
        DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL, emSize, L"", &format);
    if (status < 0 || !format) return nullptr;
    format->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
    format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
    IDWriteTextLayout *layout = nullptr;
    status = g_dwriteFactory->CreateTextLayout(text, length, format, width, height, &layout);
    format->Release();
    if (status >= 0 && layout && nativeFallbacks) ApplyNativeFallbacks(layout, text, length);
    return status >= 0 ? layout : nullptr;
}

static unsigned int CeilPositive(float value) {
    if (value <= 0.0f) return 0;
    unsigned int integer = static_cast<unsigned int>(value);
    return static_cast<float>(integer) < value ? integer + 1 : integer;
}

static unsigned long long MeasureWithDirectWrite(
    float *font, const NativeStringView &text, int maximumWidth, NativeStringView *visibleText,
    bool nativeFallbacks, bool &succeeded) {
    succeeded = false;
    wchar_t local[512] = {};
    WideConversion wide = ConvertUtf8ToWide(text, local, ARRAY_COUNT(local));
    if (!wide.data || !wide.length) {
        ReleaseWide(wide);
        return 0;
    }
    float layoutWidth = maximumWidth > 0 ? static_cast<float>(maximumWidth) : 1000000.0f;
    NativeFontStyle style = ResolveNativeFontStyle(font);
    IDWriteTextLayout *layout = CreateTextLayout(
        wide.data, wide.length, style.emSize, style.family, layoutWidth, 4096.0f,
        nativeFallbacks);
    if (!layout) {
        ReleaseWide(wide);
        return 0;
    }
    DWRITE_TEXT_METRICS metrics = {};
    HRESULT status = layout->GetMetrics(&metrics);
    if (status >= 0) {
        unsigned int visibleUnits = wide.length;
        if (maximumWidth > 0 && metrics.widthIncludingTrailingWhitespace > maximumWidth) {
            visibleUnits = 0;
            for (unsigned int unit = 0; unit < wide.length;) {
                unsigned int next = unit + 1;
                if (0xd800 <= wide.data[unit] && wide.data[unit] <= 0xdbff &&
                    next < wide.length && 0xdc00 <= wide.data[next] && wide.data[next] <= 0xdfff)
                    ++next;
                float x = 0.0f, y = 0.0f;
                DWRITE_HIT_TEST_METRICS hit = {};
                if (layout->HitTestTextPosition(next, FALSE, &x, &y, &hit) < 0 ||
                    x > static_cast<float>(maximumWidth)) break;
                visibleUnits = next;
                unit = next;
            }
        }
        if (visibleText) {
            unsigned int codepoints = 0;
            for (unsigned int unit = 0; unit < visibleUnits; ++unit) {
                if (!(0xdc00 <= wide.data[unit] && wide.data[unit] <= 0xdfff)) ++codepoints;
            }
            visibleText->data = text.data;
            visibleText->length = ByteOffsetAfterCodepoints(text, codepoints);
        }
        unsigned int width = CeilPositive(metrics.widthIncludingTrailingWhitespace);
        unsigned int height = CeilPositive(NativeFontHeight(font));
        succeeded = true;
        layout->Release();
        ReleaseWide(wide);
        return static_cast<unsigned long long>(width) |
            (static_cast<unsigned long long>(height) << 32);
    }
    layout->Release();
    ReleaseWide(wide);
    return 0;
}

static constexpr unsigned int kOverlayPacketCount = 2048;
static constexpr unsigned int kOverlayTextUnits = 262144;
static constexpr unsigned int kOverlayTextLimit = 512;

struct NativeAffineTransform {
    float sourceAnchorX;
    float sourceAnchorY;
    float targetAnchorX;
    float targetAnchorY;
    float xAxisX;
    float xAxisY;
    float yAxisX;
    float yAxisY;
    float residual;
    bool valid;
};

struct OverlayPacket {
    int rectangle[4];
    float color[4];
    float alignX;
    float alignY;
    float nativeHeight;
    float emSize;
    NativeFontFamily fontFamily;
    unsigned int textOffset;
    unsigned int textLength;
    unsigned long long textHash;
    unsigned int generation;
    NativeAffineTransform transform;
    bool active;
    bool consumed;
};

struct OverlayQueue {
    unsigned int packetCount;
    unsigned int textLength;
    OverlayPacket packets[kOverlayPacketCount];
    wchar_t text[kOverlayTextUnits];
};

static OverlayQueue g_overlayQueues[2];
static volatile LONG g_overlayLock;
static unsigned int g_overlayWriteQueue;
static volatile LONG g_overlayGeneration;

static constexpr unsigned int kNativeDrawMarkerMagic = 0x46504e55; // "UNPF"
static constexpr unsigned int kNativeMarkerCheck = 0xa9d31e47;
static constexpr unsigned int kNativeInstanceBytes = 0x48;
static constexpr unsigned int kNativeMarkerOffset = 0x30;

static void LockOverlayQueue() {
    while (_InterlockedCompareExchange(&g_overlayLock, 1, 0) != 0) YieldProcessor();
}

static void UnlockOverlayQueue() {
    _InterlockedExchange(&g_overlayLock, 0);
}

static unsigned long long HashWideText(const wchar_t *text, unsigned int length) {
    unsigned long long hash = 1469598103934665603ULL;
    for (unsigned int index = 0; index < length; ++index) {
        hash ^= static_cast<unsigned short>(text[index]);
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool SameOverlayText(const wchar_t *left, const wchar_t *right,
                            unsigned int length) {
    for (unsigned int index = 0; index < length; ++index)
        if (left[index] != right[index]) return false;
    return true;
}

static bool EnqueueInlinePacket(const float *font, const int *rectangle,
                                const NativeStringView &text,
                                const unsigned long long *color, const float *options,
                                unsigned int &token,
                                unsigned int &generation, bool &created) {
    created = false;
    wchar_t local[kOverlayTextLimit + 1] = {};
    WideConversion wide = ConvertUtf8ToWide(text, local, ARRAY_COUNT(local));
    if (!wide.data || !wide.length || wide.length > kOverlayTextLimit) {
        ReleaseWide(wide);
        UnicodeExperiment.overlayDropped++;
        return false;
    }

    OverlayPacket candidate = {};
    for (unsigned int index = 0; index < 4; ++index) {
        candidate.rectangle[index] = rectangle ? rectangle[index] : 0;
        candidate.color[index] = color ? reinterpret_cast<const float *>(color)[index] : 1.0f;
    }
    candidate.alignX = options ? options[0] : 0.0f;
    candidate.alignY = options ? options[1] : 0.0f;
    candidate.nativeHeight = NativeFontHeight(font);
    NativeFontStyle style = ResolveNativeFontStyle(font);
    candidate.emSize = style.emSize;
    candidate.fontFamily = style.family;
    candidate.textLength = wide.length;
    candidate.textHash = HashWideText(wide.data, wide.length);
    candidate.active = true;

    LockOverlayQueue();
    OverlayQueue &queue = g_overlayQueues[g_overlayWriteQueue];
    // Every packet captures File Pilot's current affine transform before it can
    // be compared with earlier submissions. Coalescing happens after capture.
    if (queue.packetCount >= kOverlayPacketCount ||
        queue.textLength + wide.length + 1 > kOverlayTextUnits) {
        UnlockOverlayQueue();
        ReleaseWide(wide);
        UnicodeExperiment.overlayDropped++;
        return false;
    }
    OverlayPacket &packet = queue.packets[queue.packetCount++];
    packet = candidate;
    created = true;
    generation = static_cast<unsigned int>(_InterlockedIncrement(&g_overlayGeneration));
    if (!generation) generation = static_cast<unsigned int>(
        _InterlockedIncrement(&g_overlayGeneration));
    packet.generation = generation;
    unsigned int packetIndex = queue.packetCount - 1;
    token = (g_overlayWriteQueue << 16) | packetIndex;
    packet.textOffset = queue.textLength;
    memcpy(queue.text + queue.textLength, wide.data, wide.length * sizeof(wchar_t));
    queue.textLength += wide.length;
    queue.text[queue.textLength++] = 0;
    UnlockOverlayQueue();
    ReleaseWide(wide);
    UnicodeExperiment.overlayQueued++;
    return true;
}

static void CancelInlinePacket(unsigned int token, unsigned int generation) {
    unsigned int queueIndex = token >> 16;
    unsigned int packetIndex = token & 0xffff;
    if (queueIndex >= ARRAY_COUNT(g_overlayQueues)) return;
    LockOverlayQueue();
    OverlayQueue &queue = g_overlayQueues[queueIndex];
    if (packetIndex < queue.packetCount &&
        queue.packets[packetIndex].generation == generation)
        queue.packets[packetIndex].active = false;
    UnlockOverlayQueue();
}

static OverlayPacket *FindInlinePacket(unsigned int token, unsigned int generation,
                                       const wchar_t *&text) {
    unsigned int queueIndex = token >> 16;
    unsigned int packetIndex = token & 0xffff;
    if (queueIndex >= ARRAY_COUNT(g_overlayQueues)) return nullptr;
    OverlayQueue &queue = g_overlayQueues[queueIndex];
    if (packetIndex >= queue.packetCount) return nullptr;
    OverlayPacket &packet = queue.packets[packetIndex];
    if (!packet.active || packet.generation != generation) return nullptr;
    text = queue.text + packet.textOffset;
    return &packet;
}

static bool SameCapturedTransform(const NativeAffineTransform &left,
                                  const NativeAffineTransform &right) {
    return left.valid == right.valid &&
        left.sourceAnchorX == right.sourceAnchorX &&
        left.sourceAnchorY == right.sourceAnchorY &&
        left.targetAnchorX == right.targetAnchorX &&
        left.targetAnchorY == right.targetAnchorY &&
        left.xAxisX == right.xAxisX && left.xAxisY == right.xAxisY &&
        left.yAxisX == right.yAxisX && left.yAxisY == right.yAxisY;
}

static bool CoalesceCapturedPacket(unsigned int &token, unsigned int &generation,
                                   OverlayPacket *&packet) {
    unsigned int queueIndex = token >> 16;
    unsigned int packetIndex = token & 0xffff;
    if (queueIndex >= ARRAY_COUNT(g_overlayQueues)) return false;
    LockOverlayQueue();
    OverlayQueue &queue = g_overlayQueues[queueIndex];
    if (!packet || packetIndex >= queue.packetCount ||
        packetIndex + 1 != queue.packetCount || &queue.packets[packetIndex] != packet) {
        UnlockOverlayQueue();
        return false;
    }
    for (unsigned int index = packetIndex; index > 0; --index) {
        OverlayPacket &queued = queue.packets[index - 1];
        bool same = queued.active &&
            queued.alignX == packet->alignX && queued.alignY == packet->alignY &&
            queued.nativeHeight == packet->nativeHeight && queued.emSize == packet->emSize &&
            queued.fontFamily == packet->fontFamily && queued.textHash == packet->textHash &&
            queued.textLength == packet->textLength &&
            SameCapturedTransform(queued.transform, packet->transform);
        for (unsigned int component = 0; component < 4 && same; ++component) {
            same = queued.rectangle[component] == packet->rectangle[component] &&
                queued.color[component] == packet->color[component];
        }
        if (!same || !SameOverlayText(queue.text + queued.textOffset,
                                      queue.text + packet->textOffset,
                                      packet->textLength)) continue;
        queue.textLength = packet->textOffset;
        queue.packetCount--;
        packet = &queued;
        token = (queueIndex << 16) | (index - 1);
        generation = queued.generation;
        UnicodeExperiment.overlayCoalesced++;
        UnlockOverlayQueue();
        return true;
    }
    UnlockOverlayQueue();
    return false;
}

enum NativeMarkerKind : unsigned int {
    NativeMarkerNone,
    NativeMarkerDraw,
};

static void WriteNativeMarker(void *instance, unsigned int token,
                              unsigned int generation) {
    auto marker = reinterpret_cast<unsigned int *>(
        static_cast<unsigned char *>(instance) + kNativeMarkerOffset);
    marker[0] = kNativeDrawMarkerMagic;
    marker[1] = token;
    marker[2] = generation;
    marker[3] = kNativeMarkerCheck ^ token ^ generation;
}

static NativeMarkerKind ReadNativeMarker(const void *instance, unsigned int &token,
                                         unsigned int &generation) {
    auto marker = reinterpret_cast<const unsigned int *>(
        static_cast<const unsigned char *>(instance) + kNativeMarkerOffset);
    NativeMarkerKind kind = marker[0] == kNativeDrawMarkerMagic
        ? NativeMarkerDraw : NativeMarkerNone;
    if (kind == NativeMarkerNone) return kind;
    token = marker[1];
    generation = marker[2];
    return marker[3] == (kNativeMarkerCheck ^ token ^ generation)
        ? kind : NativeMarkerNone;
}

static unsigned long long *NativeRenderData() {
    if (!Bindings.nativeRenderDataGlobal) return nullptr;
    return *reinterpret_cast<unsigned long long **>(Bindings.nativeRenderDataGlobal);
}

using GetCurrentThreadIdFn = DWORD (WINAPI *)();
static GetCurrentThreadIdFn g_getCurrentThreadId;

static DWORD NativeCurrentThreadId() {
    if (!g_getCurrentThreadId) {
        HMODULE kernel32 = pLoadLibraryW()(L"kernel32.dll");
        if (kernel32) g_getCurrentThreadId = reinterpret_cast<GetCurrentThreadIdFn>(
            pGetProcAddress()(kernel32, "GetCurrentThreadId"));
    }
    return g_getCurrentThreadId ? g_getCurrentThreadId() : 0;
}

struct NativeQuadCaptureState {
    volatile LONG active;
    DWORD threadId;
    OverlayPacket *packet;
    unsigned int token;
    unsigned int generation;
    unsigned char *instance;
    bool captured;
};

static NativeQuadCaptureState g_nativeQuadCapture;
static constexpr int kNativeTransformProbeBasis = 4096;

static unsigned long long PackNativePoint(int x, int y) {
    return static_cast<unsigned int>(x) |
        (static_cast<unsigned long long>(static_cast<unsigned int>(y)) << 32);
}

static void ReadNativePoint(const unsigned char *data, float &x, float &y) {
    x = static_cast<float>(*reinterpret_cast<const int *>(data));
    y = static_cast<float>(*reinterpret_cast<const int *>(data + 4));
}

static float NativeAbs(float value) {
    return value < 0.0f ? -value : value;
}

extern "C" __declspec(dllexport) void __fastcall UnicodeNativeQuadHook(
    unsigned long long *corners, long long resource, unsigned long long *style) {
    using OriginalFn = void (__fastcall *)(unsigned long long *, long long,
                                            unsigned long long *);
    auto original = reinterpret_cast<OriginalFn>(Bindings.originalNativeQuadEmitter);
    bool capture = original &&
        _InterlockedCompareExchange(&g_nativeQuadCapture.active, 0, 0) > 0 &&
        g_nativeQuadCapture.threadId == NativeCurrentThreadId() &&
        !g_nativeQuadCapture.captured && g_nativeQuadCapture.packet;
    if (!capture) {
        if (original) original(corners, resource, style);
        return;
    }

    OverlayPacket &packet = *g_nativeQuadCapture.packet;
    int anchorX = packet.rectangle[0];
    int anchorY = packet.rectangle[1];
    unsigned long long probeCorners[2] = {
        PackNativePoint(anchorX, anchorY),
        PackNativePoint(anchorX + kNativeTransformProbeBasis,
                        anchorY + kNativeTransformProbeBasis)
    };
    unsigned long long *renderData = NativeRenderData();
    unsigned long long before = renderData ? renderData[0x1b] : 0;
    original(probeCorners, resource, style);
    renderData = NativeRenderData();
    if (!renderData || renderData[0x1b] != before + 1) return;
    auto instances = reinterpret_cast<unsigned char *>(renderData[0x1d]);
    if (!instances) return;
    unsigned char *instance = instances + before * kNativeInstanceBytes;

    float bottomLeftX = 0.0f, bottomLeftY = 0.0f;
    float bottomRightX = 0.0f, bottomRightY = 0.0f;
    float topLeftX = 0.0f, topLeftY = 0.0f;
    float topRightX = 0.0f, topRightY = 0.0f;
    ReadNativePoint(instance + 0x00, bottomLeftX, bottomLeftY);
    ReadNativePoint(instance + 0x08, bottomRightX, bottomRightY);
    ReadNativePoint(instance + 0x10, topLeftX, topLeftY);
    ReadNativePoint(instance + 0x18, topRightX, topRightY);

    NativeAffineTransform transform = {};
    transform.sourceAnchorX = static_cast<float>(anchorX);
    transform.sourceAnchorY = static_cast<float>(anchorY);
    transform.targetAnchorX = topLeftX;
    transform.targetAnchorY = topLeftY;
    float inverseBasis = 1.0f / static_cast<float>(kNativeTransformProbeBasis);
    transform.xAxisX = (topRightX - topLeftX) * inverseBasis;
    transform.xAxisY = (topRightY - topLeftY) * inverseBasis;
    transform.yAxisX = (bottomLeftX - topLeftX) * inverseBasis;
    transform.yAxisY = (bottomLeftY - topLeftY) * inverseBasis;
    float predictedX = topLeftX +
        (transform.xAxisX + transform.yAxisX) * kNativeTransformProbeBasis;
    float predictedY = topLeftY +
        (transform.xAxisY + transform.yAxisY) * kNativeTransformProbeBasis;
    float residualX = NativeAbs(predictedX - bottomRightX);
    float residualY = NativeAbs(predictedY - bottomRightY);
    transform.residual = residualX > residualY ? residualX : residualY;
    float coefficientLimit = 64.0f;
    transform.valid = transform.residual <= 2.0f &&
        NativeAbs(transform.xAxisX) < coefficientLimit &&
        NativeAbs(transform.xAxisY) < coefficientLimit &&
        NativeAbs(transform.yAxisX) < coefficientLimit &&
        NativeAbs(transform.yAxisY) < coefficientLimit;
    packet.transform = transform;
    g_nativeQuadCapture.instance = instance;
    g_nativeQuadCapture.captured = true;
}

static bool SubmitNativeTextCarrier(
    unsigned long long *arena, float *font, int *rectangle, const float *options,
    unsigned int &token, unsigned int &generation) {
    using OriginalFn = void (__fastcall *)(unsigned long long *, float *, int *,
        const NativeStringView *, unsigned long long *, float *);
    unsigned long long *renderData = NativeRenderData();
    if (!renderData) return false;
    unsigned long long before = renderData[0x1b]; // +0xd8 instance count
    const wchar_t *packetText = nullptr;
    OverlayPacket *packet = FindInlinePacket(token, generation, packetText);
    if (!packet) return false;
    if (_InterlockedCompareExchange(&g_nativeQuadCapture.active, -1, 0) != 0)
        return false;
    g_nativeQuadCapture.threadId = NativeCurrentThreadId();
    g_nativeQuadCapture.packet = packet;
    g_nativeQuadCapture.token = token;
    g_nativeQuadCapture.generation = generation;
    g_nativeQuadCapture.instance = nullptr;
    g_nativeQuadCapture.captured = false;
    _InterlockedExchange(&g_nativeQuadCapture.active, 1);
    static const char markerByte[] = ".";
    NativeStringView markerText = {markerByte, 1};
    float transparent[4] = {};
    reinterpret_cast<OriginalFn>(Bindings.originalRenderText)(
        arena, font, rectangle, &markerText,
        reinterpret_cast<unsigned long long *>(transparent),
        const_cast<float *>(options));
    _InterlockedExchange(&g_nativeQuadCapture.active, 0);

    renderData = NativeRenderData();
    if (!renderData) return false;
    unsigned long long after = renderData[0x1b];
    auto instances = reinterpret_cast<unsigned char *>(renderData[0x1d]); // +0xe8
    if (!instances || after != before + 1) return false;
    unsigned char *instance = instances + before * kNativeInstanceBytes;
    bool captured = g_nativeQuadCapture.captured &&
        g_nativeQuadCapture.instance == instance && packet->transform.valid;
    if (!captured) {
        UnicodeExperiment.nativeTransformFailures++;
        return false;
    }
    UnicodeExperiment.nativeTransformCaptures++;
    unsigned long long residualBits = FloatBits(packet->transform.residual);
    if (residualBits > UnicodeExperiment.nativeTransformMaxResidualBits)
        UnicodeExperiment.nativeTransformMaxResidualBits = residualBits;
    CoalesceCapturedPacket(token, generation, packet);
    WriteNativeMarker(instance, token, generation);
    UnicodeExperiment.nativeMarkersSubmitted++;
    return true;
}

static OverlayQueue *TakeOverlayQueue() {
    LockOverlayQueue();
    unsigned int readQueue = g_overlayWriteQueue;
    g_overlayWriteQueue ^= 1;
    OverlayQueue &write = g_overlayQueues[g_overlayWriteQueue];
    write.packetCount = 0;
    write.textLength = 0;
    UnlockOverlayQueue();
    return &g_overlayQueues[readQueue];
}

static D2D1_COLOR_F PacketColor(const OverlayPacket &packet) {
    D2D1_COLOR_F color = {packet.color[0], packet.color[1], packet.color[2], packet.color[3]};
    for (unsigned int index = 0; index < 4; ++index) {
        float *component = reinterpret_cast<float *>(&color) + index;
        if (*component < 0.0f) *component = 0.0f;
        if (*component > 1.0f) *component = 1.0f;
    }
    return color;
}

static D2D1_RECT_F PacketClip(const OverlayPacket &packet) {
    D2D1_RECT_F rectangle = {
        static_cast<float>(packet.rectangle[0]), static_cast<float>(packet.rectangle[1]),
        static_cast<float>(packet.rectangle[2]), static_cast<float>(packet.rectangle[3])
    };
    if (rectangle.right < rectangle.left) rectangle.right = rectangle.left;
    if (rectangle.bottom < rectangle.top) rectangle.bottom = rectangle.top;
    return rectangle;
}

static D2D1_POINT_2F PacketOrigin(const OverlayPacket &packet, float width, float height) {
    D2D1_RECT_F clip = PacketClip(packet);
    float availableWidth = clip.right - clip.left;
    float availableHeight = clip.bottom - clip.top;
    D2D1_POINT_2F point = {
        clip.left + (availableWidth - width) * packet.alignX,
        clip.top + (availableHeight - height) * packet.alignY
    };
    // File Pilot's native atlas is placed on integral pixels.  Keep DirectWrite on
    // the same grid so grayscale coverage is not split by a fractional destination.
    point.x = static_cast<float>(static_cast<int>(point.x + (point.x >= 0.0f ? 0.5f : -0.5f)));
    point.y = static_cast<float>(static_cast<int>(point.y + (point.y >= 0.0f ? 0.5f : -0.5f)));
    return point;
}

static D2D1_POINT_2F ApplyPacketTransform(const OverlayPacket &packet, float x, float y) {
    if (!packet.transform.valid) return {x, y};
    float localX = x - packet.transform.sourceAnchorX;
    float localY = y - packet.transform.sourceAnchorY;
    return {
        packet.transform.targetAnchorX + packet.transform.xAxisX * localX +
            packet.transform.yAxisX * localY,
        packet.transform.targetAnchorY + packet.transform.xAxisY * localX +
            packet.transform.yAxisY * localY
    };
}

static bool PacketTransformIsAnimated(const OverlayPacket &packet) {
    if (!packet.transform.valid) return false;
    return NativeAbs(packet.transform.targetAnchorX - packet.transform.sourceAnchorX) > 0.01f ||
        NativeAbs(packet.transform.targetAnchorY - packet.transform.sourceAnchorY) > 0.01f ||
        NativeAbs(packet.transform.xAxisX - 1.0f) > 0.0001f ||
        NativeAbs(packet.transform.xAxisY) > 0.0001f ||
        NativeAbs(packet.transform.yAxisX) > 0.0001f ||
        NativeAbs(packet.transform.yAxisY - 1.0f) > 0.0001f;
}

struct GlyphRunRecord {
    IDWriteFontFace *fontFace;
    float emSize;
    unsigned int glyphStart;
    unsigned int glyphCount;
    DWRITE_MEASURING_MODE measuringMode;
    float baselineX;
    float baselineY;
    BOOL isSideways;
    BOOL hasAdvances;
    BOOL hasOffsets;
    unsigned int bidiLevel;
};

static constexpr unsigned int kGlyphCacheEntries = 128;
static constexpr unsigned int kGlyphCacheGlyphs = 512;
static constexpr unsigned int kGlyphCacheRuns = 16;

struct GlyphCacheEntry {
    unsigned long long hash;
    unsigned long long stamp;
    float emSize;
    float maximumWidth;
    float width;
    float height;
    NativeFontFamily fontFamily;
    bool nativeFallbacks;
    unsigned int textLength;
    unsigned int glyphCount;
    unsigned int runCount;
    wchar_t text[kOverlayTextLimit + 1];
    unsigned short glyphIndices[kGlyphCacheGlyphs];
    float glyphAdvances[kGlyphCacheGlyphs];
    DWRITE_GLYPH_OFFSET glyphOffsets[kGlyphCacheGlyphs];
    GlyphRunRecord runs[kGlyphCacheRuns];
};

static GlyphCacheEntry g_glyphCache[kGlyphCacheEntries];
static unsigned long long g_cacheStamp;

static void ReleaseGlyphEntry(GlyphCacheEntry &entry) {
    for (unsigned int index = 0; index < entry.runCount; ++index)
        if (entry.runs[index].fontFace) entry.runs[index].fontFace->Release();
    entry.hash = 0;
    entry.runCount = 0;
    entry.glyphCount = 0;
}

class GlyphCollector final : public IDWriteTextRenderer {
public:
    explicit GlyphCollector(GlyphCacheEntry *entry) : references_(1), entry_(entry), failed_(false) {}
    bool Failed() const { return failed_; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override {
        if (!object) return E_POINTER;
        if (IsEqualGUID(iid, __uuidof(IUnknown)) ||
            IsEqualGUID(iid, __uuidof(IDWritePixelSnapping)) ||
            IsEqualGUID(iid, __uuidof(IDWriteTextRenderer))) {
            *object = static_cast<IDWriteTextRenderer *>(this);
            AddRef();
            return S_OK;
        }
        *object = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(_InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override { return static_cast<ULONG>(_InterlockedDecrement(&references_)); }
    HRESULT STDMETHODCALLTYPE IsPixelSnappingDisabled(void *, BOOL *disabled) override {
        if (!disabled) return E_POINTER;
        *disabled = FALSE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCurrentTransform(void *, DWRITE_MATRIX *matrix) override {
        if (!matrix) return E_POINTER;
        matrix->m11 = 1.0f; matrix->m12 = 0.0f;
        matrix->m21 = 0.0f; matrix->m22 = 1.0f;
        matrix->dx = 0.0f; matrix->dy = 0.0f;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetPixelsPerDip(void *, FLOAT *pixelsPerDip) override {
        if (!pixelsPerDip) return E_POINTER;
        *pixelsPerDip = 1.0f;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE DrawGlyphRun(
        void *, FLOAT baselineOriginX, FLOAT baselineOriginY,
        DWRITE_MEASURING_MODE measuringMode, const DWRITE_GLYPH_RUN *glyphRun,
        const DWRITE_GLYPH_RUN_DESCRIPTION *, IUnknown *) override {
        if (!glyphRun || !glyphRun->fontFace ||
            entry_->runCount >= kGlyphCacheRuns ||
            entry_->glyphCount + glyphRun->glyphCount > kGlyphCacheGlyphs) {
            failed_ = true;
            return E_OUTOFMEMORY;
        }
        GlyphRunRecord &record = entry_->runs[entry_->runCount++];
        record.fontFace = glyphRun->fontFace;
        record.fontFace->AddRef();
        record.emSize = glyphRun->fontEmSize;
        record.glyphStart = entry_->glyphCount;
        record.glyphCount = glyphRun->glyphCount;
        record.measuringMode = measuringMode;
        record.baselineX = baselineOriginX;
        record.baselineY = baselineOriginY;
        record.isSideways = glyphRun->isSideways;
        record.hasAdvances = glyphRun->glyphAdvances != nullptr;
        record.hasOffsets = glyphRun->glyphOffsets != nullptr;
        record.bidiLevel = glyphRun->bidiLevel;
        memcpy(entry_->glyphIndices + entry_->glyphCount, glyphRun->glyphIndices,
               glyphRun->glyphCount * sizeof(unsigned short));
        if (glyphRun->glyphAdvances) memcpy(
            entry_->glyphAdvances + entry_->glyphCount, glyphRun->glyphAdvances,
            glyphRun->glyphCount * sizeof(float));
        if (glyphRun->glyphOffsets) memcpy(
            entry_->glyphOffsets + entry_->glyphCount, glyphRun->glyphOffsets,
            glyphRun->glyphCount * sizeof(DWRITE_GLYPH_OFFSET));
        entry_->glyphCount += glyphRun->glyphCount;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE DrawUnderline(
        void *, FLOAT, FLOAT, const DWRITE_UNDERLINE *, IUnknown *) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE DrawStrikethrough(
        void *, FLOAT, FLOAT, const DWRITE_STRIKETHROUGH *, IUnknown *) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE DrawInlineObject(
        void *, FLOAT, FLOAT, IDWriteInlineObject *, BOOL, BOOL, IUnknown *) override { return S_OK; }

private:
    volatile LONG references_;
    GlyphCacheEntry *entry_;
    bool failed_;
};

static bool SameText(const wchar_t *left, const wchar_t *right, unsigned int length) {
    for (unsigned int index = 0; index < length; ++index)
        if (left[index] != right[index]) return false;
    return true;
}

static GlyphCacheEntry *FindOrCreateGlyphEntry(
    const wchar_t *text, unsigned int length, const OverlayPacket &packet,
    bool nativeFallbacks = false) {
    float maximumWidth = static_cast<float>(packet.rectangle[2] - packet.rectangle[0]);
    for (unsigned int index = 0; index < kGlyphCacheEntries; ++index) {
        GlyphCacheEntry &entry = g_glyphCache[index];
        if (entry.hash == packet.textHash && entry.textLength == length &&
            entry.emSize == packet.emSize && entry.maximumWidth == maximumWidth &&
            entry.fontFamily == packet.fontFamily && entry.nativeFallbacks == nativeFallbacks &&
            SameText(entry.text, text, length)) {
            entry.stamp = ++g_cacheStamp;
            UnicodeExperiment.glyphCacheHits++;
            return &entry;
        }
    }
    UnicodeExperiment.glyphCacheMisses++;
    unsigned int victim = 0;
    for (unsigned int index = 1; index < kGlyphCacheEntries; ++index)
        if (g_glyphCache[index].stamp < g_glyphCache[victim].stamp) victim = index;
    GlyphCacheEntry &entry = g_glyphCache[victim];
    ReleaseGlyphEntry(entry);
    entry.hash = packet.textHash;
    entry.stamp = ++g_cacheStamp;
    entry.emSize = packet.emSize;
    entry.maximumWidth = maximumWidth;
    entry.fontFamily = packet.fontFamily;
    entry.nativeFallbacks = nativeFallbacks;
    entry.textLength = length;
    memcpy(entry.text, text, length * sizeof(wchar_t));
    entry.text[length] = 0;
    IDWriteTextLayout *layout = CreateTextLayout(
        text, length, packet.emSize, packet.fontFamily, maximumWidth, 4096.0f,
        nativeFallbacks);
    if (!layout) {
        ReleaseGlyphEntry(entry);
        return nullptr;
    }
    DWRITE_TEXT_METRICS metrics = {};
    layout->GetMetrics(&metrics);
    entry.width = metrics.widthIncludingTrailingWhitespace;
    entry.height = metrics.height;
    GlyphCollector collector(&entry);
    HRESULT status = layout->Draw(nullptr, &collector, 0.0f, 0.0f);
    layout->Release();
    if (status < 0 || collector.Failed()) {
        ReleaseGlyphEntry(entry);
        return nullptr;
    }
    return &entry;
}

// DirectWrite shapes text and rasterizes individual glyph masks into a shared
// atlas. Compositing stays on File Pilot's immediate D3D11 command stream.
static ID3D11Device *g_d3dAtlasDevice;
static ID3D11VertexShader *g_d3dAtlasVertexShader;
static ID3D11PixelShader *g_d3dAtlasPixelShader;
static ID3D11InputLayout *g_d3dAtlasInputLayout;
static ID3D11Buffer *g_d3dAtlasVertexBuffer;
static ID3D11SamplerState *g_d3dAtlasSampler;
static ID3D11BlendState *g_d3dAtlasBlend;
static ID3D11RasterizerState *g_d3dAtlasRasterizer;
static ID3D11DepthStencilState *g_d3dAtlasDepthStencil;
static ID3D11RenderTargetView *g_d3dAtlasTarget;
static volatile LONG g_d3dAtlasOperational;

static constexpr unsigned int kD3DGlyphAtlasSize = 2048;
static constexpr unsigned int kD3DGlyphAtlasEntries = 1024;

struct D3DGlyphAtlasEntry {
    IDWriteFontFace *fontFace;
    unsigned long long stamp;
    float emSize;
    DWRITE_MEASURING_MODE measuringMode;
    unsigned short glyphIndex;
    BOOL isSideways;
    RECT bounds;
    unsigned short atlasX;
    unsigned short atlasY;
    unsigned short atlasWidth;
    unsigned short atlasHeight;
    unsigned int generation;
};

static D3DGlyphAtlasEntry g_d3dGlyphEntries[kD3DGlyphAtlasEntries];
static ID3D11Texture2D *g_d3dGlyphAtlasTexture;
static ID3D11ShaderResourceView *g_d3dGlyphAtlasView;
static unsigned int g_d3dGlyphAtlasX;
static unsigned int g_d3dGlyphAtlasY;
static unsigned int g_d3dGlyphAtlasRowHeight;
static unsigned int g_d3dGlyphAtlasGeneration = 1;
static D3DGlyphAtlasEntry *g_d3dGlyphPacketEntries[kGlyphCacheGlyphs];

static void ReleaseD3DAtlasTarget() {
    _InterlockedExchange(&g_d3dAtlasOperational, 0);
    UnicodeExperiment.flags &= ~ExperimentD3DAtlasReady;
    if (g_d3dAtlasTarget) g_d3dAtlasTarget->Release();
    g_d3dAtlasTarget = nullptr;
}

static void ResetD3DGlyphAtlasEntries() {
    for (unsigned int index = 0; index < kD3DGlyphAtlasEntries; ++index) {
        if (g_d3dGlyphEntries[index].fontFace)
            g_d3dGlyphEntries[index].fontFace->Release();
        g_d3dGlyphEntries[index] = {};
    }
    g_d3dGlyphAtlasX = 0;
    g_d3dGlyphAtlasY = 0;
    g_d3dGlyphAtlasRowHeight = 0;
    ++g_d3dGlyphAtlasGeneration;
    if (!g_d3dGlyphAtlasGeneration) ++g_d3dGlyphAtlasGeneration;
}

static void ReleaseD3DGlyphAtlas() {
    ResetD3DGlyphAtlasEntries();
    if (g_d3dGlyphAtlasView) g_d3dGlyphAtlasView->Release();
    if (g_d3dGlyphAtlasTexture) g_d3dGlyphAtlasTexture->Release();
    g_d3dGlyphAtlasView = nullptr;
    g_d3dGlyphAtlasTexture = nullptr;
}

static void ReleaseD3DAtlasPipeline() {
    ReleaseD3DAtlasTarget();
    ReleaseD3DGlyphAtlas();
    if (g_d3dAtlasDepthStencil) g_d3dAtlasDepthStencil->Release();
    if (g_d3dAtlasRasterizer) g_d3dAtlasRasterizer->Release();
    if (g_d3dAtlasBlend) g_d3dAtlasBlend->Release();
    if (g_d3dAtlasSampler) g_d3dAtlasSampler->Release();
    if (g_d3dAtlasVertexBuffer) g_d3dAtlasVertexBuffer->Release();
    if (g_d3dAtlasInputLayout) g_d3dAtlasInputLayout->Release();
    if (g_d3dAtlasPixelShader) g_d3dAtlasPixelShader->Release();
    if (g_d3dAtlasVertexShader) g_d3dAtlasVertexShader->Release();
    g_d3dAtlasDepthStencil = nullptr;
    g_d3dAtlasRasterizer = nullptr;
    g_d3dAtlasBlend = nullptr;
    g_d3dAtlasSampler = nullptr;
    g_d3dAtlasVertexBuffer = nullptr;
    g_d3dAtlasInputLayout = nullptr;
    g_d3dAtlasPixelShader = nullptr;
    g_d3dAtlasVertexShader = nullptr;
    g_d3dAtlasDevice = nullptr;
}

struct D3DAtlasVertex {
    float position[2];
    float uv[2];
    float color[4];
};

static bool EnsureD3DAtlasPipeline(ID3D11Device *device) {
    if (!device) return false;
    if (g_d3dAtlasDevice == device && g_d3dAtlasVertexShader && g_d3dAtlasPixelShader &&
        g_d3dAtlasInputLayout && g_d3dAtlasVertexBuffer && g_d3dAtlasSampler &&
        g_d3dAtlasBlend && g_d3dAtlasRasterizer && g_d3dAtlasDepthStencil) return true;
    if (g_d3dAtlasDevice && g_d3dAtlasDevice != device) ReleaseD3DAtlasPipeline();

    HRESULT status = device->CreateVertexShader(
        kUnicodeMaskVertexShader, sizeof(kUnicodeMaskVertexShader), nullptr,
        &g_d3dAtlasVertexShader);
    if (status >= 0) status = device->CreatePixelShader(
        kUnicodeMaskPixelShader, sizeof(kUnicodeMaskPixelShader), nullptr,
        &g_d3dAtlasPixelShader);
    static const D3D11_INPUT_ELEMENT_DESC elements[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0,
         D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 8,
         D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 16,
         D3D11_INPUT_PER_VERTEX_DATA, 0},
    };
    if (status >= 0) status = device->CreateInputLayout(
        elements, ARRAY_COUNT(elements), kUnicodeMaskVertexShader,
        sizeof(kUnicodeMaskVertexShader), &g_d3dAtlasInputLayout);

    D3D11_BUFFER_DESC vertexBuffer = {};
    vertexBuffer.ByteWidth = sizeof(D3DAtlasVertex) * 6 * kGlyphCacheGlyphs;
    vertexBuffer.Usage = D3D11_USAGE_DYNAMIC;
    vertexBuffer.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    vertexBuffer.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    if (status >= 0) status = device->CreateBuffer(
        &vertexBuffer, nullptr, &g_d3dAtlasVertexBuffer);

    D3D11_SAMPLER_DESC sampler = {};
    sampler.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    sampler.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
    sampler.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
    sampler.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
    sampler.ComparisonFunc = D3D11_COMPARISON_NEVER;
    sampler.MaxLOD = 3.402823466e+38F;
    if (status >= 0) status = device->CreateSamplerState(&sampler, &g_d3dAtlasSampler);

    D3D11_BLEND_DESC blend = {};
    blend.RenderTarget[0].BlendEnable = TRUE;
    // The mask shader already emits premultiplied RGBA (color * coverage).
    // Match File Pilot's native compositor and do not multiply coverage twice.
    blend.RenderTarget[0].SrcBlend = D3D11_BLEND_ONE;
    blend.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    blend.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    blend.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
    blend.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
    blend.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
    blend.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    if (status >= 0) status = device->CreateBlendState(&blend, &g_d3dAtlasBlend);

    D3D11_RASTERIZER_DESC rasterizer = {};
    rasterizer.FillMode = D3D11_FILL_SOLID;
    rasterizer.CullMode = D3D11_CULL_NONE;
    rasterizer.DepthClipEnable = TRUE;
    rasterizer.ScissorEnable = TRUE;
    if (status >= 0) status = device->CreateRasterizerState(
        &rasterizer, &g_d3dAtlasRasterizer);

    D3D11_DEPTH_STENCIL_DESC depthStencil = {};
    depthStencil.DepthEnable = FALSE;
    depthStencil.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
    depthStencil.DepthFunc = D3D11_COMPARISON_ALWAYS;
    depthStencil.StencilEnable = FALSE;
    if (status >= 0) status = device->CreateDepthStencilState(
        &depthStencil, &g_d3dAtlasDepthStencil);

    UnicodeExperiment.lastD3DAtlasStatus = status;
    if (status < 0) {
        UnicodeExperiment.d3dAtlasFailures++;
        ReleaseD3DAtlasPipeline();
        return false;
    }
    g_d3dAtlasDevice = device;
    return true;
}

static bool EnsureD3DAtlasReady() {
    if (!Bindings.d3dRendererGlobal) return false;
    auto renderer = *reinterpret_cast<unsigned long long **>(Bindings.d3dRendererGlobal);
    if (!renderer) return false;
    auto device = reinterpret_cast<ID3D11Device *>(renderer[8]);
    auto swapChain = reinterpret_cast<IDXGISwapChain *>(renderer[10]);
    if (!device || !swapChain || !EnsureD3DAtlasPipeline(device)) return false;
    if (!g_d3dAtlasTarget) {
        ID3D11Texture2D *backBuffer = nullptr;
        HRESULT status = swapChain->GetBuffer(
            0, __uuidof(ID3D11Texture2D), reinterpret_cast<void **>(&backBuffer));
        if (status >= 0 && backBuffer)
            status = device->CreateRenderTargetView(backBuffer, nullptr, &g_d3dAtlasTarget);
        if (backBuffer) backBuffer->Release();
        UnicodeExperiment.lastD3DAtlasStatus = status;
        if (status < 0 || !g_d3dAtlasTarget) {
            UnicodeExperiment.d3dAtlasFailures++;
            ReleaseD3DAtlasTarget();
            return false;
        }
    }
    _InterlockedExchange(&g_d3dAtlasOperational, 1);
    UnicodeExperiment.flags |= ExperimentD3DAtlasReady;
    return true;
}

static bool EnsureD3DGlyphAtlas() {
    if (g_d3dGlyphAtlasTexture && g_d3dGlyphAtlasView) return true;
    if (!g_d3dAtlasDevice) return false;
    D3D11_TEXTURE2D_DESC description = {};
    description.Width = kD3DGlyphAtlasSize;
    description.Height = kD3DGlyphAtlasSize;
    description.MipLevels = 1;
    description.ArraySize = 1;
    description.Format = DXGI_FORMAT_R8_UNORM;
    description.SampleDesc.Count = 1;
    description.Usage = D3D11_USAGE_DEFAULT;
    description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    HRESULT status = g_d3dAtlasDevice->CreateTexture2D(
        &description, nullptr, &g_d3dGlyphAtlasTexture);
    if (status >= 0 && g_d3dGlyphAtlasTexture)
        status = g_d3dAtlasDevice->CreateShaderResourceView(
            g_d3dGlyphAtlasTexture, nullptr, &g_d3dGlyphAtlasView);
    UnicodeExperiment.lastD3DAtlasStatus = status;
    if (status < 0 || !g_d3dGlyphAtlasView) {
        if (g_d3dGlyphAtlasView) g_d3dGlyphAtlasView->Release();
        if (g_d3dGlyphAtlasTexture) g_d3dGlyphAtlasTexture->Release();
        g_d3dGlyphAtlasView = nullptr;
        g_d3dGlyphAtlasTexture = nullptr;
        UnicodeExperiment.d3dAtlasFailures++;
        return false;
    }
    ResetD3DGlyphAtlasEntries();
    return true;
}

static D3DGlyphAtlasEntry *FindOrCreateD3DGlyph(
    ID3D11DeviceContext *context, IDWriteFontFace *fontFace, float emSize,
    DWRITE_MEASURING_MODE measuringMode, unsigned short glyphIndex,
    BOOL isSideways) {
    for (unsigned int index = 0; index < kD3DGlyphAtlasEntries; ++index) {
        D3DGlyphAtlasEntry &entry = g_d3dGlyphEntries[index];
        if (entry.fontFace == fontFace && entry.emSize == emSize &&
            entry.measuringMode == measuringMode && entry.glyphIndex == glyphIndex &&
            entry.isSideways == isSideways &&
            entry.generation == g_d3dGlyphAtlasGeneration) {
            entry.stamp = ++g_cacheStamp;
            UnicodeExperiment.shapedGlyphCacheHits++;
            return &entry;
        }
    }
    if (!context || !fontFace || !EnsureDWriteFactory() || !EnsureD3DGlyphAtlas())
        return nullptr;

    DWRITE_GLYPH_RUN run = {};
    run.fontFace = fontFace;
    run.fontEmSize = emSize;
    run.glyphCount = 1;
    run.glyphIndices = &glyphIndex;
    run.isSideways = isSideways;
    IDWriteGlyphRunAnalysis *analysis = nullptr;
    HRESULT status = g_dwriteFactory->CreateGlyphRunAnalysis(
        &run, 1.0f, nullptr, DWRITE_RENDERING_MODE_NATURAL, measuringMode,
        0.0f, 0.0f, &analysis);
    RECT bounds = {};
    if (status >= 0 && analysis)
        status = analysis->GetAlphaTextureBounds(DWRITE_TEXTURE_CLEARTYPE_3x1, &bounds);
    unsigned int width = bounds.right > bounds.left
        ? static_cast<unsigned int>(bounds.right - bounds.left) : 0;
    unsigned int height = bounds.bottom > bounds.top
        ? static_cast<unsigned int>(bounds.bottom - bounds.top) : 0;
    if (status < 0 || width > 512 || height > 512) {
        if (analysis) analysis->Release();
        UnicodeExperiment.lastD3DAtlasStatus = status < 0 ? status : E_INVALIDARG;
        UnicodeExperiment.d3dAtlasFailures++;
        return nullptr;
    }

    unsigned int paddedWidth = width ? width + 2 : 0;
    unsigned int paddedHeight = height ? height + 2 : 0;
    if (paddedWidth && g_d3dGlyphAtlasX + paddedWidth > kD3DGlyphAtlasSize) {
        g_d3dGlyphAtlasX = 0;
        g_d3dGlyphAtlasY += g_d3dGlyphAtlasRowHeight;
        g_d3dGlyphAtlasRowHeight = 0;
    }
    if (paddedHeight && g_d3dGlyphAtlasY + paddedHeight > kD3DGlyphAtlasSize) {
        ResetD3DGlyphAtlasEntries();
    }

    if (paddedWidth) {
        SIZE_T alphaBytes = static_cast<SIZE_T>(width) * height * 3;
        SIZE_T paddedBytes = static_cast<SIZE_T>(paddedWidth) * paddedHeight;
        auto alpha = static_cast<unsigned char *>(pVirtualAlloc()(
            nullptr, alphaBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        auto coverage = static_cast<unsigned char *>(pVirtualAlloc()(
            nullptr, paddedBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!alpha || !coverage) {
            if (alpha) pVirtualFree()(alpha, 0, MEM_RELEASE);
            if (coverage) pVirtualFree()(coverage, 0, MEM_RELEASE);
            analysis->Release();
            UnicodeExperiment.lastD3DAtlasStatus = E_OUTOFMEMORY;
            UnicodeExperiment.d3dAtlasFailures++;
            return nullptr;
        }
        memset(coverage, 0, paddedBytes);
        status = analysis->CreateAlphaTexture(
            DWRITE_TEXTURE_CLEARTYPE_3x1, &bounds, alpha,
            static_cast<UINT32>(alphaBytes));
        if (status >= 0) {
            for (unsigned int y = 0; y < height; ++y) {
                for (unsigned int x = 0; x < width; ++x) {
                    coverage[static_cast<SIZE_T>(y + 1) * paddedWidth + x + 1] =
                        alpha[(static_cast<SIZE_T>(y) * width + x) * 3 + 2];
                }
            }
            D3D11_BOX box = {
                g_d3dGlyphAtlasX, g_d3dGlyphAtlasY, 0,
                g_d3dGlyphAtlasX + paddedWidth,
                g_d3dGlyphAtlasY + paddedHeight, 1
            };
            context->UpdateSubresource(
                g_d3dGlyphAtlasTexture, 0, &box, coverage, paddedWidth, 0);
            UnicodeExperiment.d3dAtlasUploadBytes += paddedBytes;
        }
        pVirtualFree()(alpha, 0, MEM_RELEASE);
        pVirtualFree()(coverage, 0, MEM_RELEASE);
        if (status < 0) {
            analysis->Release();
            UnicodeExperiment.lastD3DAtlasStatus = status;
            UnicodeExperiment.d3dAtlasFailures++;
            return nullptr;
        }
    }
    if (analysis) analysis->Release();

    unsigned int victim = 0;
    for (unsigned int index = 1; index < kD3DGlyphAtlasEntries; ++index) {
        if (!g_d3dGlyphEntries[index].fontFace) {
            victim = index;
            break;
        }
        if (g_d3dGlyphEntries[index].stamp < g_d3dGlyphEntries[victim].stamp)
            victim = index;
    }
    D3DGlyphAtlasEntry &entry = g_d3dGlyphEntries[victim];
    if (entry.fontFace) entry.fontFace->Release();
    entry = {};
    entry.fontFace = fontFace;
    fontFace->AddRef();
    entry.stamp = ++g_cacheStamp;
    entry.emSize = emSize;
    entry.measuringMode = measuringMode;
    entry.glyphIndex = glyphIndex;
    entry.isSideways = isSideways;
    entry.bounds = bounds;
    entry.atlasX = static_cast<unsigned short>(g_d3dGlyphAtlasX + (width ? 1 : 0));
    entry.atlasY = static_cast<unsigned short>(g_d3dGlyphAtlasY + (height ? 1 : 0));
    entry.atlasWidth = static_cast<unsigned short>(width);
    entry.atlasHeight = static_cast<unsigned short>(height);
    entry.generation = g_d3dGlyphAtlasGeneration;
    if (paddedWidth) {
        g_d3dGlyphAtlasX += paddedWidth;
        if (paddedHeight > g_d3dGlyphAtlasRowHeight)
            g_d3dGlyphAtlasRowHeight = paddedHeight;
    }
    UnicodeExperiment.shapedGlyphBuilds++;
    return &entry;
}

static float ToNdcX(float value, const D3D11_VIEWPORT &viewport) {
    return ((value - viewport.TopLeftX) / viewport.Width) * 2.0f - 1.0f;
}

static float ToNdcY(float value, const D3D11_VIEWPORT &viewport) {
    return 1.0f - ((value - viewport.TopLeftY) / viewport.Height) * 2.0f;
}

static void SetD3DAtlasVertex(D3DAtlasVertex &vertex, float x, float y, float u, float v,
                              const D2D1_COLOR_F &color, const D3D11_VIEWPORT &viewport) {
    vertex.position[0] = ToNdcX(x, viewport);
    vertex.position[1] = ToNdcY(y, viewport);
    vertex.uv[0] = u;
    vertex.uv[1] = v;
    vertex.color[0] = color.r;
    vertex.color[1] = color.g;
    vertex.color[2] = color.b;
    vertex.color[3] = color.a;
}

struct D3DAtlasSavedState {
    ID3D11RenderTargetView *targets[D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT];
    ID3D11DepthStencilView *depthView;
    ID3D11InputLayout *inputLayout;
    ID3D11Buffer *vertexBuffer;
    UINT vertexStride;
    UINT vertexOffset;
    D3D11_PRIMITIVE_TOPOLOGY topology;
    ID3D11VertexShader *vertexShader;
    ID3D11PixelShader *pixelShader;
    ID3D11GeometryShader *geometryShader;
    ID3D11HullShader *hullShader;
    ID3D11DomainShader *domainShader;
    ID3D11ShaderResourceView *pixelView;
    ID3D11SamplerState *pixelSampler;
    ID3D11BlendState *blend;
    FLOAT blendFactor[4];
    UINT sampleMask;
    ID3D11DepthStencilState *depthStencil;
    UINT stencilReference;
    ID3D11RasterizerState *rasterizer;
    UINT scissorCount;
    D3D11_RECT scissors[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE];
};

static void CaptureD3DAtlasState(ID3D11DeviceContext *context, D3DAtlasSavedState &state) {
    context->OMGetRenderTargets(
        D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, state.targets, &state.depthView);
    context->IAGetInputLayout(&state.inputLayout);
    context->IAGetVertexBuffers(
        0, 1, &state.vertexBuffer, &state.vertexStride, &state.vertexOffset);
    context->IAGetPrimitiveTopology(&state.topology);
    UINT classInstanceCount = 0;
    context->VSGetShader(&state.vertexShader, nullptr, &classInstanceCount);
    classInstanceCount = 0;
    context->PSGetShader(&state.pixelShader, nullptr, &classInstanceCount);
    classInstanceCount = 0;
    context->GSGetShader(&state.geometryShader, nullptr, &classInstanceCount);
    classInstanceCount = 0;
    context->HSGetShader(&state.hullShader, nullptr, &classInstanceCount);
    classInstanceCount = 0;
    context->DSGetShader(&state.domainShader, nullptr, &classInstanceCount);
    context->PSGetShaderResources(0, 1, &state.pixelView);
    context->PSGetSamplers(0, 1, &state.pixelSampler);
    context->OMGetBlendState(&state.blend, state.blendFactor, &state.sampleMask);
    context->OMGetDepthStencilState(&state.depthStencil, &state.stencilReference);
    context->RSGetState(&state.rasterizer);
    state.scissorCount = ARRAY_COUNT(state.scissors);
    context->RSGetScissorRects(&state.scissorCount, state.scissors);
}

static void RestoreD3DAtlasState(ID3D11DeviceContext *context, D3DAtlasSavedState &state) {
    context->OMSetRenderTargets(
        D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, state.targets, state.depthView);
    context->IASetInputLayout(state.inputLayout);
    context->IASetVertexBuffers(
        0, 1, &state.vertexBuffer, &state.vertexStride, &state.vertexOffset);
    context->IASetPrimitiveTopology(state.topology);
    context->VSSetShader(state.vertexShader, nullptr, 0);
    context->PSSetShader(state.pixelShader, nullptr, 0);
    context->GSSetShader(state.geometryShader, nullptr, 0);
    context->HSSetShader(state.hullShader, nullptr, 0);
    context->DSSetShader(state.domainShader, nullptr, 0);
    context->PSSetShaderResources(0, 1, &state.pixelView);
    context->PSSetSamplers(0, 1, &state.pixelSampler);
    context->OMSetBlendState(state.blend, state.blendFactor, state.sampleMask);
    context->OMSetDepthStencilState(state.depthStencil, state.stencilReference);
    context->RSSetState(state.rasterizer);
    context->RSSetScissorRects(state.scissorCount, state.scissors);

    for (unsigned int index = 0; index < ARRAY_COUNT(state.targets); ++index)
        if (state.targets[index]) state.targets[index]->Release();
    if (state.depthView) state.depthView->Release();
    if (state.inputLayout) state.inputLayout->Release();
    if (state.vertexBuffer) state.vertexBuffer->Release();
    if (state.vertexShader) state.vertexShader->Release();
    if (state.pixelShader) state.pixelShader->Release();
    if (state.geometryShader) state.geometryShader->Release();
    if (state.hullShader) state.hullShader->Release();
    if (state.domainShader) state.domainShader->Release();
    if (state.pixelView) state.pixelView->Release();
    if (state.pixelSampler) state.pixelSampler->Release();
    if (state.blend) state.blend->Release();
    if (state.depthStencil) state.depthStencil->Release();
    if (state.rasterizer) state.rasterizer->Release();
}

static LONG NativeFloorToLong(float value) {
    LONG result = static_cast<LONG>(value);
    return static_cast<float>(result) > value ? result - 1 : result;
}

static LONG NativeCeilToLong(float value) {
    LONG result = static_cast<LONG>(value);
    return static_cast<float>(result) < value ? result + 1 : result;
}

static bool InlineScissor(const OverlayPacket &packet, const D3D11_VIEWPORT &viewport,
                          const D3DAtlasSavedState &savedState, D3D11_RECT &scissor) {
    if (packet.transform.valid) {
        D2D1_POINT_2F corners[4] = {
            ApplyPacketTransform(packet, static_cast<float>(packet.rectangle[0]),
                                 static_cast<float>(packet.rectangle[1])),
            ApplyPacketTransform(packet, static_cast<float>(packet.rectangle[2]),
                                 static_cast<float>(packet.rectangle[1])),
            ApplyPacketTransform(packet, static_cast<float>(packet.rectangle[0]),
                                 static_cast<float>(packet.rectangle[3])),
            ApplyPacketTransform(packet, static_cast<float>(packet.rectangle[2]),
                                 static_cast<float>(packet.rectangle[3]))
        };
        float left = corners[0].x, top = corners[0].y;
        float right = corners[0].x, bottom = corners[0].y;
        for (unsigned int index = 1; index < ARRAY_COUNT(corners); ++index) {
            if (corners[index].x < left) left = corners[index].x;
            if (corners[index].x > right) right = corners[index].x;
            if (corners[index].y < top) top = corners[index].y;
            if (corners[index].y > bottom) bottom = corners[index].y;
        }
        scissor.left = NativeFloorToLong(left);
        scissor.top = NativeFloorToLong(top);
        scissor.right = NativeCeilToLong(right);
        scissor.bottom = NativeCeilToLong(bottom);
    } else {
        scissor.left = packet.rectangle[0];
        scissor.top = packet.rectangle[1];
        scissor.right = packet.rectangle[2];
        scissor.bottom = packet.rectangle[3];
    }
    LONG viewportLeft = static_cast<LONG>(viewport.TopLeftX);
    LONG viewportTop = static_cast<LONG>(viewport.TopLeftY);
    LONG viewportRight = static_cast<LONG>(viewport.TopLeftX + viewport.Width);
    LONG viewportBottom = static_cast<LONG>(viewport.TopLeftY + viewport.Height);
    if (scissor.left < viewportLeft) scissor.left = viewportLeft;
    if (scissor.top < viewportTop) scissor.top = viewportTop;
    if (scissor.right > viewportRight) scissor.right = viewportRight;
    if (scissor.bottom > viewportBottom) scissor.bottom = viewportBottom;
    if (savedState.scissorCount) {
        const D3D11_RECT &native = savedState.scissors[0];
        if (scissor.left < native.left) scissor.left = native.left;
        if (scissor.top < native.top) scissor.top = native.top;
        if (scissor.right > native.right) scissor.right = native.right;
        if (scissor.bottom > native.bottom) scissor.bottom = native.bottom;
    }
    return scissor.right > scissor.left && scissor.bottom > scissor.top;
}

static void BindD3DAtlasPipeline(ID3D11DeviceContext *context) {
    UINT stride = sizeof(D3DAtlasVertex);
    UINT offset = 0;
    float blendFactor[4] = {};
    context->IASetInputLayout(g_d3dAtlasInputLayout);
    context->IASetVertexBuffers(0, 1, &g_d3dAtlasVertexBuffer, &stride, &offset);
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(g_d3dAtlasVertexShader, nullptr, 0);
    context->PSSetShader(g_d3dAtlasPixelShader, nullptr, 0);
    context->GSSetShader(nullptr, nullptr, 0);
    context->HSSetShader(nullptr, nullptr, 0);
    context->DSSetShader(nullptr, nullptr, 0);
    context->PSSetSamplers(0, 1, &g_d3dAtlasSampler);
    context->OMSetBlendState(g_d3dAtlasBlend, blendFactor, 0xffffffff);
    context->OMSetDepthStencilState(g_d3dAtlasDepthStencil, 0);
    context->RSSetState(g_d3dAtlasRasterizer);
}

static float GlyphAdvance(const GlyphCacheEntry &glyphs,
                          const GlyphRunRecord &record, unsigned int glyphOffset) {
    unsigned int glyph = record.glyphStart + glyphOffset;
    if (record.hasAdvances) return glyphs.glyphAdvances[glyph];
    DWRITE_GLYPH_METRICS metrics = {};
    unsigned short glyphIndex = glyphs.glyphIndices[glyph];
    if (record.fontFace->GetDesignGlyphMetrics(
            &glyphIndex, 1, &metrics, record.isSideways) < 0)
        return record.emSize * 0.5f;
    DWRITE_FONT_METRICS fontMetrics = {};
    record.fontFace->GetMetrics(&fontMetrics);
    if (!fontMetrics.designUnitsPerEm) return record.emSize * 0.5f;
    return static_cast<float>(metrics.advanceWidth) * record.emSize /
        static_cast<float>(fontMetrics.designUnitsPerEm);
}

static bool DrawD3DShapedGlyphsInline(const OverlayPacket &packet, const wchar_t *text) {
    if (!EnsureD3DAtlasReady() || !EnsureD3DGlyphAtlas()) return false;
    auto renderer = *reinterpret_cast<unsigned long long **>(Bindings.d3dRendererGlobal);
    auto context = renderer ? reinterpret_cast<ID3D11DeviceContext *>(renderer[9]) : nullptr;
    if (!context) return false;
    GlyphCacheEntry *glyphs = FindOrCreateGlyphEntry(
        text, packet.textLength, packet, true);
    if (!glyphs) return false;

    memset(g_d3dGlyphPacketEntries, 0, sizeof(g_d3dGlyphPacketEntries));
    bool prepared = false;
    for (unsigned int attempt = 0; attempt < 2 && !prepared; ++attempt) {
        unsigned int generation = g_d3dGlyphAtlasGeneration;
        prepared = true;
        for (unsigned int runIndex = 0; runIndex < glyphs->runCount && prepared; ++runIndex) {
            const GlyphRunRecord &record = glyphs->runs[runIndex];
            for (unsigned int glyphOffset = 0; glyphOffset < record.glyphCount;
                 ++glyphOffset) {
                unsigned int glyph = record.glyphStart + glyphOffset;
                g_d3dGlyphPacketEntries[glyph] = FindOrCreateD3DGlyph(
                    context, record.fontFace, record.emSize, record.measuringMode,
                    glyphs->glyphIndices[glyph], record.isSideways);
                if (!g_d3dGlyphPacketEntries[glyph]) {
                    prepared = false;
                    break;
                }
                if (g_d3dGlyphAtlasGeneration != generation) {
                    prepared = false;
                    break;
                }
            }
        }
    }
    if (!prepared) return false;

    UINT viewportCount = 1;
    D3D11_VIEWPORT viewport = {};
    context->RSGetViewports(&viewportCount, &viewport);
    if (!viewportCount || viewport.Width <= 0.0f || viewport.Height <= 0.0f) return false;
    D3DAtlasSavedState savedState = {};
    CaptureD3DAtlasState(context, savedState);
    D3D11_RECT scissor = {};
    if (!InlineScissor(packet, viewport, savedState, scissor)) {
        RestoreD3DAtlasState(context, savedState);
        return true;
    }
    BindD3DAtlasPipeline(context);

    D3D11_MAPPED_SUBRESOURCE mapped = {};
    HRESULT status = context->Map(
        g_d3dAtlasVertexBuffer, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    UnicodeExperiment.lastD3DAtlasStatus = status;
    if (status < 0 || !mapped.pData) {
        UnicodeExperiment.d3dAtlasFailures++;
        RestoreD3DAtlasState(context, savedState);
        return false;
    }

    auto vertices = static_cast<D3DAtlasVertex *>(mapped.pData);
    unsigned int vertexCount = 0;
    D2D1_COLOR_F color = PacketColor(packet);
    D2D1_POINT_2F origin = PacketOrigin(packet, glyphs->width, glyphs->height);
    for (unsigned int runIndex = 0; runIndex < glyphs->runCount; ++runIndex) {
        const GlyphRunRecord &record = glyphs->runs[runIndex];
        float pen = 0.0f;
        float direction = (record.bidiLevel & 1) ? -1.0f : 1.0f;
        for (unsigned int glyphOffset = 0; glyphOffset < record.glyphCount; ++glyphOffset) {
            unsigned int glyph = record.glyphStart + glyphOffset;
            D3DGlyphAtlasEntry *entry = g_d3dGlyphPacketEntries[glyph];
            DWRITE_GLYPH_OFFSET placement = {};
            if (record.hasOffsets) placement = glyphs->glyphOffsets[glyph];
            float baselineX = origin.x + record.baselineX +
                direction * (pen + placement.advanceOffset);
            float baselineY = origin.y + record.baselineY - placement.ascenderOffset;
            // Glyph masks are cached at phase zero. Snap their baselines to the
            // same integer grid as File Pilot's native atlas so bilinear sampling
            // cannot soften or shimmer an otherwise stable cached glyph.
            baselineX = static_cast<float>(static_cast<int>(
                baselineX + (baselineX >= 0.0f ? 0.5f : -0.5f)));
            baselineY = static_cast<float>(static_cast<int>(
                baselineY + (baselineY >= 0.0f ? 0.5f : -0.5f)));
            if (entry->atlasWidth && entry->atlasHeight) {
                float left = baselineX + static_cast<float>(entry->bounds.left);
                float top = baselineY + static_cast<float>(entry->bounds.top);
                float right = baselineX + static_cast<float>(entry->bounds.right);
                float bottom = baselineY + static_cast<float>(entry->bounds.bottom);
                D2D1_POINT_2F topLeft = ApplyPacketTransform(packet, left, top);
                D2D1_POINT_2F topRight = ApplyPacketTransform(packet, right, top);
                D2D1_POINT_2F bottomLeft = ApplyPacketTransform(packet, left, bottom);
                D2D1_POINT_2F bottomRight = ApplyPacketTransform(packet, right, bottom);
                float u0 = static_cast<float>(entry->atlasX) / kD3DGlyphAtlasSize;
                float v0 = static_cast<float>(entry->atlasY) / kD3DGlyphAtlasSize;
                float u1 = static_cast<float>(entry->atlasX + entry->atlasWidth) /
                    kD3DGlyphAtlasSize;
                float v1 = static_cast<float>(entry->atlasY + entry->atlasHeight) /
                    kD3DGlyphAtlasSize;
                SetD3DAtlasVertex(vertices[vertexCount++], topLeft.x, topLeft.y,
                                  u0, v0, color, viewport);
                SetD3DAtlasVertex(vertices[vertexCount++], topRight.x, topRight.y,
                                  u1, v0, color, viewport);
                SetD3DAtlasVertex(vertices[vertexCount++], bottomLeft.x, bottomLeft.y,
                                  u0, v1, color, viewport);
                SetD3DAtlasVertex(vertices[vertexCount++], bottomLeft.x, bottomLeft.y,
                                  u0, v1, color, viewport);
                SetD3DAtlasVertex(vertices[vertexCount++], topRight.x, topRight.y,
                                  u1, v0, color, viewport);
                SetD3DAtlasVertex(vertices[vertexCount++], bottomRight.x, bottomRight.y,
                                  u1, v1, color, viewport);
            }
            pen += GlyphAdvance(*glyphs, record, glyphOffset);
        }
    }
    context->Unmap(g_d3dAtlasVertexBuffer, 0);
    if (vertexCount) {
        context->RSSetScissorRects(1, &scissor);
        context->PSSetShaderResources(0, 1, &g_d3dGlyphAtlasView);
        context->Draw(vertexCount, 0);
        UnicodeExperiment.d3dAtlasDrawCalls++;
        UnicodeExperiment.shapedGlyphDrawCalls++;
        UnicodeExperiment.overlayDrawn++;
    }
    ID3D11ShaderResourceView *noView = nullptr;
    context->PSSetShaderResources(0, 1, &noView);
    RestoreD3DAtlasState(context, savedState);
    return true;
}


static bool DrawInlinePacket(OverlayPacket &packet, const wchar_t *text) {
    unsigned long long started = PerformanceTicks();
    bool drawn = DrawD3DShapedGlyphsInline(packet, text);
    unsigned long long ended = PerformanceTicks();
    if (ended >= started) UnicodeExperiment.drawMicroseconds +=
        TicksToMicroseconds(ended - started);
    if (drawn) {
        packet.consumed = true;
        UnicodeExperiment.nativeMarkersDrawn++;
        if (PacketTransformIsAnimated(packet)) UnicodeExperiment.nativeAnimatedDraws++;
    }
    return drawn;
}

extern "C" __declspec(dllexport) void __fastcall UnicodeD3DDrawBatchHook(
    long long *resource, unsigned int count, unsigned char *instances) {
    using OriginalFn = void (__fastcall *)(long long *, unsigned int, unsigned char *);
    auto original = reinterpret_cast<OriginalFn>(Bindings.originalD3DDrawBatch);
    if (!original || !count || !instances) {
        if (original) original(resource, count, instances);
        return;
    }

    unsigned int nativeStart = 0;
    for (unsigned int index = 0; index < count; ++index) {
        unsigned char *instance = instances +
            static_cast<unsigned long long>(index) * kNativeInstanceBytes;
        unsigned int token = 0;
        unsigned int generation = 0;
        NativeMarkerKind markerKind = ReadNativeMarker(instance, token, generation);
        if (markerKind == NativeMarkerNone) continue;
        if (index > nativeStart) {
            original(resource, index - nativeStart,
                     instances + static_cast<unsigned long long>(nativeStart) *
                         kNativeInstanceBytes);
            UnicodeExperiment.nativeBatchSplits++;
        }
        if (markerKind == NativeMarkerDraw) {
            const wchar_t *text = nullptr;
            OverlayPacket *packet = FindInlinePacket(token, generation, text);
            if (packet && text) {
                if (!DrawInlinePacket(*packet, text)) {
                    UnicodeExperiment.backendFallbacks++;
                    UnicodeExperiment.flags |= ExperimentBackendFallback;
                }
            } else {
                UnicodeExperiment.nativeMarkersMissed++;
            }
        }
        nativeStart = index + 1;
    }
    if (nativeStart < count)
        original(resource, count - nativeStart,
                 instances + static_cast<unsigned long long>(nativeStart) *
                     kNativeInstanceBytes);
}

extern "C" __declspec(dllexport) HRESULT WINAPI UnicodeD3D11CreateDeviceHook(
    IDXGIAdapter *adapter, D3D_DRIVER_TYPE driverType, HMODULE software, UINT flags,
    const D3D_FEATURE_LEVEL *featureLevels, UINT featureLevelCount, UINT sdkVersion,
    ID3D11Device **device, D3D_FEATURE_LEVEL *featureLevel, ID3D11DeviceContext **context) {
    InstallFastGlyphRanges();
    flags |= D3D11_CREATE_DEVICE_BGRA_SUPPORT;
    HRESULT status = pD3D11CreateDevice()(adapter, driverType, software, flags,
        featureLevels, featureLevelCount, sdkVersion, device, featureLevel, context);
    if (status >= 0) {
        _InterlockedExchange(&g_d3dReady, 1);
        UnicodeExperiment.flags |= ExperimentD3DReady;
    }
    return status;
}

extern "C" __declspec(dllexport) void __fastcall UnicodeD3DRenderFrameHook(
    long long renderer, int resize) {
    using OriginalFn = void (__fastcall *)(long long, int);
    if (resize) ReleaseD3DAtlasTarget();
    // The renderer establishes its target before native text dispatch. A
    // successful enqueue can therefore suppress native text on frame one; an
    // unavailable backend uses only native text and never double-renders.
    if (!resize) EnsureD3DAtlasReady();
    reinterpret_cast<OriginalFn>(Bindings.originalD3DRenderFrame)(renderer, resize);
    UnicodeExperiment.frameCalls++;
    if (resize) EnsureD3DAtlasReady();
    OverlayQueue *queue = TakeOverlayQueue();
    for (unsigned int index = 0; index < queue->packetCount; ++index) {
        OverlayPacket &packet = queue->packets[index];
        if (packet.active && !packet.consumed) UnicodeExperiment.nativeMarkersMissed++;
    }
    queue->packetCount = 0;
    queue->textLength = 0;
}

extern "C" __declspec(dllexport) unsigned long long __fastcall UnicodeMeasureTextHook(
    float *font, const NativeStringView *text, int maximumWidth, NativeStringView *visibleText) {
    using OriginalFn = unsigned long long (__fastcall *)(
        float *, const NativeStringView *, int, NativeStringView *);
    UnicodeExperiment.measureCalls++;
    if (!text) return reinterpret_cast<OriginalFn>(Bindings.originalMeasureText)(
        font, text, maximumWidth, visibleText);
    bool complex = ContainsExtendedText(*text);
    if (_InterlockedCompareExchange(&g_d3dReady, 0, 0) != 0 &&
        _InterlockedCompareExchange(&g_d3dAtlasOperational, 0, 0) == 0)
        EnsureD3DAtlasReady();
    bool rendererReady = _InterlockedCompareExchange(&g_d3dReady, 0, 0) != 0 &&
        _InterlockedCompareExchange(&g_d3dAtlasOperational, 0, 0) != 0;
    if (complex && rendererReady) {
        bool succeeded = false;
        unsigned long long started = PerformanceTicks();
        unsigned long long result = MeasureWithDirectWrite(
            font, *text, maximumWidth, visibleText, true, succeeded);
        unsigned long long ended = PerformanceTicks();
        if (ended >= started) UnicodeExperiment.shapeMicroseconds +=
            TicksToMicroseconds(ended - started);
        if (succeeded) return result;
        UnicodeExperiment.backendFallbacks++;
    }
    ShapeResult shaped = ShapeArabic(*text);
    if (!shaped.allocation) return reinterpret_cast<OriginalFn>(Bindings.originalMeasureText)(
        font, text, maximumWidth, visibleText);
    NativeStringView shapedVisible = {};
    unsigned long long result = reinterpret_cast<OriginalFn>(Bindings.originalMeasureText)(
        font, &shaped.view, maximumWidth, &shapedVisible);
    if (visibleText) {
        unsigned int visibleCodepoints = 0;
        unsigned long long offset = 0;
        while (offset < shapedVisible.length) {
            unsigned int codepoint = 0;
            unsigned int consumed = DecodeUtf8(
                shaped.view.data + offset, shapedVisible.length - offset, codepoint);
            if (!consumed) break;
            offset += consumed;
            ++visibleCodepoints;
        }
        visibleText->data = text->data;
        visibleText->length = ByteOffsetAfterCodepoints(*text, visibleCodepoints);
    }
    ReleaseShape(shaped);
    return result;
}

extern "C" __declspec(dllexport) void __fastcall UnicodeRenderTextHook(
    unsigned long long *arena, float *font, int *rectangle, const NativeStringView *text,
    unsigned long long *color, float *options) {
    using OriginalFn = void (__fastcall *)(unsigned long long *, float *, int *,
        const NativeStringView *, unsigned long long *, float *);
    UnicodeExperiment.renderCalls++;
    if (!text) {
        reinterpret_cast<OriginalFn>(Bindings.originalRenderText)(
            arena, font, rectangle, text, color, options);
        return;
    }
    bool complex = ContainsExtendedText(*text);
    if (_InterlockedCompareExchange(&g_d3dReady, 0, 0) != 0 &&
        _InterlockedCompareExchange(&g_d3dAtlasOperational, 0, 0) == 0)
        EnsureD3DAtlasReady();
    bool rendererReady = _InterlockedCompareExchange(&g_d3dReady, 0, 0) != 0 &&
        _InterlockedCompareExchange(&g_d3dAtlasOperational, 0, 0) != 0;
    if (complex && rendererReady) {
        UnicodeExperiment.nativeRendererMode = kNativeRendererShapedGlyphs;
        UnicodeExperiment.nativeTransformMode = kNativeTransformProbe;
        UnicodeExperiment.flags |= ExperimentNativeInline;
        unsigned int token = 0;
        unsigned int generation = 0;
        bool packetCreated = false;
        if (EnqueueInlinePacket(
                font, rectangle, *text, color, options, token, generation,
                packetCreated)) {
            unsigned int cancellationToken = token;
            unsigned int cancellationGeneration = generation;
            bool submitted = SubmitNativeTextCarrier(
                arena, font, rectangle, options, token, generation);
            if (submitted) return;
            if (packetCreated) CancelInlinePacket(
                cancellationToken, cancellationGeneration);
        }
        UnicodeExperiment.backendFallbacks++;
    } else if (complex) {
        UnicodeExperiment.backendFallbacks++;
        UnicodeExperiment.flags |= ExperimentBackendFallback;
    }
    ShapeResult shaped = ShapeArabic(*text);
    reinterpret_cast<OriginalFn>(Bindings.originalRenderText)(
        arena, font, rectangle, shaped.allocation ? &shaped.view : text, color, options);
    ReleaseShape(shaped);
}

extern "C" __declspec(dllexport) long long *__fastcall UnicodeUtf16ToUtf8Hook(
    long long *output, unsigned long long *arena, const NativeWideStringView *input,
    long long *destination) {
    using OriginalFn = long long *(__fastcall *)(long long *, unsigned long long *,
        const NativeWideStringView *, long long *);
    if (!input || input->length != 1 || !input->data) {
        return reinterpret_cast<OriginalFn>(Bindings.originalUtf16ToUtf8)(
            output, arena, input, destination);
    }
    unsigned int current = static_cast<unsigned short>(input->data[0]);
    LONG pending = _InterlockedExchange(&g_pendingHighSurrogate, 0);
    if (0xd800 <= current && current <= 0xdbff) {
        if (pending) UnicodeDebug.invalidSurrogates++;
        _InterlockedExchange(&g_pendingHighSurrogate, static_cast<LONG>(current));
        output[0] = destination ? destination[0] + destination[1] : 0;
        output[1] = 0;
        return output;
    }
    wchar_t converted[2] = {};
    NativeWideStringView convertedView = {converted, 1};
    if (pending && 0xdc00 <= current && current <= 0xdfff) {
        converted[0] = static_cast<wchar_t>(pending);
        converted[1] = static_cast<wchar_t>(current);
        convertedView.length = 2;
        UnicodeDebug.pairedSurrogates++;
    } else if (pending) {
        converted[0] = static_cast<wchar_t>(0xfffd);
        converted[1] = static_cast<wchar_t>(current);
        convertedView.length = 2;
        UnicodeDebug.invalidSurrogates++;
    } else if (0xdc00 <= current && current <= 0xdfff) {
        converted[0] = static_cast<wchar_t>(0xfffd);
        UnicodeDebug.invalidSurrogates++;
    } else {
        converted[0] = static_cast<wchar_t>(current);
    }
    return reinterpret_cast<OriginalFn>(Bindings.originalUtf16ToUtf8)(
        output, arena, &convertedView, destination);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }

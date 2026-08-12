#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d2d1.h>
#include <dwrite.h>

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
    unsigned long long iatVirtualAlloc;
    unsigned long long iatVirtualFree;
    unsigned long long originalMeasureText;
    unsigned long long originalRenderText;
    unsigned long long originalFontCreateAtlas;
    unsigned long long originalFontRasterizer;
    unsigned long long originalUtf16ToUtf8;
    unsigned long long originalNativeQuadEmitter;
};

static constexpr unsigned long long kUnicodeBindingsMagic =
    0x53474e4942555046ULL; // "FPUBINGS"
static constexpr unsigned long long kUnicodeBindingsVersion = 9;

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
static auto pVirtualAlloc() {
    return Iat<decltype(&VirtualAlloc)>(Bindings.iatVirtualAlloc);
}
static auto pVirtualFree() {
    return Iat<decltype(&VirtualFree)>(Bindings.iatVirtualFree);
}

enum ExperimentFlags : unsigned int {
    ExperimentInitialized = 1u << 0,
    ExperimentBackendFallback = 1u << 1,
    ExperimentNativeRows = 1u << 2,
};

static constexpr unsigned int kNativeRendererRowResource = 3;
static constexpr unsigned int kNativeTransformEmitter = 3;

struct UnicodeExperimentState {
    unsigned int version;
    unsigned int flags;
    unsigned long long measureCalls;
    unsigned long long renderCalls;
    unsigned long long backendFallbacks;
    unsigned long long glyphCacheHits;
    unsigned long long glyphCacheMisses;
    unsigned long long shapeMicroseconds;
    long long lastDWriteStatus;
    unsigned long long atlasSuccessMask;
    unsigned long long fontMetricHits;
    unsigned long long fontMetricMisses;
    unsigned long long lastNativeFontSizeBits;
    unsigned long long lastDWriteEmSizeBits;
    unsigned long long rowBuilds;
    unsigned long long rowCacheHits;
    unsigned long long rowCacheMisses;
    unsigned long long rowFailures;
    unsigned long long rowSubmissions;
    unsigned long long rowUploadBytes;
    long long lastRowStatus;
    unsigned int nativeRendererMode;
    unsigned int nativeTransformMode;
};

extern "C" __declspec(dllexport) volatile UnicodeExperimentState UnicodeExperiment = {
    8, ExperimentInitialized
};

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

static constexpr unsigned int kOverlayTextLimit = 512;

struct OverlayPacket {
    int rectangle[4];
    float alignX;
    float alignY;
    float emSize;
    NativeFontFamily fontFamily;
    unsigned int textLength;
    unsigned long long textHash;
};

static unsigned long long HashWideText(const wchar_t *text, unsigned int length) {
    unsigned long long hash = 1469598103934665603ULL;
    for (unsigned int index = 0; index < length; ++index) {
        hash ^= static_cast<unsigned short>(text[index]);
        hash *= 1099511628211ULL;
    }
    return hash;
}


static unsigned long long PackNativePoint(int x, int y) {
    return static_cast<unsigned int>(x) |
        (static_cast<unsigned long long>(static_cast<unsigned int>(y)) << 32);
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

// File Pilot's native texture descriptor. FUN_140049CC0 consumes the CPU pixels
// and fills the final two qwords with its backend resource identity. Keeping this
// descriptor and its pixel buffer stable makes the native command stream stable.
struct NativeTextureResource {
    unsigned char *pixels;       // +0x00
    int width;                   // +0x08
    int height;                  // +0x0c
    unsigned short arrayCount;   // +0x10
    unsigned short bytesPerPixel;// +0x12 (1 selects R8_UNORM)
    short immutable;             // +0x14
    unsigned short reserved;     // +0x16
    unsigned long long object;   // +0x18, populated by File Pilot
    unsigned long long generation;// +0x20, populated by File Pilot
};

static_assert(sizeof(NativeTextureResource) == 0x28,
              "native texture descriptor layout changed");

static constexpr unsigned int kNativeRowCacheEntries = 256;

struct NativeRowCacheEntry {
    unsigned long long hash;
    unsigned long long stamp;
    float emSize;
    float maximumWidth;
    float layoutWidth;
    float layoutHeight;
    NativeFontFamily fontFamily;
    unsigned int textLength;
    RECT bounds;
    NativeTextureResource resource;
    wchar_t text[kOverlayTextLimit + 1];
};

static NativeRowCacheEntry g_nativeRowCache[kNativeRowCacheEntries];

static void ReleaseNativeRowEntry(NativeRowCacheEntry &entry) {
    if (entry.resource.pixels)
        pVirtualFree()(entry.resource.pixels, 0, MEM_RELEASE);
    // File Pilot owns the backend objects recorded in object/generation and
    // retires them through its normal per-frame resource cache. Clearing the
    // descriptor prevents a recycled cache slot from reusing the old identity.
    entry = {};
}

static void ReleaseGlyphAnalyses(IDWriteGlyphRunAnalysis **analyses) {
    for (unsigned int index = 0; index < kGlyphCacheRuns; ++index)
        if (analyses[index]) analyses[index]->Release();
}

static NativeRowCacheEntry *FindOrCreateNativeRow(
    const wchar_t *text, const OverlayPacket &packet) {
    float maximumWidth = static_cast<float>(packet.rectangle[2] - packet.rectangle[0]);
    for (unsigned int index = 0; index < kNativeRowCacheEntries; ++index) {
        NativeRowCacheEntry &entry = g_nativeRowCache[index];
        if (entry.hash == packet.textHash && entry.textLength == packet.textLength &&
            entry.emSize == packet.emSize && entry.maximumWidth == maximumWidth &&
            entry.fontFamily == packet.fontFamily &&
            SameText(entry.text, text, packet.textLength)) {
            entry.stamp = ++g_cacheStamp;
            UnicodeExperiment.rowCacheHits++;
            return &entry;
        }
    }
    UnicodeExperiment.rowCacheMisses++;

    GlyphCacheEntry *glyphs = FindOrCreateGlyphEntry(
        text, packet.textLength, packet, true);
    if (!glyphs || !EnsureDWriteFactory()) return nullptr;

    IDWriteGlyphRunAnalysis *analyses[kGlyphCacheRuns] = {};
    RECT runBounds[kGlyphCacheRuns] = {};
    RECT coverageBounds = {};
    bool haveBounds = false;
    HRESULT status = S_OK;
    for (unsigned int index = 0; index < glyphs->runCount; ++index) {
        const GlyphRunRecord &record = glyphs->runs[index];
        DWRITE_GLYPH_RUN run = {};
        run.fontFace = record.fontFace;
        run.fontEmSize = record.emSize;
        run.glyphCount = record.glyphCount;
        run.glyphIndices = glyphs->glyphIndices + record.glyphStart;
        run.glyphAdvances = record.hasAdvances
            ? glyphs->glyphAdvances + record.glyphStart : nullptr;
        run.glyphOffsets = record.hasOffsets
            ? glyphs->glyphOffsets + record.glyphStart : nullptr;
        run.isSideways = record.isSideways;
        run.bidiLevel = record.bidiLevel;
        status = g_dwriteFactory->CreateGlyphRunAnalysis(
            &run, 1.0f, nullptr, DWRITE_RENDERING_MODE_NATURAL,
            record.measuringMode, record.baselineX, record.baselineY, &analyses[index]);
        if (status < 0 || !analyses[index]) break;
        status = analyses[index]->GetAlphaTextureBounds(
            DWRITE_TEXTURE_CLEARTYPE_3x1, &runBounds[index]);
        if (status < 0) break;
        const RECT &current = runBounds[index];
        if (current.right <= current.left || current.bottom <= current.top) continue;
        if (!haveBounds) {
            coverageBounds = current;
            haveBounds = true;
        } else {
            if (current.left < coverageBounds.left) coverageBounds.left = current.left;
            if (current.top < coverageBounds.top) coverageBounds.top = current.top;
            if (current.right > coverageBounds.right) coverageBounds.right = current.right;
            if (current.bottom > coverageBounds.bottom) coverageBounds.bottom = current.bottom;
        }
    }
    if (status < 0 || !haveBounds) {
        UnicodeExperiment.lastRowStatus = status;
        UnicodeExperiment.rowFailures++;
        ReleaseGlyphAnalyses(analyses);
        return nullptr;
    }

    unsigned int contentWidth = static_cast<unsigned int>(
        coverageBounds.right - coverageBounds.left);
    unsigned int contentHeight = static_cast<unsigned int>(
        coverageBounds.bottom - coverageBounds.top);
    if (!contentWidth || !contentHeight || contentWidth > 4094 || contentHeight > 254) {
        UnicodeExperiment.lastRowStatus = E_INVALIDARG;
        UnicodeExperiment.rowFailures++;
        ReleaseGlyphAnalyses(analyses);
        return nullptr;
    }

    // A transparent one-pixel gutter prevents clamp sampling from extending edge
    // coverage when the row is transformed or scaled by File Pilot.
    unsigned int width = contentWidth + 2;
    unsigned int height = contentHeight + 2;
    SIZE_T coverageBytes = static_cast<SIZE_T>(width) * height;
    auto coverage = static_cast<unsigned char *>(pVirtualAlloc()(
        nullptr, coverageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!coverage) {
        UnicodeExperiment.lastRowStatus = E_OUTOFMEMORY;
        UnicodeExperiment.rowFailures++;
        ReleaseGlyphAnalyses(analyses);
        return nullptr;
    }
    memset(coverage, 0, coverageBytes);

    for (unsigned int index = 0; index < glyphs->runCount && status >= 0; ++index) {
        const RECT &current = runBounds[index];
        if (!analyses[index] || current.right <= current.left || current.bottom <= current.top)
            continue;
        unsigned int runWidth = static_cast<unsigned int>(current.right - current.left);
        unsigned int runHeight = static_cast<unsigned int>(current.bottom - current.top);
        SIZE_T alphaBytes = static_cast<SIZE_T>(runWidth) * runHeight * 3;
        auto alpha = static_cast<unsigned char *>(pVirtualAlloc()(
            nullptr, alphaBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!alpha) {
            status = E_OUTOFMEMORY;
            break;
        }
        status = analyses[index]->CreateAlphaTexture(
            DWRITE_TEXTURE_CLEARTYPE_3x1, &current, alpha,
            static_cast<UINT32>(alphaBytes));
        if (status >= 0) {
            unsigned int destinationX = static_cast<unsigned int>(
                current.left - coverageBounds.left) + 1;
            unsigned int destinationY = static_cast<unsigned int>(
                current.top - coverageBounds.top) + 1;
            for (unsigned int y = 0; y < runHeight; ++y) {
                for (unsigned int x = 0; x < runWidth; ++x) {
                    unsigned char sample = alpha[
                        (static_cast<SIZE_T>(y) * runWidth + x) * 3 + 2];
                    unsigned char &destination = coverage[
                        static_cast<SIZE_T>(destinationY + y) * width +
                        destinationX + x];
                    if (sample > destination) destination = sample;
                }
            }
        }
        pVirtualFree()(alpha, 0, MEM_RELEASE);
    }
    ReleaseGlyphAnalyses(analyses);
    if (status < 0) {
        pVirtualFree()(coverage, 0, MEM_RELEASE);
        UnicodeExperiment.lastRowStatus = status;
        UnicodeExperiment.rowFailures++;
        return nullptr;
    }

    unsigned int victim = 0;
    for (unsigned int index = 1; index < kNativeRowCacheEntries; ++index) {
        if (!g_nativeRowCache[index].hash) {
            victim = index;
            break;
        }
        if (g_nativeRowCache[index].stamp < g_nativeRowCache[victim].stamp)
            victim = index;
    }
    NativeRowCacheEntry &entry = g_nativeRowCache[victim];
    ReleaseNativeRowEntry(entry);
    entry.hash = packet.textHash;
    entry.stamp = ++g_cacheStamp;
    entry.emSize = packet.emSize;
    entry.maximumWidth = maximumWidth;
    entry.layoutWidth = glyphs->width;
    entry.layoutHeight = glyphs->height;
    entry.fontFamily = packet.fontFamily;
    entry.textLength = packet.textLength;
    entry.bounds = {
        coverageBounds.left - 1, coverageBounds.top - 1,
        coverageBounds.right + 1, coverageBounds.bottom + 1
    };
    entry.resource.pixels = coverage;
    entry.resource.width = static_cast<int>(width);
    entry.resource.height = static_cast<int>(height);
    entry.resource.arrayCount = 1;
    entry.resource.bytesPerPixel = 1;
    entry.resource.immutable = 1;
    memcpy(entry.text, text, packet.textLength * sizeof(wchar_t));
    entry.text[packet.textLength] = 0;
    UnicodeExperiment.rowBuilds++;
    UnicodeExperiment.rowUploadBytes += coverageBytes;
    UnicodeExperiment.lastRowStatus = S_OK;
    return &entry;
}

static bool SubmitNativeRow(
    unsigned long long *color, const OverlayPacket &packet,
    NativeRowCacheEntry &row) {
    using NativeQuadFn = void (__fastcall *)(
        unsigned long long *, long long, unsigned long long *);
    if (!Bindings.originalNativeQuadEmitter ||
        !row.resource.pixels || row.resource.width <= 0 || row.resource.height <= 0)
        return false;

    D2D1_POINT_2F origin = PacketOrigin(packet, row.layoutWidth, row.layoutHeight);
    int left = static_cast<int>(origin.x) + row.bounds.left;
    int top = static_cast<int>(origin.y) + row.bounds.top;
    int right = static_cast<int>(origin.x) + row.bounds.right;
    int bottom = static_cast<int>(origin.y) + row.bounds.bottom;
    unsigned long long corners[2] = {
        PackNativePoint(left, top), PackNativePoint(right, bottom)
    };
    unsigned char rowStyle[0x60] = {};
    if (color) memcpy(rowStyle, color, 0x10);
    // FUN_1401BA410 constructs the native full-texture image style with these
    // exact UV and sampling fields before calling FUN_1401B9B50.
    *reinterpret_cast<unsigned long long *>(rowStyle + 0x4c) = 0;
    *reinterpret_cast<float *>(rowStyle + 0x54) = 0.0f;
    *reinterpret_cast<float *>(rowStyle + 0x58) = 1.0f;
    *reinterpret_cast<float *>(rowStyle + 0x5c) = 1.0f;
    reinterpret_cast<NativeQuadFn>(Bindings.originalNativeQuadEmitter)(
        corners, reinterpret_cast<long long>(&row.resource),
        reinterpret_cast<unsigned long long *>(rowStyle));
    UnicodeExperiment.rowSubmissions++;
    return true;
}

extern "C" __declspec(dllexport) unsigned long long __fastcall UnicodeMeasureTextHook(
    float *font, const NativeStringView *text, int maximumWidth, NativeStringView *visibleText) {
    using OriginalFn = unsigned long long (__fastcall *)(
        float *, const NativeStringView *, int, NativeStringView *);
    UnicodeExperiment.measureCalls++;
    if (!text) return reinterpret_cast<OriginalFn>(Bindings.originalMeasureText)(
        font, text, maximumWidth, visibleText);
    bool complex = ContainsExtendedText(*text);
    if (!complex) return reinterpret_cast<OriginalFn>(Bindings.originalMeasureText)(
        font, text, maximumWidth, visibleText);
    bool succeeded = false;
    unsigned long long started = PerformanceTicks();
    unsigned long long result = MeasureWithDirectWrite(
        font, *text, maximumWidth, visibleText, true, succeeded);
    unsigned long long ended = PerformanceTicks();
    if (ended >= started) UnicodeExperiment.shapeMicroseconds +=
        TicksToMicroseconds(ended - started);
    if (succeeded) return result;
    UnicodeExperiment.backendFallbacks++;
    ShapeResult shaped = ShapeArabic(*text);
    if (!shaped.allocation) return reinterpret_cast<OriginalFn>(Bindings.originalMeasureText)(
        font, text, maximumWidth, visibleText);
    NativeStringView shapedVisible = {};
    unsigned long long fallbackResult = reinterpret_cast<OriginalFn>(Bindings.originalMeasureText)(
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
    return fallbackResult;
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
    if (!complex) {
        reinterpret_cast<OriginalFn>(Bindings.originalRenderText)(
            arena, font, rectangle, text, color, options);
        return;
    }
    UnicodeExperiment.nativeRendererMode = kNativeRendererRowResource;
    UnicodeExperiment.nativeTransformMode = kNativeTransformEmitter;
    UnicodeExperiment.flags |= ExperimentNativeRows;
    wchar_t local[kOverlayTextLimit + 1] = {};
    WideConversion wide = ConvertUtf8ToWide(*text, local, ARRAY_COUNT(local));
    if (wide.data && wide.length && wide.length <= kOverlayTextLimit) {
        OverlayPacket packet = {};
        if (rectangle) {
            for (unsigned int index = 0; index < 4; ++index)
                packet.rectangle[index] = rectangle[index];
        }
        packet.alignX = options ? options[0] : 0.0f;
        packet.alignY = options ? options[1] : 0.0f;
        NativeFontStyle style = ResolveNativeFontStyle(font);
        packet.emSize = style.emSize;
        packet.fontFamily = style.family;
        packet.textLength = wide.length;
        packet.textHash = HashWideText(wide.data, wide.length);
        unsigned long long started = PerformanceTicks();
        NativeRowCacheEntry *row = FindOrCreateNativeRow(wide.data, packet);
        unsigned long long ended = PerformanceTicks();
        if (ended >= started) UnicodeExperiment.shapeMicroseconds +=
            TicksToMicroseconds(ended - started);
        bool submitted = row && SubmitNativeRow(color, packet, *row);
        ReleaseWide(wide);
        if (submitted) return;
    } else {
        ReleaseWide(wide);
    }
    UnicodeExperiment.backendFallbacks++;
    UnicodeExperiment.flags |= ExperimentBackendFallback;
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

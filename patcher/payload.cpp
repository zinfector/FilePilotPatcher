#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <shellapi.h>
#include <shlobj.h>
#include <exdisp.h>
#include <shlwapi.h>
#include <servprov.h>
#include <intrin.h>
#include <new>

// The payload intentionally has no CRT dependency. MSVC may still lower large aggregate
// initialization to memset, so provide the tiny implementation locally.
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

// The patcher relocates this image and fills every target-specific value below. Keeping the
// bindings in exported data lets the same payload binary support compatible future File Pilot
// builds without compiling target addresses into the code.
struct PayloadBindings {
    unsigned long long magic;
    unsigned long long version;
    unsigned long long size;
    unsigned long long iatGetCommandLineW;
    unsigned long long iatCommandLineToArgvW;
    unsigned long long iatLocalFree;
    unsigned long long iatGetFileAttributesW;
    unsigned long long iatPathRemoveFileSpecW;
    unsigned long long iatPathFindFileNameW;
    unsigned long long iatSHParseDisplayName;
    unsigned long long iatWideCharToMultiByte;
    unsigned long long iatGetCurrentThreadId;
    unsigned long long iatLoadLibraryW;
    unsigned long long iatGetProcAddress;
    unsigned long long iatInvalidateRect;
    unsigned long long iatPostMessageW;
    unsigned long long iatCoCreateInstance;
    unsigned long long iatCoTaskMemFree;
    unsigned long long iatPropVariantClear;
    unsigned long long selectDisplayedItemMatchingName;
    unsigned long long originalInitializer;
    unsigned long long originalLiveSelection;
    unsigned long long selectionCommit;
    unsigned long long selectionCancel;
    unsigned long long toggleCursorSelection;
    unsigned long long originalFrame;
    unsigned long long selectionStateDisplayOffset;
    unsigned long long displayModeOffset;
    unsigned long long displayPrimaryOffset;
    unsigned long long displayAlternateOffset;
    unsigned long long displayCountOffset;
    unsigned long long panelSelectionModeOffset;
    unsigned long long originalItemInteraction;
    unsigned long long originalBeginQueuedCommand;
    unsigned long long getItemMetadata;
    unsigned long long inspectorSync;
    unsigned long long inspectorFrame;
    unsigned long long inspectorRenderer;
    unsigned long long inspectorChildSurfaceRenderer;
    unsigned long long panelSurfaceRenderer;
    unsigned long long panelViewportRenderer;
    unsigned long long findImGuiWindow;
    unsigned long long panelRenderer;
    unsigned long long inspectorLayoutActivate;
    unsigned long long panelHeaderRenderer;
    unsigned long long panelFooterRenderer;
    unsigned long long layoutContextGlobal;
    unsigned long long layoutPhaseOffset;
    unsigned long long navigatePanel;
    unsigned long long openSelectedItems;
    unsigned long long closeAllTabs;
    unsigned long long appActivePanelOffset;
    unsigned long long panelInspectorOffset;
    unsigned long long panelBackingOffset;
    unsigned long long panelViewOffset;
    unsigned long long panelIdentityOffset;
    unsigned long long panelContainerOffset;
    unsigned long long childOwnerOffset;
    unsigned long long childFlagOffset;
    unsigned long long inspectorExtentOffset;
    unsigned long long inspectorRatioOffset;
    unsigned long long inspectorLayoutOffset;
    unsigned long long inspectorWidthOffset;
    unsigned long long inspectorModeOffset;
    unsigned long long inspectorCurrentItemOffset;
    unsigned long long inspectorBackingOffset;
    unsigned long long inspectorChildOffset;
    unsigned long long viewSettingsOffset;
    unsigned long long itemFlagsOffset;
    unsigned long long metadataPathOffset;
    unsigned long long metadataFlagsOffset;
    unsigned long long backingPathOffset;
    unsigned long long panelFocusedItemOffset;
    unsigned long long tabIntegrationEnabled;
    unsigned long long parseOpenWindowPanelJson;
    unsigned long long createTabInGroupBefore;
    unsigned long long applyDeserializedPanelStateToTab;
    unsigned long long focusTab;
    unsigned long long originalTabSurfaceRenderer;
    unsigned long long inputStateGlobal;
    unsigned long long frameGenerationGlobal;
    unsigned long long originalTabHoverTest;
};

static constexpr unsigned long long kBindingsMagic = 0x53474e4942504c46ULL; // "FLPBINGS"
static constexpr unsigned long long kBindingsVersion = 21;

extern "C" __declspec(dllexport) volatile PayloadBindings Bindings = {
    kBindingsMagic, kBindingsVersion, sizeof(PayloadBindings)
};

struct MillerDebugState {
    unsigned long long childRenderCalls;
    unsigned long long recursiveFrames;
    unsigned long long inspectorSyncCalls;
    unsigned long long navigationCalls;
    unsigned long long beginOpenCalls;
    unsigned long long handledFolderActivations;
    unsigned long long itemInteractionCalls;
    unsigned long long columnCount;
    unsigned long long lastPanel;
    unsigned long long lastItem;
    unsigned long long syncPanel;
    unsigned long long syncChild;
    unsigned long long syncMode;
    unsigned long long renderChild;
    unsigned long long surfaceInspectorCalls;
    unsigned long long surfaceInspectorMillerCalls;
    unsigned long long surfaceInspectorPanel;
    unsigned long long surfaceInspectorMode;
    unsigned long long surfaceInspectorOrientation;
    unsigned long long surfaceInspectorWidthBits;
};

extern "C" __declspec(dllexport) volatile MillerDebugState MillerDebug = {};

template <typename T> static T Iat(unsigned long long slot) {
    return *reinterpret_cast<T *>(slot);
}

static auto pGetCommandLineW() { return Iat<decltype(&GetCommandLineW)>(Bindings.iatGetCommandLineW); }
static auto pCommandLineToArgvW() { return Iat<decltype(&CommandLineToArgvW)>(Bindings.iatCommandLineToArgvW); }
static auto pLocalFree() { return Iat<decltype(&LocalFree)>(Bindings.iatLocalFree); }
static auto pGetFileAttributesW() { return Iat<decltype(&GetFileAttributesW)>(Bindings.iatGetFileAttributesW); }
static auto pPathRemoveFileSpecW() { return Iat<decltype(&PathRemoveFileSpecW)>(Bindings.iatPathRemoveFileSpecW); }
static auto pPathFindFileNameW() { return Iat<decltype(&PathFindFileNameW)>(Bindings.iatPathFindFileNameW); }
static auto pSHParseDisplayName() { return Iat<decltype(&SHParseDisplayName)>(Bindings.iatSHParseDisplayName); }
static auto pWideCharToMultiByte() { return Iat<decltype(&WideCharToMultiByte)>(Bindings.iatWideCharToMultiByte); }
static auto pGetCurrentThreadId() { return Iat<decltype(&GetCurrentThreadId)>(Bindings.iatGetCurrentThreadId); }
static auto pLoadLibraryW() { return Iat<decltype(&LoadLibraryW)>(Bindings.iatLoadLibraryW); }
static auto pGetProcAddress() { return Iat<decltype(&GetProcAddress)>(Bindings.iatGetProcAddress); }
static auto pInvalidateRect() { return Iat<decltype(&InvalidateRect)>(Bindings.iatInvalidateRect); }
static auto pPostMessageW() { return Iat<decltype(&PostMessageW)>(Bindings.iatPostMessageW); }
static auto pCoCreateInstance() { return Iat<decltype(&CoCreateInstance)>(Bindings.iatCoCreateInstance); }
static auto pCoTaskMemFree() { return Iat<decltype(&CoTaskMemFree)>(Bindings.iatCoTaskMemFree); }
static auto pPropVariantClear() { return Iat<decltype(&PropVariantClear)>(Bindings.iatPropVariantClear); }

static const GUID kClsidShellWindows =
    {0x9ba05972, 0xf6a8, 0x11cf, {0xa4, 0x42, 0x00, 0xa0, 0xc9, 0x0a, 0x8f, 0x39}};
static const GUID kIidShellWindows =
    {0x85cb6900, 0x4d95, 0x11cf, {0x96, 0x0c, 0x00, 0x80, 0xc7, 0xf4, 0xee, 0x85}};
static const GUID kIidIUnknown =
    {0x00000000, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID kIidIDispatch =
    {0x00020400, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID kIidIServiceProvider =
    {0x6d5140c1, 0x7436, 0x11ce, {0x80, 0x34, 0x00, 0xaa, 0x00, 0x60, 0x09, 0xfa}};
static const GUID kIidIWebBrowser =
    {0xeab22ac1, 0x30c1, 0x11cf, {0xa7, 0xeb, 0x00, 0x00, 0xc0, 0x5b, 0xae, 0x0b}};
static const GUID kIidIWebBrowserApp =
    {0x0002df05, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID kIidIOleWindow =
    {0x00000114, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID kIidIShellView =
    {0x000214e3, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID kIidIFolderView =
    {0xcde725b0, 0xccc9, 0x4519, {0x91, 0x7e, 0x32, 0x5d, 0x72, 0xfa, 0xb4, 0xce}};

static bool GuidEqual(REFGUID a, REFGUID b) {
    auto x = reinterpret_cast<const unsigned long long *>(&a);
    auto y = reinterpret_cast<const unsigned long long *>(&b);
    return x[0] == y[0] && x[1] == y[1];
}

using SelectDisplayedItemMatchingNameFn = unsigned long long (__fastcall *)(
    unsigned long long, void *, unsigned long long, unsigned long long);

static PIDLIST_ABSOLUTE g_parentPidl;
static HWND g_hwnd;
static volatile LONG g_initialized;
static wchar_t g_fullPath[32768];
static char g_pendingName[4096];
static unsigned long long g_pendingNameLength;
static unsigned long long g_pendingAttempts;
static volatile LONG g_pendingReady;
static volatile LONG g_pendingLock;
static unsigned long long g_selectionStates[16];
static unsigned long long g_selectionStateCount;
static unsigned long long g_primarySelectionState;

// Every Miller column after the root is a native Inspector child. The controller only owns the
// recursive topology and selection state; File Pilot continues to allocate, navigate, and render
// each panel through its native Inspector implementation.
static constexpr unsigned int kMillerMaxColumns = 32;
static constexpr unsigned int kMillerPathCapacity = 32768;
static constexpr unsigned int kMillerNameCapacity = 4096;

struct NativeStringView {
    const char *data;
    unsigned long long length;
};

struct MillerColumn {
    unsigned long long panel;
    unsigned long long generation;
    unsigned long long pathLength;
    unsigned long long selectedLength;
    unsigned long long selectedItem;
    unsigned int suppressInspector;
    unsigned int selectionPending;
    unsigned int selectionAttempts;
    unsigned int reserved;
    unsigned char surface[0x80];
    char path[kMillerPathCapacity];
    char selected[kMillerNameCapacity];
};

struct MillerController {
    volatile LONG lock;
    unsigned int columnCount;
    unsigned int freeCount;
    unsigned long long generation;
    MillerColumn columns[kMillerMaxColumns];
    unsigned long long freePanels[kMillerMaxColumns];
};

static MillerController g_miller;
static unsigned long long g_renderContext;
static unsigned long long g_renderPanel;
static unsigned long long g_renderItem;
static unsigned long long g_inspectorSyncSource;
static unsigned long long g_inspectorSurfaceContext;
static unsigned long long g_inspectorSurfacePanel;
static unsigned int g_recursiveSurfaceDepth;
static unsigned int g_constructedColumnMask;
static char g_millerWorkName[kMillerNameCapacity];

static void AcquireSpinLock(volatile LONG *lock) {
    while (_InterlockedCompareExchange(lock, 1, 0) != 0) _mm_pause();
}

static void ReleaseSpinLock(volatile LONG *lock) {
    _InterlockedExchange(lock, 0);
}

static unsigned long long CopyBounded(char *destination, unsigned long long capacity,
                                      const char *source, unsigned long long length) {
    if (!destination || !capacity) return 0;
    if (!source) length = 0;
    if (length >= capacity) length = capacity - 1;
    for (unsigned long long i = 0; i < length; ++i) destination[i] = source[i];
    destination[length] = 0;
    return length;
}

static unsigned long long LeafOffset(const char *path, unsigned long long length) {
    while (length && (path[length - 1] == '/' || path[length - 1] == '\\')) --length;
    unsigned long long offset = length;
    while (offset && path[offset - 1] != '/' && path[offset - 1] != '\\') --offset;
    return offset;
}

static void AcquirePendingLock() {
    while (_InterlockedCompareExchange(&g_pendingLock, 1, 0) != 0) {
        _mm_pause();
    }
}

static void ReleasePendingLock() {
    _InterlockedExchange(&g_pendingLock, 0);
}

static void PublishSelection(PCUITEMID_CHILD child) {
    if (!g_parentPidl || !child) return;

    using ILCombineFn = PIDLIST_ABSOLUTE (WINAPI *)(PCIDLIST_ABSOLUTE, PCUIDLIST_RELATIVE);
    using SHGetPathFn = BOOL (WINAPI *)(PCIDLIST_ABSOLUTE, LPWSTR);
    HMODULE shell32 = pLoadLibraryW()(L"shell32.dll");
    if (!shell32) return;
    auto ilCombine = reinterpret_cast<ILCombineFn>(pGetProcAddress()(shell32, "ILCombine"));
    auto getPath = reinterpret_cast<SHGetPathFn>(pGetProcAddress()(shell32, "SHGetPathFromIDListW"));
    if (!ilCombine || !getPath) return;

    PIDLIST_ABSOLUTE full = ilCombine(g_parentPidl, child);
    if (!full) return;
    BOOL ok = getPath(full, g_fullPath);
    pCoTaskMemFree()(full);
    if (!ok) return;

    const wchar_t *leaf = pPathFindFileNameW()(g_fullPath);
    if (!leaf || !*leaf) return;

    AcquirePendingLock();
    int count = pWideCharToMultiByte()(CP_UTF8, 0, leaf, -1, g_pendingName,
        sizeof(g_pendingName), nullptr, nullptr);
    if (count > 1) {
        g_pendingNameLength = static_cast<unsigned long long>(count - 1);
        g_pendingAttempts = 0;
        _InterlockedExchange(&g_pendingReady, 1);
    }
    ReleasePendingLock();

    // File Pilot sleeps when no UI work is pending. Ensure the live-list hook below gets a frame
    // in which it can apply the selection; asynchronous enumeration will schedule later frames.
    pInvalidateRect()(g_hwnd, nullptr, FALSE);
    pPostMessageW()(g_hwnd, WM_PAINT, 0, 0);
}

static bool TryApplyNamedSelection(unsigned long long selectionState, const char *name,
                                   unsigned long long nameLength) {
    if (!selectionState || !name || !nameLength) return false;

    auto displayState = *reinterpret_cast<unsigned char **>(
        selectionState + Bindings.selectionStateDisplayOffset);
    if (!displayState) return false;
    unsigned long long displayOffset =
        *reinterpret_cast<unsigned long long *>(displayState + Bindings.displayModeOffset)
        ? Bindings.displayPrimaryOffset : Bindings.displayAlternateOffset;
    unsigned long long displayItems = reinterpret_cast<unsigned long long>(displayState) + displayOffset;
    unsigned long long itemCount = *reinterpret_cast<unsigned long long *>(
        displayItems + Bindings.displayCountOffset) +
        *reinterpret_cast<unsigned long long *>(displayItems + Bindings.displayCountOffset + 8);
    if (!itemCount) return false;

    unsigned long long request[13] = {};
    request[0] = reinterpret_cast<unsigned long long>(name);
    request[1] = nameLength;
    auto select = reinterpret_cast<SelectDisplayedItemMatchingNameFn>(
        Bindings.selectDisplayedItemMatchingName);
    return select(selectionState, request, displayItems, itemCount) != 0;
}

static bool TryApplyPendingSelectionLocked(unsigned long long selectionState) {
    return TryApplyNamedSelection(selectionState, g_pendingName, g_pendingNameLength);
}

static void ApplyNativeSingleSelection(unsigned long long context,
                                       unsigned long long panel);

static void ApplyPendingSelection(unsigned long long context) {
    if (_InterlockedCompareExchange(&g_pendingReady, 0, 0) == 0) return;

    AcquirePendingLock();
    if (!g_pendingReady) {
        ReleasePendingLock();
        return;
    }

    unsigned long long selectedPanel = 0;
    bool found = TryApplyPendingSelectionLocked(g_primarySelectionState);
    if (found) selectedPanel = g_primarySelectionState;
    for (unsigned long long i = 0; !found && i < g_selectionStateCount; ++i) {
        if (g_selectionStates[i] == g_primarySelectionState) continue;
        if (TryApplyPendingSelectionLocked(g_selectionStates[i])) {
            g_primarySelectionState = g_selectionStates[i];
            selectedPanel = g_selectionStates[i];
            found = true;
        }
    }
    if (found || ++g_pendingAttempts >= 0x10000) {
        _InterlockedExchange(&g_pendingReady, 0);
    }
    ReleasePendingLock();
    if (selectedPanel) ApplyNativeSingleSelection(context, selectedPanel);
}

static void RememberSelectionState(unsigned long long selectionState) {
    if (!selectionState) return;
    AcquirePendingLock();
    for (unsigned long long i = 0; i < g_selectionStateCount; ++i) {
        if (g_selectionStates[i] == selectionState) {
            ReleasePendingLock();
            return;
        }
    }
    if (g_selectionStateCount < sizeof(g_selectionStates) / sizeof(g_selectionStates[0])) {
        g_selectionStates[g_selectionStateCount++] = selectionState;
    }
    ReleasePendingLock();
}

using ItemMetadataFn = unsigned char *(__fastcall *)(unsigned long long, unsigned long long);
using NavigatePanelFn = void (__fastcall *)(unsigned long long, unsigned long long,
                                             const NativeStringView *, int, int *);
using InspectorSyncFn = void (__fastcall *)(unsigned long long, unsigned long long);
using InspectorFrameFn = void (__fastcall *)(unsigned long long, unsigned long long);
using InspectorRendererFn = void (__fastcall *)(unsigned long long, unsigned long long, int);
using InspectorChildSurfaceRendererFn = void (__fastcall *)(
    unsigned long long, unsigned long long, unsigned long long);
using PanelSurfaceRendererFn = void (__fastcall *)(unsigned long long, unsigned long long);
using PanelRendererFn = void (__fastcall *)(unsigned long long, unsigned long long);
using PanelFooterRendererFn = void (__fastcall *)(
    unsigned long long, unsigned long long, unsigned int);
using InspectorLayoutActivateFn = void (__fastcall *)(
    unsigned long long, unsigned long long);
using FindImGuiWindowFn = unsigned long long (__fastcall *)(unsigned long long);

static void SetColumn(MillerColumn &column, unsigned long long panel,
                      unsigned long long generation, const char *path,
                      unsigned long long pathLength, const char *selected,
                      unsigned long long selectedLength, bool suppressInspector) {
    column.panel = panel;
    column.generation = generation;
    column.pathLength = CopyBounded(column.path, sizeof(column.path), path, pathLength);
    column.selectedLength = CopyBounded(column.selected, sizeof(column.selected),
                                        selected, selectedLength);
    column.selectedItem = 0;
    column.suppressInspector = suppressInspector ? 1U : 0U;
    column.selectionPending = 0;
    column.selectionAttempts = 0;
    memset(column.surface, 0, sizeof(column.surface));
}

static void ResetColumn(MillerColumn &column) {
    if (column.panel) {
        auto container = reinterpret_cast<unsigned long long *>(
            column.panel + Bindings.panelContainerOffset);
        if (*container == reinterpret_cast<unsigned long long>(column.surface)) {
            *container = 0;
        }
    }
    column.panel = 0;
    column.generation = 0;
    column.pathLength = 0;
    column.selectedLength = 0;
    column.selectedItem = 0;
    column.suppressInspector = 0;
    column.selectionPending = 0;
    column.selectionAttempts = 0;
    memset(column.surface, 0, sizeof(column.surface));
    column.path[0] = 0;
    column.selected[0] = 0;
}

static bool StringsEqual(const char *left, unsigned long long leftLength,
                         const char *right, unsigned long long rightLength) {
    if (leftLength != rightLength) return false;
    for (unsigned long long i = 0; i < leftLength; ++i) {
        if (left[i] != right[i]) return false;
    }
    return true;
}

static unsigned int FindColumnUnlocked(unsigned long long panel) {
    for (unsigned int i = 0; i < g_miller.columnCount; ++i) {
        if (g_miller.columns[i].panel == panel) return i;
    }
    return kMillerMaxColumns;
}

static unsigned long long PanelInspector(unsigned long long panel) {
    if (!panel) return 0;
    return *reinterpret_cast<unsigned long long *>(panel + Bindings.panelInspectorOffset);
}

static bool ConfigureColumnSurfaceUnlocked(unsigned int index);

static void PushFreePanelUnlocked(unsigned long long panel) {
    if (!panel) return;
    for (unsigned int i = 0; i < g_miller.freeCount; ++i) {
        if (g_miller.freePanels[i] == panel) return;
    }
    if (g_miller.freeCount < kMillerMaxColumns) {
        g_miller.freePanels[g_miller.freeCount++] = panel;
    }
}

static void ConfigureInspectorLayoutUnlocked() {
    if (g_miller.columnCount < 2) return;
    unsigned long long rootInspector = PanelInspector(g_miller.columns[0].panel);
    if (!rootInspector) return;
    for (unsigned int i = 0; i + 1 < g_miller.columnCount; ++i) {
        unsigned long long inspector = PanelInspector(g_miller.columns[i].panel);
        if (!inspector) continue;
        if (i != 0) {
            // Root mode 0 is adaptive. Recursive surfaces are narrower than the full panel and
            // can otherwise flip to a vertical Inspector; force File Pilot's horizontal/right
            // layout for every descendant.
            *reinterpret_cast<int *>(inspector + Bindings.inspectorLayoutOffset) = 1;
        }
        unsigned int remaining = g_miller.columnCount - i;
        // The live/persisted ratio is the Inspector subtree share. Set both values to avoid
        // newly-created descendants animating from zero and drawing over the final column.
        float inspectorShare = static_cast<float>(remaining - 1) /
            static_cast<float>(remaining);
        *reinterpret_cast<float *>(inspector + Bindings.inspectorExtentOffset) = inspectorShare;
        *reinterpret_cast<float *>(inspector + Bindings.inspectorRatioOffset) = inspectorShare;
        if (i != 0) {
            unsigned long long ownerInspector = PanelInspector(g_miller.columns[i - 1].panel);
            float ownerWidth = ownerInspector ? *reinterpret_cast<float *>(
                ownerInspector + Bindings.inspectorWidthOffset) : 0.0f;
            if (ownerWidth > 0.0f) {
                *reinterpret_cast<float *>(inspector + Bindings.inspectorWidthOffset) =
                    ownerWidth * inspectorShare;
            }
        }
    }
    for (unsigned int i = 1; i < g_miller.columnCount; ++i) {
        ConfigureColumnSurfaceUnlocked(i);
    }
}

// The native Inspector content renderer resolves its rectangle through the owner panel's
// surface container. Inspector children do not normally own one, because stock FilePilot stops
// after a single Inspector. Give every recursive child a lightweight clone narrowed to its
// owner's Inspector subtree; this is the geometry link that makes the next native child safe and
// positions it relative to the correct column.
static bool ConfigureColumnSurfaceUnlocked(unsigned int index) {
    if (index == 0 || index >= g_miller.columnCount) return false;
    MillerColumn &column = g_miller.columns[index];
    unsigned long long ownerPanel = g_miller.columns[index - 1].panel;
    unsigned long long ownerInspector = PanelInspector(ownerPanel);
    unsigned long long ownerContainer = ownerPanel ?
        *reinterpret_cast<unsigned long long *>(
            ownerPanel + Bindings.panelContainerOffset) : 0;
    if (!column.panel || !ownerInspector || !ownerContainer) return false;

    memcpy(column.surface, reinterpret_cast<const void *>(ownerContainer),
           sizeof(column.surface));
    auto words = reinterpret_cast<unsigned long long *>(column.surface);
    auto rectangle = reinterpret_cast<float *>(column.surface + 0x38);
    auto ownerRectangle = reinterpret_cast<const float *>(ownerContainer + 0x38);
    float left = ownerRectangle[0];
    float top = ownerRectangle[1];
    float right = ownerRectangle[2];
    float bottom = ownerRectangle[3];
    float available = right - left;
    float inspectorWidth = *reinterpret_cast<float *>(
        ownerInspector + Bindings.inspectorWidthOffset);
    if (inspectorWidth <= 0.0f || inspectorWidth > available) {
        inspectorWidth = available * *reinterpret_cast<float *>(
            ownerInspector + Bindings.inspectorRatioOffset);
    }
    if (inspectorWidth <= 0.0f || inspectorWidth > available) return false;

    words[0] ^= column.panel + static_cast<unsigned long long>(index + 1);
    words[1] = column.panel;
    for (unsigned int i = 2; i <= 5; ++i) words[i] = 0;
    for (unsigned int i = 9; i <= 14; ++i) words[i] = 0;
    rectangle[0] = right - inspectorWidth;
    rectangle[1] = top;
    rectangle[2] = right;
    rectangle[3] = bottom;
    *reinterpret_cast<unsigned long long *>(
        column.panel + Bindings.panelContainerOffset) =
            reinterpret_cast<unsigned long long>(column.surface);
    return true;
}

static void TruncateAfterIndexUnlocked(unsigned int sourceIndex, bool suppressSource) {
    if (sourceIndex >= g_miller.columnCount) return;
    for (unsigned int i = sourceIndex; i + 1 < g_miller.columnCount; ++i) {
        unsigned long long inspector = PanelInspector(g_miller.columns[i].panel);
        if (inspector) {
            auto child = reinterpret_cast<unsigned long long *>(
                inspector + Bindings.inspectorChildOffset);
            if (*child == g_miller.columns[i + 1].panel) *child = 0;
        }
    }
    for (unsigned int i = sourceIndex + 1; i < g_miller.columnCount; ++i) {
        PushFreePanelUnlocked(g_miller.columns[i].panel);
        ResetColumn(g_miller.columns[i]);
    }
    g_miller.columnCount = sourceIndex + 1;
    if (suppressSource) g_miller.columns[sourceIndex].suppressInspector = 1;
    ++g_miller.generation;
    ConfigureInspectorLayoutUnlocked();
}

static bool ReadItemTarget(unsigned long long panel, unsigned long long selectedItem,
                           NativeStringView &path, unsigned long long &leaf,
                           unsigned long long &leafLength, bool &directory) {
    if (!panel || !selectedItem) return false;
    unsigned long long backing = *reinterpret_cast<unsigned long long *>(
        panel + Bindings.panelBackingOffset);
    if (!backing) return false;
    auto metadata = reinterpret_cast<ItemMetadataFn>(Bindings.getItemMetadata);
    auto selectedMetadata = metadata(backing, selectedItem);
    if (!selectedMetadata) return false;
    unsigned int flags = *reinterpret_cast<unsigned int *>(
        selectedItem + Bindings.itemFlagsOffset);
    directory = (flags & 2) != 0;
    if (!directory && (flags & 0x20) != 0) {
        directory = (*reinterpret_cast<unsigned int *>(
            selectedMetadata + Bindings.metadataFlagsOffset) & 2) != 0;
    }
    path = *reinterpret_cast<NativeStringView *>(
        selectedMetadata + Bindings.metadataPathOffset);
    if (!path.data || !path.length) return false;
    leaf = LeafOffset(path.data, path.length);
    leafLength = path.length - leaf;
    while (leafLength && (path.data[leaf + leafLength - 1] == '/' ||
                          path.data[leaf + leafLength - 1] == '\\')) --leafLength;
    return leafLength != 0;
}

static bool ReadPanelPath(unsigned long long panel, NativeStringView &path) {
    unsigned long long backing = panel ? *reinterpret_cast<unsigned long long *>(
        panel + Bindings.panelBackingOffset) : 0;
    if (!backing) return false;
    path = *reinterpret_cast<NativeStringView *>(backing + Bindings.backingPathOffset);
    return path.data && path.length;
}

static bool ReadInspectorTarget(unsigned long long panel, NativeStringView &path,
                                unsigned long long &item, unsigned long long &leaf,
                                unsigned long long &leafLength, bool &directory) {
    unsigned long long inspector = PanelInspector(panel);
    if (!inspector || *reinterpret_cast<int *>(
            inspector + Bindings.inspectorModeOffset) == 0) return false;
    item = *reinterpret_cast<unsigned long long *>(
        inspector + Bindings.inspectorCurrentItemOffset);
    unsigned long long backing = *reinterpret_cast<unsigned long long *>(
        inspector + Bindings.inspectorBackingOffset);
    if (!item || !backing) return false;
    auto metadata = reinterpret_cast<ItemMetadataFn>(Bindings.getItemMetadata)(backing, item);
    if (!metadata) return false;
    unsigned int flags = *reinterpret_cast<unsigned int *>(item + Bindings.itemFlagsOffset);
    directory = (flags & 2) != 0;
    if (!directory && (flags & 0x20) != 0) {
        directory = (*reinterpret_cast<unsigned int *>(
            metadata + Bindings.metadataFlagsOffset) & 2) != 0;
    }
    path = *reinterpret_cast<NativeStringView *>(metadata + Bindings.metadataPathOffset);
    if (!path.data || !path.length) return false;
    leaf = LeafOffset(path.data, path.length);
    leafLength = path.length - leaf;
    while (leafLength && (path.data[leaf + leafLength - 1] == '/' ||
                          path.data[leaf + leafLength - 1] == '\\')) --leafLength;
    return leafLength != 0;
}

static bool IsDirectPanelChild(const NativeStringView &panelPath,
                               const NativeStringView &targetPath,
                               unsigned long long leaf) {
    unsigned long long panelLength = panelPath.length;
    while (panelLength && (panelPath.data[panelLength - 1] == '/' ||
                           panelPath.data[panelLength - 1] == '\\')) --panelLength;
    unsigned long long parentLength = leaf;
    while (parentLength && (targetPath.data[parentLength - 1] == '/' ||
                            targetPath.data[parentLength - 1] == '\\')) --parentLength;
    return StringsEqual(panelPath.data, panelLength, targetPath.data, parentLength);
}

// Mirror File Pilot's file cursor into the controller.  The native single-selection callbacks
// below turn this focus into the solid selection which drives the ordinary folder Inspector.
static bool UpdatePanelFocus(unsigned long long panel, bool &changed) {
    changed = false;
    NativeStringView panelPath = {}, targetPath = {};
    unsigned long long item = panel ? *reinterpret_cast<unsigned long long *>(
        panel + Bindings.panelFocusedItemOffset) : 0;
    unsigned long long leaf = 0, leafLength = 0;
    bool directory = false;
    if (!ReadPanelPath(panel, panelPath) || !item ||
            !ReadItemTarget(panel, item, targetPath, leaf, leafLength, directory) ||
            !IsDirectPanelChild(panelPath, targetPath, leaf)) return false;

    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    if (index == kMillerMaxColumns) {
        if (g_miller.columnCount != 0 || *reinterpret_cast<unsigned short *>(
                panel + Bindings.childFlagOffset) != 0) {
            ReleaseSpinLock(&g_miller.lock);
            return false;
        }
        unsigned long long generation = ++g_miller.generation;
        SetColumn(g_miller.columns[0], panel, generation,
                  panelPath.data, panelPath.length,
                  targetPath.data + leaf, leafLength, !directory);
        g_miller.columns[0].selectedItem = item;
        g_miller.columnCount = 1;
        index = 0;
        changed = true;
    } else {
        MillerColumn &column = g_miller.columns[index];
        bool panelChanged = !StringsEqual(column.path, column.pathLength,
                                          panelPath.data, panelPath.length);
        bool selectionChanged = column.selectedItem != item ||
            !StringsEqual(column.selected, column.selectedLength,
                          targetPath.data + leaf, leafLength);
        if (panelChanged || selectionChanged) {
            if (g_miller.columnCount > index + 1) {
                TruncateAfterIndexUnlocked(index, !directory);
            }
            column.pathLength = CopyBounded(column.path, sizeof(column.path),
                                             panelPath.data, panelPath.length);
            column.selectedLength = CopyBounded(column.selected, sizeof(column.selected),
                targetPath.data + leaf, leafLength);
            column.selectedItem = item;
            column.selectionPending = 0;
            column.suppressInspector = directory ? 0U : 1U;
            column.generation = ++g_miller.generation;
            changed = true;
        }
    }
    bool focusedDirectory = directory && !g_miller.columns[index].suppressInspector;
    ReleaseSpinLock(&g_miller.lock);
    return focusedDirectory;
}

using SelectionCancelFn = unsigned int (__fastcall *)(
    unsigned long long, unsigned long long *, int);
using ToggleCursorSelectionFn = bool (__fastcall *)(
    unsigned long long, unsigned long long *, unsigned long long, unsigned long long);

static void ApplyNativeSingleSelection(unsigned long long context,
                                       unsigned long long panel) {
    if (!context || !panel) return;
    unsigned long long argument = panel;
    reinterpret_cast<SelectionCancelFn>(Bindings.selectionCancel)(context, &argument, 2);
    reinterpret_cast<ToggleCursorSelectionFn>(Bindings.toggleCursorSelection)(
        context, &argument, 2, 0);
}

enum InspectorChildDisposition {
    kRenderNativeChild,
    kHideMillerChild,
    kRenderRecursiveChild,
};

static InspectorChildDisposition PrepareInspectorChild(unsigned long long child,
                                                        unsigned int &childIndex) {
    childIndex = kMillerMaxColumns;
    if (!child || *reinterpret_cast<unsigned short *>(
            child + Bindings.childFlagOffset) == 0) return kRenderNativeChild;
    unsigned long long owner = *reinterpret_cast<unsigned long long *>(
        child + Bindings.childOwnerOffset);
    unsigned long long ownerInspector = PanelInspector(owner);
    if (!owner || !ownerInspector || *reinterpret_cast<unsigned long long *>(
            ownerInspector + Bindings.inspectorChildOffset) != child)
        return kRenderNativeChild;

    NativeStringView path = {};
    unsigned long long selectedItem = 0, leaf = 0, leafLength = 0;
    bool directory = false;
    bool folderTarget = ReadInspectorTarget(owner, path, selectedItem, leaf, leafLength,
                                            directory) && directory;

    AcquireSpinLock(&g_miller.lock);
    unsigned int ownerIndex = FindColumnUnlocked(owner);
    if (!folderTarget) {
        if (ownerIndex != kMillerMaxColumns) {
            TruncateAfterIndexUnlocked(ownerIndex, true);
            auto linkedChild = reinterpret_cast<unsigned long long *>(
                ownerInspector + Bindings.inspectorChildOffset);
            if (*linkedChild == child) {
                *linkedChild = 0;
                PushFreePanelUnlocked(child);
            }
            ReleaseSpinLock(&g_miller.lock);
            return kHideMillerChild;
        }
        ReleaseSpinLock(&g_miller.lock);
        return kRenderNativeChild;
    }

    if (ownerIndex == kMillerMaxColumns) {
        if (g_miller.columnCount != 0 ||
                *reinterpret_cast<unsigned short *>(owner + Bindings.childFlagOffset) != 0) {
            ReleaseSpinLock(&g_miller.lock);
            return kRenderNativeChild;
        }
        unsigned long long generation = ++g_miller.generation;
        SetColumn(g_miller.columns[0], owner, generation, nullptr, 0,
                  path.data + leaf, leafLength, false);
        g_miller.columns[0].selectedItem = selectedItem;
        g_miller.columnCount = 1;
        ownerIndex = 0;
    }

    if (g_miller.columns[ownerIndex].suppressInspector) {
        TruncateAfterIndexUnlocked(ownerIndex, true);
        auto linkedChild = reinterpret_cast<unsigned long long *>(
            ownerInspector + Bindings.inspectorChildOffset);
        if (*linkedChild == child) {
            *linkedChild = 0;
            PushFreePanelUnlocked(child);
        }
        ReleaseSpinLock(&g_miller.lock);
        return kHideMillerChild;
    }

    MillerColumn &ownerColumn = g_miller.columns[ownerIndex];
    ownerColumn.selectedItem = selectedItem;
    ownerColumn.selectedLength = CopyBounded(ownerColumn.selected,
        sizeof(ownerColumn.selected), path.data + leaf, leafLength);

    if (ownerIndex + 1 >= kMillerMaxColumns) {
        ReleaseSpinLock(&g_miller.lock);
        return kRenderNativeChild;
    }
    if (g_miller.columnCount > ownerIndex + 1 &&
            g_miller.columns[ownerIndex + 1].panel != child) {
        TruncateAfterIndexUnlocked(ownerIndex, false);
    }

    childIndex = ownerIndex + 1;
    if (g_miller.columnCount <= childIndex) {
        unsigned long long generation = ++g_miller.generation;
        SetColumn(g_miller.columns[childIndex], child, generation,
                  path.data, path.length, nullptr, 0, false);
        g_miller.columnCount = childIndex + 1;
    } else {
        MillerColumn &column = g_miller.columns[childIndex];
        if (!StringsEqual(column.path, column.pathLength, path.data, path.length)) {
            TruncateAfterIndexUnlocked(childIndex, true);
            column.pathLength = CopyBounded(column.path, sizeof(column.path),
                                            path.data, path.length);
            column.selectedLength = 0;
            column.selectedItem = 0;
        }
        column.panel = child;
        column.generation = g_miller.generation;
    }
    ConfigureInspectorLayoutUnlocked();
    ReleaseSpinLock(&g_miller.lock);
    return kRenderRecursiveChild;
}

static bool ShouldProcessInspector(unsigned long long panel) {
    bool result = false;
    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    unsigned long long inspector = PanelInspector(panel);
    if (index != kMillerMaxColumns && index + 1 < g_miller.columnCount &&
            !g_miller.columns[index].suppressInspector && inspector &&
            *reinterpret_cast<int *>(inspector + Bindings.inspectorModeOffset) == 2 &&
            *reinterpret_cast<unsigned long long *>(
                inspector + Bindings.inspectorChildOffset) != 0) result = true;
    ReleaseSpinLock(&g_miller.lock);
    return result;
}

static bool UsesRecursiveSurface(unsigned long long panel) {
    bool result = false;
    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    result = index != 0 && index < g_miller.columnCount;
    ReleaseSpinLock(&g_miller.lock);
    return result;
}

static unsigned long long PanelViewportId(unsigned long long panel) {
    unsigned long long result = *reinterpret_cast<unsigned long long *>(
        panel + Bindings.panelIdentityOffset);
    const char panelName[] = "Panel";
    const char viewportName[] = "Viewport";
    for (unsigned int i = 0; i + 1 < sizeof(panelName); ++i) {
        result = result * 0x21 + static_cast<unsigned char>(panelName[i]);
    }
    for (unsigned int i = 0; i + 1 < sizeof(viewportName); ++i) {
        result = result * 0x21 + static_cast<unsigned char>(viewportName[i]);
    }
    return result;
}

static unsigned long long PanelInspectorId(unsigned long long panel) {
    unsigned long long result = *reinterpret_cast<unsigned long long *>(
        panel + Bindings.panelIdentityOffset);
    const char panelName[] = "Panel";
    const char inspectorName[] = "Inspector";
    for (unsigned int i = 0; i + 1 < sizeof(panelName); ++i) {
        result = result * 0x21 + static_cast<unsigned char>(panelName[i]);
    }
    for (unsigned int i = 0; i + 1 < sizeof(inspectorName); ++i) {
        result = result * 0x21 + static_cast<unsigned char>(inspectorName[i]);
    }
    return result;
}

static unsigned long long PanelFooterSliderButtonId(unsigned long long panel) {
    unsigned long long result = *reinterpret_cast<unsigned long long *>(
        panel + Bindings.panelIdentityOffset);
    const char panelName[] = "Panel";
    const char footerName[] = "Footer";
    const char sliderButtonName[] = "SliderButton";
    for (unsigned int i = 0; i + 1 < sizeof(panelName); ++i) {
        result = result * 0x21 + static_cast<unsigned char>(panelName[i]);
    }
    for (unsigned int i = 0; i + 1 < sizeof(footerName); ++i) {
        result = result * 0x21 + static_cast<unsigned char>(footerName[i]);
    }
    for (unsigned int i = 0; i + 1 < sizeof(sliderButtonName); ++i) {
        result = result * 0x21 + static_cast<unsigned char>(sliderButtonName[i]);
    }
    return result;
}

static unsigned long long FindExactLayoutNode(unsigned long long identifier) {
    unsigned long long node = reinterpret_cast<FindImGuiWindowFn>(
        Bindings.findImGuiWindow)(identifier);
    if (!node || *reinterpret_cast<unsigned long long *>(node + 8) != identifier) return 0;
    return node;
}

static unsigned long long CurrentLayoutContext() {
    if (!Bindings.layoutContextGlobal) return 0;
    unsigned long long layout = *reinterpret_cast<unsigned long long *>(
        Bindings.layoutContextGlobal);
    return layout;
}

static unsigned short CurrentLayoutPhase() {
    unsigned long long layout = CurrentLayoutContext();
    if (!layout) return 0xffff;
    return *reinterpret_cast<unsigned short *>(layout + Bindings.layoutPhaseOffset);
}

static unsigned long long *CurrentLayoutNodeSlot() {
    unsigned long long layout = CurrentLayoutContext();
    if (!layout) return nullptr;
    int depth = *reinterpret_cast<int *>(layout + 0xec);
    unsigned long long stack = depth ? layout + 0xf0 +
        static_cast<unsigned long long>(depth - 1) * 0x20 : layout + 0x1f0;
    return reinterpret_cast<unsigned long long *>(stack + 0x10);
}

struct LayoutStackSnapshot {
    unsigned long long *currentSlot;
    unsigned long long savedCurrent;
    unsigned int count;
    unsigned long long nodes[kMillerMaxColumns * 2];
    unsigned long long links[kMillerMaxColumns * 2];
};

static void CaptureLayoutStack(LayoutStackSnapshot &snapshot) {
    snapshot = {};
    snapshot.currentSlot = CurrentLayoutNodeSlot();
    if (!snapshot.currentSlot) return;
    snapshot.savedCurrent = *snapshot.currentSlot;
    unsigned long long sentinel = *(snapshot.currentSlot - 1);
    unsigned long long node = snapshot.savedCurrent;
    while (node && node != sentinel &&
            snapshot.count < sizeof(snapshot.nodes) / sizeof(snapshot.nodes[0])) {
        bool repeated = false;
        for (unsigned int i = 0; i < snapshot.count; ++i) {
            if (snapshot.nodes[i] == node) {
                repeated = true;
                break;
            }
        }
        if (repeated) break;
        snapshot.nodes[snapshot.count] = node;
        snapshot.links[snapshot.count] = *reinterpret_cast<unsigned long long *>(node + 0x1d8);
        node = snapshot.links[snapshot.count++];
    }
}

static void RestoreLayoutStack(const LayoutStackSnapshot &snapshot) {
    for (unsigned int i = 0; i < snapshot.count; ++i) {
        *reinterpret_cast<unsigned long long *>(snapshot.nodes[i] + 0x1d8) = snapshot.links[i];
    }
    if (snapshot.currentSlot) *snapshot.currentSlot = snapshot.savedCurrent;
}

static void RenderInspectorWithScope(unsigned long long context,
                                     unsigned long long panel,
                                     int orientation,
                                     bool nested) {
    unsigned long long previousContext = g_inspectorSurfaceContext;
    unsigned long long previousPanel = g_inspectorSurfacePanel;
    g_inspectorSurfaceContext = context;
    g_inspectorSurfacePanel = panel;
    LayoutStackSnapshot layoutSnapshot = {};
    unsigned long long *sentinelSlot = nullptr;
    unsigned long long savedSentinel = 0;
    if (nested) {
        CaptureLayoutStack(layoutSnapshot);
        if (layoutSnapshot.currentSlot) {
            sentinelSlot = layoutSnapshot.currentSlot - 1;
            savedSentinel = *sentinelSlot;
            *sentinelSlot = layoutSnapshot.savedCurrent;
        }
    }
    reinterpret_cast<InspectorRendererFn>(Bindings.inspectorRenderer)(context, panel, orientation);
    if (nested) {
        if (sentinelSlot) *sentinelSlot = savedSentinel;
        RestoreLayoutStack(layoutSnapshot);
    }
    g_inspectorSurfaceContext = previousContext;
    g_inspectorSurfacePanel = previousPanel;
}

struct RecursiveColumnTarget {
    unsigned long long childPanel;
    unsigned int childIndex;
    unsigned int childBit;
    bool hasInspectorChild;
};

static bool PrepareRecursiveColumnTarget(unsigned long long ownerPanel,
                                         unsigned long long expectedChild,
                                         bool requirePhase0Construction,
                                         RecursiveColumnTarget &target) {
    target = {};
    if (!ownerPanel || g_recursiveSurfaceDepth >= kMillerMaxColumns) return false;

    AcquireSpinLock(&g_miller.lock);
    unsigned int ownerIndex = FindColumnUnlocked(ownerPanel);
    if (ownerIndex != kMillerMaxColumns && ownerIndex + 1 < g_miller.columnCount &&
            !g_miller.columns[ownerIndex].suppressInspector) {
        unsigned long long inspector = PanelInspector(ownerPanel);
        unsigned long long childPanel = inspector ? *reinterpret_cast<unsigned long long *>(
            inspector + Bindings.inspectorChildOffset) : 0;
        unsigned int childIndex = ownerIndex + 1;
        unsigned int childBit = 1U << childIndex;
        if (childPanel && childPanel == g_miller.columns[childIndex].panel &&
                (!expectedChild || expectedChild == childPanel) &&
                (!requirePhase0Construction || (g_constructedColumnMask & childBit) != 0) &&
                ConfigureColumnSurfaceUnlocked(childIndex)) {
            target.childPanel = childPanel;
            target.childIndex = childIndex;
            target.childBit = childBit;
            if (childIndex + 1 < g_miller.columnCount) {
                unsigned long long childInspector = PanelInspector(childPanel);
                target.hasInspectorChild = childInspector &&
                    *reinterpret_cast<int *>(childInspector + Bindings.inspectorModeOffset) == 2 &&
                    *reinterpret_cast<unsigned long long *>(
                        childInspector + Bindings.inspectorChildOffset) ==
                            g_miller.columns[childIndex + 1].panel;
            }
        }
    }
    ReleaseSpinLock(&g_miller.lock);
    return target.childPanel != 0;
}

// A full panel surface owns an internal layout root and cannot be nested: doing so links that root
// back to the active Inspector and creates a cycle in File Pilot's +0x1d8 stack chain. Construct
// only the components Miller needs, directly under the active Inspector node. The Footer is not
// cosmetic: the child-content renderer resolves Panel/Footer/SliderButton to derive its clip and
// horizontal extent, so omitting it makes every descendant paint across the remaining subtree.
static bool ConstructNextMillerColumn(unsigned long long context,
                                      unsigned long long ownerPanel) {
    if (!context) return false;
    RecursiveColumnTarget target = {};
    if (!PrepareRecursiveColumnTarget(ownerPanel, 0, false, target)) return false;

    auto childMarker = reinterpret_cast<unsigned short *>(
        target.childPanel + Bindings.childFlagOffset);
    unsigned short savedMarker = *childMarker;
    *childMarker = 0;
    ++g_recursiveSurfaceDepth;
    LayoutStackSnapshot layoutSnapshot = {};
    CaptureLayoutStack(layoutSnapshot);
    unsigned int inset = static_cast<unsigned int>(
        *reinterpret_cast<int *>(context + 0xa60) + 2);
    reinterpret_cast<PanelFooterRendererFn>(Bindings.panelFooterRenderer)(
        context, target.childPanel, inset);
    RestoreLayoutStack(layoutSnapshot);
    CaptureLayoutStack(layoutSnapshot);
    reinterpret_cast<PanelRendererFn>(Bindings.panelViewportRenderer)(context, target.childPanel);
    RestoreLayoutStack(layoutSnapshot);
    if (target.hasInspectorChild) RenderInspectorWithScope(context, target.childPanel, 1, true);
    --g_recursiveSurfaceDepth;
    *childMarker = savedMarker;
    g_constructedColumnMask |= target.childBit;
    ++MillerDebug.recursiveFrames;
    return true;
}

static void SetLayoutNodeRectangle(unsigned long long node,
                                   int left, int top, int right, int bottom) {
    if (!node) return;
    auto size = reinterpret_cast<int *>(node + 0x268);
    auto rectangle = reinterpret_cast<int *>(node + 0x270);
    auto visibleRectangle = reinterpret_cast<int *>(node + 0x290);
    size[0] = right > left ? right - left : 0;
    size[1] = bottom > top ? bottom - top : 0;
    rectangle[0] = visibleRectangle[0] = left;
    rectangle[1] = visibleRectangle[1] = top;
    rectangle[2] = visibleRectangle[2] = right;
    rectangle[3] = visibleRectangle[3] = bottom;
}

static void ApplyRecursiveNodeRectangles(unsigned long long context) {
    unsigned long long panels[kMillerMaxColumns] = {};
    unsigned int count = 0;
    AcquireSpinLock(&g_miller.lock);
    count = g_miller.columnCount;
    for (unsigned int i = 0; i < count; ++i) panels[i] = g_miller.columns[i].panel;
    ReleaseSpinLock(&g_miller.lock);
    if (count < 2 || !panels[0]) return;

    unsigned long long rootInspector = FindExactLayoutNode(PanelInspectorId(panels[0]));
    if (!rootInspector) return;
    auto rootRectangle = reinterpret_cast<int *>(rootInspector + 0x290);
    int left = rootRectangle[0];
    int top = rootRectangle[1];
    int right = rootRectangle[2];
    int bottom = rootRectangle[3];
    if (right <= left || bottom <= top) return;
    int inset = *reinterpret_cast<int *>(context + 0xa60) + 2;
    int viewportTop = top + inset;
    int viewportBottom = bottom - inset;
    if (viewportBottom < viewportTop) viewportBottom = viewportTop;
    int totalWidth = right - left;
    unsigned int descendantCount = count - 1;

    for (unsigned int i = 1; i < count; ++i) {
        int columnRight = i + 1 == count ? right :
            rootRectangle[0] + totalWidth * static_cast<int>(i) /
                static_cast<int>(descendantCount);
        SetLayoutNodeRectangle(FindExactLayoutNode(PanelViewportId(panels[i])),
                               left, viewportTop, columnRight, viewportBottom);
        SetLayoutNodeRectangle(FindExactLayoutNode(PanelFooterSliderButtonId(panels[i])),
                               left, viewportBottom, columnRight, bottom);
        if (i + 1 < count) {
            SetLayoutNodeRectangle(FindExactLayoutNode(PanelInspectorId(panels[i])),
                                   columnRight, top, right, bottom);
        }
        left = columnRight;
    }
}

static bool PaintNextMillerColumn(unsigned long long context,
                                  unsigned long long ownerPanel,
                                  unsigned long long expectedChild,
                                  unsigned long long parentInspectorWindow) {
    if (!context) return false;
    RecursiveColumnTarget target = {};
    if (!PrepareRecursiveColumnTarget(ownerPanel, expectedChild, true, target)) return false;
    unsigned long long viewport = FindExactLayoutNode(PanelViewportId(target.childPanel));
    if (!viewport || !parentInspectorWindow) return false;
    unsigned long long childInspectorWindow = target.hasInspectorChild ?
        FindExactLayoutNode(PanelInspectorId(target.childPanel)) : 0;
    bool paintInspector = childInspectorWindow != 0;

    auto parentRectangle = reinterpret_cast<int *>(parentInspectorWindow + 0x290);
    int parentLeft = parentRectangle[0];
    int parentTop = parentRectangle[1];
    int parentRight = parentRectangle[2];
    int parentBottom = parentRectangle[3];
    unsigned int remainingColumns = 0;
    AcquireSpinLock(&g_miller.lock);
    if (target.childIndex < g_miller.columnCount) {
        remainingColumns = g_miller.columnCount - target.childIndex;
    }
    ReleaseSpinLock(&g_miller.lock);
    if (!remainingColumns || parentRight <= parentLeft || parentBottom <= parentTop) return false;
    int columnRight = parentLeft + (parentRight - parentLeft) /
        static_cast<int>(remainingColumns);
    if (remainingColumns == 1 || columnRight <= parentLeft) columnRight = parentRight;
    int verticalInset = *reinterpret_cast<int *>(context + 0xa60) + 2;
    int viewportTop = parentTop + verticalInset;
    int viewportBottom = parentBottom - verticalInset;
    if (viewportBottom < viewportTop) viewportBottom = viewportTop;

    SetLayoutNodeRectangle(viewport, parentLeft, viewportTop, columnRight, viewportBottom);
    SetLayoutNodeRectangle(
        FindExactLayoutNode(PanelFooterSliderButtonId(target.childPanel)),
        parentLeft, viewportBottom, columnRight, parentBottom);
    if (paintInspector) {
        SetLayoutNodeRectangle(
            childInspectorWindow, columnRight, parentTop, parentRight, parentBottom);
    }

    auto childMarker = reinterpret_cast<unsigned short *>(
        target.childPanel + Bindings.childFlagOffset);
    unsigned short savedMarker = *childMarker;
    *childMarker = 0;
    ++g_recursiveSurfaceDepth;
    LayoutStackSnapshot layoutSnapshot = {};
    CaptureLayoutStack(layoutSnapshot);
    unsigned long long container = *reinterpret_cast<unsigned long long *>(
        target.childPanel + Bindings.panelContainerOffset);
    float savedContainerRectangle[4] = {};
    float *containerRectangle = container ? reinterpret_cast<float *>(container + 0x38) : nullptr;
    if (containerRectangle) {
        for (unsigned int i = 0; i < 4; ++i) savedContainerRectangle[i] = containerRectangle[i];
        containerRectangle[0] = static_cast<float>(parentLeft);
        containerRectangle[1] = static_cast<float>(parentTop);
        containerRectangle[2] = static_cast<float>(columnRight);
        containerRectangle[3] = static_cast<float>(parentBottom);
    }
    reinterpret_cast<InspectorChildSurfaceRendererFn>(
        Bindings.inspectorChildSurfaceRenderer)(context, target.childPanel, viewport);
    if (containerRectangle) {
        for (unsigned int i = 0; i < 4; ++i) containerRectangle[i] = savedContainerRectangle[i];
    }
    RestoreLayoutStack(layoutSnapshot);
    if (paintInspector) RenderInspectorWithScope(context, target.childPanel, 1, true);
    --g_recursiveSurfaceDepth;
    *childMarker = savedMarker;
    ++MillerDebug.recursiveFrames;
    return true;
}

static bool QueueMillerFolderActivation(unsigned long long panel,
                                        unsigned long long selectedItem) {
    if (!panel || !selectedItem || *reinterpret_cast<unsigned short *>(
            panel + Bindings.childFlagOffset) == 0) return false;
    NativeStringView path = {};
    unsigned long long leaf = 0, leafLength = 0;
    bool directory = false;
    if (!ReadItemTarget(panel, selectedItem, path, leaf, leafLength, directory) || !directory)
        return false;

    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    if (index == kMillerMaxColumns) {
        ReleaseSpinLock(&g_miller.lock);
        return false;
    }
    if (g_miller.columnCount > index + 2) {
        TruncateAfterIndexUnlocked(index + 1, true);
    }
    MillerColumn &column = g_miller.columns[index];
    column.selectedItem = selectedItem;
    column.selectedLength = CopyBounded(column.selected, sizeof(column.selected),
                                         path.data + leaf, leafLength);
    column.suppressInspector = 0;
    column.selectionPending = 1;
    column.selectionAttempts = 0;
    column.generation = ++g_miller.generation;
    ReleaseSpinLock(&g_miller.lock);
    return true;
}

static void RecordNativeSelection(unsigned long long panel, unsigned long long selectedItem) {
    NativeStringView path = {};
    unsigned long long leaf = 0, leafLength = 0;
    bool directory = false;
    if (!ReadItemTarget(panel, selectedItem, path, leaf, leafLength, directory)) return;
    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    if (index != kMillerMaxColumns) {
        MillerColumn &column = g_miller.columns[index];
        bool changed = column.selectedItem != selectedItem ||
            !StringsEqual(column.selected, column.selectedLength,
                          path.data + leaf, leafLength);
        if (changed) {
            column.selectedItem = selectedItem;
            column.selectedLength = CopyBounded(column.selected, sizeof(column.selected),
                                                 path.data + leaf, leafLength);
            if (!directory && g_miller.columnCount > index + 1) {
                TruncateAfterIndexUnlocked(index, true);
            } else if (directory) {
                column.suppressInspector = 0;
            }
        }
    }
    ReleaseSpinLock(&g_miller.lock);
}

static bool ShouldHighlightItem(unsigned long long panel, unsigned long long item) {
    NativeStringView path = {};
    unsigned long long leaf = 0, leafLength = 0;
    bool directory = false;
    bool hasPath = ReadItemTarget(panel, item, path, leaf, leafLength, directory);
    bool result = false;
    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    if (index != kMillerMaxColumns) {
        MillerColumn &column = g_miller.columns[index];
        result = column.selectedLength && (column.selectedItem == item ||
            (hasPath && StringsEqual(column.selected, column.selectedLength,
                                     path.data + leaf, leafLength)));
    }
    ReleaseSpinLock(&g_miller.lock);
    return result;
}

static void BeforePanelNavigation(unsigned long long panel, bool suppressPanelInspector) {
    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    if (index != kMillerMaxColumns) {
        TruncateAfterIndexUnlocked(index, suppressPanelInspector);
        MillerColumn &column = g_miller.columns[index];
        column.pathLength = 0;
        column.path[0] = 0;
        column.selectedLength = 0;
        column.selected[0] = 0;
        column.selectedItem = 0;
        column.selectionPending = 0;
    }
    ReleaseSpinLock(&g_miller.lock);
}

static void ReattachPooledChild(unsigned long long panel) {
    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    unsigned long long inspector = PanelInspector(panel);
    if (index != kMillerMaxColumns && inspector &&
            !g_miller.columns[index].suppressInspector && g_miller.freeCount) {
        auto child = reinterpret_cast<unsigned long long *>(
            inspector + Bindings.inspectorChildOffset);
        if (!*child) {
            unsigned long long reused = g_miller.freePanels[--g_miller.freeCount];
            g_miller.freePanels[g_miller.freeCount] = 0;
            *child = reused;
            *reinterpret_cast<unsigned long long *>(
                reused + Bindings.childOwnerOffset) = panel;
            *reinterpret_cast<unsigned short *>(
                reused + Bindings.childFlagOffset) = 1;
        }
    }
    ReleaseSpinLock(&g_miller.lock);
}

static void DiscardSuppressedChild(unsigned long long panel) {
    AcquireSpinLock(&g_miller.lock);
    unsigned int index = FindColumnUnlocked(panel);
    unsigned long long inspector = PanelInspector(panel);
    if (index != kMillerMaxColumns && inspector &&
            g_miller.columns[index].suppressInspector) {
        auto child = reinterpret_cast<unsigned long long *>(
            inspector + Bindings.inspectorChildOffset);
        if (*child) {
            unsigned long long discarded = *child;
            *child = 0;
            if (g_miller.columnCount > index + 1 &&
                    g_miller.columns[index + 1].panel == discarded) {
                TruncateAfterIndexUnlocked(index, true);
            } else {
                PushFreePanelUnlocked(discarded);
            }
        }
    }
    ReleaseSpinLock(&g_miller.lock);
}

static void ApplyMillerNavigation(unsigned long long context) {
    for (unsigned int i = 0; i < kMillerMaxColumns; ++i) {
        unsigned long long panel = 0, nameLength = 0, generation = 0;
        AcquireSpinLock(&g_miller.lock);
        if (i < g_miller.columnCount && g_miller.columns[i].selectionPending) {
            MillerColumn &column = g_miller.columns[i];
            panel = column.panel;
            generation = column.generation;
            nameLength = CopyBounded(g_millerWorkName, sizeof(g_millerWorkName), column.selected,
                                     column.selectedLength);
        }
        ReleaseSpinLock(&g_miller.lock);
        if (!panel || !nameLength) continue;

        bool selected = TryApplyNamedSelection(panel, g_millerWorkName, nameLength);
        if (selected) ApplyNativeSingleSelection(context, panel);
        AcquireSpinLock(&g_miller.lock);
        unsigned int current = FindColumnUnlocked(panel);
        if (current != kMillerMaxColumns &&
                g_miller.columns[current].generation == generation) {
            MillerColumn &column = g_miller.columns[current];
            if (selected || ++column.selectionAttempts >= 0x1000) {
                column.selectionPending = 0;
            }
        }
        ReleaseSpinLock(&g_miller.lock);
    }
}

class ShellView final : public IShellView {
public:
    volatile LONG refs = 1;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (GuidEqual(iid, kIidIUnknown) || GuidEqual(iid, kIidIOleWindow) || GuidEqual(iid, kIidIShellView))
            *out = static_cast<IShellView *>(this);
        if (!*out) return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(_InterlockedIncrement(&refs)); }
    ULONG STDMETHODCALLTYPE Release() override { return static_cast<ULONG>(_InterlockedDecrement(&refs)); }
    HRESULT STDMETHODCALLTYPE GetWindow(HWND *out) override { if (!out) return E_POINTER; *out = g_hwnd; return S_OK; }
    HRESULT STDMETHODCALLTYPE ContextSensitiveHelp(BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE TranslateAccelerator(MSG *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EnableModeless(BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE UIActivate(UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Refresh() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CreateViewWindow(IShellView *, LPCFOLDERSETTINGS, IShellBrowser *, RECT *, HWND *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DestroyViewWindow() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCurrentInfo(LPFOLDERSETTINGS) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE AddPropertySheetPages(DWORD, LPFNSVADDPROPSHEETPAGE, LPARAM) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SaveViewState() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SelectItem(PCUITEMID_CHILD child, SVSIF flags) override {
        if (flags & SVSI_SELECT) { PublishSelection(child); return S_OK; }
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetItemObject(UINT, REFIID, void **) override { return E_NOTIMPL; }
};

class Document final : public IDispatch, public IServiceProvider {
public:
    volatile LONG refs = 1;
    ShellView *view = nullptr;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (GuidEqual(iid, kIidIUnknown) || GuidEqual(iid, kIidIDispatch)) *out = static_cast<IDispatch *>(this);
        else if (GuidEqual(iid, kIidIServiceProvider)) *out = static_cast<IServiceProvider *>(this);
        if (!*out) return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(_InterlockedIncrement(&refs)); }
    ULONG STDMETHODCALLTYPE Release() override { return static_cast<ULONG>(_InterlockedDecrement(&refs)); }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT *n) override { if (n) *n = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo **) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR *, UINT, LCID, DISPID *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE QueryService(REFGUID service, REFIID iid, void **out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (GuidEqual(service, kIidIFolderView) && view) return view->QueryInterface(iid, out);
        return E_NOINTERFACE;
    }
};

class Browser final : public IWebBrowserApp {
public:
    volatile LONG refs = 1;
    Document *document = nullptr;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (GuidEqual(iid, kIidIUnknown) || GuidEqual(iid, kIidIDispatch) ||
            GuidEqual(iid, kIidIWebBrowser) || GuidEqual(iid, kIidIWebBrowserApp))
            *out = static_cast<IWebBrowserApp *>(this);
        if (!*out) return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(_InterlockedIncrement(&refs)); }
    ULONG STDMETHODCALLTYPE Release() override { return static_cast<ULONG>(_InterlockedDecrement(&refs)); }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT *n) override { if (n) *n = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo **) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR *, UINT, LCID, DISPID *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GoBack() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GoForward() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GoHome() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GoSearch() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Navigate(BSTR, VARIANT *, VARIANT *, VARIANT *, VARIANT *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Refresh() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Refresh2(VARIANT *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Stop() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Application(IDispatch **) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Parent(IDispatch **) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Container(IDispatch **) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Document(IDispatch **out) override {
        if (!out || !document) return E_POINTER;
        *out = static_cast<IDispatch *>(document); document->AddRef(); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_TopLevelContainer(VARIANT_BOOL *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Type(BSTR *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Left(long *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_Left(long) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Top(long *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_Top(long) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Width(long *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_Width(long) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Height(long *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_Height(long) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_LocationName(BSTR *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_LocationURL(BSTR *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Busy(VARIANT_BOOL *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Quit() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE ClientToWindow(int *, int *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE PutProperty(BSTR, VARIANT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetProperty(BSTR, VARIANT *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Name(BSTR *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_HWND(SHANDLE_PTR *out) override { if (!out) return E_POINTER; *out = reinterpret_cast<SHANDLE_PTR>(g_hwnd); return S_OK; }
    HRESULT STDMETHODCALLTYPE get_FullName(BSTR *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Path(BSTR *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Visible(VARIANT_BOOL *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_Visible(VARIANT_BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_StatusBar(VARIANT_BOOL *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_StatusBar(VARIANT_BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_StatusText(BSTR *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_StatusText(BSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_ToolBar(int *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_ToolBar(int) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_MenuBar(VARIANT_BOOL *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_MenuBar(VARIANT_BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_FullScreen(VARIANT_BOOL *) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE put_FullScreen(VARIANT_BOOL) override { return E_NOTIMPL; }
};

alignas(ShellView) static unsigned char g_viewStorage[sizeof(ShellView)];
alignas(Document) static unsigned char g_documentStorage[sizeof(Document)];
alignas(Browser) static unsigned char g_browserStorage[sizeof(Browser)];
static IShellWindows *g_shellWindows;
static long g_cookies[2];
static unsigned long long g_cookieCount;

using InitVariantFromBufferFn = HRESULT (WINAPI *)(const void *, UINT, VARIANT *);

static UINT PidlSize(PCUIDLIST_ABSOLUTE pidl) {
    if (!pidl) return 0;
    UINT size = 2;
    for (auto p = pidl; p->mkid.cb;
        p = reinterpret_cast<PCUIDLIST_ABSOLUTE>(
            reinterpret_cast<const BYTE *>(p) + p->mkid.cb)) {
        size += p->mkid.cb;
    }
    return size;
}

static bool PidlsByteEqual(PCUIDLIST_ABSOLUTE first, PCUIDLIST_ABSOLUTE second) {
    UINT firstSize = PidlSize(first);
    UINT secondSize = PidlSize(second);
    if (!firstSize || firstSize != secondSize) return false;
    auto firstBytes = reinterpret_cast<const BYTE *>(first);
    auto secondBytes = reinterpret_cast<const BYTE *>(second);
    for (UINT i = 0; i < firstSize; ++i) {
        if (firstBytes[i] != secondBytes[i]) return false;
    }
    return true;
}

static PIDLIST_ABSOLUTE ParseWithDesktopFolder(const wchar_t *path) {
    using SHGetDesktopFolderFn = HRESULT (WINAPI *)(IShellFolder **);
    HMODULE shell32 = pLoadLibraryW()(L"shell32.dll");
    if (!shell32) return nullptr;
    auto getDesktopFolder = reinterpret_cast<SHGetDesktopFolderFn>(
        pGetProcAddress()(shell32, "SHGetDesktopFolder"));
    if (!getDesktopFolder) return nullptr;

    IShellFolder *desktop = nullptr;
    if (FAILED(getDesktopFolder(&desktop)) || !desktop) return nullptr;
    PIDLIST_RELATIVE parsed = nullptr;
    HRESULT hr = desktop->ParseDisplayName(nullptr, nullptr, const_cast<wchar_t *>(path),
        nullptr, &parsed, nullptr);
    desktop->Release();
    if (FAILED(hr)) return nullptr;
    return reinterpret_cast<PIDLIST_ABSOLUTE>(parsed);
}

static bool RegisterShellWindowAlias(PCUIDLIST_ABSOLUTE pidl, IDispatch *browser,
    InitVariantFromBufferFn initVariant) {
    if (!pidl || !browser || !initVariant || !g_shellWindows) return false;

    VARIANT pidlVariant = {};
    VARIANT empty = {};
    if (FAILED(initVariant(pidl, PidlSize(pidl), &pidlVariant))) return false;

    long pendingCookie = 0;
    HRESULT hr = g_shellWindows->RegisterPending(pGetCurrentThreadId()(), &pidlVariant,
        &empty, SWC_BROWSER, &pendingCookie);
    if (SUCCEEDED(hr)) {
        long registeredCookie = 0;
        hr = g_shellWindows->Register(browser,
            static_cast<long>(reinterpret_cast<LONG_PTR>(g_hwnd)), SWC_BROWSER,
            &registeredCookie);
        if (SUCCEEDED(hr)) {
            if (g_cookieCount < sizeof(g_cookies) / sizeof(g_cookies[0])) {
                g_cookies[g_cookieCount++] = registeredCookie;
            }
            g_shellWindows->OnNavigate(registeredCookie, &pidlVariant);
        } else {
            g_shellWindows->Revoke(pendingCookie);
        }
    }
    pPropVariantClear()(reinterpret_cast<PROPVARIANT *>(&pidlVariant));
    return SUCCEEDED(hr);
}

using GetCurrentProcessIdFn = DWORD (WINAPI *)();
using EnumWindowsFn = BOOL (WINAPI *)(WNDENUMPROC, LPARAM);
using GetWindowThreadProcessIdFn = DWORD (WINAPI *)(HWND, LPDWORD);
using IsWindowVisibleFn = BOOL (WINAPI *)(HWND);
using GetWindowFn = HWND (WINAPI *)(HWND, UINT);

struct WindowSearch {
    DWORD processId;
    GetWindowThreadProcessIdFn getWindowThreadProcessId;
    IsWindowVisibleFn isWindowVisible;
    GetWindowFn getWindow;
    HWND result;
};

static BOOL CALLBACK FindMainWindowCallback(HWND hwnd, LPARAM parameter) {
    auto *search = reinterpret_cast<WindowSearch *>(parameter);
    DWORD processId = 0;
    search->getWindowThreadProcessId(hwnd, &processId);
    if (processId == search->processId && search->isWindowVisible(hwnd)
        && !search->getWindow(hwnd, GW_OWNER)) {
        search->result = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND FindMainWindow() {
    HMODULE kernel32 = pLoadLibraryW()(L"kernel32.dll");
    HMODULE user32 = pLoadLibraryW()(L"user32.dll");
    if (!kernel32 || !user32) return nullptr;
    auto getCurrentProcessId = reinterpret_cast<GetCurrentProcessIdFn>(
        pGetProcAddress()(kernel32, "GetCurrentProcessId"));
    auto enumWindows = reinterpret_cast<EnumWindowsFn>(
        pGetProcAddress()(user32, "EnumWindows"));
    auto getWindowThreadProcessId = reinterpret_cast<GetWindowThreadProcessIdFn>(
        pGetProcAddress()(user32, "GetWindowThreadProcessId"));
    auto isWindowVisible = reinterpret_cast<IsWindowVisibleFn>(
        pGetProcAddress()(user32, "IsWindowVisible"));
    auto getWindow = reinterpret_cast<GetWindowFn>(pGetProcAddress()(user32, "GetWindow"));
    if (!getCurrentProcessId || !enumWindows || !getWindowThreadProcessId
        || !isWindowVisible || !getWindow) return nullptr;

    WindowSearch search = {getCurrentProcessId(), getWindowThreadProcessId,
        isWindowVisible, getWindow, nullptr};
    enumWindows(FindMainWindowCallback, reinterpret_cast<LPARAM>(&search));
    return search.result;
}

// File Pilot implements every top-level window as a separate process. Native tab moves therefore
// cannot cross the window boundary: command 0x58 carries process-local panel and tab pointers.
// The tab-specific bridge in .fpt calls CrossWindowTryTransfer after File Pilot has serialized the
// dragged panel but before it queues the normal CreateProcess worker. A synchronous WM_COPYDATA
// round trip gives the receiving UI thread a private JSON copy and lets the sender fall back to the
// stock tear-off path when the target is unpatched, busy, or rejects the transfer.
static constexpr ULONG_PTR kCrossWindowMagic = 0x33545046; // "FPT3"
static constexpr DWORD_PTR kCrossWindowAck = 0x334b4f46;   // "FOK3"
static constexpr unsigned int kCrossWindowVersion = 1;
static constexpr unsigned int kCrossWindowMaxJson = 16 * 1024 * 1024;
static constexpr unsigned int kPanelStateSize = 0x1d8;
static constexpr ULONG_PTR kPreviewMagic = 0x56545046;     // "FPTV"
static constexpr DWORD_PTR kPreviewAck = 0x4b505446;       // "FTPK"
static constexpr unsigned int kPreviewVersion = 1;
static constexpr UINT kPreviewMessage = WM_APP + 0x51a;
static constexpr unsigned int kPreviewUpdate = 1;
static constexpr unsigned int kPreviewEnd = 2;
static constexpr unsigned int kPreviewCopy = 1;
static constexpr ULONGLONG kPreviewFreshMilliseconds = 250;

struct CrossWindowHeader {
    unsigned int magic;
    unsigned short version;
    unsigned short headerSize;
    unsigned int jsonBytes;
    int cursorX;
    int cursorY;
    unsigned int sourceProcessId;
    unsigned int flags;
    unsigned int reserved;
};

static_assert(sizeof(CrossWindowHeader) == 0x20, "cross-window header layout changed");

struct PreviewBeginHeader {
    unsigned int magic;
    unsigned short version;
    unsigned short headerSize;
    unsigned int session;
    unsigned int sourceProcessId;
    int cursorX;
    int cursorY;
    unsigned int flags;
    unsigned int reserved;
};

static_assert(sizeof(PreviewBeginHeader) == 0x20, "preview header layout changed");

using GetClassNameWFn = int (WINAPI *)(HWND, LPWSTR, int);
using GetWindowRectFn = BOOL (WINAPI *)(HWND, LPRECT);
using ScreenToClientFn = BOOL (WINAPI *)(HWND, LPPOINT);
using WindowFromPointFn = HWND (WINAPI *)(POINT);
using GetAncestorFn = HWND (WINAPI *)(HWND, UINT);
using SetWindowLongPtrWFn = LONG_PTR (WINAPI *)(HWND, int, LONG_PTR);
using CallWindowProcWFn = LRESULT (WINAPI *)(WNDPROC, HWND, UINT, WPARAM, LPARAM);
using SendMessageTimeoutWFn = LRESULT (WINAPI *)(HWND, UINT, WPARAM, LPARAM,
                                                  UINT, UINT, PDWORD_PTR);
using VirtualAllocFn = LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualFreeFn = BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD);
using GetCursorPosFn = BOOL (WINAPI *)(LPPOINT);
using GetKeyStateFn = SHORT (WINAPI *)(int);
using GetTickCount64Fn = ULONGLONG (WINAPI *)();

struct CrossWindowApis {
    GetCurrentProcessIdFn getCurrentProcessId;
    EnumWindowsFn enumWindows;
    GetWindowThreadProcessIdFn getWindowThreadProcessId;
    IsWindowVisibleFn isWindowVisible;
    GetClassNameWFn getClassNameW;
    GetWindowRectFn getWindowRect;
    ScreenToClientFn screenToClient;
    WindowFromPointFn windowFromPoint;
    GetAncestorFn getAncestor;
    SetWindowLongPtrWFn setWindowLongPtrW;
    CallWindowProcWFn callWindowProcW;
    SendMessageTimeoutWFn sendMessageTimeoutW;
    VirtualAllocFn virtualAlloc;
    VirtualFreeFn virtualFree;
    GetCursorPosFn getCursorPos;
    GetKeyStateFn getKeyState;
    GetTickCount64Fn getTickCount64;
    bool ready;
};

static CrossWindowApis g_crossWindowApis = {};
static volatile unsigned long long g_filePilotApp;
static HWND g_crossWindowHwnd;
static WNDPROC g_originalWindowProc;
static HWND g_previewTarget;
static HWND g_previewRejectedTarget;
static unsigned int g_previewSession;
static volatile long g_previewSessionCounter;
static ULONGLONG g_previewRetryAfter;
static ULONGLONG g_previewLastPulse;
static ULONGLONG g_previewLastSurfacePulse;
static volatile long g_sourceTabDragActive;

struct RemotePreviewState {
    bool active;
    bool destinationValid;
    HWND source;
    DWORD sourceProcessId;
    unsigned int session;
    unsigned int flags;
    POINT screenPoint;
    ULONGLONG lastUpdate;
    unsigned long long destinationGroup;
    unsigned long long destinationBefore;
    unsigned int destinationOrientation;
    unsigned int destinationPlacement;
    POINT destinationPoint;
    ULONGLONG destinationTick;
};

static RemotePreviewState g_remotePreview = {};
__declspec(align(16)) static unsigned char g_remoteTabSentinel[0x700] = {};
static bool IsRemotePreviewFresh();

extern "C" __declspec(dllexport) bool __fastcall RemoteTabHoverHook(
    unsigned long long *itemState) {
    using OriginalFn = bool (__fastcall *)(unsigned long long *);
    bool remoteDrag = Bindings.tabIntegrationEnabled && g_filePilotApp
        && *reinterpret_cast<unsigned long long *>(g_filePilotApp + 0xea8)
            == reinterpret_cast<unsigned long long>(g_remoteTabSentinel)
        && IsRemotePreviewFresh();
    return remoteDrag ? true
        : reinterpret_cast<OriginalFn>(Bindings.originalTabHoverTest)(itemState);
}

struct CrossWindowPreviewDebugState {
    unsigned long long beginsReceived;
    unsigned long long updatesReceived;
    unsigned long long surfaceCalls;
    unsigned long long destinationsCaptured;
    unsigned long long dropsUsingPreview;
    unsigned long long dropsUsingFallback;
    unsigned long long lastSession;
    unsigned long long lastGroup;
    unsigned long long lastBefore;
    unsigned long long lastPlacement;
    unsigned long long sourceDragFrames;
    unsigned long long sourceTargetsFound;
    unsigned long long beginAttempts;
    unsigned long long beginAccepted;
    unsigned long long updatesSent;
    unsigned long long lastFrameGeneration;
    unsigned long long lastSavedSurfaceGeneration;
};

extern "C" __declspec(dllexport) volatile CrossWindowPreviewDebugState
    CrossWindowPreviewDebug = {};

static bool ResolveCrossWindowApis() {
    if (g_crossWindowApis.ready) return true;
    HMODULE kernel32 = pLoadLibraryW()(L"kernel32.dll");
    HMODULE user32 = pLoadLibraryW()(L"user32.dll");
    if (!kernel32 || !user32) return false;

    g_crossWindowApis.getCurrentProcessId = reinterpret_cast<GetCurrentProcessIdFn>(
        pGetProcAddress()(kernel32, "GetCurrentProcessId"));
    g_crossWindowApis.virtualAlloc = reinterpret_cast<VirtualAllocFn>(
        pGetProcAddress()(kernel32, "VirtualAlloc"));
    g_crossWindowApis.virtualFree = reinterpret_cast<VirtualFreeFn>(
        pGetProcAddress()(kernel32, "VirtualFree"));
    g_crossWindowApis.getTickCount64 = reinterpret_cast<GetTickCount64Fn>(
        pGetProcAddress()(kernel32, "GetTickCount64"));
    g_crossWindowApis.enumWindows = reinterpret_cast<EnumWindowsFn>(
        pGetProcAddress()(user32, "EnumWindows"));
    g_crossWindowApis.getWindowThreadProcessId = reinterpret_cast<GetWindowThreadProcessIdFn>(
        pGetProcAddress()(user32, "GetWindowThreadProcessId"));
    g_crossWindowApis.isWindowVisible = reinterpret_cast<IsWindowVisibleFn>(
        pGetProcAddress()(user32, "IsWindowVisible"));
    g_crossWindowApis.getClassNameW = reinterpret_cast<GetClassNameWFn>(
        pGetProcAddress()(user32, "GetClassNameW"));
    g_crossWindowApis.getWindowRect = reinterpret_cast<GetWindowRectFn>(
        pGetProcAddress()(user32, "GetWindowRect"));
    g_crossWindowApis.screenToClient = reinterpret_cast<ScreenToClientFn>(
        pGetProcAddress()(user32, "ScreenToClient"));
    g_crossWindowApis.windowFromPoint = reinterpret_cast<WindowFromPointFn>(
        pGetProcAddress()(user32, "WindowFromPoint"));
    g_crossWindowApis.getAncestor = reinterpret_cast<GetAncestorFn>(
        pGetProcAddress()(user32, "GetAncestor"));
    g_crossWindowApis.setWindowLongPtrW = reinterpret_cast<SetWindowLongPtrWFn>(
        pGetProcAddress()(user32, "SetWindowLongPtrW"));
    g_crossWindowApis.callWindowProcW = reinterpret_cast<CallWindowProcWFn>(
        pGetProcAddress()(user32, "CallWindowProcW"));
    g_crossWindowApis.sendMessageTimeoutW = reinterpret_cast<SendMessageTimeoutWFn>(
        pGetProcAddress()(user32, "SendMessageTimeoutW"));
    g_crossWindowApis.getCursorPos = reinterpret_cast<GetCursorPosFn>(
        pGetProcAddress()(user32, "GetCursorPos"));
    g_crossWindowApis.getKeyState = reinterpret_cast<GetKeyStateFn>(
        pGetProcAddress()(user32, "GetKeyState"));
    g_crossWindowApis.ready = g_crossWindowApis.getCurrentProcessId
        && g_crossWindowApis.virtualAlloc && g_crossWindowApis.virtualFree
        && g_crossWindowApis.enumWindows && g_crossWindowApis.getWindowThreadProcessId
        && g_crossWindowApis.isWindowVisible && g_crossWindowApis.getClassNameW
        && g_crossWindowApis.getWindowRect && g_crossWindowApis.screenToClient
        && g_crossWindowApis.windowFromPoint && g_crossWindowApis.getAncestor
        && g_crossWindowApis.setWindowLongPtrW && g_crossWindowApis.callWindowProcW
        && g_crossWindowApis.sendMessageTimeoutW && g_crossWindowApis.getCursorPos
        && g_crossWindowApis.getKeyState && g_crossWindowApis.getTickCount64;
    return g_crossWindowApis.ready;
}

static bool IsFilePilotWindow(HWND hwnd, DWORD *processId = nullptr) {
    if (!hwnd || !ResolveCrossWindowApis()) return false;
    wchar_t className[16] = {};
    int length = g_crossWindowApis.getClassNameW(hwnd, className,
        static_cast<int>(sizeof(className) / sizeof(className[0])));
    static constexpr wchar_t expected[] = L"File Pilot";
    if (length != static_cast<int>((sizeof(expected) / sizeof(expected[0])) - 1)) return false;
    for (int i = 0; i < length; ++i) if (className[i] != expected[i]) return false;
    DWORD foundProcessId = 0;
    g_crossWindowApis.getWindowThreadProcessId(hwnd, &foundProcessId);
    if (processId) *processId = foundProcessId;
    return foundProcessId != 0;
}

struct CrossTargetSearch {
    POINT point;
    DWORD sourceProcessId;
    HWND result;
};

static BOOL CALLBACK FindCrossTargetCallback(HWND hwnd, LPARAM parameter) {
    auto *search = reinterpret_cast<CrossTargetSearch *>(parameter);
    if (!g_crossWindowApis.isWindowVisible(hwnd)) return TRUE;
    RECT rectangle = {};
    if (!g_crossWindowApis.getWindowRect(hwnd, &rectangle)
        || search->point.x < rectangle.left || search->point.x >= rectangle.right
        || search->point.y < rectangle.top || search->point.y >= rectangle.bottom) return TRUE;

    DWORD processId = 0;
    g_crossWindowApis.getWindowThreadProcessId(hwnd, &processId);
    if (processId == search->sourceProcessId) {
        // Ignore the source's drag-image and drag-text helpers. Encountering its main window means
        // the pointer is still over the local drop surface, so do not select a window underneath.
        return hwnd == g_hwnd ? FALSE : TRUE;
    }
    if (IsFilePilotWindow(hwnd)) search->result = hwnd;
    // EnumWindows is in z-order. A visible foreign top-level window at the point occludes every
    // candidate below it, whether or not it is File Pilot.
    return FALSE;
}

static HWND FindCrossWindowTarget(POINT point) {
    if (!ResolveCrossWindowApis()) return nullptr;
    DWORD sourceProcessId = g_crossWindowApis.getCurrentProcessId();
    HWND direct = g_crossWindowApis.windowFromPoint(point);
    if (direct) direct = g_crossWindowApis.getAncestor(direct, GA_ROOT);
    if (direct) {
        DWORD directProcessId = 0;
        g_crossWindowApis.getWindowThreadProcessId(direct, &directProcessId);
        if (directProcessId != sourceProcessId) return IsFilePilotWindow(direct) ? direct : nullptr;
        if (direct == g_hwnd) return nullptr;
    }

    CrossTargetSearch search = {point, sourceProcessId, nullptr};
    g_crossWindowApis.enumWindows(FindCrossTargetCallback, reinterpret_cast<LPARAM>(&search));
    return search.result;
}

static LPARAM PackPreviewPoint(POINT point) {
    unsigned long long packed = static_cast<unsigned int>(point.x);
    packed |= static_cast<unsigned long long>(static_cast<unsigned int>(point.y)) << 32;
    return static_cast<LPARAM>(packed);
}

static POINT UnpackPreviewPoint(LPARAM packedPoint) {
    unsigned long long packed = static_cast<unsigned long long>(packedPoint);
    POINT point = {
        static_cast<int>(static_cast<unsigned int>(packed)),
        static_cast<int>(static_cast<unsigned int>(packed >> 32)),
    };
    return point;
}

static WPARAM PackPreviewControl(unsigned int session, unsigned int action,
                                 unsigned int flags = 0) {
    unsigned long long control = session;
    control |= static_cast<unsigned long long>(action | (flags << 8)) << 32;
    return static_cast<WPARAM>(control);
}

static void ClearRemotePreview() {
    memset(&g_remotePreview, 0, sizeof(g_remotePreview));
}

static bool IsRemotePreviewFresh() {
    if (!g_remotePreview.active || !ResolveCrossWindowApis()) return false;
    ULONGLONG now = g_crossWindowApis.getTickCount64();
    if (now - g_remotePreview.lastUpdate <= kPreviewFreshMilliseconds) return true;
    ClearRemotePreview();
    return false;
}

static LRESULT ReceiveRemotePreviewBegin(HWND sender, const COPYDATASTRUCT *copyData) {
    if (!Bindings.tabIntegrationEnabled || !copyData || copyData->dwData != kPreviewMagic
        || copyData->cbData != sizeof(PreviewBeginHeader) || !copyData->lpData
        || !ResolveCrossWindowApis()) return 0;
    auto header = static_cast<const PreviewBeginHeader *>(copyData->lpData);
    if (header->magic != kPreviewMagic || header->version != kPreviewVersion
        || header->headerSize != sizeof(PreviewBeginHeader) || !header->session) return 0;
    DWORD senderProcessId = 0;
    if (!IsFilePilotWindow(sender, &senderProcessId)
        || senderProcessId != header->sourceProcessId
        || senderProcessId == g_crossWindowApis.getCurrentProcessId()) return 0;

    ClearRemotePreview();
    g_remotePreview.active = true;
    g_remotePreview.source = sender;
    g_remotePreview.sourceProcessId = senderProcessId;
    g_remotePreview.session = header->session;
    g_remotePreview.flags = header->flags;
    g_remotePreview.screenPoint = {header->cursorX, header->cursorY};
    g_remotePreview.lastUpdate = g_crossWindowApis.getTickCount64();
    ++CrossWindowPreviewDebug.beginsReceived;
    CrossWindowPreviewDebug.lastSession = header->session;
    if (g_crossWindowHwnd) pInvalidateRect()(g_crossWindowHwnd, nullptr, FALSE);
    return static_cast<LRESULT>(kPreviewAck ^ header->session);
}

static bool ReceiveRemotePreviewMessage(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    unsigned long long control = static_cast<unsigned long long>(wParam);
    unsigned int session = static_cast<unsigned int>(control);
    unsigned int encoded = static_cast<unsigned int>(control >> 32);
    unsigned int action = encoded & 0xff;
    unsigned int flags = encoded >> 8;
    if (!g_remotePreview.active || !session || session != g_remotePreview.session) return false;
    if (action == kPreviewEnd) {
        ClearRemotePreview();
        pInvalidateRect()(hwnd, nullptr, FALSE);
        return true;
    }
    if (action != kPreviewUpdate || !ResolveCrossWindowApis()) return false;
    g_remotePreview.flags = flags;
    g_remotePreview.screenPoint = UnpackPreviewPoint(lParam);
    g_remotePreview.lastUpdate = g_crossWindowApis.getTickCount64();
    g_remotePreview.destinationValid = false;
    ++CrossWindowPreviewDebug.updatesReceived;
    pInvalidateRect()(hwnd, nullptr, FALSE);
    return true;
}

static void EndCrossWindowPreview() {
    HWND target = g_previewTarget;
    unsigned int session = g_previewSession;
    g_previewTarget = nullptr;
    g_previewSession = 0;
    if (target && session) pPostMessageW()(target, kPreviewMessage,
        PackPreviewControl(session, kPreviewEnd), 0);
}

static bool BeginCrossWindowPreview(HWND target, POINT point, unsigned int flags) {
    if (!target || !g_hwnd || !ResolveCrossWindowApis()) return false;
    ++CrossWindowPreviewDebug.beginAttempts;
    unsigned int session = static_cast<unsigned int>(
        g_crossWindowApis.getCurrentProcessId()
        ^ static_cast<unsigned int>(g_crossWindowApis.getTickCount64())
        ^ static_cast<unsigned int>(_InterlockedIncrement(&g_previewSessionCounter)));
    if (!session) session = 1;
    PreviewBeginHeader header = {
        static_cast<unsigned int>(kPreviewMagic), kPreviewVersion,
        sizeof(PreviewBeginHeader), session, g_crossWindowApis.getCurrentProcessId(),
        point.x, point.y, flags, 0,
    };
    COPYDATASTRUCT copyData = {kPreviewMagic, sizeof(header), &header};
    DWORD_PTR result = 0;
    LRESULT delivered = g_crossWindowApis.sendMessageTimeoutW(target, WM_COPYDATA,
        reinterpret_cast<WPARAM>(g_hwnd), reinterpret_cast<LPARAM>(&copyData),
        SMTO_BLOCK | SMTO_ABORTIFHUNG, 100, &result);
    if (!delivered || result != (kPreviewAck ^ session)) return false;
    g_previewTarget = target;
    g_previewSession = session;
    ++CrossWindowPreviewDebug.beginAccepted;
    return true;
}

static void UpdateCrossWindowPreviewAtCursor() {
    if (!Bindings.tabIntegrationEnabled || !g_hwnd || !ResolveCrossWindowApis()) {
        EndCrossWindowPreview();
        return;
    }
    ++CrossWindowPreviewDebug.sourceDragFrames;
    POINT point = {};
    if (!g_crossWindowApis.getCursorPos(&point)) {
        EndCrossWindowPreview();
        return;
    }
    HWND target = FindCrossWindowTarget(point);
    if (!target) {
        EndCrossWindowPreview();
        g_previewRejectedTarget = nullptr;
        return;
    }
    ++CrossWindowPreviewDebug.sourceTargetsFound;
    unsigned int flags = g_crossWindowApis.getKeyState(VK_CONTROL) < 0
        ? kPreviewCopy : 0;
    if (target != g_previewTarget) {
        EndCrossWindowPreview();
        ULONGLONG now = g_crossWindowApis.getTickCount64();
        if (target == g_previewRejectedTarget && now < g_previewRetryAfter) return;
        if (!BeginCrossWindowPreview(target, point, flags)) {
            g_previewRejectedTarget = target;
            g_previewRetryAfter = now + 500;
            return;
        }
        g_previewRejectedTarget = nullptr;
    }
    pPostMessageW()(g_previewTarget, kPreviewMessage,
        PackPreviewControl(g_previewSession, kPreviewUpdate, flags), PackPreviewPoint(point));
    ++CrossWindowPreviewDebug.updatesSent;
}

// The native drag-image updater runs only while a tab is actually being dragged. Its .fpt hook is
// a more reliable source-side clock than the application frame epilogue, where File Pilot may
// already have hidden its transient drag pointer.
extern "C" __declspec(dllexport) void CrossWindowPreviewPulse() {
    if (!ResolveCrossWindowApis()) return;
    g_previewLastPulse = g_crossWindowApis.getTickCount64();
    UpdateCrossWindowPreviewAtCursor();
}

static void ExpireCrossWindowPreviewPulse() {
    if (!g_previewTarget || !ResolveCrossWindowApis()) return;
    if (g_crossWindowApis.getTickCount64() - g_previewLastPulse
        > kPreviewFreshMilliseconds) EndCrossWindowPreview();
}

struct TabUiRect {
    int left;
    int top;
    int right;
    int bottom;
};

static bool ReadTabUiRect(unsigned long long tab, TabUiRect &rectangle) {
    if (!tab || !Bindings.findImGuiWindow) return false;
    unsigned long long group = *reinterpret_cast<unsigned long long *>(tab + 0x4f0);
    if (!group) return false;
    unsigned long long identifier = *reinterpret_cast<unsigned long long *>(group);
    static constexpr char nodeName[] = "Node";
    static constexpr char panelName[] = "Panel";
    for (unsigned int i = 0; i < sizeof(nodeName) - 1; ++i)
        identifier = identifier * 0x21 + static_cast<unsigned char>(nodeName[i]);
    identifier = identifier * 0x21
        + *reinterpret_cast<unsigned long long *>(tab + 0x78);
    for (unsigned int i = 0; i < sizeof(panelName) - 1; ++i)
        identifier = identifier * 0x21 + static_cast<unsigned char>(panelName[i]);
    unsigned long long window = reinterpret_cast<FindImGuiWindowFn>(
        Bindings.findImGuiWindow)(identifier);
    if (!window) return false;
    rectangle = *reinterpret_cast<TabUiRect *>(window + 0x290);
    return rectangle.right > rectangle.left && rectangle.bottom > rectangle.top;
}

struct TabDestination {
    unsigned long long group;
    unsigned long long before;
};

static unsigned long long GroupAtPoint(unsigned long long app, POINT point) {
    unsigned long long groups[64] = {};
    unsigned int groupCount = 0;
    unsigned long long tab = *reinterpret_cast<unsigned long long *>(app + 0xc10);
    for (unsigned int guard = 0; tab && guard < 512; ++guard,
         tab = *reinterpret_cast<unsigned long long *>(tab + 0x88)) {
        unsigned long long group = *reinterpret_cast<unsigned long long *>(tab + 0x4f0);
        bool duplicate = false;
        for (unsigned int i = 0; i < groupCount; ++i) duplicate |= groups[i] == group;
        if (group && !duplicate && groupCount < sizeof(groups) / sizeof(groups[0]))
            groups[groupCount++] = group;
    }

    unsigned long long bestGroup = 0;
    float bestArea = 0.0f;
    for (unsigned int i = 0; i < groupCount; ++i) {
        auto bounds = reinterpret_cast<const float *>(groups[i] + 0x38);
        float left = bounds[0], top = bounds[1], right = bounds[2], bottom = bounds[3];
        if (!(right > left && bottom > top) || point.x < left || point.x >= right
            || point.y < top || point.y >= bottom) continue;
        float area = (right - left) * (bottom - top);
        if (!bestGroup || area < bestArea) { bestGroup = groups[i]; bestArea = area; }
    }
    if (bestGroup) return bestGroup;

    // Some layouts do not retain panel bounds between render phases. The per-tab ImGui rectangles
    // are persistent, so use the horizontally nearest strip with a matching vertical band.
    unsigned long long bestTabGroup = 0;
    int bestDistance = 0x7fffffff;
    tab = *reinterpret_cast<unsigned long long *>(app + 0xc10);
    for (unsigned int guard = 0; tab && guard < 512; ++guard,
         tab = *reinterpret_cast<unsigned long long *>(tab + 0x88)) {
        TabUiRect rectangle = {};
        if (!ReadTabUiRect(tab, rectangle) || point.y < rectangle.top
            || point.y >= rectangle.bottom) continue;
        int distance = point.x < rectangle.left ? rectangle.left - point.x
            : point.x >= rectangle.right ? point.x - rectangle.right : 0;
        if (distance < bestDistance) {
            bestDistance = distance;
            bestTabGroup = *reinterpret_cast<unsigned long long *>(tab + 0x4f0);
        }
    }
    return bestTabGroup;
}

static bool FindTabDestination(unsigned long long app, HWND hwnd, POINT screenPoint,
                               TabDestination &destination) {
    if (!app) return false;
    POINT coordinate = screenPoint;
    if (hwnd && g_crossWindowApis.screenToClient(hwnd, &coordinate))
        destination.group = GroupAtPoint(app, coordinate);
    if (!destination.group) {
        coordinate = screenPoint;
        destination.group = GroupAtPoint(app, coordinate);
    }
    if (!destination.group) {
        unsigned long long active = *reinterpret_cast<unsigned long long *>(
            app + Bindings.appActivePanelOffset);
        if (active) destination.group = *reinterpret_cast<unsigned long long *>(active + 0x4f0);
    }
    if (!destination.group) return false;

    destination.before = 0;
    unsigned long long tab = *reinterpret_cast<unsigned long long *>(destination.group + 8);
    for (unsigned int guard = 0; tab && guard < 512; ++guard,
         tab = *reinterpret_cast<unsigned long long *>(tab + 0x4f8)) {
        TabUiRect rectangle = {};
        if (ReadTabUiRect(tab, rectangle)
            && coordinate.x < rectangle.left + (rectangle.right - rectangle.left) / 2) {
            destination.before = tab;
            break;
        }
    }
    return true;
}

static bool FindPreviewDestination(HWND sender, const CrossWindowHeader *header,
                                   POINT screenPoint, TabDestination &destination) {
    if (!header || !header->reserved || !IsRemotePreviewFresh()
        || !g_remotePreview.destinationValid
        || g_remotePreview.source != sender
        || g_remotePreview.session != header->reserved
        || g_remotePreview.sourceProcessId != header->sourceProcessId
        || g_remotePreview.destinationPlacement != 2
        || !g_remotePreview.destinationGroup) return false;
    ULONGLONG now = g_crossWindowApis.getTickCount64();
    if (now - g_remotePreview.destinationTick > kPreviewFreshMilliseconds) return false;
    long long dx = static_cast<long long>(screenPoint.x) - g_remotePreview.destinationPoint.x;
    long long dy = static_cast<long long>(screenPoint.y) - g_remotePreview.destinationPoint.y;
    if (dx < -64 || dx > 64 || dy < -64 || dy > 64) return false;
    destination.group = g_remotePreview.destinationGroup;
    destination.before = g_remotePreview.destinationBefore;
    return true;
}

extern "C" __declspec(dllexport) void __fastcall RemoteTabSurfaceHook(
    unsigned long long app, unsigned long long *group, unsigned long long context) {
    using OriginalFn = void (__fastcall *)(
        unsigned long long, unsigned long long *, unsigned long long);
    auto original = reinterpret_cast<OriginalFn>(Bindings.originalTabSurfaceRenderer);
    if (!original) return;
    unsigned long long localDrag = app
        ? *reinterpret_cast<unsigned long long *>(app + 0xea8) : 0;
    if (Bindings.tabIntegrationEnabled && app && app == g_filePilotApp
        && g_crossWindowHwnd && localDrag && ResolveCrossWindowApis()) {
        _InterlockedExchange(&g_sourceTabDragActive, 1);
        ULONGLONG now = g_crossWindowApis.getTickCount64();
        if (now - g_previewLastSurfacePulse >= 8) {
            g_previewLastSurfacePulse = now;
            CrossWindowPreviewPulse();
        }
    }
    if (!Bindings.tabIntegrationEnabled || !app || app != g_filePilotApp
        || !Bindings.inputStateGlobal || !g_crossWindowHwnd
        || !IsRemotePreviewFresh()
        || localDrag) {
        original(app, group, context);
        return;
    }

    POINT clientPoint = g_remotePreview.screenPoint;
    if (!g_crossWindowApis.screenToClient(g_crossWindowHwnd, &clientPoint)) {
        original(app, group, context);
        return;
    }
    unsigned long long input = *reinterpret_cast<unsigned long long *>(
        Bindings.inputStateGlobal);
    if (!input) {
        original(app, group, context);
        return;
    }

    auto drag = reinterpret_cast<unsigned long long *>(app + 0xea8);
    auto inputPoint = reinterpret_cast<unsigned long long *>(input);
    auto inputModifiers = reinterpret_cast<unsigned char *>(input + 0x38);
    auto surfaceGeneration = reinterpret_cast<unsigned int *>(app + 0xe9c);
    auto frameGeneration = reinterpret_cast<unsigned int *>(Bindings.frameGenerationGlobal);
    unsigned long long savedDrag = *drag;
    unsigned long long savedPoint = *inputPoint;
    unsigned char savedModifiers = *inputModifiers;
    unsigned int savedSurfaceGeneration = *surfaceGeneration;
    unsigned int currentFrameGeneration = frameGeneration ? *frameGeneration : 0;
    unsigned long long packedClientPoint = static_cast<unsigned int>(clientPoint.x);
    packedClientPoint |= static_cast<unsigned long long>(
        static_cast<unsigned int>(clientPoint.y)) << 32;

    *inputPoint = packedClientPoint;
    *inputModifiers = static_cast<unsigned char>((savedModifiers & ~2u)
        | ((g_remotePreview.flags & kPreviewCopy) ? 2u : 0u));
    *drag = reinterpret_cast<unsigned long long>(g_remoteTabSentinel);
    // The native surface only admits a newly-hovered insertion target when its per-surface
    // generation trails the global UI generation by one. A receiver has no local drag-start
    // event to establish that relationship, so mirror it only for this native render call.
    *surfaceGeneration = currentFrameGeneration - 1;
    CrossWindowPreviewDebug.lastFrameGeneration = currentFrameGeneration;
    CrossWindowPreviewDebug.lastSavedSurfaceGeneration = savedSurfaceGeneration;
    ++CrossWindowPreviewDebug.surfaceCalls;
    original(app, group, context);

    unsigned long long destinationGroup =
        *reinterpret_cast<unsigned long long *>(app + 0xeb0);
    unsigned int destinationPlacement =
        *reinterpret_cast<unsigned int *>(app + 0xec4);
    if (destinationGroup && destinationPlacement == 2) {
        g_remotePreview.destinationValid = true;
        g_remotePreview.destinationGroup = destinationGroup;
        g_remotePreview.destinationBefore =
            *reinterpret_cast<unsigned long long *>(app + 0xeb8);
        g_remotePreview.destinationOrientation =
            *reinterpret_cast<unsigned int *>(app + 0xec0);
        g_remotePreview.destinationPlacement = destinationPlacement;
        g_remotePreview.destinationPoint = g_remotePreview.screenPoint;
        g_remotePreview.destinationTick = g_crossWindowApis.getTickCount64();
        ++CrossWindowPreviewDebug.destinationsCaptured;
        CrossWindowPreviewDebug.lastGroup = destinationGroup;
        CrossWindowPreviewDebug.lastBefore = g_remotePreview.destinationBefore;
        CrossWindowPreviewDebug.lastPlacement = destinationPlacement;
    }

    *drag = savedDrag;
    *surfaceGeneration = savedSurfaceGeneration;
    *inputPoint = savedPoint;
    *inputModifiers = savedModifiers;
}

static bool ReceiveCrossWindowTab(HWND sender, const COPYDATASTRUCT *copyData) {
    if (!Bindings.tabIntegrationEnabled || !copyData
        || copyData->dwData != kCrossWindowMagic
        || copyData->cbData < sizeof(CrossWindowHeader) || !copyData->lpData
        || !ResolveCrossWindowApis()) return false;
    auto header = static_cast<const CrossWindowHeader *>(copyData->lpData);
    if (header->magic != kCrossWindowMagic || header->version != kCrossWindowVersion
        || header->headerSize != sizeof(CrossWindowHeader) || !header->jsonBytes
        || header->jsonBytes > kCrossWindowMaxJson
        || copyData->cbData != sizeof(CrossWindowHeader) + header->jsonBytes) return false;

    DWORD senderProcessId = 0;
    if (!IsFilePilotWindow(sender, &senderProcessId)
        || senderProcessId != header->sourceProcessId
        || senderProcessId == g_crossWindowApis.getCurrentProcessId()) return false;
    unsigned long long app = g_filePilotApp;
    TabDestination destination = {};
    POINT point = {header->cursorX, header->cursorY};
    bool usedPreviewDestination = app
        && FindPreviewDestination(sender, header, point, destination);
    if (!app || (!usedPreviewDestination
        && !FindTabDestination(app, g_crossWindowHwnd, point, destination))) return false;
    if (usedPreviewDestination) ++CrossWindowPreviewDebug.dropsUsingPreview;
    else ++CrossWindowPreviewDebug.dropsUsingFallback;

    SIZE_T stateOffset = (static_cast<SIZE_T>(header->jsonBytes) + 1 + 15) & ~SIZE_T(15);
    SIZE_T allocationSize = stateOffset + kPanelStateSize;
    auto allocation = static_cast<unsigned char *>(g_crossWindowApis.virtualAlloc(
        nullptr, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!allocation) return false;
    const unsigned char *serialized = reinterpret_cast<const unsigned char *>(header + 1);
    memcpy(allocation, serialized, header->jsonBytes);
    allocation[header->jsonBytes] = 0;
    unsigned char *panelState = allocation + stateOffset;
    memset(panelState, 0, kPanelStateSize);
    NativeStringView json = {reinterpret_cast<const char *>(allocation), header->jsonBytes};

    using ParsePanelFn = unsigned long long (__fastcall *)(
        unsigned long long *, unsigned long long, int *, unsigned long long *);
    bool parsed = reinterpret_cast<ParsePanelFn>(Bindings.parseOpenWindowPanelJson)(
        reinterpret_cast<unsigned long long *>(app), app,
        reinterpret_cast<int *>(panelState), reinterpret_cast<unsigned long long *>(&json)) != 0;
    if (!parsed) {
        g_crossWindowApis.virtualFree(allocation, 0, MEM_RELEASE);
        return false;
    }

    // The startup receiver removes File Pilot's literal Root sentinel before it queues command
    // 0x21. Preserve that normalization for the direct live-window path.
    auto root = reinterpret_cast<NativeStringView *>(panelState + 0x20);
    if (root->data && root->length == 4 && root->data[0] == 'R' && root->data[1] == 'o'
        && root->data[2] == 'o' && root->data[3] == 't') *root = {};

    using CreateTabFn = unsigned long long (__fastcall *)(
        unsigned long long, unsigned long long, unsigned long long);
    unsigned long long newTab = reinterpret_cast<CreateTabFn>(
        Bindings.createTabInGroupBefore)(app, destination.group, destination.before);
    if (!newTab) {
        g_crossWindowApis.virtualFree(allocation, 0, MEM_RELEASE);
        return false;
    }
    using ApplyPanelFn = void (__fastcall *)(unsigned long long, unsigned long long,
                                             unsigned long long);
    using FocusTabFn = void (__fastcall *)(unsigned long long, unsigned long long);
    reinterpret_cast<ApplyPanelFn>(Bindings.applyDeserializedPanelStateToTab)(
        app, newTab, reinterpret_cast<unsigned long long>(panelState));
    reinterpret_cast<FocusTabFn>(Bindings.focusTab)(app, newTab);
    // Panel state may retain StringViews into the serialized block. File Pilot's startup importer
    // gives the equivalent storage application lifetime, so deliberately retain this small block.
    ClearRemotePreview();
    return true;
}

static LRESULT CALLBACK CrossWindowWndProc(HWND hwnd, UINT message,
                                            WPARAM wParam, LPARAM lParam) {
    if (message == kPreviewMessage && ReceiveRemotePreviewMessage(hwnd, wParam, lParam)) return 0;
    if (message == WM_COPYDATA) {
        auto sender = reinterpret_cast<HWND>(wParam);
        auto copyData = reinterpret_cast<const COPYDATASTRUCT *>(lParam);
        LRESULT previewResult = ReceiveRemotePreviewBegin(sender, copyData);
        if (previewResult) return previewResult;
        if (ReceiveCrossWindowTab(sender, copyData)) return static_cast<LRESULT>(kCrossWindowAck);
    }
    return g_originalWindowProc && ResolveCrossWindowApis()
        ? g_crossWindowApis.callWindowProcW(g_originalWindowProc, hwnd, message, wParam, lParam)
        : 0;
}

static void EnsureCrossWindowTransport(HWND hwnd) {
    if (!Bindings.tabIntegrationEnabled || !hwnd || !ResolveCrossWindowApis()) return;
    if (g_crossWindowHwnd == hwnd && g_originalWindowProc) return;
    WNDPROC original = reinterpret_cast<WNDPROC>(g_crossWindowApis.setWindowLongPtrW(
        hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&CrossWindowWndProc)));
    if (!original) return;
    g_hwnd = hwnd;
    g_crossWindowHwnd = hwnd;
    g_originalWindowProc = original;
}

extern "C" __declspec(dllexport) int __fastcall CrossWindowTryTransfer(
    const NativeStringView *serialized) {
    if (!Bindings.tabIntegrationEnabled || !serialized || !serialized->data
        || !serialized->length || serialized->length > kCrossWindowMaxJson
        || !g_hwnd || !ResolveCrossWindowApis()) return 0;
    POINT point = {};
    if (!g_crossWindowApis.getCursorPos(&point)) {
        EndCrossWindowPreview();
        return 0;
    }
    HWND target = FindCrossWindowTarget(point);
    if (!target) {
        EndCrossWindowPreview();
        return 0;
    }
    unsigned int previewSession = target == g_previewTarget ? g_previewSession : 0;

    SIZE_T transferSize = sizeof(CrossWindowHeader) + static_cast<SIZE_T>(serialized->length);
    auto transfer = static_cast<unsigned char *>(g_crossWindowApis.virtualAlloc(
        nullptr, transferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!transfer) return 0;
    auto header = reinterpret_cast<CrossWindowHeader *>(transfer);
    *header = {static_cast<unsigned int>(kCrossWindowMagic), kCrossWindowVersion,
        sizeof(CrossWindowHeader), static_cast<unsigned int>(serialized->length),
        point.x, point.y, g_crossWindowApis.getCurrentProcessId(), 0, previewSession};
    memcpy(header + 1, serialized->data, serialized->length);
    COPYDATASTRUCT copyData = {kCrossWindowMagic, static_cast<DWORD>(transferSize), transfer};
    DWORD_PTR result = 0;
    LRESULT delivered = g_crossWindowApis.sendMessageTimeoutW(target, WM_COPYDATA,
        reinterpret_cast<WPARAM>(g_hwnd), reinterpret_cast<LPARAM>(&copyData),
        SMTO_BLOCK | SMTO_ABORTIFHUNG, 2000, &result);
    g_crossWindowApis.virtualFree(transfer, 0, MEM_RELEASE);
    bool accepted = delivered && result == kCrossWindowAck;
    EndCrossWindowPreview();
    return accepted ? 1 : 0;
}

static void RegisterShellWindow(HWND hwnd) {
    if (!hwnd || _InterlockedCompareExchange(&g_initialized, 1, 0) != 0) return;
    g_hwnd = hwnd;

    int argc = 0;
    LPWSTR *argv = pCommandLineToArgvW()(pGetCommandLineW()(), &argc);
    if (!argv || argc != 2 || argv[1][0] == L'-') { if (argv) pLocalFree()(argv); return; }
    wchar_t *path = argv[1];
    DWORD attrs = pGetFileAttributesW()(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) { pLocalFree()(argv); return; }
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY) && !pPathRemoveFileSpecW()(path)) { pLocalFree()(argv); return; }
    if (FAILED(pSHParseDisplayName()(path, nullptr, &g_parentPidl, 0, nullptr)) || !g_parentPidl) {
        pLocalFree()(argv); return;
    }
    PIDLIST_ABSOLUTE desktopPidl = ParseWithDesktopFolder(path);
    pLocalFree()(argv);

    HMODULE propsys = pLoadLibraryW()(L"propsys.dll");
    auto initVariant = propsys ? reinterpret_cast<InitVariantFromBufferFn>(pGetProcAddress()(propsys, "InitVariantFromBuffer")) : nullptr;
    if (!initVariant) { if (desktopPidl) pCoTaskMemFree()(desktopPidl); return; }

    void *shellWindows = nullptr;
    HRESULT hr = pCoCreateInstance()(kClsidShellWindows, nullptr, CLSCTX_LOCAL_SERVER, kIidShellWindows, &shellWindows);
    if (SUCCEEDED(hr)) g_shellWindows = static_cast<IShellWindows *>(shellWindows);
    if (!g_shellWindows) { if (desktopPidl) pCoTaskMemFree()(desktopPidl); return; }

    auto *view = reinterpret_cast<ShellView *>(g_viewStorage);
    auto *doc = reinterpret_cast<Document *>(g_documentStorage);
    auto *browser = reinterpret_cast<Browser *>(g_browserStorage);
    new (view) ShellView();
    new (doc) Document();
    new (browser) Browser();
    doc->view = view;
    browser->document = doc;

    // Chromium obtains PIDLs through the desktop IShellFolder, while common Windows "Open file
    // location" paths can use the compact SHParseDisplayName representation. These PIDLs resolve
    // to the same path but are not byte-identical, and IShellWindows uses the PIDL identity when it
    // matches a pending SHOpenFolderAndSelectItems request. Register both aliases against the same
    // facade so either caller can discover this File Pilot window.
    if (desktopPidl) {
        RegisterShellWindowAlias(desktopPidl, static_cast<IDispatch *>(browser), initVariant);
    }
    if (!desktopPidl || !PidlsByteEqual(desktopPidl, g_parentPidl)) {
        RegisterShellWindowAlias(g_parentPidl, static_cast<IDispatch *>(browser), initVariant);
    }
    if (desktopPidl) pCoTaskMemFree()(desktopPidl);
}

extern "C" __declspec(dllexport) void __fastcall Hook(unsigned long long *config, void *output) {
    using OriginalFn = void (__fastcall *)(unsigned long long *, void *);
    reinterpret_cast<OriginalFn>(Bindings.originalInitializer)(config, output);
    HWND hwnd = FindMainWindow();
    EnsureCrossWindowTransport(hwnd);
    RegisterShellWindow(hwnd);
}

extern "C" __declspec(dllexport) void __fastcall LiveSelectionHook(
    unsigned long long root, unsigned long long selectionState, unsigned long long *command) {
    using OriginalFn = void (__fastcall *)(unsigned long long, unsigned long long,
        unsigned long long *);
    reinterpret_cast<OriginalFn>(Bindings.originalLiveSelection)(root, selectionState, command);
    RememberSelectionState(selectionState);
}

extern "C" __declspec(dllexport) void __fastcall MillerNavigateHook(
    unsigned long long context, unsigned long long panel, const NativeStringView *path,
    int option, int *settings) {
    ++MillerDebug.navigationCalls;
    bool inspectorRetarget = g_inspectorSyncSource &&
        *reinterpret_cast<unsigned long long *>(panel + Bindings.childOwnerOffset) ==
            g_inspectorSyncSource;
    BeforePanelNavigation(panel, !inspectorRetarget);
    reinterpret_cast<NavigatePanelFn>(Bindings.navigatePanel)(
        context, panel, path, option, settings);
}

extern "C" __declspec(dllexport) void __fastcall MillerInspectorSyncHook(
    unsigned long long context, unsigned long long panel) {
    ++MillerDebug.inspectorSyncCalls;
    MillerDebug.syncPanel = panel;
    bool focusChanged = false;
    UpdatePanelFocus(panel, focusChanged);
    if (focusChanged) ApplyNativeSingleSelection(context, panel);
    ReattachPooledChild(panel);
    unsigned long long previousSource = g_inspectorSyncSource;
    g_inspectorSyncSource = panel;
    reinterpret_cast<InspectorSyncFn>(Bindings.inspectorSync)(context, panel);
    unsigned long long syncInspector = PanelInspector(panel);
    MillerDebug.syncMode = syncInspector ? *reinterpret_cast<unsigned int *>(
        syncInspector + Bindings.inspectorModeOffset) : 0;
    MillerDebug.syncChild = syncInspector ? *reinterpret_cast<unsigned long long *>(
        syncInspector + Bindings.inspectorChildOffset) : 0;
    g_inspectorSyncSource = previousSource;
    DiscardSuppressedChild(panel);
}

extern "C" __declspec(dllexport) void __fastcall RecursiveInspectorRenderHook(
    unsigned long long context, unsigned long long childPanel) {
    ++MillerDebug.childRenderCalls;
    MillerDebug.renderChild = childPanel;
    unsigned int childIndex = kMillerMaxColumns;
    InspectorChildDisposition disposition = PrepareInspectorChild(childPanel, childIndex);
    if (disposition == kHideMillerChild) return;

    // InspectorFrame runs in layout phase 4. It is the correct place to synchronize and extend
    // the logical child chain, but panel surfaces ignore this phase. Keep only File Pilot's native
    // model pass here and recurse through InspectorFrame so every logical descendant stays live.
    reinterpret_cast<PanelRendererFn>(Bindings.panelRenderer)(context, childPanel);
    if (disposition == kRenderRecursiveChild && childIndex < kMillerMaxColumns) {
        reinterpret_cast<InspectorFrameFn>(Bindings.inspectorFrame)(context, childPanel);
        if (childIndex == 1) ApplyRecursiveNodeRectangles(context);
    }
    MillerDebug.columnCount = g_miller.columnCount;
}

extern "C" __declspec(dllexport) void __fastcall InspectorPhase0ActivateHook(
    unsigned long long layoutStack, unsigned long long inspectorNode) {
    // File Pilot has already constructed the PanelInspector node. Make it current first, then
    // construct the next panel before the native epilogue pops this node from the layout stack.
    reinterpret_cast<InspectorLayoutActivateFn>(Bindings.inspectorLayoutActivate)(
        layoutStack, inspectorNode);
    ConstructNextMillerColumn(g_inspectorSurfaceContext, g_inspectorSurfacePanel);
}

extern "C" __declspec(dllexport) void __fastcall RecursiveInspectorChildSurfaceHook(
    unsigned long long context, unsigned long long childPanel,
    unsigned long long inspectorWindow) {
    // This call site is inside the active PanelInspector scope in phase 1. Paint the child viewport
    // and then its own Inspector component; that nested Inspector reaches this hook again.
    if (PaintNextMillerColumn(
            context, g_inspectorSurfacePanel, childPanel, inspectorWindow)) return;
    reinterpret_cast<InspectorChildSurfaceRendererFn>(
        Bindings.inspectorChildSurfaceRenderer)(context, childPanel, inspectorWindow);
}

extern "C" __declspec(dllexport) void __fastcall PanelViewportHook(
    unsigned long long context, unsigned long long panel) {
    // Phase 0 must run the ordinary viewport constructor. In phase 1 descendants use the native
    // Inspector child-content painter, which omits a panel tab while preserving rows and input.
    if (CurrentLayoutPhase() == 1 && UsesRecursiveSurface(panel)) {
        unsigned long long window = reinterpret_cast<FindImGuiWindowFn>(
            Bindings.findImGuiWindow)(PanelViewportId(panel));
        if (window) {
            // A stock split viewport treats an Inspector child as a hidden tab. Render the child
            // through the Inspector's own content callback while the synthetic, correctly-sized
            // viewport is active. This preserves native rows and selection styling.
            reinterpret_cast<InspectorChildSurfaceRendererFn>(
                Bindings.inspectorChildSurfaceRenderer)(context, panel, window);
            return;
        }
    }
    reinterpret_cast<PanelRendererFn>(Bindings.panelViewportRenderer)(context, panel);
}

extern "C" __declspec(dllexport) void __fastcall PanelHeaderHook(
    unsigned long long context, unsigned long long panel) {
    // Recursive columns live inside an Inspector and therefore use the Inspector's own subbar.
    // Omitting Panel/Header in both construction and paint phases prevents per-folder tabs.
    if (UsesRecursiveSurface(panel)) return;
    reinterpret_cast<PanelRendererFn>(Bindings.panelHeaderRenderer)(context, panel);
}

extern "C" __declspec(dllexport) void __fastcall PanelInspectorSurfaceHook(
    unsigned long long context, unsigned long long panel, int orientation) {
    ++MillerDebug.surfaceInspectorCalls;
    MillerDebug.surfaceInspectorPanel = panel;
    MillerDebug.surfaceInspectorOrientation = static_cast<unsigned int>(orientation);
    unsigned long long inspector = PanelInspector(panel);
    if (inspector) {
        MillerDebug.surfaceInspectorMode = *reinterpret_cast<unsigned int *>(
            inspector + Bindings.inspectorModeOffset);
        MillerDebug.surfaceInspectorWidthBits = *reinterpret_cast<unsigned int *>(
            inspector + Bindings.inspectorWidthOffset);
    }
    AcquireSpinLock(&g_miller.lock);
    if (FindColumnUnlocked(panel) != kMillerMaxColumns) {
        ++MillerDebug.surfaceInspectorMillerCalls;
    }
    ReleaseSpinLock(&g_miller.lock);
    if (CurrentLayoutPhase() == 0) {
        AcquireSpinLock(&g_miller.lock);
        if (FindColumnUnlocked(panel) == 0) g_constructedColumnMask = 1;
        ReleaseSpinLock(&g_miller.lock);
    }
    RenderInspectorWithScope(context, panel, orientation, false);
}

extern "C" __declspec(dllexport) void __fastcall ItemInteractionHook(
    unsigned long long context, char *panel, unsigned long long *item,
    unsigned long long *itemState, unsigned long long itemId,
    unsigned long long *interaction, int option7, int option8, int option9,
    int option10, int option11, int option12, int option13, unsigned int option14) {
    using OriginalFn = void (__fastcall *)(unsigned long long, char *, unsigned long long *,
        unsigned long long *, unsigned long long, unsigned long long *, int, int, int, int,
        int, int, int, unsigned int);
    unsigned long long previousContext = g_renderContext;
    unsigned long long previousPanel = g_renderPanel;
    unsigned long long previousItem = g_renderItem;
    ++MillerDebug.itemInteractionCalls;
    MillerDebug.lastPanel = reinterpret_cast<unsigned long long>(panel);
    MillerDebug.lastItem = reinterpret_cast<unsigned long long>(item);
    g_renderContext = context;
    g_renderPanel = reinterpret_cast<unsigned long long>(panel);
    g_renderItem = reinterpret_cast<unsigned long long>(item);
    bool nativeSelected = option7 != 0;
    if (!nativeSelected && ShouldHighlightItem(g_renderPanel, g_renderItem)) option7 = 1;
    reinterpret_cast<OriginalFn>(Bindings.originalItemInteraction)(context, panel, item,
        itemState, itemId, interaction, option7, option8, option9, option10, option11,
        option12, option13, option14);
    if (nativeSelected) RecordNativeSelection(g_renderPanel, g_renderItem);
    g_renderContext = previousContext;
    g_renderPanel = previousPanel;
    g_renderItem = previousItem;
}

static void __fastcall IgnoreCommandArgument(void *, unsigned long long) {}

extern "C" __declspec(dllexport) void *__fastcall BeginOpenHook(
    void *storage, unsigned int command, unsigned long long argument,
    unsigned long long context) {
    ++MillerDebug.beginOpenCalls;
    if (g_renderContext && g_renderPanel && g_renderItem) {
        bool handled = (command == 0x30 || command == 0x31) &&
            QueueMillerFolderActivation(g_renderPanel, g_renderItem);
        if (handled) {
            ++MillerDebug.handledFolderActivations;
            // Supply the binder slot consumed by the item renderer while suppressing in-place
            // activation. The next frame lets this panel's own Inspector create or retarget the
            // following Miller column.
            memset(storage, 0, 0x50);
            *reinterpret_cast<void **>(reinterpret_cast<unsigned char *>(storage) + 0x20) =
                reinterpret_cast<void *>(&IgnoreCommandArgument);
            return storage;
        }
    }
    using OriginalFn = void *(__fastcall *)(void *, unsigned int,
                                             unsigned long long, unsigned long long);
    return reinterpret_cast<OriginalFn>(Bindings.originalBeginQueuedCommand)(
        storage, command, argument, context);
}

extern "C" __declspec(dllexport) void __fastcall FrameHook(unsigned long long app) {
    using OriginalFn = void (__fastcall *)(unsigned long long);
    reinterpret_cast<OriginalFn>(Bindings.originalFrame)(app);
    if (Bindings.tabIntegrationEnabled) {
        g_filePilotApp = app;
        EnsureCrossWindowTransport(g_hwnd ? g_hwnd : FindMainWindow());
        ExpireCrossWindowPreviewPulse();
        if (_InterlockedCompareExchange(&g_sourceTabDragActive, 0, 0) != 0
            && ResolveCrossWindowApis()) {
            if (g_crossWindowApis.getKeyState(VK_LBUTTON) < 0) {
                ULONGLONG now = g_crossWindowApis.getTickCount64();
                if (now - g_previewLastSurfacePulse >= 8) {
                    g_previewLastSurfacePulse = now;
                    CrossWindowPreviewPulse();
                }
            } else {
                _InterlockedExchange(&g_sourceTabDragActive, 0);
            }
        }
    }
    if (_InterlockedCompareExchange(&g_initialized, 0, 0) == 0) {
        RegisterShellWindow(FindMainWindow());
    }
    ApplyPendingSelection(app);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }

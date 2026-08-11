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
    unsigned long long selectionCancel;
    unsigned long long toggleCursorSelection;
    unsigned long long originalFrame;
    unsigned long long selectionStateDisplayOffset;
    unsigned long long displayModeOffset;
    unsigned long long displayPrimaryOffset;
    unsigned long long displayAlternateOffset;
    unsigned long long displayCountOffset;
    unsigned long long appActivePanelOffset;
    unsigned long long findImGuiWindow;
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
static constexpr unsigned long long kBindingsVersion = 22;

extern "C" __declspec(dllexport) volatile PayloadBindings Bindings = {
    kBindingsMagic, kBindingsVersion, sizeof(PayloadBindings)
};

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

struct NativeStringView {
    const char *data;
    unsigned long long length;
};

using FindImGuiWindowFn = unsigned long long (__fastcall *)(unsigned long long);

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

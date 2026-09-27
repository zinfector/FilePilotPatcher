#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// This DLL is copied into the executable as a manually mapped PE image. Keep it
// self-contained: no CRT, static constructors, or ordinary imported calls.

struct MenuBindings {
    unsigned long long magic;
    unsigned long long version;
    unsigned long long size;
    unsigned long long iatLoadLibraryW;
    unsigned long long iatGetProcAddress;
    unsigned long long iatGetKeyState;
    unsigned long long originalAcquire;
    unsigned long long originalRelease;
};

static constexpr unsigned long long kMenuBindingsMagic =
    0x53474e49424d5046ULL; // "FPMBINGS"
static constexpr unsigned long long kMenuBindingsVersion = 1;

extern "C" __declspec(dllexport) volatile MenuBindings Bindings = {
    kMenuBindingsMagic, kMenuBindingsVersion, sizeof(MenuBindings)
};

enum MenuExperimentFlags : unsigned int {
    MenuExperimentInitialized = 1u << 0,
    MenuExperimentClipboardSequenceAvailable = 1u << 1,
    MenuExperimentHasCachedWrapper = 1u << 2,
    MenuExperimentHasDeferredReleases = 1u << 3,
    MenuExperimentSelectedClipboardIndependent = 1u << 4,
};

// Selected-item wrappers are bound to their exact Shell items and cannot be
// safely retargeted. Keep enough recent selections to cover a normal populated
// folder, and prevent background-menu traffic from evicting that working set.
static constexpr unsigned int kSelectedCacheCapacity = 64;
static constexpr unsigned int kBackgroundCacheCapacity = 4;
static constexpr unsigned int kCacheCapacity =
    kSelectedCacheCapacity + kBackgroundCacheCapacity;
static constexpr unsigned int kDeferredCapacity = 8;

struct MenuExperimentState {
    unsigned int version;
    unsigned int flags;
    unsigned long long acquireCalls;
    unsigned long long cacheHits;
    unsigned long long cacheMisses;
    unsigned long long retainedReleases;
    unsigned long long forwardedReleases;
    unsigned long long invalidKeys;
    unsigned long long lastHashA;
    unsigned long long lastHashB;
    unsigned long long cachedWrapper;
    unsigned int lastClipboardSequence;
    unsigned int lastModifierState;
    unsigned long long lastFolderLength;
    unsigned long long lastSelectionCount;
    unsigned long long lastContextCount;
    unsigned long long lastSelectionTextBytes;
    unsigned long long lastContextTextBytes;
    unsigned long long cacheEvictions;
    unsigned long long postCloseReleases;
    unsigned long long uncachedBuilds;
    unsigned int cacheCapacity;
    unsigned int cacheEntries;
    unsigned int deferredCount;
    unsigned int lastCacheSlot;
};

extern "C" __declspec(dllexport) volatile MenuExperimentState MenuExperiment = {
    3, MenuExperimentInitialized | MenuExperimentSelectedClipboardIndependent
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

static auto pGetKeyState() {
    return Iat<decltype(&GetKeyState)>(Bindings.iatGetKeyState);
}

using GetClipboardSequenceNumberFn = DWORD (WINAPI *)();
using AcquireFn = unsigned long long *(__fastcall *)(
    unsigned long long *, unsigned long long *, unsigned int, unsigned int,
    unsigned long long *);
using ReleaseFn = void (__fastcall *)(unsigned long long *);

struct MenuKey {
    unsigned long long hashA;
    unsigned long long hashB;
    unsigned long long folderLength;
    unsigned long long selectionCount;
    unsigned long long contextCount;
    unsigned long long selectionTextBytes;
    unsigned long long contextTextBytes;
    unsigned int queryFlags;
    unsigned int selectionMode;
    unsigned int clipboardSequence;
    unsigned int modifierState;
};

struct KeyBuilder {
    unsigned long long hashA;
    unsigned long long hashB;
    bool valid;
};

struct CacheEntry {
    MenuKey key;
    unsigned long long *wrapper;
    unsigned long long lastUse;
    unsigned int activeUses;
};

static CacheEntry g_cache[kCacheCapacity];
static unsigned long long *g_deferredReleases[kDeferredCapacity];
static unsigned long long g_useClock;
static unsigned int g_deferredCount;
static GetClipboardSequenceNumberFn g_getClipboardSequenceNumber;
static bool g_clipboardResolverAttempted;

static void MixByte(KeyBuilder &builder, unsigned char value) {
    builder.hashA ^= value;
    builder.hashA *= 1099511628211ULL;
    builder.hashB += value + 0x9e3779b97f4a7c15ULL;
    builder.hashB ^= builder.hashB >> 27;
    builder.hashB *= 0x3c79ac492ba7b653ULL;
    builder.hashB ^= builder.hashB >> 33;
}

static void MixQword(KeyBuilder &builder, unsigned long long value) {
    for (unsigned int index = 0; index < 8; ++index) {
        MixByte(builder, static_cast<unsigned char>(value));
        value >>= 8;
    }
}

static void MixView(KeyBuilder &builder, const unsigned long long *view,
                    unsigned long long &lengthOutput) {
    // File Pilot paths are byte StringViews. Refuse implausibly large or malformed
    // views rather than dereferencing them merely to obtain a cache key.
    static constexpr unsigned long long kMaximumPathBytes = 0x10000;
    if (!view) {
        builder.valid = false;
        lengthOutput = 0;
        return;
    }
    auto data = reinterpret_cast<const unsigned char *>(view[0]);
    unsigned long long length = view[1];
    lengthOutput = length;
    MixQword(builder, length);
    if (length > kMaximumPathBytes || (length != 0 && !data)) {
        builder.valid = false;
        return;
    }
    for (unsigned long long index = 0; index < length; ++index)
        MixByte(builder, data[index]);
}

static void MixContextVector(KeyBuilder &builder, const unsigned long long *context,
                             unsigned long long &countOutput,
                             unsigned long long &textBytesOutput) {
    static constexpr unsigned long long kMaximumContextItems = 0x100;
    countOutput = context ? context[0] : 0;
    textBytesOutput = 0;
    MixQword(builder, countOutput);
    if (!context || countOutput > kMaximumContextItems ||
        (countOutput != 0 && context[2] == 0)) {
        builder.valid = false;
        return;
    }
    auto items = reinterpret_cast<const unsigned long long *>(context[2]);
    for (unsigned long long index = 0; index < countOutput; ++index) {
        unsigned long long itemLength = 0;
        MixView(builder, items + index * 2, itemLength);
        textBytesOutput += itemLength;
    }
}

static GetClipboardSequenceNumberFn ResolveClipboardSequenceNumber() {
    if (g_clipboardResolverAttempted) return g_getClipboardSequenceNumber;
    g_clipboardResolverAttempted = true;
    HMODULE user32 = pLoadLibraryW()(L"user32.dll");
    if (user32) {
        g_getClipboardSequenceNumber = reinterpret_cast<GetClipboardSequenceNumberFn>(
            pGetProcAddress()(user32, "GetClipboardSequenceNumber"));
    }
    if (g_getClipboardSequenceNumber)
        MenuExperiment.flags |= MenuExperimentClipboardSequenceAvailable;
    return g_getClipboardSequenceNumber;
}

static unsigned int CurrentModifierState() {
    unsigned int state = 0;
    if (pGetKeyState()(VK_SHIFT) < 0) state |= 1u << 0;
    if (pGetKeyState()(VK_CONTROL) < 0) state |= 1u << 1;
    if (pGetKeyState()(VK_MENU) < 0) state |= 1u << 2;
    return state;
}

static MenuKey BuildKey(unsigned long long *folder, unsigned long long *selection,
                        unsigned int queryFlags, unsigned int selectionMode,
                        unsigned long long *context, bool &valid) {
    KeyBuilder builder = {1469598103934665603ULL, 0xd6e8feb86659fd93ULL, true};
    MenuKey key = {};
    MixQword(builder, 0x7265646c6f66ULL); // "folder"
    MixView(builder, folder, key.folderLength);
    MixQword(builder, 0x6e6f697463656c73ULL); // selection separator
    // Selection is also a count/capacity/StringView-pointer vector. Treating
    // its count as a character pointer would fault on selected-item menus.
    MixContextVector(builder, selection, key.selectionCount, key.selectionTextBytes);
    MixQword(builder, 0x747865746e6f63ULL); // "context"
    // The fifth argument is a vector: count, capacity, pointer to 16-byte
    // StringViews. Capacity and allocation address are presentation-lifetime
    // details and change while idle, so identity comes from the deep contents.
    MixContextVector(builder, context, key.contextCount, key.contextTextBytes);
    key.queryFlags = queryFlags;
    key.selectionMode = selectionMode;
    auto clipboard = ResolveClipboardSequenceNumber();
    // Paste availability belongs to the folder-background menu. A selected
    // item's Cut/Copy/Delete/Rename/Open verbs do not depend on clipboard
    // contents, so clipboard-manager activity must not invalidate every cached
    // selected-file wrapper while File Pilot is idle.
    key.clipboardSequence =
        key.selectionCount == 0 && clipboard ? clipboard() : 0;
    key.modifierState = CurrentModifierState();
    MixQword(builder, queryFlags);
    MixQword(builder, selectionMode);
    MixQword(builder, key.clipboardSequence);
    MixQword(builder, key.modifierState);
    key.hashA = builder.hashA;
    key.hashB = builder.hashB;
    valid = builder.valid;
    return key;
}

static bool KeysEqual(const MenuKey &left, const MenuKey &right) {
    return left.hashA == right.hashA && left.hashB == right.hashB &&
        left.folderLength == right.folderLength &&
        left.selectionCount == right.selectionCount &&
        left.contextCount == right.contextCount &&
        left.selectionTextBytes == right.selectionTextBytes &&
        left.contextTextBytes == right.contextTextBytes &&
        left.queryFlags == right.queryFlags &&
        left.selectionMode == right.selectionMode &&
        left.clipboardSequence == right.clipboardSequence &&
        left.modifierState == right.modifierState;
}

static void ForwardRelease(unsigned long long *wrapper) {
    reinterpret_cast<ReleaseFn>(Bindings.originalRelease)(wrapper);
    MenuExperiment.forwardedReleases++;
}

static void SyncCacheTelemetry() {
    unsigned int count = 0;
    for (unsigned int index = 0; index < kCacheCapacity; ++index) {
        if (g_cache[index].wrapper) ++count;
    }
    MenuExperiment.cacheCapacity = kCacheCapacity;
    MenuExperiment.cacheEntries = count;
    MenuExperiment.deferredCount = g_deferredCount;
    if (count)
        MenuExperiment.flags |= MenuExperimentHasCachedWrapper;
    else
        MenuExperiment.flags &= ~MenuExperimentHasCachedWrapper;
    if (g_deferredCount)
        MenuExperiment.flags |= MenuExperimentHasDeferredReleases;
    else
        MenuExperiment.flags &= ~MenuExperimentHasDeferredReleases;
}

static int FindCachedKey(const MenuKey &key) {
    for (unsigned int index = 0; index < kCacheCapacity; ++index) {
        if (g_cache[index].wrapper && KeysEqual(key, g_cache[index].key))
            return static_cast<int>(index);
    }
    return -1;
}

static int FindCachedWrapper(unsigned long long *wrapper) {
    for (unsigned int index = 0; index < kCacheCapacity; ++index) {
        if (wrapper && g_cache[index].wrapper == wrapper)
            return static_cast<int>(index);
    }
    return -1;
}

static int FindInstallSlot(const MenuKey &key) {
    unsigned int begin = key.selectionCount ? 0 : kSelectedCacheCapacity;
    unsigned int end = key.selectionCount ?
        kSelectedCacheCapacity : kCacheCapacity;
    for (unsigned int index = begin; index < end; ++index) {
        if (!g_cache[index].wrapper) return static_cast<int>(index);
    }

    int victim = -1;
    unsigned long long oldestUse = ~0ULL;
    for (unsigned int index = begin; index < end; ++index) {
        // A re-entrant Shell callback can open another menu. Never evict a
        // wrapper until every acquire that returned it has reached close.
        if (!g_cache[index].activeUses && g_cache[index].lastUse < oldestUse) {
            oldestUse = g_cache[index].lastUse;
            victim = static_cast<int>(index);
        }
    }
    return victim;
}

static bool InstallCacheEntry(const MenuKey &key, unsigned long long *wrapper) {
    int slot = FindInstallSlot(key);
    if (slot < 0) return false;

    CacheEntry &entry = g_cache[slot];
    if (entry.wrapper) {
        // Do not destroy the old IContextMenu/HMENU here. The new wrapper has
        // already been built, and destruction is deferred until menu close so
        // teardown can never lengthen a subsequent right-click open.
        if (g_deferredCount == kDeferredCapacity) return false;
        g_deferredReleases[g_deferredCount++] = entry.wrapper;
        MenuExperiment.cacheEvictions++;
    }

    entry.key = key;
    entry.wrapper = wrapper;
    entry.lastUse = ++g_useClock;
    entry.activeUses = 1;
    MenuExperiment.cachedWrapper = reinterpret_cast<unsigned long long>(wrapper);
    MenuExperiment.lastCacheSlot = static_cast<unsigned int>(slot);
    SyncCacheTelemetry();
    return true;
}

static void DrainDeferredReleases() {
    while (g_deferredCount) {
        unsigned long long *wrapper = g_deferredReleases[--g_deferredCount];
        g_deferredReleases[g_deferredCount] = nullptr;
        ForwardRelease(wrapper);
        MenuExperiment.postCloseReleases++;
    }
    SyncCacheTelemetry();
}

extern "C" __declspec(dllexport) unsigned long long *__fastcall MenuAcquireHook(
    unsigned long long *folder, unsigned long long *selection, unsigned int queryFlags,
    unsigned int selectionMode, unsigned long long *context) {
    MenuExperiment.acquireCalls++;
    bool valid = false;
    MenuKey key = BuildKey(folder, selection, queryFlags, selectionMode, context, valid);
    MenuExperiment.lastHashA = key.hashA;
    MenuExperiment.lastHashB = key.hashB;
    MenuExperiment.lastClipboardSequence = key.clipboardSequence;
    MenuExperiment.lastModifierState = key.modifierState;
    MenuExperiment.lastFolderLength = key.folderLength;
    MenuExperiment.lastSelectionCount = key.selectionCount;
    MenuExperiment.lastContextCount = key.contextCount;
    MenuExperiment.lastSelectionTextBytes = key.selectionTextBytes;
    MenuExperiment.lastContextTextBytes = key.contextTextBytes;

    if (valid) {
        int slot = FindCachedKey(key);
        if (slot >= 0) {
            CacheEntry &entry = g_cache[slot];
            MenuExperiment.cacheHits++;
            entry.lastUse = ++g_useClock;
            entry.activeUses++;
            MenuExperiment.cachedWrapper =
                reinterpret_cast<unsigned long long>(entry.wrapper);
            MenuExperiment.lastCacheSlot = static_cast<unsigned int>(slot);
            SyncCacheTelemetry();
            return entry.wrapper;
        }
    }

    MenuExperiment.cacheMisses++;
    if (!valid) MenuExperiment.invalidKeys++;

    // Build first while all existing Shell wrappers remain alive. This avoids
    // unloading extensions immediately before QueryContextMenu needs them.
    auto wrapper = reinterpret_cast<AcquireFn>(Bindings.originalAcquire)(
        folder, selection, queryFlags, selectionMode, context);
    if (valid && wrapper && !InstallCacheEntry(key, wrapper))
        MenuExperiment.uncachedBuilds++;
    return wrapper;
}

extern "C" __declspec(dllexport) void __fastcall MenuReleaseHook(
    unsigned long long *wrapper) {
    int slot = FindCachedWrapper(wrapper);
    if (slot >= 0) {
        // The wrapper owns the already-enumerated HMENU, its File Pilot model, and
        // IContextMenu interfaces. Keep bounded entries alive across closes.
        if (g_cache[slot].activeUses) g_cache[slot].activeUses--;
        MenuExperiment.retainedReleases++;
        DrainDeferredReleases();
        return;
    }
    ForwardRelease(wrapper);
    DrainDeferredReleases();
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }

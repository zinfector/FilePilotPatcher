#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <shellapi.h>

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) return 2;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    PIDLIST_ABSOLUTE full = nullptr;
    HRESULT hr = SHParseDisplayName(argv[1], nullptr, &full, 0, nullptr);
    if (FAILED(hr)) return 3;
    PIDLIST_ABSOLUTE parent = ILCloneFull(full);
    PCUITEMID_CHILD child = ILFindLastID(full);
    if (!parent || !ILRemoveLastID(parent)) return 4;
    hr = SHOpenFolderAndSelectItems(parent, 1, &child, 0);
    CoTaskMemFree(parent);
    CoTaskMemFree(full);
    CoUninitialize();
    return FAILED(hr) ? 5 : 0;
}

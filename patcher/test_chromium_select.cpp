#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>

#include <cstdio>

// Reproduces Chromium's ShowItemInFolderOnWorkerThread PIDL construction:
// parse both the folder and complete file through the desktop IShellFolder,
// then pass the complete file PIDL to SHOpenFolderAndSelectItems.
int wmain(int argc, wchar_t **argv) {
    if (argc != 2) return 2;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 3;

    wchar_t folderPath[32768] = {};
    if (wcslen(argv[1]) >= _countof(folderPath)) {
        CoUninitialize();
        return 4;
    }
    wcscpy_s(folderPath, argv[1]);
    wchar_t *lastSlash = wcsrchr(folderPath, L'\\');
    if (!lastSlash) {
        CoUninitialize();
        return 5;
    }
    lastSlash[1] = L'\0';

    IShellFolder *desktop = nullptr;
    hr = SHGetDesktopFolder(&desktop);
    if (FAILED(hr) || !desktop) {
        CoUninitialize();
        return 6;
    }

    PIDLIST_RELATIVE folder = nullptr;
    PIDLIST_RELATIVE file = nullptr;
    hr = desktop->ParseDisplayName(nullptr, nullptr, folderPath, nullptr, &folder, nullptr);
    if (SUCCEEDED(hr)) {
        hr = desktop->ParseDisplayName(nullptr, nullptr, argv[1], nullptr, &file, nullptr);
    }
    if (SUCCEEDED(hr)) {
        const ITEMIDLIST *selection[] = {file};
        hr = SHOpenFolderAndSelectItems(
            reinterpret_cast<PCIDLIST_ABSOLUTE>(folder), _countof(selection), selection, 0);
    }

    if (file) CoTaskMemFree(file);
    if (folder) CoTaskMemFree(folder);
    desktop->Release();
    CoUninitialize();

    ::wprintf(L"SHOpenFolderAndSelectItems returned 0x%08X\n", static_cast<unsigned>(hr));
    return FAILED(hr) ? 7 : 0;
}

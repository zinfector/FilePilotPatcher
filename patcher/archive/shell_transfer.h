#pragma once
#include "backend.h"
#include <oleidl.h>

namespace fpa {
// Returns nullptr if every source is a real filesystem path. No disk staging.
IDataObject* transferObject(const std::vector<std::wstring>& paths);
bool launchEntry(HWND owner,const std::wstring& path);
void showLaunchCache(HWND owner);
std::wstring utf8Path(const char* text,size_t length);
}

#pragma once
#define NOMINMAX
#include <windows.h>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <map>

namespace fpa {
using Bytes = std::vector<unsigned char>;
struct Entry {
    std::wstring path;
    unsigned index = ~0u;
    unsigned long long size = 0;
    FILETIME time{};
    bool directory = false;
};
class Archive {
    struct Impl;
    std::unique_ptr<Impl> impl;
public:
    std::vector<Entry> entries;
    explicit Archive(const std::wstring& path);
    ~Archive();
    std::shared_ptr<Bytes> read(unsigned index);
    Bytes readRange(unsigned index, unsigned long long offset, size_t length);
    void extractEntry(unsigned index, const std::wstring& destination);
    void extract(const std::wstring& destination);
};
struct Location {
    std::shared_ptr<Archive> archive;
    std::wstring inside;
    std::wstring physical;
    Entry entry;
};
bool extension(const std::wstring& name);
bool resolve(const wchar_t* path, Location& result);
std::vector<Entry> children(const Location& location);
void extractDialog(HWND owner);
}

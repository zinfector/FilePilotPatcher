#include "backend.h"
#include <algorithm>
#include <stdexcept>
#include <shlobj.h>
#include <commdlg.h>
#include "../vendor/7zip/CPP/7zip/Archive/IArchive.h"

extern "C" HRESULT WINAPI CreateObject(const GUID*, const GUID*, void**);
extern "C" HRESULT WINAPI GetNumberOfFormats(UINT32*);
extern "C" HRESULT WINAPI GetHandlerProperty2(UInt32, PROPID, PROPVARIANT*);

namespace fpa {
static std::wstring lower(std::wstring s) {
    if (!s.empty()) CharLowerBuffW(&s[0], (DWORD)s.size());
    return s;
}
bool recycleMetadataName(std::wstring_view name) {
    return name.size()>2 && name[0]==L'$' && (name[1]==L'I'||name[1]==L'i');
}
bool recyclePath(std::wstring_view path) {
    size_t start=0;
    for(size_t i=0;i<=path.size();++i){
        if(i!=path.size()&&path[i]!=L'\\'&&path[i]!=L'/')continue;
        auto part=path.substr(start,i-start);
        if(part.size()==12 && CompareStringOrdinal(part.data(),12,L"$Recycle.Bin",12,TRUE)==CSTR_EQUAL)return true;
        start=i+1;
    }
    return false;
}
bool recycleMetadata(std::wstring_view path) {
    if(!recyclePath(path))return false;
    size_t start=0;
    for(size_t i=0;i<=path.size();++i){
        if(i!=path.size()&&path[i]!=L'\\'&&path[i]!=L'/')continue;
        if(recycleMetadataName(path.substr(start,i-start)))return true;
        start=i+1;
    }
    return false;
}
bool extension(std::wstring_view name) {
    if(recycleMetadata(name))return false;
    auto p = name.find_last_of(L'.');
    if (p == std::wstring::npos) return false;
    const auto ext = name.substr(p);
    static constexpr std::wstring_view supported[] = {L".zip",L".rar",L".7z",L".tar",L".gz",L".gzip",L".bz2",L".xz",L".zst",L".cab",L".iso",L".wim",L".lzh",L".arj",L".cpio",L".tgz",L".tbz2",L".txz"};
    for (auto s : supported) {
        if(ext.size()!=s.size())continue;
        size_t i=0;for(;i<s.size();++i){auto c=ext[i];if(c>=L'A'&&c<=L'Z')c+=L'a'-L'A';if(c!=s[i])break;}
        if(i==s.size())return true;
    }
    return false;
}
bool archivePath(std::wstring_view path,bool includeLeaf){
    if(recycleMetadata(path))return false;
    size_t start=0;
    for(size_t i=0;i<=path.size();++i){
        if(i!=path.size()&&path[i]!=L'\\'&&path[i]!=L'/')continue;
        if((i!=path.size()||includeLeaf)&&extension(path.substr(start,i-start)))return true;
        start=i+1;
    }
    return false;
}
static bool normalize(std::wstring& s) {
    std::replace(s.begin(), s.end(), L'/', L'\\');
    while (!s.empty() && s.back() == L'\\') s.pop_back();
    if (s.empty() || s[0] == L'\\' || s.find(L':') != s.npos) return false;
    size_t pos = 0;
    while (pos < s.size()) {
        auto end = s.find(L'\\', pos);
        auto part = s.substr(pos, end == s.npos ? s.npos : end-pos);
        if (part.empty() || part == L"." || part == L".." || part.back()==L'.' || part.back()==L' ') return false;
        auto stem = lower(part.substr(0, part.find(L'.')));
        if (stem==L"con" || stem==L"prn" || stem==L"aux" || stem==L"nul" ||
            (stem.size()==4 && (stem.substr(0,3)==L"com" || stem.substr(0,3)==L"lpt") && stem[3]>=L'0' && stem[3]<=L'9')) return false;
        if (part.find_first_of(L"<>\"|?*") != part.npos) return false;
        if (end == s.npos) break;
        pos = end+1;
    }
    return true;
}
#define REFS \
    ULONG refs=1; \
    ULONG STDMETHODCALLTYPE AddRef() noexcept override {return InterlockedIncrement(&refs);} \
    ULONG STDMETHODCALLTYPE Release() noexcept override {auto n=InterlockedDecrement(&refs); if(!n) delete this; return n;}
class Input final : public IInStream {
    HANDLE file;
public:
    REFS
    explicit Input(const std::wstring& name) : file(CreateFileW(name.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {
        if (file==INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot read archive");
    }
    ~Input() {CloseHandle(file);}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** p) noexcept override {
        *p=nullptr;
        if (id==IID_IUnknown || id==IID_IInStream || id==IID_ISequentialInStream) {*p=static_cast<IInStream*>(this); AddRef(); return S_OK;}
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Read(void* p, UInt32 n, UInt32* done) noexcept override {
        DWORD d=0; BOOL ok=ReadFile(file,p,n,&d,nullptr); if(done)*done=d; return ok?S_OK:HRESULT_FROM_WIN32(GetLastError());
    }
    HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 origin, UInt64* result) noexcept override {
        LARGE_INTEGER o{},r{}; o.QuadPart=offset;
        if(!SetFilePointerEx(file,o,&r,origin)) return HRESULT_FROM_WIN32(GetLastError());
        if(result)*result=r.QuadPart; return S_OK;
    }
};
class Output final : public ISequentialOutStream {
public:
    REFS
    std::shared_ptr<Bytes> bytes;
    HANDLE file=INVALID_HANDLE_VALUE;
    bool ranged=false, rangeComplete=false, stopAfterRange=true;
    UInt64 skip=0;
    size_t remaining=0;
    explicit Output(std::shared_ptr<Bytes> b):bytes(b){}
    explicit Output(HANDLE h):file(h){}
    ~Output(){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** p) noexcept override {
        *p=nullptr; if(id==IID_IUnknown || id==IID_ISequentialOutStream){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Write(const void* p,UInt32 n,UInt32* done) noexcept override {
        if(done)*done=0;
        if(file!=INVALID_HANDLE_VALUE){DWORD d=0; BOOL ok=WriteFile(file,p,n,&d,nullptr);if(done)*done=d;return ok?S_OK:HRESULT_FROM_WIN32(GetLastError());}
        if(ranged){
            UInt32 bypass=(UInt32)std::min<UInt64>(skip,n);skip-=bypass;
            size_t take=std::min<size_t>(remaining,n-bypass);
            try{bytes->insert(bytes->end(),(const unsigned char*)p+bypass,(const unsigned char*)p+bypass+take);}catch(...){return E_OUTOFMEMORY;}
            remaining-=take;if(done)*done=n;
            if(!remaining){rangeComplete=true;if(stopAfterRange)return E_ABORT;}return S_OK;
        }
        // A process-local preview must never silently spill decompressed data to disk.
        if(bytes->size()+n > 256ull*1024*1024) return E_OUTOFMEMORY;
        try {bytes->insert(bytes->end(),(const unsigned char*)p,(const unsigned char*)p+n);}catch(...){return E_OUTOFMEMORY;}
        if(done)*done=n; return S_OK;
    }
};
class Extract final : public IArchiveExtractCallback {
public:
    REFS
    ISequentialOutStream* output;
    UInt32 wanted;
    Int32 result=-1;
    Extract(UInt32 i,ISequentialOutStream* o):output(o),wanted(i){output->AddRef();}
    ~Extract(){output->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** p) noexcept override {
        *p=nullptr;if(id==IID_IUnknown || id==IID_IProgress || id==IID_IArchiveExtractCallback){*p=this;AddRef();return S_OK;}return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE SetTotal(UInt64) noexcept override {return S_OK;}
    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*) noexcept override {return S_OK;}
    HRESULT STDMETHODCALLTYPE GetStream(UInt32 i,ISequentialOutStream** p,Int32 mode) noexcept override {
        *p=nullptr;if(i==wanted && mode==0){*p=output;output->AddRef();}return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) noexcept override {return S_OK;}
    HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 r) noexcept override {result=r;return S_OK;}
};
class OpenProgress final : public IArchiveOpenCallback {
public:
    REFS
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** p) noexcept override {
        *p=nullptr;
        if(id==IID_IUnknown || id==IID_IArchiveOpenCallback){*p=static_cast<IArchiveOpenCallback*>(this);AddRef();return S_OK;}
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE SetTotal(const UInt64*,const UInt64*) noexcept override {return S_OK;}
    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*,const UInt64*) noexcept override {return S_OK;}
};
struct Archive::Impl {
    IInArchive* reader=nullptr;
    Input* input=nullptr;
    std::mutex mutex;
    std::map<unsigned,std::weak_ptr<Bytes>> cache;
    ~Impl(){if(reader){reader->Close();reader->Release();}if(input)input->Release();}
    void extract(unsigned index,Output* output){
        auto cb=new Extract(index,output);output->Release();
        HRESULT hr=reader->Extract(&index,1,0,cb);auto status=cb->result;cb->Release();
        if(hr!=S_OK || status!=0) throw std::runtime_error("Cannot extract entry (encrypted, damaged, unsupported, or memory limit)");
    }
};
Archive::Archive(const std::wstring& path):impl(new Impl){
    impl->input=new Input(path);
    UINT32 count=0;GetNumberOfFormats(&count);
    std::wstring suffix=lower(path.substr(path.find_last_of(L'.')+1));
    for(int pass=0;pass<2 && !impl->reader;++pass) for(UINT32 i=0;i<count;++i){
        PROPVARIANT ext{};GetHandlerProperty2(i,2,&ext); // NArchive::NHandlerPropID::kExtension
        bool preferred=false;
        if(ext.vt==VT_BSTR){std::wstring e=L" "+lower(ext.bstrVal)+L" ";preferred=e.find(L" "+suffix+L" ")!=e.npos;}
        PropVariantClear(&ext);if(preferred!=(pass==0))continue;
        PROPVARIANT cls{};GetHandlerProperty2(i,1,&cls);
        IInArchive* candidate=nullptr;
        if(cls.vt==VT_BSTR && SysStringByteLen(cls.bstrVal)==sizeof(GUID))CreateObject((GUID*)cls.bstrVal,&IID_IInArchive,(void**)&candidate);
        PropVariantClear(&cls);if(!candidate)continue;
        impl->input->Seek(0,0,nullptr);UInt64 probe=1<<20;
        // Some format probes (including Base64) unconditionally report progress.
        auto progress=new OpenProgress;
        HRESULT opened=candidate->Open(impl->input,&probe,progress);progress->Release();
        if(opened==S_OK)impl->reader=candidate;
        else candidate->Release();
        if(impl->reader)break;
    }
    if(!impl->reader)throw std::runtime_error("Unsupported, encrypted, or damaged archive");
    UInt32 n=0;impl->reader->GetNumberOfItems(&n);
    std::map<std::wstring,Entry> tree;
    for(UInt32 i=0;i<n;++i){
        Entry e;e.index=i;PROPVARIANT v{};
        impl->reader->GetProperty(i,kpidPath,&v);if(v.vt==VT_BSTR)e.path=v.bstrVal;PropVariantClear(&v);
        if(e.path.empty()){e.path=path.substr(path.find_last_of(L"\\/")+1);e.path=e.path.substr(0,e.path.find_last_of(L'.'));}
        if(!normalize(e.path))continue;
        impl->reader->GetProperty(i,kpidIsDir,&v);e.directory=v.vt==VT_BOOL && v.boolVal;PropVariantClear(&v);
        impl->reader->GetProperty(i,kpidSize,&v);if(v.vt==VT_UI8)e.size=v.uhVal.QuadPart;else if(v.vt==VT_UI4)e.size=v.ulVal;PropVariantClear(&v);
        impl->reader->GetProperty(i,kpidMTime,&v);if(v.vt==VT_FILETIME)e.time=v.filetime;PropVariantClear(&v);
        // Do not project archive links into the host namespace.
        impl->reader->GetProperty(i,kpidSymLink,&v);bool link=v.vt==VT_BSTR && SysStringLen(v.bstrVal);PropVariantClear(&v);if(link)continue;
        auto key=lower(e.path);auto existing=tree.find(key);
        if(existing==tree.end() || existing->second.index==~0u)tree[key]=e;
        for(auto end=e.path.find(L'\\');end!=e.path.npos;end=e.path.find(L'\\',end+1)){
            auto parent=e.path.substr(0,end);auto k=lower(parent);
            if(!tree.count(k)){Entry d;d.path=parent;d.directory=true;tree.emplace(k,d);}
        }
    }
    for(auto& pair:tree)entries.push_back(pair.second);
}
Archive::~Archive()=default;
Bytes Archive::readRange(unsigned index,unsigned long long offset,size_t length){
    if(!length)return {};
    std::lock_guard<std::mutex> lock(impl->mutex);
    auto bytes=std::make_shared<Bytes>();auto output=new Output(bytes);
    output->ranged=true;output->skip=offset;output->remaining=length;
    for(auto& e:entries)if(e.index==index){output->stopAfterRange=offset+length<e.size;break;}
    auto cb=new Extract(index,output);
    HRESULT hr=impl->reader->Extract(&index,1,0,cb);
    bool stopped=output->rangeComplete && output->stopAfterRange;auto result=cb->result;cb->Release();output->Release();
    if(!stopped && (hr!=S_OK || result!=0))throw std::runtime_error("Cannot decode archive entry");
    return std::move(*bytes);
}
void Archive::extractEntry(unsigned index,const std::wstring& path){
    std::lock_guard<std::mutex> lock(impl->mutex);
    HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create launch file");
    try{impl->extract(index,new Output(file));}catch(...){DeleteFileW(path.c_str());throw;}
}
std::shared_ptr<Bytes> Archive::read(unsigned index){
    std::lock_guard<std::mutex> lock(impl->mutex);
    auto data=impl->cache[index].lock();if(data)return data;
    data=std::make_shared<Bytes>();impl->extract(index,new Output(data));impl->cache[index]=data;return data;
}
static void directory(const std::wstring& path){
    // Every extraction ancestor must be a real directory, never a junction/symlink.
    size_t root=3;
    if(path.rfind(L"\\\\",0)==0){auto server=path.find(L'\\',2);root=server==path.npos?path.size():server+1;}
    for(size_t i=path.find(L'\\',root);;i=path.find(L'\\',i+1)){
        auto part=i==path.npos?path:path.substr(0,i);
        DWORD attrs=GetFileAttributesW(part.c_str());
        if(attrs==INVALID_FILE_ATTRIBUTES){if(!CreateDirectoryW(part.c_str(),nullptr) && GetLastError()!=ERROR_ALREADY_EXISTS)throw std::runtime_error("Cannot create extraction directory");attrs=GetFileAttributesW(part.c_str());}
        if(!(attrs&FILE_ATTRIBUTE_DIRECTORY) || (attrs&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Extraction destination contains a link or non-directory");
        if(i==path.npos)break;
    }
}
void Archive::extract(const std::wstring& dest){
    std::lock_guard<std::mutex> lock(impl->mutex);directory(dest);
    for(auto& e:entries){auto path=dest+L"\\"+e.path;
        if(e.directory){directory(path);continue;}
        directory(path.substr(0,path.find_last_of(L'\\')));
        HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(h==INVALID_HANDLE_VALUE)throw std::runtime_error("Destination file exists or cannot be created");
        try{impl->extract(e.index,new Output(h));}catch(...){DeleteFileW(path.c_str());throw;}
    }
}
static std::mutex archivesMutex;
struct Cached {std::wstring path;FILETIME time;ULONGLONG size;std::shared_ptr<Archive> archive;};
static std::vector<Cached> archives;
bool cachedDirectory(const wchar_t* raw,bool& directory){
    if(!raw || !archivePath(raw))return false;
    std::wstring path=raw;std::replace(path.begin(),path.end(),L'/',L'\\');
    while(path.size()>3 && path.back()==L'\\')path.pop_back();
    auto key=lower(path);
    std::shared_ptr<Archive> archive;size_t prefix=0;
    {
        std::lock_guard<std::mutex> lock(archivesMutex);
        for(auto& cached:archives){
            auto root=lower(cached.path);
            if(key.size()>root.size() && key.compare(0,root.size(),root)==0 && key[root.size()]==L'\\'){
                archive=cached.archive;prefix=root.size()+1;break;
            }
        }
    }
    if(!archive)return false;
    auto inside=key.substr(prefix);
    // Constructor emits entries in the lowercase tree's sorted order.
    auto found=std::lower_bound(archive->entries.begin(),archive->entries.end(),inside,
        [](const Entry& entry,const std::wstring& value){return lower(entry.path)<value;});
    if(found==archive->entries.end() || lower(found->path)!=inside)return false;
    directory=found->directory;return true;
}
bool resolve(const wchar_t* raw,Location& out){
    if(!raw || !archivePath(raw))return false;std::wstring path=raw;std::replace(path.begin(),path.end(),L'/',L'\\');
    while(path.size()>3 && path.back()==L'\\')path.pop_back();
    for(size_t end=0;end<=path.size();++end){
        if(end!=path.size() && path[end]!=L'\\')continue;
        auto prefix=path.substr(0,end);if(!extension(prefix))continue;
        WIN32_FILE_ATTRIBUTE_DATA attrs{};
        if(!GetFileAttributesExW(prefix.c_str(),GetFileExInfoStandard,&attrs) || (attrs.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))continue;
        out.physical=prefix;out.inside=end==path.size()?L"":path.substr(end+1);
        std::unique_lock<std::mutex> lock(archivesMutex);
        auto key=lower(prefix);auto size=((ULONGLONG)attrs.nFileSizeHigh<<32)|attrs.nFileSizeLow;
        for(auto& c:archives)if(lower(c.path)==key && c.size==size && CompareFileTime(&c.time,&attrs.ftLastWriteTime)==0){out.archive=c.archive;break;}
        if(!out.archive){
            // Codec I/O and indexing must not serialize unrelated archive lookups.
            lock.unlock();auto opened=std::make_shared<Archive>(prefix);lock.lock();
            for(auto& c:archives)if(lower(c.path)==key && c.size==size && CompareFileTime(&c.time,&attrs.ftLastWriteTime)==0){out.archive=c.archive;break;}
            std::shared_ptr<Archive> retired;
            if(!out.archive){
                out.archive=opened;
                if(archives.size()==4){retired=std::move(archives.front().archive);archives.erase(archives.begin());}
                archives.push_back({prefix,attrs.ftLastWriteTime,size,out.archive});
            }
            lock.unlock(); // Release redundant/evicted readers outside the cache lock too.
        }else lock.unlock();
        out.entry.directory=true;
        if(out.inside.empty())return true;
        auto insideKey=lower(out.inside);
        for(auto& e:out.archive->entries)if(lower(e.path)==insideKey){out.entry=e;return true;}
        throw std::runtime_error("Archive entry does not exist");
    }
    return false;
}
std::vector<Entry> children(const Location& loc){
    std::vector<Entry> list;auto prefix=loc.inside.empty()?L"":loc.inside+L"\\";
    for(auto e:loc.archive->entries){if(e.path.size()<=prefix.size() || lower(e.path.substr(0,prefix.size()))!=lower(prefix))continue;
        auto tail=e.path.substr(prefix.size());if(tail.find(L'\\')!=tail.npos)continue;e.path=tail;list.push_back(e);}
    return list;
}
void extractDialog(HWND owner){
    wchar_t source[32768]{};OPENFILENAMEW ofn{sizeof(ofn)};ofn.hwndOwner=owner;ofn.lpstrFile=source;ofn.nMaxFile=32768;
    ofn.lpstrTitle=L"Extract archive directly to a destination";ofn.lpstrFilter=L"Archives\0*.zip;*.rar;*.7z;*.tar;*.gz;*.bz2;*.xz;*.cab;*.iso;*.wim\0All files\0*.*\0";ofn.Flags=OFN_FILEMUSTEXIST|OFN_NOCHANGEDIR;
    if(!GetOpenFileNameW(&ofn))return;
    BROWSEINFOW bi{};bi.hwndOwner=owner;bi.lpszTitle=L"Choose extraction destination (existing files are not overwritten)";bi.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
    auto pidl=SHBrowseForFolderW(&bi);if(!pidl)return;wchar_t dest[MAX_PATH]{};bool ok=SHGetPathFromIDListW(pidl,dest)!=0;CoTaskMemFree(pidl);if(!ok)return;
    try{Archive archive(source);archive.extract(dest);MessageBoxW(owner,L"Extraction complete.",L"File Pilot archives",MB_OK);}
    catch(const std::exception& e){MessageBoxA(owner,e.what(),"File Pilot archives",MB_OK|MB_ICONERROR);}
    catch(...){MessageBoxW(owner,L"Archive extraction failed.",L"File Pilot archives",MB_OK|MB_ICONERROR);}
}
}

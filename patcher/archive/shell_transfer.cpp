#include "shell_transfer.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <set>
#include <stdexcept>
#include <limits>

namespace fpa {
std::wstring utf8Path(const char* text,size_t length){
    if(!text || !length)return {};
    if(length>INT_MAX)throw std::runtime_error("Path is too long");
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text,(int)length,nullptr,0);
    if(!n)throw std::runtime_error("Invalid path encoding");
    std::wstring out(n,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text,(int)length,&out[0],n);return out;
}
static std::wstring fold(std::wstring s){if(!s.empty())CharLowerBuffW(&s[0],(DWORD)s.size());return s;}
static bool prefix(const std::wstring& p,const std::wstring& root){return p.size()>root.size() && p[root.size()]==L'\\' && _wcsnicmp(p.c_str(),root.c_str(),root.size())==0;}
struct TransferFile {
    std::wstring name,physical;
    std::shared_ptr<Archive> archive;
    Entry entry;
};
static HRESULT failure(){return HRESULT_FROM_WIN32(GetLastError());}

class EntryStream final:public IStream {
    std::atomic<ULONG> refs{1};
    TransferFile source;
    ULONGLONG position=0,windowStart=0;
    Bytes window;
    std::shared_ptr<Bytes> cachedBytes;
    HANDLE file=INVALID_HANDLE_VALUE;
    IUnknown* marshaler=nullptr;
    std::mutex mutex;
public:
    explicit EntryStream(const TransferFile& f):source(f){
        CoCreateFreeThreadedMarshaler(static_cast<IStream*>(this),&marshaler);
        if(!source.archive){file=CreateFileW(source.physical.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);if(file==INVALID_HANDLE_VALUE){if(marshaler)marshaler->Release();throw std::runtime_error("Cannot read transfer source");}}
    }
    ~EntryStream(){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);if(marshaler)marshaler->Release();}
    ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release() override{ULONG n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** p) override{
        if(!p)return E_POINTER;*p=nullptr;
        if(id==IID_IUnknown||id==IID_ISequentialStream||id==IID_IStream){*p=static_cast<IStream*>(this);AddRef();return S_OK;}
        if(id==IID_IMarshal && marshaler)return marshaler->QueryInterface(id,p);return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Read(void* dest,ULONG size,ULONG* done) override{
        if(done)*done=0;if(!dest && size)return STG_E_INVALIDPOINTER;
        try{
            std::lock_guard<std::mutex> lock(mutex);ULONG total=0;
            while(total<size && position<source.entry.size){
                ULONG n=(ULONG)std::min<ULONGLONG>(size-total,source.entry.size-position);
                if(!source.archive){LARGE_INTEGER at{};at.QuadPart=position;if(!SetFilePointerEx(file,at,nullptr,FILE_BEGIN))return failure();DWORD count=0;if(!ReadFile(file,(BYTE*)dest+total,n,&count,nullptr))return failure();n=count;}
                else if(source.entry.size<=32ull*1024*1024){if(!cachedBytes)cachedBytes=source.archive->read(source.entry.index);n=(ULONG)std::min<ULONGLONG>(n,cachedBytes->size()>position?cachedBytes->size()-position:0);if(n)memcpy((BYTE*)dest+total,cachedBytes->data()+position,n);}
                else{
                    // Seekable, bounded RAM fallback: decode a read-ahead window. Seeking
                    // or advancing may replay compressed input; nothing is spooled to disk.
                    if(window.empty()||position<windowStart||position>=windowStart+window.size()){
                        windowStart=position;window=source.archive->readRange(source.entry.index,position,(size_t)std::min<ULONGLONG>(8ull*1024*1024,source.entry.size-position));
                    }
                    n=(ULONG)std::min<size_t>(n,window.size()-(size_t)(position-windowStart));
                    if(n)memcpy((BYTE*)dest+total,window.data()+position-windowStart,n);
                }
                if(!n)return STG_E_READFAULT;position+=n;total+=n;if(done)*done=total;
            }
            return total==size?S_OK:S_FALSE;
        }catch(const std::bad_alloc&){return E_OUTOFMEMORY;}catch(...){return STG_E_READFAULT;}
    }
    HRESULT STDMETHODCALLTYPE Write(const void*,ULONG,ULONG* n) override{if(n)*n=0;return STG_E_ACCESSDENIED;}
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER delta,DWORD origin,ULARGE_INTEGER* result) override{
        std::lock_guard<std::mutex> lock(mutex);ULONGLONG base;
        if(origin==STREAM_SEEK_SET)base=0;else if(origin==STREAM_SEEK_CUR)base=position;else if(origin==STREAM_SEEK_END)base=source.entry.size;else return STG_E_INVALIDFUNCTION;
        if(delta.QuadPart<0){ULONGLONG back=0-(ULONGLONG)delta.QuadPart;if(back>base)return STG_E_INVALIDFUNCTION;position=base-back;}
        else{if((ULONGLONG)delta.QuadPart>ULLONG_MAX-base)return STG_E_INVALIDFUNCTION;position=base+delta.QuadPart;}
        if(result)result->QuadPart=position;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER) override{return STG_E_ACCESSDENIED;}
    HRESULT STDMETHODCALLTYPE CopyTo(IStream* target,ULARGE_INTEGER amount,ULARGE_INTEGER* read,ULARGE_INTEGER* written) override{
        if(read)read->QuadPart=0;if(written)written->QuadPart=0;if(!target)return E_POINTER;
        BYTE buffer[65536];ULONGLONG total=0;
        while(total<amount.QuadPart){ULONG n=0;HRESULT hr=Read(buffer,(ULONG)std::min<ULONGLONG>(sizeof(buffer),amount.QuadPart-total),&n);if(read)read->QuadPart+=n;
            ULONG off=0;while(off<n){ULONG w=0;HRESULT whr=target->Write(buffer+off,n-off,&w);if(written)written->QuadPart+=w;if(FAILED(whr))return whr;if(!w)return STG_E_WRITEFAULT;off+=w;}
            total+=n;if(hr!=S_OK)return hr;
        }return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Commit(DWORD) override{return S_OK;}
    HRESULT STDMETHODCALLTYPE Revert() override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD) override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD) override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* stat,DWORD flags) override{
        if(!stat)return E_POINTER;memset(stat,0,sizeof(*stat));stat->type=STGTY_STREAM;stat->cbSize.QuadPart=source.entry.size;stat->mtime=source.entry.time;stat->grfMode=STGM_READ;
        if(!(flags&STATFLAG_NONAME)){size_t bytes=(source.name.size()+1)*2;stat->pwcsName=(LPWSTR)CoTaskMemAlloc(bytes);if(!stat->pwcsName)return E_OUTOFMEMORY;memcpy(stat->pwcsName,source.name.c_str(),bytes);}return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Clone(IStream** result) override{
        if(!result)return E_POINTER;*result=nullptr;try{std::lock_guard<std::mutex> lock(mutex);auto clone=new EntryStream(source);clone->position=position;clone->cachedBytes=cachedBytes;*result=clone;return S_OK;}catch(...){return E_OUTOFMEMORY;}
    }
};

class Files final:public IDataObject {
    std::atomic<ULONG> refs{1};
    std::vector<TransferFile> files;
    CLIPFORMAT descriptors=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW);
    CLIPFORMAT contents=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS);
    CLIPFORMAT preferred=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_PREFERREDDROPEFFECT);
    CLIPFORMAT performed=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_PERFORMEDDROPEFFECT);
    CLIPFORMAT logical=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_LOGICALPERFORMEDDROPEFFECT);
    CLIPFORMAT pasted=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_PASTESUCCEEDED);
    IUnknown* marshaler=nullptr;
public:
    explicit Files(std::vector<TransferFile> list):files(std::move(list)){CoCreateFreeThreadedMarshaler(static_cast<IDataObject*>(this),&marshaler);}
    ~Files(){if(marshaler)marshaler->Release();}
    ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release() override{ULONG n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void** p) override{
        if(!p)return E_POINTER;*p=nullptr;if(id==IID_IUnknown||id==IID_IDataObject){*p=static_cast<IDataObject*>(this);AddRef();return S_OK;}
        if(id==IID_IMarshal && marshaler)return marshaler->QueryInterface(id,p);return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC* f) override{
        if(!f)return E_POINTER;if(f->dwAspect!=DVASPECT_CONTENT)return DV_E_DVASPECT;
        if(f->cfFormat==contents){if(!(f->tymed&TYMED_ISTREAM))return DV_E_TYMED;if(f->lindex<0||(size_t)f->lindex>=files.size()||files[f->lindex].entry.directory)return DV_E_LINDEX;return S_OK;}
        if(f->cfFormat==descriptors||f->cfFormat==preferred){if(f->lindex!=-1)return DV_E_LINDEX;return(f->tymed&TYMED_HGLOBAL)?S_OK:DV_E_TYMED;}return DV_E_FORMATETC;
    }
    HRESULT STDMETHODCALLTYPE GetData(FORMATETC* f,STGMEDIUM* out) override{
        if(!out)return E_POINTER;memset(out,0,sizeof(*out));HRESULT hr=QueryGetData(f);if(FAILED(hr))return hr;
        try{
            if(f->cfFormat==contents){out->pstm=new EntryStream(files[f->lindex]);out->tymed=TYMED_ISTREAM;return S_OK;}
            SIZE_T bytes=f->cfFormat==preferred?sizeof(DWORD):FIELD_OFFSET(FILEGROUPDESCRIPTORW,fgd)+files.size()*sizeof(FILEDESCRIPTORW);
            HGLOBAL mem=GlobalAlloc(GMEM_MOVEABLE|GMEM_ZEROINIT,bytes);if(!mem)return E_OUTOFMEMORY;
            void* ptr=GlobalLock(mem);if(!ptr){GlobalFree(mem);return E_OUTOFMEMORY;}
            if(f->cfFormat==preferred)*(DWORD*)ptr=DROPEFFECT_COPY;
            else{auto group=(FILEGROUPDESCRIPTORW*)ptr;group->cItems=(UINT)files.size();for(size_t i=0;i<files.size();++i){auto& d=group->fgd[i];auto& file=files[i];
                d.dwFlags=FD_ATTRIBUTES|FD_WRITESTIME|FD_PROGRESSUI|FD_UNICODE;
                d.dwFileAttributes=file.entry.directory?FILE_ATTRIBUTE_DIRECTORY:FILE_ATTRIBUTE_NORMAL;
                d.ftLastWriteTime=file.entry.time;if(!file.entry.directory){d.dwFlags|=FD_FILESIZE;d.nFileSizeHigh=(DWORD)(file.entry.size>>32);d.nFileSizeLow=(DWORD)file.entry.size;}
                memcpy(d.cFileName,file.name.c_str(),(file.name.size()+1)*2);
            }}
            GlobalUnlock(mem);out->tymed=TYMED_HGLOBAL;out->hGlobal=mem;return S_OK;
        }catch(const std::bad_alloc&){return E_OUTOFMEMORY;}catch(...){return STG_E_READFAULT;}
    }
    HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC*,STGMEDIUM*) override{return DATA_E_FORMATETC;}
    HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC*,FORMATETC* out) override{if(out)out->ptd=nullptr;return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE SetData(FORMATETC* f,STGMEDIUM* m,BOOL release) override{
        if(!f||!m)return E_POINTER;
        if(f->cfFormat!=performed&&f->cfFormat!=logical&&f->cfFormat!=pasted)return DV_E_FORMATETC;
        if(m->tymed!=TYMED_HGLOBAL)return DV_E_TYMED;
        // A target's move notification must never cause removal from the archive.
        if(release)ReleaseStgMedium(m);return S_OK;
    }
    HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD direction,IEnumFORMATETC** out) override{
        if(!out)return E_POINTER;*out=nullptr;if(direction!=DATADIR_GET)return E_NOTIMPL;
        FORMATETC formats[]={{descriptors,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL},{contents,nullptr,DVASPECT_CONTENT,-1,TYMED_ISTREAM},{preferred,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL}};
        return SHCreateStdEnumFmtEtc(3,formats,out);
    }
    HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC*,DWORD,IAdviseSink*,DWORD*) override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE DUnadvise(DWORD) override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA** p) override{if(p)*p=nullptr;return OLE_E_ADVISENOTSUPPORTED;}
};

static void addPhysical(std::vector<TransferFile>& files,const std::wstring& path,const std::wstring& name){
    WIN32_FILE_ATTRIBUTE_DATA d{};if(!GetFileAttributesExW(path.c_str(),GetFileExInfoStandard,&d))throw std::runtime_error("Transfer source is unavailable");
    if(d.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)throw std::runtime_error("Mixed archive transfers do not follow filesystem links");
    TransferFile f;f.name=name;f.physical=path;f.entry.directory=(d.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0;f.entry.size=((ULONGLONG)d.nFileSizeHigh<<32)|d.nFileSizeLow;f.entry.time=d.ftLastWriteTime;files.push_back(f);
    if(!f.entry.directory)return;
    WIN32_FIND_DATAW child{};HANDLE h=FindFirstFileW((path+L"\\*").c_str(),&child);
    if(h==INVALID_HANDLE_VALUE){if(GetLastError()==ERROR_FILE_NOT_FOUND)return;throw std::runtime_error("Cannot enumerate transfer directory");}
    try{do{if(wcscmp(child.cFileName,L".")==0||wcscmp(child.cFileName,L"..")==0)continue;addPhysical(files,path+L"\\"+child.cFileName,name+L"\\"+child.cFileName);}while(FindNextFileW(h,&child));}catch(...){FindClose(h);throw;}FindClose(h);
}
IDataObject* transferObject(const std::vector<std::wstring>& input){
    struct Root{std::wstring path;Location loc;bool virtualEntry=false;};
    std::vector<Root> roots;bool hasVirtual=false;
    for(auto path:input){std::replace(path.begin(),path.end(),L'/',L'\\');while(path.size()>3&&path.back()==L'\\')path.pop_back();Root root;root.path=path;
        // A selected container is copied as the original file, not expanded.
        if(GetFileAttributesW(path.c_str())==INVALID_FILE_ATTRIBUTES){root.virtualEntry=resolve(path.c_str(),root.loc)&&!root.loc.inside.empty();hasVirtual|=root.virtualEntry;}
        roots.push_back(std::move(root));}
    if(!hasVirtual)return nullptr;
    std::vector<TransferFile> files;std::set<std::wstring> names;
    for(size_t i=0;i<roots.size();++i){auto& root=roots[i];bool covered=false;for(size_t j=0;j<roots.size();++j)if(j!=i&&(prefix(root.path,roots[j].path)||(j<i&&fold(root.path)==fold(roots[j].path)))){covered=true;break;}if(covered)continue;
        std::wstring name=root.path.substr(root.path.find_last_of(L'\\')+1),candidate=name;unsigned serial=2;
        while(names.count(fold(candidate))){auto dot=name.find_last_of(L'.');if(dot==name.npos)dot=name.size();candidate=name.substr(0,dot)+L" ("+std::to_wstring(serial++)+L")"+name.substr(dot);}name=candidate;names.insert(fold(name));
        if(!root.virtualEntry){addPhysical(files,root.path,name);continue;}
        files.push_back({name,L"",root.loc.archive,root.loc.entry});
        if(root.loc.entry.directory)for(auto& e:root.loc.archive->entries)if(prefix(e.path,root.loc.inside))files.push_back({name+e.path.substr(root.loc.inside.size()),L"",root.loc.archive,e});
    }
    for(auto& f:files)if(f.name.size()>=MAX_PATH)throw std::runtime_error("A transfer path exceeds the Shell virtual-file descriptor limit");
    return new Files(std::move(files));
}

static std::wstring cacheRoot(){
    PWSTR local=nullptr;HRESULT hr=SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&local);if(FAILED(hr))throw std::runtime_error("Cannot locate launch cache");std::wstring path=std::wstring(local)+L"\\FilePilotArchiveLaunch";CoTaskMemFree(local);
    if(!CreateDirectoryW(path.c_str(),nullptr)&&GetLastError()!=ERROR_ALREADY_EXISTS)throw std::runtime_error("Cannot create launch cache");
    DWORD attrs=GetFileAttributesW(path.c_str());if(attrs==INVALID_FILE_ATTRIBUTES||!(attrs&FILE_ATTRIBUTE_DIRECTORY)||(attrs&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Launch cache is not a regular directory");return path;
}
static void copyZone(const std::wstring& source,const std::wstring& destination){
    HANDLE in=CreateFileW((source+L":Zone.Identifier").c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
    if(in==INVALID_HANDLE_VALUE)return;char data[65536];DWORD n=0;BOOL ok=ReadFile(in,data,sizeof(data),&n,nullptr);CloseHandle(in);if(!ok||!n)return;
    HANDLE out=CreateFileW((destination+L":Zone.Identifier").c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,0,nullptr);if(out==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot preserve archive security-zone metadata");DWORD written=0;ok=WriteFile(out,data,n,&written,nullptr);CloseHandle(out);if(!ok||written!=n)throw std::runtime_error("Cannot preserve archive security-zone metadata");
}
bool launchEntry(HWND owner,const std::wstring& path){
    // Never extract a real on-disk archive merely because it has an archive suffix.
    if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES)return false;
    Location loc;if(!resolve(path.c_str(),loc)||loc.inside.empty()||loc.entry.directory)return false;
    auto root=cacheRoot();GUID id{};if(FAILED(CoCreateGuid(&id)))throw std::runtime_error("Cannot name launch session");wchar_t guid[40];StringFromGUID2(id,guid,40);
    auto directory=root+L"\\"+guid;if(!CreateDirectoryW(directory.c_str(),nullptr))throw std::runtime_error("Cannot create launch session");
    auto name=loc.inside.substr(loc.inside.find_last_of(L'\\')+1);auto file=directory+L"\\"+name;
    try{loc.archive->extractEntry(loc.entry.index,file);copyZone(loc.physical,file);SetFileAttributesW(file.c_str(),FILE_ATTRIBUTE_READONLY);
        SHELLEXECUTEINFOW info{sizeof(info)};info.hwnd=owner;info.fMask=SEE_MASK_FLAG_NO_UI|SEE_MASK_NOASYNC;info.lpVerb=L"open";info.lpFile=file.c_str();info.lpDirectory=directory.c_str();info.nShow=SW_SHOWNORMAL;
        if(!ShellExecuteExW(&info))throw std::runtime_error("Windows could not open the cached entry with its associated application");
    }catch(...){SetFileAttributesW(file.c_str(),FILE_ATTRIBUTE_NORMAL);DeleteFileW(file.c_str());RemoveDirectoryW(directory.c_str());throw;}
    // Retain the copy across File Pilot shutdown: associated apps can reuse existing
    // processes and hold no detectable handle. Explicit cache access avoids timed deletion.
    return true;
}
void showLaunchCache(HWND owner){auto path=cacheRoot();ShellExecuteW(owner,L"open",path.c_str(),nullptr,nullptr,SW_SHOWNORMAL);}
}


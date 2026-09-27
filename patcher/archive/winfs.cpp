// Host-only Win32 adapter. The embedded engine uses its own unhooked IAT.
#include "backend.h"
#include "bindings.h"
#include "shell_transfer.h"
#include <winternl.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <algorithm>
#include <cstring>

namespace {
using namespace fpa;
using NtQuery = NTSTATUS(NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS,BOOLEAN,PUNICODE_STRING,BOOLEAN);
NtQuery ntQuery;
ArchiveBinding native{};
using OpenSelection = void(__fastcall*)(void*,BYTE*,int*);
using DescribeItem = BYTE*(__fastcall*)(void*,BYTE*);
OpenSelection originalOpen;
DescribeItem describeItem;
using Clipboard = int(__fastcall*)(BYTE*);
using Drag = void(__fastcall*)(BYTE*,size_t*,size_t*);
Clipboard originalClipboard;
Drag originalDrag;
using SidebarOpen = void(__fastcall*)(void*,size_t*,int);
SidebarOpen originalSidebarOpen;

void __fastcall sidebarOpen(void* app,size_t* path,int directory){
    // Recents/Places supply a cached type flag instead of using panel Open.
    // Only archive candidates need an attribute query; never index a container here.
    if(!directory && path){
        try{
            auto name=utf8Path((const char*)path[0],path[1]);
            if(archivePath(name)){
                DWORD physical=GetFileAttributesW(name.c_str());
                if(physical!=INVALID_FILE_ATTRIBUTES){
                    if((physical&FILE_ATTRIBUTE_DIRECTORY)||extension(name))directory=1;
                }else{
                    Location loc;
                    if(resolve(name.c_str(),loc)){
                        if(loc.entry.directory)directory=1;
                        else if(launchEntry(GetActiveWindow(),name))return;
                    }
                }
            }
        }catch(const std::exception& e){MessageBoxA(GetActiveWindow(),e.what(),"File Pilot archives",MB_OK|MB_ICONERROR);return;}
        catch(...){MessageBoxA(GetActiveWindow(),"Cannot open archive path.","File Pilot archives",MB_OK|MB_ICONERROR);return;}
    }
    originalSidebarOpen(app,path,directory);
}

std::wstring itemPath(BYTE* model,BYTE* item){
    if(!item)return {};
    BYTE* descriptor=describeItem(model,item);if(!descriptor)return {};
    auto path=*(const char**)(descriptor+native.descriptorPathOffset);
    auto length=*(LONGLONG*)(descriptor+native.descriptorLengthOffset);
    return length>0?utf8Path(path,(size_t)length):std::wstring{};
}
void reportShellError(const char* message){MessageBoxA(GetActiveWindow(),message,"File Pilot archives",MB_OK|MB_ICONERROR);}
bool openVirtualFile(BYTE* model,BYTE* item){
    try{return launchEntry(GetActiveWindow(),itemPath(model,item));}
    catch(const std::exception& e){reportShellError(e.what());return true;}
    catch(...){reportShellError("Cannot open archive entry.");return true;}
}

void classifyArchive(BYTE* model,BYTE* item){
    if(!item)return;
    auto flags=(DWORD*)(item+native.itemFlagsOffset);
    if(*flags&2)return;
    BYTE* descriptor=describeItem(model,item);
    if(!descriptor)return;
    auto path=*(const char**)(descriptor+native.descriptorPathOffset);
    auto length=*(LONGLONG*)(descriptor+native.descriptorLengthOffset);
    if(!path || length<=0 || length>32767*4)return;
    int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,(int)length,nullptr,0);
    if(!count)return;
    std::wstring name(count,L'\0');
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,(int)length,&name[0],count);
    if(!extension(name))return;
    DWORD attributes=GetFileAttributesW(name.c_str());
    if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_DIRECTORY))return;
    // This is the bit consumed by FUN_14005e090, distinct from Win32's 0x10.
    *flags|=2;
}
void __fastcall openSelection(void* app,BYTE* panel,int* options){
    if(panel && options && options[0]==0){
        BYTE* model=*(BYTE**)(panel+native.panelModelOffset);
        if(*(DWORD*)(panel+native.panelSelectionModeOffset)==0){
            if(openVirtualFile(model,*(BYTE**)(panel+native.panelCursorOffset)))return;
        }else{
            try{
                auto count=*(size_t*)(panel+native.panelSelectionCountOffset);
                auto items=*(BYTE**)(panel+native.panelSelectionArrayOffset);
                std::vector<BYTE> remaining;remaining.reserve(count*native.selectionStride);
                for(size_t i=0;i<count;++i){auto record=items+i*native.selectionStride;
                    if(!openVirtualFile(model,*(BYTE**)record))remaining.insert(remaining.end(),record,record+native.selectionStride);}
                if(remaining.size()!=count*native.selectionStride){
                    if(remaining.empty())return;
                    // The native handler snapshots records synchronously. Restore the
                    // selection immediately after dispatching only the unhandled items.
                    struct Restore{BYTE* panel;size_t count;BYTE* items;~Restore(){*(size_t*)(panel+native.panelSelectionCountOffset)=count;*(BYTE**)(panel+native.panelSelectionArrayOffset)=items;}} restore{panel,count,items};
                    *(size_t*)(panel+native.panelSelectionCountOffset)=remaining.size()/native.selectionStride;
                    *(BYTE**)(panel+native.panelSelectionArrayOffset)=remaining.data();
                    for(size_t i=0;i<remaining.size();i+=native.selectionStride)classifyArchive(model,*(BYTE**)(remaining.data()+i));
                    originalOpen(app,panel,options);return;
                }
            }catch(...){reportShellError("Cannot prepare archive entry selection.");return;}
        }
    }
    // Explicit "open externally" remains available. Normal Open enters archives.
    if(panel && options && options[1]==0){
        try{
            BYTE* model=*(BYTE**)(panel+native.panelModelOffset);
            if(*(DWORD*)(panel+native.panelSelectionModeOffset)==0)
                classifyArchive(model,*(BYTE**)(panel+native.panelCursorOffset));
            else{
                auto count=*(size_t*)(panel+native.panelSelectionCountOffset);
                auto items=*(BYTE**)(panel+native.panelSelectionArrayOffset);
                for(size_t i=0;i<count;++i)classifyArchive(model,*(BYTE**)(items+i*native.selectionStride));
            }
        }catch(...){/* Allocation failure leaves the normal native action available. */}
    }
    originalOpen(app,panel,options);
}
void jump(BYTE* at,const void* target){
    at[0]=0xff;at[1]=0x25;*(DWORD*)(at+2)=0;memcpy(at+6,&target,8);
}
void* detour(BYTE* entry,DWORD span,void* replacement){
    BYTE* trampoline=(BYTE*)VirtualAlloc(nullptr,span+14,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!trampoline)return nullptr;memcpy(trampoline,entry,span);jump(trampoline+span,entry+span);
    DWORD old;VirtualProtect(trampoline,span+14,PAGE_EXECUTE_READ,&old);
    if(!VirtualProtect(entry,span,PAGE_EXECUTE_READWRITE,&old)){VirtualFree(trampoline,0,MEM_RELEASE);return nullptr;}
    jump(entry,replacement);for(DWORD i=14;i<span;++i)entry[i]=0x90;
    VirtualProtect(entry,span,old,&old);FlushInstructionCache(GetCurrentProcess(),entry,span);FlushInstructionCache(GetCurrentProcess(),trampoline,span+14);return trampoline;
}
std::vector<std::wstring> transferPaths(size_t* list,const std::wstring& folder=L""){
    std::vector<std::wstring> paths;
    // Native string vector: count, capacity, pointer to UTF-8 {pointer,length}.
    size_t count=list[0];auto strings=(size_t*)list[2];paths.reserve(count);
    for(size_t i=0;i<count;++i){auto path=utf8Path((const char*)strings[i*2],strings[i*2+1]);
        if(!folder.empty()&&PathIsRelativeW(path.c_str()))path=folder+L"\\"+path;
        paths.push_back(std::move(path));}return paths;
}
int __fastcall clipboard(BYTE* state){
    IDataObject* data=nullptr;
    try{data=transferObject(transferPaths((size_t*)(state+native.clipboardListOffset)));
        if(!data)return originalClipboard(state);
        HRESULT hr=OleSetClipboard(data);data->Release();data=nullptr;
        if(FAILED(hr)){reportShellError("Windows could not accept the archive clipboard data.");return 0;}return 1;
    }catch(const std::exception& e){if(data)data->Release();reportShellError(e.what());return 0;}
    catch(...){if(data)data->Release();reportShellError("Cannot copy archive entries.");return 0;}
}
void __fastcall drag(BYTE* state,size_t* folder,size_t* list){
    IDataObject* data=nullptr;
    try{data=transferObject(transferPaths(list,utf8Path((const char*)folder[0],folder[1])));
        if(!data){originalDrag(state,folder,list);return;}
        HWND owner=*(HWND*)(state+native.dragOwnerOffset);DWORD effect=0;
        *(DWORD*)(state+native.dragActiveOffset)=1;
        HRESULT hr=SHDoDragDrop(owner,data,nullptr,DROPEFFECT_COPY,&effect);
        *(DWORD*)(state+native.dragActiveOffset)=0;data->Release();data=nullptr;
        if(FAILED(hr))reportShellError("Windows could not transfer the archive entries.");
    }catch(const std::exception& e){*(DWORD*)(state+native.dragActiveOffset)=0;if(data)data->Release();reportShellError(e.what());}
    catch(...){*(DWORD*)(state+native.dragActiveOffset)=0;if(data)data->Release();reportShellError("Cannot drag archive entries.");}
}
void installOpen(BYTE* host){
    BYTE* entry=host+native.openSelectionRva;
    // The profile describes whole non-relative prologue instructions. Ports update
    // this span alongside the layout, rather than relying on a generic detour decoder.
    BYTE* trampoline=(BYTE*)VirtualAlloc(nullptr,native.openPrologueBytes+14,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!trampoline)return;
    memcpy(trampoline,entry,native.openPrologueBytes);
    jump(trampoline+native.openPrologueBytes,entry+native.openPrologueBytes);
    DWORD old;VirtualProtect(trampoline,native.openPrologueBytes+14,PAGE_EXECUTE_READ,&old);
    originalOpen=(OpenSelection)trampoline;describeItem=(DescribeItem)(host+native.describeItemRva);
    if(!VirtualProtect(entry,native.openPrologueBytes,PAGE_EXECUTE_READWRITE,&old))return;
    jump(entry,(void*)openSelection);
    for(DWORD i=14;i<native.openPrologueBytes;++i)entry[i]=0x90;
    VirtualProtect(entry,native.openPrologueBytes,old,&old);
    FlushInstructionCache(GetCurrentProcess(),entry,native.openPrologueBytes);
    FlushInstructionCache(GetCurrentProcess(),trampoline,native.openPrologueBytes+14);
}
struct Handle {
    Location location;
    std::wstring path;
    std::vector<Entry> entries;
    std::shared_ptr<Bytes> data;
    size_t cursor=0;
    ULONGLONG position=0;
    std::wstring pattern=L"*";
    bool find=false;
    std::mutex mutex;
};
std::mutex handlesMutex;
std::map<HANDLE,std::shared_ptr<Handle>> handles;
std::shared_ptr<Handle> lookup(HANDLE h){std::lock_guard<std::mutex> lock(handlesMutex);auto i=handles.find(h);return i==handles.end()?nullptr:i->second;}
HANDLE put(std::shared_ptr<Handle> h){HANDLE key=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!key)return INVALID_HANDLE_VALUE;std::lock_guard<std::mutex> lock(handlesMutex);handles[key]=h;return key;}
DWORD attrs(const Entry& e){return FILE_ATTRIBUTE_READONLY|(e.directory?FILE_ATTRIBUTE_DIRECTORY:FILE_ATTRIBUTE_ARCHIVE);}
void decorate(WIN32_FIND_DATAW* d){if(!(d->dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&extension(d->cFileName))d->dwFileAttributes|=FILE_ATTRIBUTE_DIRECTORY;}
void fill(const Entry& e,WIN32_FIND_DATAW* d){
    memset(d,0,sizeof(*d));d->dwFileAttributes=attrs(e);d->ftCreationTime=d->ftLastAccessTime=d->ftLastWriteTime=e.time;
    d->nFileSizeLow=(DWORD)e.size;d->nFileSizeHigh=(DWORD)(e.size>>32);wcsncpy_s(d->cFileName,e.path.c_str(),_TRUNCATE);
}
bool match(const std::wstring& n,const std::wstring& p){return p.empty()||p==L"*"||p==L"*.*"||PathMatchSpecW(n.c_str(),p.c_str());}
bool next(Handle& h,WIN32_FIND_DATAW* data){while(h.cursor<h.entries.size()){auto& e=h.entries[h.cursor++];if(match(e.path,h.pattern)){fill(e,data);return true;}}SetLastError(ERROR_NO_MORE_FILES);return false;}
DWORD WINAPI attributes(LPCWSTR path){
    DWORD a=GetFileAttributesW(path);
    if(a!=INVALID_FILE_ATTRIBUTES){if(!(a&FILE_ATTRIBUTE_DIRECTORY)&&extension(path))a|=FILE_ATTRIBUTE_DIRECTORY;return a;}
    try{Location loc;if(resolve(path,loc))return attrs(loc.entry);}catch(...){SetLastError(ERROR_PATH_NOT_FOUND);}
    return INVALID_FILE_ATTRIBUTES;
}
BOOL WINAPI attributesEx(LPCWSTR path,GET_FILEEX_INFO_LEVELS level,LPVOID buffer){
    if(GetFileAttributesExW(path,level,buffer)){if(level==GetFileExInfoStandard){auto d=(WIN32_FILE_ATTRIBUTE_DATA*)buffer;if(!(d->dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&extension(path))d->dwFileAttributes|=FILE_ATTRIBUTE_DIRECTORY;}return TRUE;}
    try{Location loc;if(level==GetFileExInfoStandard && resolve(path,loc)){auto d=(WIN32_FILE_ATTRIBUTE_DATA*)buffer;memset(d,0,sizeof(*d));d->dwFileAttributes=attrs(loc.entry);d->ftCreationTime=d->ftLastAccessTime=d->ftLastWriteTime=loc.entry.time;d->nFileSizeHigh=(DWORD)(loc.entry.size>>32);d->nFileSizeLow=(DWORD)loc.entry.size;return TRUE;}}catch(...){SetLastError(ERROR_PATH_NOT_FOUND);}return FALSE;
}
HANDLE WINAPI create(LPCWSTR name,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD flags,HANDLE templ){
    if(!name || !archivePath(name,(flags&FILE_FLAG_BACKUP_SEMANTICS)!=0))
        return CreateFileW(name,access,share,security,disposition,flags,templ);
    // Opening the container's raw bytes remains possible without directory semantics.
    auto realAttrs=GetFileAttributesW(name);
    if(realAttrs!=INVALID_FILE_ATTRIBUTES && ((realAttrs&FILE_ATTRIBUTE_DIRECTORY) || !(flags&FILE_FLAG_BACKUP_SEMANTICS)))return CreateFileW(name,access,share,security,disposition,flags,templ);
    try{Location loc;if(resolve(name,loc)){
        if(disposition!=OPEN_EXISTING || (access&(GENERIC_WRITE|GENERIC_ALL|DELETE|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA))){SetLastError(ERROR_WRITE_PROTECT);return INVALID_HANDLE_VALUE;}
        auto h=std::make_shared<Handle>();h->location=loc;h->path=name;
        if(loc.entry.directory)h->entries=children(loc);
        return put(h);
    }}catch(...){SetLastError(ERROR_INVALID_DATA);return INVALID_HANDLE_VALUE;}
    return CreateFileW(name,access,share,security,disposition,flags,templ);
}
BOOL WINAPI closeHandle(HANDLE key){
    {std::lock_guard<std::mutex> lock(handlesMutex);handles.erase(key);}return CloseHandle(key);
}
BOOL WINAPI findClose(HANDLE key){if(lookup(key))return closeHandle(key);return FindClose(key);}
HANDLE WINAPI firstEx(LPCWSTR raw,FINDEX_INFO_LEVELS level,LPVOID data,FINDEX_SEARCH_OPS op,LPVOID filter,DWORD flags){
    // Existing filesystem entries (including archive files) need no archive index.
    HANDLE real=FindFirstFileExW(raw,level,data,op,filter,flags);
    if(real!=INVALID_HANDLE_VALUE){decorate((WIN32_FIND_DATAW*)data);return real;}
    if(!raw || !archivePath(raw))return real;
    DWORD nativeError=GetLastError();
    try{std::wstring path=raw;auto slash=path.find_last_of(L"\\/");Location loc;
        if(slash!=path.npos && resolve(path.substr(0,slash).c_str(),loc)){
            if(!loc.entry.directory){SetLastError(ERROR_DIRECTORY);return INVALID_HANDLE_VALUE;}
            auto h=std::make_shared<Handle>();h->location=loc;h->path=path;h->find=true;h->pattern=path.substr(slash+1);h->entries=children(loc);
            if(!next(*h,(WIN32_FIND_DATAW*)data)){SetLastError(ERROR_FILE_NOT_FOUND);return INVALID_HANDLE_VALUE;}return put(h);
        }
        // Exact-name queries are also used by native metadata paths.
        if(path.find_first_of(L"*?")==path.npos && resolve(raw,loc)){
            auto h=std::make_shared<Handle>();h->location=loc;h->find=true;Entry e=loc.entry;e.path=path.substr(slash+1);fill(e,(WIN32_FIND_DATAW*)data);return put(h);
        }
    }catch(...){SetLastError(ERROR_INVALID_DATA);return INVALID_HANDLE_VALUE;}
    SetLastError(nativeError);return INVALID_HANDLE_VALUE;
}
HANDLE WINAPI first(LPCWSTR p,LPWIN32_FIND_DATAW d){return firstEx(p,FindExInfoStandard,d,FindExSearchNameMatch,nullptr,0);}
BOOL WINAPI findNext(HANDLE key,LPWIN32_FIND_DATAW d){auto h=lookup(key);if(h){std::lock_guard<std::mutex> lock(h->mutex);return next(*h,d);}BOOL ok=FindNextFileW(key,d);if(ok)decorate(d);return ok;}
BOOL WINAPI read(HANDLE key,LPVOID p,DWORD n,LPDWORD done,LPOVERLAPPED ov){
    auto h=lookup(key);if(!h)return ReadFile(key,p,n,done,ov);
    if(done)*done=0;
    try{std::lock_guard<std::mutex> lock(h->mutex);if(h->location.entry.directory){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
        if(!h->data)h->data=h->location.archive->read(h->location.entry.index);
        auto offset=ov?((ULONGLONG)ov->OffsetHigh<<32)|ov->Offset:h->position;
        DWORD count=offset>=h->data->size()?0:(DWORD)std::min<ULONGLONG>(n,h->data->size()-offset);
        if(count)memcpy(p,h->data->data()+offset,count);if(done)*done=count;
        if(ov){ov->Internal=0;ov->InternalHigh=count;if(ov->hEvent)SetEvent(ov->hEvent);}else h->position+=count;return TRUE;
    }catch(...){SetLastError(ERROR_INVALID_DATA);return FALSE;}
}
BOOL WINAPI sizeEx(HANDLE key,PLARGE_INTEGER size){auto h=lookup(key);if(!h)return GetFileSizeEx(key,size);size->QuadPart=h->location.entry.size;return TRUE;}
DWORD WINAPI size(HANDLE key,LPDWORD high){LARGE_INTEGER n{};if(!sizeEx(key,&n))return INVALID_FILE_SIZE;if(high)*high=n.HighPart;SetLastError(NO_ERROR);return n.LowPart;}
BOOL WINAPI seekEx(HANDLE key,LARGE_INTEGER move,PLARGE_INTEGER result,DWORD origin){auto h=lookup(key);if(!h)return SetFilePointerEx(key,move,result,origin);std::lock_guard<std::mutex> lock(h->mutex);LONGLONG p=origin==FILE_BEGIN?0:origin==FILE_CURRENT?h->position:h->location.entry.size;p+=move.QuadPart;if(p<0){SetLastError(ERROR_NEGATIVE_SEEK);return FALSE;}h->position=p;if(result)result->QuadPart=p;return TRUE;}
DWORD WINAPI finalPath(HANDLE key,LPWSTR dest,DWORD n,DWORD flags){auto h=lookup(key);if(!h)return GetFinalPathNameByHandleW(key,dest,n,flags);std::wstring p=h->path;if(!(flags&VOLUME_NAME_NONE)&&p.rfind(L"\\\\?\\",0)!=0)p=p.rfind(L"\\\\",0)==0?L"\\\\?\\UNC\\"+p.substr(2):L"\\\\?\\"+p;if(n<=p.size())return(DWORD)p.size()+1;memcpy(dest,p.c_str(),(p.size()+1)*2);return(DWORD)p.size();}
BOOL WINAPI info(HANDLE key,LPBY_HANDLE_FILE_INFORMATION data){auto h=lookup(key);if(!h)return GetFileInformationByHandle(key,data);memset(data,0,sizeof(*data));data->dwFileAttributes=attrs(h->location.entry);data->ftCreationTime=data->ftLastAccessTime=data->ftLastWriteTime=h->location.entry.time;data->nFileSizeLow=(DWORD)h->location.entry.size;data->nFileSizeHigh=(DWORD)(h->location.entry.size>>32);data->nNumberOfLinks=1;data->nFileIndexLow=h->location.entry.index+1;return TRUE;}
BOOL WINAPI changes(HANDLE key,LPVOID p,DWORD n,BOOL subtree,DWORD filter,LPDWORD returned,LPOVERLAPPED ov,LPOVERLAPPED_COMPLETION_ROUTINE callback){if(!lookup(key))return ReadDirectoryChangesW(key,p,n,subtree,filter,returned,ov,callback);if(returned)*returned=0;SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}
BOOL WINAPI exists(LPCWSTR p){return attributes(p)!=INVALID_FILE_ATTRIBUTES;}
DWORD_PTR WINAPI shellInfo(LPCWSTR path,DWORD a,SHFILEINFOW* info,UINT size,UINT flags){
    if((flags&(SHGFI_PIDL|SHGFI_USEFILEATTRIBUTES)) || !path || !archivePath(path))
        return SHGetFileInfoW(path,a,info,size,flags);
    DWORD physical=GetFileAttributesW(path);
    if(physical!=INVALID_FILE_ATTRIBUTES){
        if(!(physical&FILE_ATTRIBUTE_DIRECTORY)&&extension(path))
            return SHGetFileInfoW(path,physical|FILE_ATTRIBUTE_DIRECTORY,info,size,flags|SHGFI_USEFILEATTRIBUTES);
        return SHGetFileInfoW(path,a,info,size,flags);
    }
    try{Location loc;if(resolve(path,loc))return SHGetFileInfoW(path,attrs(loc.entry),info,size,flags|SHGFI_USEFILEATTRIBUTES);}catch(...){}
    return SHGetFileInfoW(path,a,info,size,flags);
}
BOOL WINAPI write(HANDLE h,LPCVOID p,DWORD n,LPDWORD done,LPOVERLAPPED ov){if(lookup(h)){if(done)*done=0;SetLastError(ERROR_WRITE_PROTECT);return FALSE;}return WriteFile(h,p,n,done,ov);}
BOOL WINAPI remove(LPCWSTR p){try{Location loc;if(resolve(p,loc)&&!loc.inside.empty()){SetLastError(ERROR_WRITE_PROTECT);return FALSE;}}catch(...){}return DeleteFileW(p);}
// FILE_*_DIR_INFORMATION layouts. File Pilot 0.8.5 uses class 60 (name at +88).
unsigned nameOffset(unsigned cls){switch(cls){case 1:return 64;case 2:return 68;case 3:return 94;case 12:return 12;case 37:return 104;case 38:return 80;case 60:return 88;case 63:return 114;default:return 0;}}
void decorateNt(void* buffer,ULONG bytes,unsigned cls){unsigned off=nameOffset(cls);if(!off || cls==12)return;auto p=(BYTE*)buffer;ULONG pos=0;while(pos+off<=bytes){ULONG len=*(ULONG*)(p+pos+60);if(len>bytes-pos-off)break;DWORD& a=*(DWORD*)(p+pos+56);if(!(a&FILE_ATTRIBUTE_DIRECTORY)&&extension(std::wstring_view((wchar_t*)(p+pos+off),len/2)))a|=FILE_ATTRIBUTE_DIRECTORY;ULONG next=*(ULONG*)(p+pos);if(!next || next>bytes-pos)break;pos+=next;}}
NTSTATUS NTAPI query(HANDLE key,HANDLE event,PIO_APC_ROUTINE apc,PVOID context,PIO_STATUS_BLOCK ios,PVOID buffer,ULONG length,FILE_INFORMATION_CLASS cls,BOOLEAN single,PUNICODE_STRING pattern,BOOLEAN restart){
    auto h=lookup(key);if(!h){auto status=ntQuery(key,event,apc,context,ios,buffer,length,cls,single,pattern,restart);if(status==0)decorateNt(buffer,(ULONG)ios->Information,(unsigned)cls);return status;}
    unsigned off=nameOffset((unsigned)cls);NTSTATUS status=0;
    std::lock_guard<std::mutex> lock(h->mutex);if(restart)h->cursor=0;if(pattern)h->pattern.assign(pattern->Buffer,pattern->Length/2);
    ULONG used=0,last=0;bool any=false;
    if(!off)status=(NTSTATUS)0xc0000003;
    else if(!h->location.entry.directory)status=(NTSTATUS)0xc0000103;
    else while(h->cursor<h->entries.size()){
        auto& e=h->entries[h->cursor];if(!match(e.path,h->pattern)){++h->cursor;continue;}
        ULONG bytes=off+(ULONG)e.path.size()*2;ULONG padded=(bytes+7)&~7u;
        if(padded>length-used){if(!any)status=(NTSTATUS)0x80000005;break;}
        BYTE* p=(BYTE*)buffer+used;memset(p,0,padded);*(ULONG*)(p+4)=(ULONG)h->cursor+1;
        if((unsigned)cls==12)*(ULONG*)(p+8)=(ULONG)e.path.size()*2;
        else{for(unsigned t=8;t<40;t+=8)memcpy(p+t,&e.time,8);*(ULONGLONG*)(p+40)=e.size;*(ULONGLONG*)(p+48)=(e.size+4095)&~4095ull;*(DWORD*)(p+56)=attrs(e);*(DWORD*)(p+60)=(DWORD)e.path.size()*2;if((unsigned)cls==60)*(ULONGLONG*)(p+72)=e.index+1;}
        memcpy(p+off,e.path.data(),e.path.size()*2);if(any)*(ULONG*)((BYTE*)buffer+last)=used-last;last=used;used+=padded;any=true;++h->cursor;if(single)break;
    }
    if(!any && status==0)status=(NTSTATUS)0x80000006;
    ios->Status=status;ios->Information=used;if(event)SetEvent(event);
    // File Pilot uses synchronous directory handles with no APC.
    return status;
}
struct Hook{const char* name;void* function;};
FARPROC WINAPI proc(HMODULE,LPCSTR);
Hook hooks[]={
    {"CreateFileW",(void*)create},{"CloseHandle",(void*)closeHandle},{"FindClose",(void*)findClose},
    {"GetFileAttributesW",(void*)attributes},{"GetFileAttributesExW",(void*)attributesEx},
    {"FindFirstFileExW",(void*)firstEx},{"FindFirstFileW",(void*)first},{"FindNextFileW",(void*)findNext},
    {"ReadFile",(void*)read},{"WriteFile",(void*)write},{"GetFileSize",(void*)size},{"GetFileSizeEx",(void*)sizeEx},
    {"SetFilePointerEx",(void*)seekEx},{"GetFileInformationByHandle",(void*)info},
    {"GetFinalPathNameByHandleW",(void*)finalPath},{"ReadDirectoryChangesW",(void*)changes},
    {"PathFileExistsW",(void*)exists},{"SHGetFileInfoW",(void*)shellInfo},{"DeleteFileW",(void*)remove},
    {"GetProcAddress",(void*)proc},{"NtQueryDirectoryFile",(void*)query}
};
FARPROC WINAPI proc(HMODULE module,LPCSTR name){if((ULONG_PTR)name>65535)for(auto& h:hooks)if(strcmp(name,h.name)==0)return(FARPROC)h.function;return GetProcAddress(module,name);}
HHOOK keyboard;
LRESULT CALLBACK messages(int code,WPARAM w,LPARAM l){
    if(code>=0&&w==PM_REMOVE){auto msg=(MSG*)l;if(msg->message==WM_KEYDOWN&&msg->wParam=='K'&&(GetKeyState(VK_CONTROL)&0x8000)&&(GetKeyState(VK_SHIFT)&0x8000)){
        HWND owner=GetAncestor(msg->hwnd,GA_ROOT);msg->message=WM_NULL;
        try{showLaunchCache(owner);}catch(const std::exception& e){reportShellError(e.what());}
    }}
    if(code>=0 && w==PM_REMOVE){auto msg=(MSG*)l;if(msg->message==WM_KEYDOWN && msg->wParam=='E' && (GetKeyState(VK_CONTROL)&0x8000) && (GetKeyState(VK_SHIFT)&0x8000)){
        HWND owner=GetAncestor(msg->hwnd,GA_ROOT);msg->message=WM_NULL;
        // A separate thread keeps the native File Pilot frame responsive during extraction.
        auto thread=CreateThread(nullptr,0,[](void* p)->DWORD{CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);fpa::extractDialog((HWND)p);CoUninitialize();return 0;},owner,0,nullptr);if(thread)CloseHandle(thread);
    }}return CallNextHookEx(keyboard,code,w,l);
}
}
extern "C" __declspec(dllexport) void WINAPI ArchiveInstall(BYTE* host,const ArchiveBinding* binding){
    native=*binding;
    unsigned ntPointerRva=native.ntPointerRva;
    ntQuery=(NtQuery)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryDirectoryFile");
    auto nt=(IMAGE_NT_HEADERS64*)(host+((IMAGE_DOS_HEADER*)host)->e_lfanew);
    auto imports=(IMAGE_IMPORT_DESCRIPTOR*)(host+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for(auto i=imports;i->Name;++i){auto names=(IMAGE_THUNK_DATA64*)(host+i->OriginalFirstThunk);auto slots=(IMAGE_THUNK_DATA64*)(host+i->FirstThunk);
        for(;names->u1.AddressOfData;++names,++slots){if(IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal))continue;auto name=(IMAGE_IMPORT_BY_NAME*)(host+names->u1.AddressOfData);
            for(auto& hook:hooks)if(strcmp((char*)name->Name,hook.name)==0){DWORD old;VirtualProtect(&slots->u1.Function,sizeof(void*),PAGE_READWRITE,&old);InterlockedExchangePointer((void**)&slots->u1.Function,hook.function);VirtualProtect(&slots->u1.Function,sizeof(void*),old,&old);break;}
        }
    }
    if(ntPointerRva){DWORD old;auto slot=(void**)(host+ntPointerRva);VirtualProtect(slot,8,PAGE_READWRITE,&old);*slot=(void*)query;VirtualProtect(slot,8,old,&old);}
    installOpen(host);
    originalSidebarOpen=(SidebarOpen)detour(host+native.sidebarOpenRva,native.sidebarOpenPrologueBytes,(void*)sidebarOpen);
    originalClipboard=(Clipboard)detour(host+native.clipboardRva,native.clipboardPrologueBytes,(void*)clipboard);
    originalDrag=(Drag)detour(host+native.dragRva,native.dragPrologueBytes,(void*)drag);
    keyboard=SetWindowsHookExW(WH_GETMESSAGE,messages,nullptr,GetCurrentThreadId());
}

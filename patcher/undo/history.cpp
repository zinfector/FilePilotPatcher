#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <sddl.h>
#include <sherrors.h>
#include <wrl/client.h>
#include <algorithm>
#include <atomic>
#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <cstring>
#include <cstdio>
using Microsoft::WRL::ComPtr;
namespace fs = std::filesystem;

namespace history {
static bool traceEnabled=false;
static bool tracing() {return traceEnabled;}
static void trace(const std::wstring& value) {
    wchar_t path[32768];if(!GetEnvironmentVariableW(L"FP_UNDO_TRACE",path,32768))return;
    FILE* f=nullptr;if(_wfopen_s(&f,path,L"a, ccs=UTF-8")==0){fwprintf(f,L"%s\n",value.c_str());fclose(f);}
}
struct Identity {
    DWORD volume=0, high=0, low=0;
    DWORD createdHigh=0, createdLow=0;
    bool valid=false;
    bool operator==(const Identity& b) const {
        return valid && b.valid && volume==b.volume && high==b.high && low==b.low &&
            createdHigh==b.createdHigh && createdLow==b.createdLow;
    }
};
static Identity identify(const std::wstring& p) {
    Identity id;
    HANDLE h=CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if(h==INVALID_HANDLE_VALUE) return id;
    BY_HANDLE_FILE_INFORMATION info{};
    if(GetFileInformationByHandle(h,&info) && !(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) && info.nNumberOfLinks<=1)
        id={info.dwVolumeSerialNumber,info.nFileIndexHigh,info.nFileIndexLow,
            info.ftCreationTime.dwHighDateTime,info.ftCreationTime.dwLowDateTime,true};
    CloseHandle(h); return id;
}
static bool exists(const std::wstring& p) { return GetFileAttributesW(p.c_str())!=INVALID_FILE_ATTRIBUTES; }
static std::wstring pathOf(IShellItem* item) {
    if(!item) return {};
    PWSTR p=nullptr;
    if(FAILED(item->GetDisplayName(SIGDN_FILESYSPATH,&p))) return {};
    std::wstring value(p); CoTaskMemFree(p); return value;
}
static std::wstring normalizedPath(std::wstring value) {
        std::replace(value.begin(),value.end(),L'/',L'\\');
        if(value.compare(0,8,L"\\\\?\\UNC\\")==0)value=L"\\\\"+value.substr(8);
        else if(value.compare(0,4,L"\\\\?\\")==0)value.erase(0,4);
        while(value.size()>3 && value.back()==L'\\')value.pop_back();
        return value;
}
static bool samePath(const std::wstring& a,const std::wstring& b) {
    auto left=normalizedPath(a),right=normalizedPath(b);
    return !left.empty() && CompareStringOrdinal(left.c_str(),-1,right.c_str(),-1,TRUE)==CSTR_EQUAL;
}
static std::vector<BYTE> pidlOf(IShellItem* item) {
    PIDLIST_ABSOLUTE p=nullptr;
    if(!item || FAILED(SHGetIDListFromObject(item,&p))) return {};
    std::vector<BYTE> result((BYTE*)p,(BYTE*)p+ILGetSize(p)); CoTaskMemFree(p); return result;
}
static ComPtr<IShellItem> recycledIdentity(const Identity& id) {
    ComPtr<IShellItem> bin,match;
    auto hr=SHGetKnownFolderItem(FOLDERID_RecycleBinFolder,KF_FLAG_DEFAULT,nullptr,IID_PPV_ARGS(&bin));
    trace(L"bin hr="+std::to_wstring((unsigned)hr)+L" sourceid="+std::to_wstring(id.low)+L" valid="+std::to_wstring(id.valid));
    if(!id.valid || FAILED(hr)) return match;
    ComPtr<IEnumShellItems> items;
    hr=bin->BindToHandler(nullptr,BHID_EnumItems,IID_PPV_ARGS(&items));trace(L"enum hr="+std::to_wstring((unsigned)hr));if(FAILED(hr))return match;
    for(unsigned n=0;n<100000;++n) {
        ComPtr<IShellItem> item;
        auto next=items->Next(1,&item,nullptr);
        if(next==S_FALSE)return match;
        if(next!=S_OK)return {};
        if(identify(pathOf(item.Get()))==id) {
            if(match) return {}; // Never choose between ambiguous hard-link identities.
            match=item;
        }
    }
    return {}; // Enumeration limit reached without establishing uniqueness.
}
struct Item {
    std::wstring original,current;
    Identity identity;
    std::vector<BYTE> recycle;
    bool deleted=false,undone=false;
};
struct Batch { std::vector<Item> items; std::wstring barrier; };
struct Context {
    int kind=-1;
    std::vector<std::wstring> sources;
    bool replay=false;
    bool complete=true;
};
// Explicit Windows TLS works for an embedded runtime and for existing host threads.
static DWORD contextTls=TLS_OUT_OF_INDEXES;
static Context* getContext() {return contextTls==TLS_OUT_OF_INDEXES?nullptr:static_cast<Context*>(TlsGetValue(contextTls));}
// Native workers may run together; only replay excludes native operations.
static std::shared_mutex execution;
static std::mutex stateMutex;
static std::vector<Batch> undoStack,redoStack;
static std::atomic<unsigned> active{0};
static std::atomic<bool> replayPending{false};
static std::atomic<bool> poisoned{false};
static unsigned long long generation=0;
static std::wstring lastError;
static BYTE* host=nullptr;
static std::atomic<unsigned> callbackExecutions{0};
static void error(const std::wstring& text) { std::lock_guard lock(stateMutex); lastError=text; }
#include "shared_history.h"
static void publish(Batch batch) {
    if(batch.items.empty() && batch.barrier.empty()) return;
    std::lock_guard lock(stateMutex);
    sharedHistory::Lock shared;
    if(!shared.acquired || !sharedHistory::load())return;
    ++generation;
    redoStack.clear(); undoStack.push_back(std::move(batch));
    if(undoStack.size()>100) undoStack.erase(undoStack.begin());
    sharedHistory::save();
}
static void barrier(const wchar_t* reason) { Batch b; b.barrier=reason; publish(std::move(b)); }

class Sink final : public IFileOperationProgressSink {
    LONG refs=1;
    struct Pending { std::wstring path; bool collision=false; Identity before; bool started=false,recorded=false; };
    struct PathLess {
        bool operator()(const std::wstring& a,const std::wstring& b) const {
            return CompareStringOrdinal(a.c_str(),(int)a.size(),b.c_str(),(int)b.size(),TRUE)==CSTR_LESS_THAN;
        }
    };
    std::map<std::wstring,Pending,PathLess> pending;
    std::vector<Pending> unresolvedDeletes;
    Context context;
    template<class F> HRESULT safe(F action) noexcept {
        try { return action(); } catch(...) { unsafe=true; return context.replay?E_OUTOFMEMORY:S_OK; }
    }
    HRESULT pre(IShellItem* item,IShellItem* dest,LPCWSTR name) {
        auto p=pathOf(item);
        if(tracing())trace(L"pre "+p+L" dest="+pathOf(dest)+L" name="+(name?name:L"<null>"));
        auto found=pending.find(normalizedPath(p));
        if(found==pending.end()) return S_OK;
        bool collision=false;
        if(dest) {
            auto d=fs::path(pathOf(dest))/((name && *name)?name:fs::path(p).filename().wstring());
            collision=exists(d.wstring());
        }
        if(context.replay && collision) return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
        // Only recycled deletes need the old identity for Recycle Bin lookup.
        found->second={p,collision,context.kind==2?identify(p):Identity{},true,false};
        return S_OK;
    }
    HRESULT post(IShellItem* item,HRESULT hr,IShellItem* result,bool deleted) {
        auto original=pathOf(item);
        if(tracing())trace(L"post "+original+L" result="+pathOf(result)+L" hr="+std::to_wstring((unsigned)hr));
        auto found=pending.find(normalizedPath(original));
        if(found==pending.end()) return S_OK;
        if(deleted && !result && context.kind==2 &&
           (hr==S_OK || hr==COPYENGINE_S_DONT_PROCESS_CHILDREN || hr==COPYENGINE_S_ALREADY_DONE) && found->second.started) {
            unresolvedDeletes.push_back(found->second); found->second.recorded=true; return S_OK;
        }
        // Shell skip/ignore success HRESULTs do not prove a mutation.
        if((hr!=S_OK && hr!=COPYENGINE_S_DONT_PROCESS_CHILDREN && hr!=COPYENGINE_S_ALREADY_DONE) || !result) {
            if(!exists(original)) {unsafe=true;reason=L"Unclassified Shell result: "+std::to_wstring((unsigned)hr)+(result?L" with item":L" without item");}
            return S_OK;
        }
        Item record; record.original=original; record.current=pathOf(result);
        record.identity=identify(record.current); record.deleted=deleted;
        if(deleted) record.recycle=pidlOf(result);
        if(!found->second.started) {unsafe=true;reason=L"Missing pre-operation callback.";}
        else if(found->second.collision) {unsafe=true;reason=L"The operation replaced or merged an existing destination.";}
        else if(!record.identity.valid) {unsafe=true;reason=L"Result identity unavailable.";}
        else if(deleted && record.recycle.empty()) {unsafe=true;reason=L"Recycle item identity unavailable.";}
        found->second.recorded=true;
        records.push_back(std::move(record)); return S_OK;
    }
public:
    bool unsafe=false;
    std::wstring reason;
    std::vector<Item> records;
    explicit Sink(const Context& ctx):context(ctx) {
        for(const auto& source:ctx.sources)pending.emplace(normalizedPath(source),Pending{source});
        records.reserve(ctx.sources.size());
    }
    void finalize() {
        for(auto& p:unresolvedDeletes) {
            auto item=recycledIdentity(p.before);
            if(!item || exists(p.path)) {unsafe=true;reason=L"The deleted item could not be identified in the Recycle Bin.";continue;}
            Item record;record.original=p.path;record.current=pathOf(item.Get());
            record.identity=identify(record.current);record.recycle=pidlOf(item.Get());record.deleted=true;
            if(record.recycle.empty()) {unsafe=true;reason=L"Recycle item identity unavailable.";}
            records.push_back(std::move(record));
        }
        // Some providers omit callbacks. Do not silently skip a mutation in history.
        for(auto& entry:pending) {
            if(!entry.second.recorded && !exists(entry.second.path)) {
                unsafe=true;reason=L"Windows did not provide a reversible result for every changed item.";
            }
        }
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p) override {
        if(!p)return E_POINTER; *p=nullptr;
        if(iid==IID_IUnknown || iid==__uuidof(IFileOperationProgressSink)) { *p=static_cast<IFileOperationProgressSink*>(this); AddRef(); return S_OK; }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override { auto n=InterlockedDecrement(&refs); if(!n)delete this; return n; }
    HRESULT STDMETHODCALLTYPE StartOperations() override {return S_OK;}
    HRESULT STDMETHODCALLTYPE FinishOperations(HRESULT) override {return S_OK;}
    HRESULT STDMETHODCALLTYPE PreMoveItem(DWORD,IShellItem* i,IShellItem* d,LPCWSTR n) override {return safe([&]{return pre(i,d,n);});}
    HRESULT STDMETHODCALLTYPE PostMoveItem(DWORD,IShellItem* i,IShellItem*,LPCWSTR,HRESULT hr,IShellItem* r) override {return safe([&]{return post(i,hr,r,false);});}
    HRESULT STDMETHODCALLTYPE PreDeleteItem(DWORD,IShellItem* i) override {return safe([&]{return pre(i,nullptr,nullptr);});}
    HRESULT STDMETHODCALLTYPE PostDeleteItem(DWORD,IShellItem* i,HRESULT hr,IShellItem* r) override {return safe([&]{return post(i,hr,r,true);});}
    HRESULT STDMETHODCALLTYPE PreRenameItem(DWORD,IShellItem*,LPCWSTR) override {return S_OK;}
    HRESULT STDMETHODCALLTYPE PostRenameItem(DWORD,IShellItem*,LPCWSTR,HRESULT hr,IShellItem*) override {if(SUCCEEDED(hr) && hr!=COPYENGINE_S_USER_IGNORED)unsafe=true;return S_OK;}
    HRESULT STDMETHODCALLTYPE PreCopyItem(DWORD,IShellItem*,IShellItem*,LPCWSTR) override {return S_OK;}
    HRESULT STDMETHODCALLTYPE PostCopyItem(DWORD,IShellItem*,IShellItem*,LPCWSTR,HRESULT hr,IShellItem*) override {if(SUCCEEDED(hr) && hr!=COPYENGINE_S_USER_IGNORED)unsafe=true;return S_OK;}
    HRESULT STDMETHODCALLTYPE PreNewItem(DWORD,IShellItem*,LPCWSTR) override {return S_OK;}
    HRESULT STDMETHODCALLTYPE PostNewItem(DWORD,IShellItem*,LPCWSTR,LPCWSTR,DWORD,HRESULT hr,IShellItem*) override {if(SUCCEEDED(hr) && hr!=COPYENGINE_S_USER_IGNORED)unsafe=true;return S_OK;}
    HRESULT STDMETHODCALLTYPE UpdateProgress(UINT,UINT) override {return S_OK;}
    HRESULT STDMETHODCALLTYPE ResetTimer() override {return S_OK;}
    HRESULT STDMETHODCALLTYPE PauseTimer() override {return S_OK;}
    HRESULT STDMETHODCALLTYPE ResumeTimer() override {return S_OK;}
};

static HRESULT observed(IFileOperation* operation,Context& context,Batch& result) {
    ComPtr<Sink> sink;
    try {sink.Attach(new Sink(context));} catch(...) {
        if(context.replay)return E_OUTOFMEMORY;
        HRESULT hr=operation->PerformOperations();
        result.barrier=L"History recorder allocation failed.";return hr;
    }
    DWORD cookie=0;
    HRESULT advised=operation->Advise(sink.Get(),&cookie);
    if(FAILED(advised)) {
        if(context.replay) return advised;
        result.barrier=L"This operation could not be recorded.";
        return operation->PerformOperations();
    }
    HRESULT hr=operation->PerformOperations();
    BOOL aborted=FALSE; HRESULT abortHr=operation->GetAnyOperationsAborted(&aborted);
    operation->Unadvise(cookie);
    sink->finalize();
    result.items=std::move(sink->records);
    if(sink->unsafe || FAILED(abortHr)) result.barrier=sink->reason.empty()?L"This operation cannot be safely reversed (replacement, permanent deletion, or unknown result).":sink->reason;
    return hr;
}
static HRESULT WINAPI performHook(IFileOperation* op) noexcept {
    HRESULT hr=E_OUTOFMEMORY;
    try {
        Context fallback;
        Context* currentContext=getContext();
        Context& ctx=currentContext?*currentContext:fallback;
        Batch result;
        hr=observed(op,ctx,result);
        if(!currentContext || !ctx.complete) result.barrier=L"An operation bypassed the history context.";
        publish(std::move(result)); return hr;
    } catch(...) {
        // Never call PerformOperations a second time after an ambiguous exception.
        poisoned=true;
        try {barrier(L"History recording failed; the operation outcome is uncertain.");} catch(...) {}
        return hr;
    }
}
static std::wstring utf8(const char* p,size_t count) {
    if(!p || count>32768*4) return {};
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,p,(int)count,nullptr,0);
    if(n<=0)return {};
    std::wstring value(n,L'\0'); MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,p,(int)count,value.data(),n); return value;
}
using Worker=unsigned(__fastcall*)(void*,void*);
static unsigned __fastcall workerHook(void* arena,void* request) noexcept {
    ++active;
    unsigned result=0;
    try {
        std::shared_lock<std::shared_mutex> lock(execution,std::defer_lock);
        if(!getContext())lock.lock(); // Nested native workers share the outer admission.
        sharedHistory::Activity activity;
        Context ctx; ctx.kind=*(int*)request;
        try { if(ctx.kind>=0 && ctx.kind<=3) {
            auto p=(BYTE*)request;
            auto count=*(size_t*)(p+0x18);
            auto strings=*(size_t**)(p+0x28);
            if(count>100000) throw std::bad_alloc();
            for(size_t i=0;i<count;++i) ctx.sources.push_back(utf8((char*)strings[2*i],strings[2*i+1]));
        }} catch(...) {ctx.complete=false;ctx.sources.clear();}
        struct Scope {
            Context* old;
            Scope(Context* c):old(getContext()){if(!TlsSetValue(contextTls,c))c->complete=false;}
            ~Scope(){TlsSetValue(contextTls,old);}
        } scope(&ctx);
        result=((Worker)(host+0x110ae0))(arena,request);
        if(ctx.kind>=8) barrier(L"A Recycle Bin action changed files outside reversible history.");
    } catch(...) {
        poisoned=true;
        try {barrier(L"The operation could not be recorded.");} catch(...) {}
    }
    --active; return result;
}

static void dropEffect(IDataObject* data,LPCSTR format,DWORD effect) noexcept {
    FORMATETC request{(CLIPFORMAT)RegisterClipboardFormatA(format),nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
    if(!request.cfFormat)return;
    STGMEDIUM medium{};medium.tymed=TYMED_HGLOBAL;
    medium.hGlobal=GlobalAlloc(GMEM_MOVEABLE,sizeof(DWORD));
    if(!medium.hGlobal)return;
    auto value=(DWORD*)GlobalLock(medium.hGlobal);
    if(!value){GlobalFree(medium.hGlobal);return;}
    *value=effect;GlobalUnlock(medium.hGlobal);
    if(FAILED(data->SetData(&request,&medium,TRUE)))ReleaseStgMedium(&medium);
}
struct DragMove {
    Context context;
    std::wstring destination;
    HWND owner=nullptr;
};
static HRESULT runDragMove(IDataObject* data,const DragMove& move) noexcept {
    HRESULT hr=E_FAIL;
    bool began=false,moved=false;
    try {
        std::shared_lock<std::shared_mutex> admission(execution);
        sharedHistory::Activity activity;
        ComPtr<IFileOperation> operation;
        ComPtr<IShellItem> destination;
        ComPtr<IShellItemArray> sources;
        hr=SHCreateItemFromParsingName(move.destination.c_str(),nullptr,IID_PPV_ARGS(&destination));
        if(SUCCEEDED(hr))hr=SHCreateShellItemArrayFromDataObject(data,IID_PPV_ARGS(&sources));
        if(SUCCEEDED(hr))hr=CoCreateInstance(CLSID_FileOperation,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&operation));
        if(SUCCEEDED(hr))hr=operation->SetOperationFlags(FOF_ALLOWUNDO|FOF_NOCONFIRMMKDIR);
        if(SUCCEEDED(hr))hr=operation->SetOwnerWindow(move.owner);
        if(SUCCEEDED(hr))hr=operation->MoveItems(sources.Get(),destination.Get());
        if(SUCCEEDED(hr)) {
            Context context=move.context;
            Batch batch;
            began=true;
            hr=observed(operation.Get(),context,batch);
            moved=!batch.items.empty();
            publish(std::move(batch));
        }
    } catch(...) {
        hr=E_OUTOFMEMORY;
        if(began) {
            poisoned=true;
            try {barrier(L"A dragged move could not be fully recorded.");} catch(...) {}
        }
    }
    // We perform the source removal ourselves. Never ask the drag source to
    // delete originals again, including after cancellation or partial success.
    dropEffect(data,CFSTR_PERFORMEDDROPEFFECT,DROPEFFECT_NONE);
    dropEffect(data,CFSTR_LOGICALPERFORMEDDROPEFFECT,moved?DROPEFFECT_MOVE:DROPEFFECT_NONE);
    if(FAILED(hr) && hr!=HRESULT_FROM_WIN32(ERROR_CANCELLED) && hr!=COPYENGINE_E_USER_CANCELLED)
        MessageBoxW(move.owner,L"Windows could not complete the dragged move. Completed items, if any, are retained in file history.",L"File Pilot move",MB_OK|MB_ICONINFORMATION);
    return hr;
}
static HRESULT STDMETHODCALLTYPE dragDropHook(IDropTarget* target,IDataObject* data,DWORD keys,POINTL point,DWORD* effect) noexcept {
    bool owned=false;
    try {
        // The native Drop caller has already resolved its destination Shell target.
        auto app=*(BYTE**)(host+0x249240);
        auto drag=app?*(BYTE**)(app+0x8b8):nullptr;
        if(!drag || !data || !effect || drag[0x109] || (keys&MK_RBUTTON))
            return target->Drop(data,keys,point,effect);
        DWORD negotiated=*effect;
        if(FAILED(target->DragOver(keys,point,&negotiated)) ||
           (negotiated&~DROPEFFECT_SCROLL)!=DROPEFFECT_MOVE)
            return target->Drop(data,keys,point,effect);
        DragMove move;
        move.destination=utf8(*(char**)(drag+0x70),*(size_t*)(drag+0x78));
        move.owner=*(HWND*)(drag+0x50);
        move.context.kind=1;
        if(move.destination.empty())return target->Drop(data,keys,point,effect);
        ComPtr<IShellItem> destination;
        ComPtr<IShellItemArray> sources;
        SFGAOF attributes=0;
        if(FAILED(SHCreateItemFromParsingName(move.destination.c_str(),nullptr,IID_PPV_ARGS(&destination))) ||
           FAILED(destination->GetAttributes(SFGAO_FILESYSTEM|SFGAO_FOLDER,&attributes)) ||
           (attributes&(SFGAO_FILESYSTEM|SFGAO_FOLDER))!=(SFGAO_FILESYSTEM|SFGAO_FOLDER) ||
           FAILED(SHCreateShellItemArrayFromDataObject(data,IID_PPV_ARGS(&sources))))
            return target->Drop(data,keys,point,effect);
        DWORD count=0;
        if(FAILED(sources->GetCount(&count)) || !count)return target->Drop(data,keys,point,effect);
        move.context.sources.reserve(count);
        for(DWORD i=0;i<count;++i) {
            ComPtr<IShellItem> item;
            if(FAILED(sources->GetItemAt(i,&item)))return target->Drop(data,keys,point,effect);
            auto path=pathOf(item.Get());
            if(path.empty())return target->Drop(data,keys,point,effect);
            move.context.sources.push_back(std::move(path));
        }
        // Use Shell's asynchronous data-transfer contract where the source supports
        // it. Marshal COM interfaces instead of sharing apartment-bound pointers.
        ComPtr<IDataObjectAsyncCapability> async;
        BOOL asynchronous=FALSE;
        if(SUCCEEDED(data->QueryInterface(IID_PPV_ARGS(&async))) &&
           SUCCEEDED(async->GetAsyncMode(&asynchronous)) && asynchronous) {
            ComPtr<IStream> stream;
            if(SUCCEEDED(CoMarshalInterThreadInterfaceInStream(IID_IDataObject,data,&stream)) &&
               SUCCEEDED(async->StartOperation(nullptr))) {
                ++active;
                try {
                    // Keep stream owned on this thread until std::thread succeeds.
                    IStream* marshaled=stream.Get();
                    auto transfer=std::make_shared<DragMove>(std::move(move));
                    std::thread worker([marshaled,transfer] {
                        HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
                        ComPtr<IDataObject> source;
                        HRESULT hr=init;
                        if(SUCCEEDED(init))hr=CoGetInterfaceAndReleaseStream(marshaled,IID_PPV_ARGS(&source));
                        else marshaled->Release();
                        if(source) {
                            hr=runDragMove(source.Get(),*transfer);
                            ComPtr<IDataObjectAsyncCapability> completion;
                            if(SUCCEEDED(source.As(&completion)))completion->EndOperation(hr,nullptr,DROPEFFECT_NONE);
                        }
                        source.Reset();
                        --active;
                        if(SUCCEEDED(init))CoUninitialize();
                    });
                    stream.Detach();
                    worker.detach();
                    owned=true;
                    target->DragLeave();
                    *effect=DROPEFFECT_NONE;
                    return S_OK;
                } catch(...) {
                    --active;
                    async->EndOperation(E_OUTOFMEMORY,nullptr,DROPEFFECT_NONE);
                    // move may have been consumed by the failed thread construction;
                    // the original Shell target still owns the untouched drag data.
                    if(stream)CoReleaseMarshalData(stream.Get());
                    return target->Drop(data,keys,point,effect);
                }
            }
            if(stream)CoReleaseMarshalData(stream.Get());
        }
        owned=true;
        target->DragLeave();
        ++active;
        HRESULT hr=runDragMove(data,move);
        --active;
        *effect=DROPEFFECT_NONE;
        return hr;
    } catch(...) {
        if(!owned)return target->Drop(data,keys,point,effect);
        if(effect)*effect=DROPEFFECT_NONE;
        return E_OUTOFMEMORY;
    }
}

static bool replayBatch(Batch& batch,bool undo) {
    struct PathLess {
        bool operator()(const std::wstring& a,const std::wstring& b) const {
            return CompareStringOrdinal(a.c_str(),(int)a.size(),b.c_str(),(int)b.size(),TRUE)==CSTR_LESS_THAN;
        }
    };
    ComPtr<IFileOperation> operation;
    HRESULT hr=CoCreateInstance(CLSID_FileOperation,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&operation));
    if(FAILED(hr))return false;
    bool recycling=std::any_of(batch.items.begin(),batch.items.end(),[&](const Item& i){return i.deleted && !undo;});
    DWORD flags=FOF_NOCONFIRMMKDIR|FOF_NOERRORUI|FOFX_EARLYFAILURE|FOF_RENAMEONCOLLISION;
    if(recycling)flags|=FOF_ALLOWUNDO|FOFX_RECYCLEONDELETE|FOF_WANTNUKEWARNING;
    hr=operation->SetOperationFlags(flags);if(FAILED(hr))return false;
    Context context;context.replay=true;context.kind=recycling?2:1;
    std::map<std::wstring,size_t,PathLess> indices;
    std::map<std::wstring,ComPtr<IShellItem>,PathLess> folders;
    std::set<std::wstring,PathLess> destinations,changedFolders;
    for(size_t n=0;n<batch.items.size();++n) {
        size_t index=undo?batch.items.size()-1-n:n;
        const auto& item=batch.items[index];
        if(item.undone==undo)continue;
        if(!(identify(item.current)==item.identity)) {
            error(L"A recorded item is missing or has been replaced. Nothing was changed.");return false;
        }
        ComPtr<IShellItem> source;
        if(item.deleted && undo)hr=SHCreateItemFromIDList((PCIDLIST_ABSOLUTE)item.recycle.data(),IID_PPV_ARGS(&source));
        else hr=SHCreateItemFromParsingName(item.current.c_str(),nullptr,IID_PPV_ARGS(&source));
        if(FAILED(hr))return false;
        if(item.deleted && !undo)hr=operation->DeleteItem(source.Get(),nullptr);
        else {
            // Ordinary move records exchange their endpoints after either direction.
            const auto& target=item.original;
            if(!destinations.insert(normalizedPath(target)).second || exists(target)) {
                error(L"A destination name is occupied. Nothing was overwritten.");return false;
            }
            auto parent=fs::path(target).parent_path().wstring();
            auto& folder=folders[normalizedPath(parent)];
            if(!folder)hr=SHCreateItemFromParsingName(parent.c_str(),nullptr,IID_PPV_ARGS(&folder));
            if(FAILED(hr))return false;
            hr=operation->MoveItem(source.Get(),folder.Get(),fs::path(target).filename().c_str(),nullptr);
        }
        if(FAILED(hr))return false;
        if(!indices.emplace(normalizedPath(item.current),index).second) {
            error(L"The history batch contains a duplicate source.");return false;
        }
        context.sources.push_back(item.current);
    }
    if(indices.empty())return true;
    // Every request is queued before the one execution call. A crash from this
    // point leaves shared history dirty, so another process cannot repeat it.
    sharedHistory::header->dirty=1;
    Batch outcome;
    hr=observed(operation.Get(),context,outcome);
    size_t completed=0;
    for(auto& actual:outcome.items) {
        auto found=indices.find(normalizedPath(actual.original));
        if(found==indices.end())continue;
        auto& item=batch.items[found->second];
        auto before=item.current;
        changedFolders.insert(fs::path(before).parent_path().wstring());
        changedFolders.insert(fs::path(actual.current).parent_path().wstring());
        item.current=std::move(actual.current);item.identity=actual.identity;
        if(item.deleted && !undo)item.recycle=std::move(actual.recycle);
        if(!item.deleted)item.original=std::move(before);
        item.undone=undo;
        ++completed;indices.erase(found);
    }
    for(const auto& folder:changedFolders)
        SHChangeNotify(SHCNE_UPDATEDIR,SHCNF_PATHW|SHCNF_FLUSHNOWAIT,folder.c_str(),nullptr);
    if(FAILED(hr) || completed!=context.sources.size() || !outcome.barrier.empty()) {
        error(outcome.barrier.empty()?L"Windows did not complete every item. Completed results were retained and this batch is blocked.":outcome.barrier);
        return false;
    }
    return true;
}
static bool replay(bool undo,unsigned long long expectedGeneration=~0ULL) {
    std::unique_lock<std::shared_mutex> serial(execution);
    sharedHistory::Lock shared;
    if(!shared.acquired){error(L"Shared history is unavailable.");return false;}
    if(sharedHistory::busy()){error(L"A file operation is still running in another window.");return false;}
    Batch batch;
    {
        std::lock_guard lock(stateMutex);
        if(!sharedHistory::load())return false;
        if(poisoned) {lastError=L"History recording failed. Restart File Pilot before recording more history.";return false;}
        if(expectedGeneration!=~0ULL && generation!=expectedGeneration) {lastError=L"Another operation completed before undo could start. Please try again.";return false;}
        auto& stack=undo?undoStack:redoStack;
        if(stack.empty()) {lastError=L"No file operation to undo or redo.";return false;}
        if(!stack.back().barrier.empty()) {lastError=stack.back().barrier;return false;}
        batch=stack.back(); lastError.clear();
    }
    bool success=replayBatch(batch,undo);
    {
        std::lock_guard lock(stateMutex);
        auto& from=undo?undoStack:redoStack; auto& to=undo?redoStack:undoStack;
        ++generation;
        if(success) {from.pop_back();to.push_back(std::move(batch));}
        else {
            if(lastError.empty()) lastError=L"Windows could not complete the operation. Check the item and its destination.";
            // Preserve per-item state but do not allow traversal over an ambiguous partial replay.
            batch.barrier=lastError; from.back()=std::move(batch);
        }
        if(!sharedHistory::save())success=false;
    }
    return success;
}
static bool available(bool undo) {
    if(active || replayPending)return false;
    sharedHistory::Lock shared(0);
    if(!shared.acquired)return false;
    if(sharedHistory::header->blocked)return true;
    if(sharedHistory::busy())return false;
    return (undo?sharedHistory::header->undoCount:sharedHistory::header->redoCount)!=0;
}
static void queueReplay(bool undo) {
    if(active || replayPending.exchange(true))return;
    unsigned long long expected;
    {sharedHistory::Lock shared;if(!shared.acquired){replayPending=false;return;}expected=sharedHistory::header->generation;}
    try {
        std::thread([undo,expected]{
            HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
            bool ok=false;
            try {if(SUCCEEDED(init))ok=replay(undo,expected);} catch(...) {poisoned=true;error(L"History replay failed.");}
            if(!ok) {std::wstring text;{std::lock_guard lock(stateMutex);text=lastError;} if(text.empty())text=L"History could not start.";MessageBoxW(nullptr,text.c_str(),L"File Pilot undo",MB_OK|MB_ICONINFORMATION);}
            if(SUCCEEDED(init))CoUninitialize(); replayPending=false;
        }).detach();
    } catch(...) {replayPending=false;}
}
using Callback=unsigned(__fastcall*)(void*,void*,int);
static unsigned historyCommand(bool undo,int event) {
    // Native dispatch (196c70/175470): byte 0 means disabled, byte 2 means
    // handled. Event 0 queries availability; event 1 invokes the shortcut.
    // Consume invocation here instead of queuing a native command by name.
    if(!available(undo))return 1;
    if(event==1 || event==2) {
        ++callbackExecutions;
        queueReplay(undo);
        return 0x10000;
    }
    return 0;
}
static unsigned __fastcall undoCommand(void*,void*,int event) {
    return historyCommand(true,event);
}
static unsigned __fastcall redoCommand(void*,void*,int event) {
    return historyCommand(false,event);
}
struct Text {const char* p;size_t n;};
struct Binding {const char* name;const char* key;Callback callback;};
static const Binding bindings[]={
    {"Undo File Operation","Ctrl+Z",undoCommand},
    {"Redo File Operation","Ctrl+Y",redoCommand},
    {"Redo File Operation (alternate)","Ctrl+Shift+Z",redoCommand}
};
static void bindDefault(const Binding& binding,void* descriptor) {
    // Native parsing lowercases its input in place.
    char bytes[32];
    size_t length=strlen(binding.key);
    memcpy(bytes,binding.key,length+1);
    Text shortcut{bytes,length};
    ((unsigned(__fastcall*)(Text*,void*,int))(host+0x36880))(&shortcut,descriptor,0);
}
using Registrar=void*(__fastcall*)(void*,void*,Text*,Text*,void*,unsigned);
static void* __fastcall registerHook(void* arena,void* registry,Text* name,Text* group,void* cb,unsigned flags) {
    auto native=(Registrar)(host+0x260d0);
    void* original=native(arena,registry,name,group,cb,flags);
    for(const auto& b:bindings) {
        Text key{b.name,strlen(b.name)};
        void* descriptor=native(arena,registry,&key,group,(void*)b.callback,flags);
        bindDefault(b,descriptor);
    }
    return original;
}

// 0.8.5 JSON tokens: type, byte start/end, child count, parent index.
struct JsonToken {int type,start,end,children,parent;};
static_assert(sizeof(JsonToken)==20);
static bool configuredCommand(size_t* document,int array,const Binding& binding) {
    auto count=document[2];
    auto tokens=(const JsonToken*)document[3];
    auto text=(const char*)document[0];
    if(array<0 || (size_t)array>=count)return true; // Do not migrate malformed input.
    Text command{"Command",7};
    auto find=(int(__fastcall*)(size_t*,int,Text*))(host+0x36f80);
    for(size_t i=(size_t)array+1;i<count;++i) {
        if(tokens[i].parent!=array || tokens[i].type!=1)continue;
        int key=find(document,(int)i,&command);
        if(key<0 || (size_t)key+1>=count)continue;
        const auto& value=tokens[key+1];
        if(value.type==4 && value.parent==key && value.start>=0 && value.end>=value.start &&
           (size_t)(value.end-value.start)==strlen(binding.name) &&
           memcmp(text+value.start,binding.name,value.end-value.start)==0)return true;
    }
    return false;
}
static void __fastcall settingsHook(size_t* settings,size_t* document,int array) {
    // Native loading clears all keys, then restores only JSON entries. Registration
    // alone therefore cannot add defaults to a pre-existing configuration.
    bool configured[3];
    for(size_t i=0;i<3;++i)configured[i]=configuredCommand(document,array,bindings[i]);
    ((void(__fastcall*)(size_t*,size_t*,int))(host+0x36a20))(settings,document,array);
    // Use the active registry, not the separate defaults registry. The native
    // settings writer subsequently persists these descriptors with all others.
    auto entries=(BYTE*)settings[0x14];
    for(size_t slot=0;slot<settings[0xd];++slot) {
        for(auto descriptor=*(BYTE**)(entries+slot*0x18+0x10);descriptor;
            descriptor=*(BYTE**)(descriptor+0x40)) {
            auto name=(Text*)(descriptor+0x10);
            for(size_t i=0;i<3;++i) {
                if(!configured[i] && name->n==strlen(bindings[i].name) &&
                   memcmp(name->p,bindings[i].name,name->n)==0) {
                    bindDefault(bindings[i],descriptor);
                    break;
                }
            }
        }
    }
}
static Text* __fastcall saveSettingsHook(Text* output,size_t options,size_t* settings,void* arena) {
    ((Text*(__fastcall*)(Text*,size_t,size_t*,void*))(host+0x33e90))(output,options,settings,arena);
    try {
        bool present[3]={},written[3]={};
        auto entries=(BYTE*)settings[0x14];
        for(size_t slot=0;slot<settings[0xd];++slot) {
            for(auto descriptor=*(BYTE**)(entries+slot*0x18+0x10);descriptor;
                descriptor=*(BYTE**)(descriptor+0x40)) {
                auto name=(Text*)(descriptor+0x10);
                for(size_t i=0;i<3;++i) {
                    if(name->n==strlen(bindings[i].name) && memcmp(name->p,bindings[i].name,name->n)==0) {
                        present[i]=true;
                        // Match the native writer's filter, including additional bindings.
                        written[i]|=descriptor[2]!=0 && *(unsigned short*)(descriptor+0x3c)==0;
                    }
                }
            }
        }
        bool needed=false;
        for(size_t i=0;i<3;++i)needed|=present[i] && !written[i];
        if(!needed)return output;
        std::string json(output->p,output->n);
        auto hotkeys=json.find("\"Hotkeys\":");
        auto open=hotkeys==std::string::npos?std::string::npos:json.find('[',hotkeys);
        auto close=json.rfind(']'); // Hotkeys is the last array emitted by 0.8.5.
        if(open==std::string::npos || close==std::string::npos || close<=open)return output;
        bool comma=json.find_first_not_of(" \r\n\t",open+1)!=close;
        std::string additions;
        for(size_t i=0;i<3;++i)if(present[i] && !written[i]) {
            if(comma)additions+=',';
            additions+="\n\t\t{ \"Keys\": [], \"Command\": \"";
            additions+=bindings[i].name;
            additions+="\" }";
            comma=true;
        }
        additions+="\n\t";
        json.insert(close,additions);
        // Return host-owned text; no pointer into a temporary C++ string escapes.
        Text copied{};
        ((Text*(__fastcall*)(Text*,void*,const char*,size_t))(host+0x212000))
            (&copied,arena,json.data(),json.size());
        *output=copied;
    } catch(...) {
        // Keep the native serialized settings intact if allocation fails.
    }
    return output;
}

static constexpr DWORD sites[]={0x1131a8,0x108907,0x110a97,0x20b1fd,0x7ea16,0x7ec26,0x113a2b,0x113b1c,0x1f6985};
static constexpr DWORD saveSites[]={0x3dc1e,0x7e0ce};
static bool install(BYTE* base) {
    if(host)return host==base;
    if(!sharedHistory::initialize())return false;
    wchar_t traceValue[2];
    traceEnabled=GetEnvironmentVariableW(L"FP_UNDO_TRACE",traceValue,2)!=0;
    if(contextTls==TLS_OUT_OF_INDEXES)contextTls=TlsAlloc();
    if(contextTls==TLS_OUT_OF_INDEXES)return false;
    for(auto rva:sites) if(base[rva]!=0xe8 || rva+5+*(int32_t*)(base+rva+1)!=0x110ae0)return false;
    const BYTE perform[]={0xff,0x90,0xa8,0,0,0};
    const BYTE drop[]={0x48,0x8b,0x01,0x48,0x89,0x54,0x24,0x20,0x49,0x8b,0xd4,0xff,0x50,0x30};
    if(memcmp(base+0x111f93,perform,6) || base[0x27697]!=0xe8 || 0x27697+5+*(int32_t*)(base+0x27698)!=0x260d0)return false;
    if(memcmp(base+0x1f1168,drop,sizeof(drop)))return false;
    if(base[0x3ca4e]!=0xe8 || 0x3ca53+*(int32_t*)(base+0x3ca4f)!=0x36a20)return false;
    for(auto rva:saveSites)if(base[rva]!=0xe8 || rva+5+*(int32_t*)(base+rva+1)!=0x33e90)return false;
    BYTE* relay=nullptr;
    for(size_t delta=0x1000000;delta<0x70000000 && !relay;delta+=0x10000)
        relay=(BYTE*)VirtualAlloc(base+delta,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!relay)return false;
    void* targets[]={(void*)workerHook,(void*)performHook,(void*)registerHook,(void*)settingsHook,(void*)saveSettingsHook,(void*)dragDropHook};
    for(int i=0;i<6;++i){BYTE* p=relay+i*16;p[0]=0x48;p[1]=0xb8;memcpy(p+2,&targets[i],8);p[10]=0xff;p[11]=0xe0;}
    DWORD old;
    if(!VirtualProtect(relay,4096,PAGE_EXECUTE_READ,&old)){VirtualFree(relay,0,MEM_RELEASE);return false;}
    // All patches are made at process entry, before any native worker or registry runs.
    if(!VirtualProtect(base+0x26000,0xef000,PAGE_EXECUTE_READWRITE,&old)){VirtualFree(relay,0,MEM_RELEASE);return false;}
    // Some worker calls are in later code pages. Preflight protection before writing any hook.
    DWORD oldLater;
    if(!VirtualProtect(base+0x1f0000,0x1c000,PAGE_EXECUTE_READWRITE,&oldLater)){DWORD ignored;VirtualProtect(base+0x26000,0xef000,old,&ignored);VirtualFree(relay,0,MEM_RELEASE);return false;}
    host=base;
    auto patch=[&](DWORD rva,BYTE* target){base[rva]=0xe8;int32_t d=(int32_t)(target-(base+rva+5));memcpy(base+rva+1,&d,4);};
    for(auto rva:sites)patch(rva,relay);
    patch(0x111f93,relay+16);base[0x111f98]=0x90;
    patch(0x27697,relay+32);
    patch(0x3ca4e,relay+48);
    for(auto rva:saveSites)patch(rva,relay+64);
    // Keep the original stack argument and IDataObject setup; replace the indirect
    // Drop call with a rel32 call without moving the following instructions.
    const BYTE dropArguments[]={0x48,0x89,0x54,0x24,0x20,0x49,0x8b,0xd4};
    memcpy(base+0x1f1168,dropArguments,sizeof(dropArguments));
    patch(0x1f1170,relay+80);base[0x1f1175]=0x90;
    DWORD ignored;VirtualProtect(base+0x26000,0xef000,old,&ignored);VirtualProtect(base+0x1f0000,0x1c000,oldLater,&ignored);
    FlushInstructionCache(GetCurrentProcess(),nullptr,0);return true;
}
}
extern "C" __declspec(dllexport) BOOL WINAPI HistoryInitialize(BYTE* base) {try{return history::install(base);}catch(...){return FALSE;}}

#ifdef HISTORY_TEST_API
// Only dedicated development builds expose destructive test entrypoints.
extern "C" __declspec(dllexport) HRESULT WINAPI HistoryTestOperation(int kind,LPCWSTR source,LPCWSTR destination) {
    using namespace history;
    try {
        std::unique_lock<std::shared_mutex> lock(execution);
        ComPtr<IFileOperation> op; HRESULT hr=CoCreateInstance(CLSID_FileOperation,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&op));if(FAILED(hr))return hr;
        op->SetOperationFlags(FOF_NOCONFIRMATION|FOF_SILENT|FOF_NOCONFIRMMKDIR|FOF_NOERRORUI|FOFX_EARLYFAILURE|FOFX_ADDUNDORECORD|FOFX_RECYCLEONDELETE);
        ComPtr<IShellItem> item,folder;
        hr=SHCreateItemFromParsingName(source,nullptr,IID_PPV_ARGS(&item));trace(L"test source hr="+std::to_wstring((unsigned)hr));if(FAILED(hr))return hr;
        if(kind==1){hr=SHCreateItemFromParsingName(destination,nullptr,IID_PPV_ARGS(&folder));if(SUCCEEDED(hr))hr=op->MoveItem(item.Get(),folder.Get(),nullptr,nullptr);}
        else if(kind==2)hr=op->DeleteItem(item.Get(),nullptr);else return E_INVALIDARG;
        if(FAILED(hr))return hr;
        Context ctx;ctx.kind=kind;ctx.sources={source};Batch b;hr=observed(op.Get(),ctx,b);publish(std::move(b));return hr;
    }catch(...){return E_FAIL;}
}
extern "C" __declspec(dllexport) BOOL WINAPI HistoryTestReplay(BOOL undo) {try{return history::replay(undo!=FALSE);}catch(...){return FALSE;}}
extern "C" __declspec(dllexport) void WINAPI HistoryTestReset(){std::lock_guard lock(history::stateMutex);history::undoStack.clear();history::redoStack.clear();history::lastError.clear();history::poisoned=false;++history::generation;}
extern "C" __declspec(dllexport) unsigned WINAPI HistoryTestCount(BOOL undo){std::lock_guard lock(history::stateMutex);return (unsigned)(undo?history::undoStack:history::redoStack).size();}
extern "C" __declspec(dllexport) unsigned WINAPI HistoryTestError(wchar_t* p,unsigned size){std::lock_guard lock(history::stateMutex);wcsncpy_s(p,size,history::lastError.c_str(),_TRUNCATE);return (unsigned)history::lastError.size();}
#endif
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(instance);return TRUE;}

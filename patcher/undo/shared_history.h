// Included inside namespace history after the process-local state declarations.
namespace sharedHistory {
constexpr size_t capacity=32*1024*1024;
constexpr DWORD version=0x554e4404;
struct Participant {DWORD pid,count;};
struct Header {
    DWORD magic,bytes,dirty,blocked,undoCount,redoCount;
    unsigned long long generation;
    Participant participants[64];
};
static HANDLE mutex=nullptr,mapping=nullptr;
static Header* header=nullptr;
struct Lock {
    bool acquired=false;
    explicit Lock(DWORD timeout=INFINITE) {
        if(!header)return;
        DWORD result=WaitForSingleObject(mutex,timeout);
        acquired=result==WAIT_OBJECT_0 || result==WAIT_ABANDONED;
        if(acquired && (result==WAIT_ABANDONED || header->dirty)) {
            // A process may have died after moving files but before committing history.
            header->blocked=1;header->dirty=0;++header->generation;
        }
    }
    ~Lock(){if(acquired)ReleaseMutex(mutex);}
};
static bool initialize() {
    HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;
    DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<BYTE> buffer(size);
    BOOL ok=GetTokenInformation(token,TokenUser,buffer.data(),size,&size);
    CloseHandle(token);
    LPWSTR sid=nullptr;
    if(!ok || !ConvertSidToStringSidW(((TOKEN_USER*)buffer.data())->User.Sid,&sid))return false;
    std::wstring name=L"Local\\FilePilot085.Undo.v4.";name+=sid;LocalFree(sid);
    mutex=CreateMutexW(nullptr,FALSE,(name+L".Lock").c_str());
    if(!mutex)return false;
    DWORD wait=WaitForSingleObject(mutex,INFINITE);
    if(wait!=WAIT_OBJECT_0 && wait!=WAIT_ABANDONED)return false;
    mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,(DWORD)(sizeof(Header)+capacity),(name+L".State").c_str());
    if(mapping)header=(Header*)MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,0);
    if(header && header->magic!=version) {
        memset(header,0,sizeof(Header));header->magic=version;
    }
    if(header && wait==WAIT_ABANDONED)header->blocked=1;
    ReleaseMutex(mutex);
    return header!=nullptr;
}
struct Writer {
    std::vector<BYTE> bytes;
    void raw(const void* data,size_t n) {
        if(n>capacity-bytes.size())throw std::bad_alloc();
        if(n)bytes.insert(bytes.end(),(const BYTE*)data,(const BYTE*)data+n);
    }
    template<class T> void value(const T& v){raw(&v,sizeof(v));}
    void text(const std::wstring& s){value((size_t)s.size());raw(s.data(),s.size()*sizeof(wchar_t));}
    void stack(const std::vector<Batch>& batches) {
        value((size_t)batches.size());
        for(const auto& batch:batches) {
            text(batch.barrier);value((size_t)batch.items.size());
            for(const auto& item:batch.items) {
                text(item.original);text(item.current);value(item.identity);
                value((size_t)item.recycle.size());raw(item.recycle.data(),item.recycle.size());
                value(item.deleted);value(item.undone);
            }
        }
    }
};
struct Reader {
    const BYTE* p;size_t left;
    void raw(void* out,size_t n){if(n>left)throw std::bad_alloc();if(n)memcpy(out,p,n);p+=n;left-=n;}
    template<class T> T value(){T v{};raw(&v,sizeof(v));return v;}
    std::wstring text(){auto n=value<size_t>();if(n>left/2)throw std::bad_alloc();std::wstring s(n,L'\0');raw(s.data(),n*2);return s;}
    std::vector<Batch> stack() {
        auto n=value<size_t>();if(n>100)throw std::bad_alloc();
        std::vector<Batch> result;result.reserve(n);
        for(size_t i=0;i<n;++i) {
            Batch batch;batch.barrier=text();auto count=value<size_t>();
            if(count>left/sizeof(Identity))throw std::bad_alloc();
            batch.items.reserve(count);
            for(size_t j=0;j<count;++j) {
                Item item;item.original=text();item.current=text();item.identity=value<Identity>();
                auto bytes=value<size_t>();if(bytes>left)throw std::bad_alloc();
                item.recycle.resize(bytes);raw(item.recycle.data(),bytes);
                item.deleted=value<bool>();item.undone=value<bool>();batch.items.push_back(std::move(item));
            }
            result.push_back(std::move(batch));
        }
        return result;
    }
};
// Caller holds Lock. These vectors are transaction-local copies, never another
// independent history that could replay the same operation twice.
static bool load() {
    generation=header->generation;
    if(header->blocked){lastError=L"Shared history was interrupted or could not be saved. Close all FilePilot windows to start a new history session.";return false;}
    try {
        if(!header->bytes){undoStack.clear();redoStack.clear();return true;}
        if(header->bytes>capacity)throw std::bad_alloc();
        Reader reader{(const BYTE*)(header+1),header->bytes};
        auto undo=reader.stack(),redo=reader.stack();
        if(reader.left)throw std::bad_alloc();
        undoStack=std::move(undo);redoStack=std::move(redo);return true;
    } catch(...) {header->blocked=1;lastError=L"Shared history could not be read.";return false;}
}
static bool save() {
    try {
        Writer writer;writer.stack(undoStack);writer.stack(redoStack);
        header->dirty=1;
        memcpy(header+1,writer.bytes.data(),writer.bytes.size());
        header->bytes=(DWORD)writer.bytes.size();
        header->undoCount=(DWORD)undoStack.size();header->redoCount=(DWORD)redoStack.size();
        header->generation=generation;header->dirty=0;
        return true;
    } catch(...) {header->blocked=1;header->dirty=0;lastError=L"Shared history capacity was exceeded or could not be saved.";return false;}
}
static bool busy() {
    bool result=false;
    for(auto& entry:header->participants)if(entry.count) {
        HANDLE process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.pid);
        bool dead=process?WaitForSingleObject(process,0)==WAIT_OBJECT_0:GetLastError()==ERROR_INVALID_PARAMETER;
        if(process)CloseHandle(process);
        if(dead) {entry={};header->blocked=1;}
        else result=true;
    }
    return result;
}
struct Activity {
    Participant* entry=nullptr;
    Activity() {
        Lock lock;
        if(!lock.acquired)return;
        DWORD pid=GetCurrentProcessId();
        for(auto& participant:header->participants)if(participant.pid==pid){entry=&participant;break;}
        if(!entry)for(auto& participant:header->participants)if(!participant.count){entry=&participant;entry->pid=pid;break;}
        if(entry)++entry->count;else header->blocked=1;
    }
    ~Activity(){if(entry){Lock lock;if(lock.acquired && entry->count)--entry->count;}}
};
}

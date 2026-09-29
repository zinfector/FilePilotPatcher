// Shared batch arena: only the affected batch is copied or rewritten.
namespace sharedHistory {
constexpr size_t capacity=32*1024*1024;
constexpr DWORD version=0x554e4405;
constexpr DWORD pageSize=4096,pageCount=(DWORD)(capacity/pageSize),noPage=~0UL;
struct Participant {DWORD pid,count;};
struct Slot {DWORD first,bytes;};
struct Header {
    DWORD magic,dirty,blocked,undoCount,redoCount,replayPid;
    unsigned long long generation;
    Participant participants[64];
    DWORD undo[100],redo[100];
    Slot slots[100];
    DWORD freePage,next[pageCount];
};
static HANDLE mutex=nullptr,mapping=nullptr,idle=nullptr;
static Header* header=nullptr;
static bool dead(DWORD pid) {
    HANDLE process=OpenProcess(SYNCHRONIZE,FALSE,pid);
    bool result=process?WaitForSingleObject(process,0)==WAIT_OBJECT_0:GetLastError()==ERROR_INVALID_PARAMETER;
    if(process)CloseHandle(process);
    return result;
}
struct Lock {
    bool acquired=false;
    explicit Lock(DWORD timeout=INFINITE) {
        if(!header)return;
        DWORD result=WaitForSingleObject(mutex,timeout);
        acquired=result==WAIT_OBJECT_0 || result==WAIT_ABANDONED;
        if(acquired) {
            if(result==WAIT_ABANDONED || header->dirty) {
                header->blocked=1;header->dirty=0;++header->generation;
            }
            if(header->replayPid && dead(header->replayPid)) {
                header->blocked=1;header->replayPid=0;++header->generation;SetEvent(idle);
            }
        }
    }
    ~Lock(){if(acquired)ReleaseMutex(mutex);}
};
static bool initialize() {
    HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;
    DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<BYTE> buffer(size);
    BOOL ok=GetTokenInformation(token,TokenUser,buffer.data(),size,&size);CloseHandle(token);
    LPWSTR sid=nullptr;
    if(!ok || !ConvertSidToStringSidW(((TOKEN_USER*)buffer.data())->User.Sid,&sid))return false;
    std::wstring name=L"Local\\FilePilot085.Undo.v5.";name+=sid;LocalFree(sid);
    mutex=CreateMutexW(nullptr,FALSE,(name+L".Lock").c_str());
    idle=CreateEventW(nullptr,TRUE,TRUE,(name+L".Idle").c_str());
    if(!mutex || !idle)return false;
    DWORD wait=WaitForSingleObject(mutex,INFINITE);
    if(wait!=WAIT_OBJECT_0 && wait!=WAIT_ABANDONED)return false;
    mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,(DWORD)(sizeof(Header)+capacity),(name+L".State").c_str());
    if(mapping)header=(Header*)MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,0);
    if(header && header->magic!=version) {
        memset(header,0,sizeof(Header));
        for(DWORD n=0;n<pageCount;++n)header->next[n]=n+1;
        header->next[pageCount-1]=noPage;
        header->magic=version;SetEvent(idle);
    }
    if(header && wait==WAIT_ABANDONED)header->blocked=1;
    ReleaseMutex(mutex);return header!=nullptr;
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

static std::vector<BYTE> encode(Batch batch) {
    std::vector<Batch> one;one.push_back(std::move(batch));
    Writer writer;writer.stack(one);return std::move(writer.bytes);
}
static Batch decode(const std::vector<BYTE>& bytes) {
    Reader reader{bytes.data(),bytes.size()};auto batches=reader.stack();
    if(batches.size()!=1 || reader.left)throw std::bad_alloc();
    return std::move(batches.front());
}
// Fixed pages avoid fragmentation and never relocate unrelated batches.
// Caller owns the mutex and marks metadata dirty before changing page chains.
static void releaseSlot(DWORD index) {
    auto& slot=header->slots[index];
    DWORD page=slot.first;
    for(DWORD left=slot.bytes;left;) {
        DWORD next=header->next[page];
        header->next[page]=header->freePage;header->freePage=page;page=next;
        left-=std::min(left,pageSize);
    }
    slot={};
}
static bool writeSlot(DWORD index,const std::vector<BYTE>& bytes) {
    if(bytes.size()>capacity)return false;
    releaseSlot(index);
    auto& slot=header->slots[index];
    DWORD previous=noPage;
    size_t offset=0;
    while(offset<bytes.size()) {
        DWORD page=header->freePage;
        if(page==noPage){releaseSlot(index);return false;}
        header->freePage=header->next[page];header->next[page]=noPage;
        if(previous==noPage)slot.first=page;else header->next[previous]=page;
        size_t count=std::min(size_t(pageSize),bytes.size()-offset);
        memcpy((BYTE*)(header+1)+size_t(page)*pageSize,bytes.data()+offset,count);
        offset+=count;slot.bytes=(DWORD)offset;previous=page;
    }
    return true;
}
static std::vector<BYTE> readSlot(DWORD index) {
    if(index>=100)throw std::bad_alloc();
    auto slot=header->slots[index];
    if(slot.bytes>capacity)throw std::bad_alloc();
    std::vector<BYTE> bytes(slot.bytes);
    DWORD page=slot.first;
    for(size_t offset=0;offset<bytes.size();) {
        if(page>=pageCount)throw std::bad_alloc();
        size_t count=std::min(size_t(pageSize),bytes.size()-offset);
        memcpy(bytes.data()+offset,(const BYTE*)(header+1)+size_t(page)*pageSize,count);
        offset+=count;page=header->next[page];
    }
    return bytes;
}
static bool busy() {
    bool result=header->replayPid!=0;
    for(auto& entry:header->participants)if(entry.count) {
        if(dead(entry.pid)){entry={};header->blocked=1;}
        else result=true;
    }
    return result;
}
static void append(Batch batch) {
    auto bytes=encode(std::move(batch)); // Allocations and serialization outside mutex.
    Lock lock;if(!lock.acquired || header->blocked)return;
    header->dirty=1;
    for(DWORD n=0;n<header->redoCount;++n)releaseSlot(header->redo[n]);
    header->redoCount=0;
    if(header->undoCount==100) {
        releaseSlot(header->undo[0]);
        memmove(header->undo,header->undo+1,99*sizeof(DWORD));--header->undoCount;
    }
    DWORD slot=0;while(slot<100 && header->slots[slot].bytes)++slot;
    if(slot==100 || !writeSlot(slot,bytes))header->blocked=1;
    else header->undo[header->undoCount++]=slot;
    ++header->generation;header->dirty=0;
}
struct Reservation {
    DWORD slot=0;bool held=false;
    bool take(bool undo,unsigned long long expected,std::vector<BYTE>& bytes) {
        Lock lock;if(!lock.acquired)return false;
        if(busy()){error(L"A file operation is still running in another window.");return false;}
        if(header->blocked){error(L"Shared history was interrupted. Close all FilePilot windows to start a new session.");return false;}
        if(expected!=~0ULL && expected!=header->generation){error(L"Another operation completed before undo could start. Please try again.");return false;}
        DWORD count=undo?header->undoCount:header->redoCount;
        if(!count){error(L"No file operation to undo or redo.");return false;}
        slot=(undo?header->undo:header->redo)[count-1];
        bytes=readSlot(slot);
        header->replayPid=GetCurrentProcessId();ResetEvent(idle);held=true;return true;
    }
    bool commit(bool undo,bool success,const std::vector<BYTE>& bytes) {
        Lock lock;if(!lock.acquired)return false;
        header->dirty=1;
        bool saved=writeSlot(slot,bytes);
        if(!saved)header->blocked=1;
        else if(success) {
            auto& from=undo?header->undoCount:header->redoCount;
            auto& to=undo?header->redoCount:header->undoCount;
            --from;(undo?header->redo:header->undo)[to++]=slot;
        }
        ++header->generation;header->dirty=0;header->replayPid=0;held=false;SetEvent(idle);
        return saved;
    }
    ~Reservation() {
        if(held){Lock lock;if(lock.acquired){header->blocked=1;header->replayPid=0;++header->generation;SetEvent(idle);}}
    }
};
struct Activity {
    Participant* entry=nullptr;
    Activity() {
        for(;;) {
            {
                Lock lock;if(!lock.acquired)throw std::bad_alloc();
                if(!header->replayPid) {
                    DWORD pid=GetCurrentProcessId();
                    for(auto& p:header->participants)if(p.pid==pid){entry=&p;break;}
                    if(!entry)for(auto& p:header->participants)if(!p.count){entry=&p;entry->pid=pid;break;}
                    if(entry)++entry->count;else {header->blocked=1;throw std::bad_alloc();}
                    return;
                }
            }
            // Event wakes immediately on completion. Timeout only detects a dead owner.
            WaitForSingleObject(idle,1000);
        }
    }
    ~Activity(){if(entry){Lock lock;if(lock.acquired && entry->count)--entry->count;}}
};
}

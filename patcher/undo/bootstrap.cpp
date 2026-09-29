// Import-free loader for the embedded undo runtime. No sidecar or extracted DLL.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
struct UndoBinding { DWORD engineRva, originalRva, loadLibraryRva, getProcRva; };
extern "C" __declspec(dllexport) volatile UndoBinding UndoBindings={};
#pragma function(memset, memcpy)
extern "C" void* __cdecl memset(void* dest,int value,size_t n){auto p=(volatile unsigned char*)dest;while(n--)*p++=(unsigned char)value;return dest;}
extern "C" void* __cdecl memcpy(void* dest,const void* src,size_t n){auto p=(volatile unsigned char*)dest;auto q=(const volatile unsigned char*)src;while(n--)*p++=*q++;return dest;}
static bool equal(const char* a,const char* b){while(*a && *a==*b){++a;++b;}return *a==*b;}
static void* load(BYTE* host){
    auto library=*(decltype(&LoadLibraryW)*)(host+UndoBindings.loadLibraryRva);
    auto proc=*(decltype(&GetProcAddress)*)(host+UndoBindings.getProcRva);
    HMODULE kernel=library(L"kernel32.dll");
    auto alloc=(decltype(&VirtualAlloc))proc(kernel,"VirtualAlloc");
    auto protect=(decltype(&VirtualProtect))proc(kernel,"VirtualProtect");
    auto functions=(decltype(&RtlAddFunctionTable))proc(kernel,"RtlAddFunctionTable");
    auto flush=(decltype(&FlushInstructionCache))proc(kernel,"FlushInstructionCache");
    BYTE* raw=host+UndoBindings.engineRva;
    auto nt=(IMAGE_NT_HEADERS64*)(raw+((IMAGE_DOS_HEADER*)raw)->e_lfanew);
    BYTE* base=(BYTE*)alloc(nullptr,nt->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!base)return nullptr;
    memcpy(base,raw,nt->OptionalHeader.SizeOfHeaders);
    auto section=IMAGE_FIRST_SECTION(nt);
    for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i)memcpy(base+section[i].VirtualAddress,raw+section[i].PointerToRawData,section[i].SizeOfRawData);
    auto delta=(ULONGLONG)base-nt->OptionalHeader.ImageBase;
    auto relocDir=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    for(DWORD off=0;off<relocDir.Size;){auto block=(IMAGE_BASE_RELOCATION*)(base+relocDir.VirtualAddress+off);if(!block->SizeOfBlock)break;
        auto words=(WORD*)(block+1);for(unsigned i=0;i<(block->SizeOfBlock-sizeof(*block))/2;++i)if((words[i]>>12)==IMAGE_REL_BASED_DIR64)*(ULONGLONG*)(base+block->VirtualAddress+(words[i]&4095))+=delta;
        off+=block->SizeOfBlock;
    }
    auto imports=(IMAGE_IMPORT_DESCRIPTOR*)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for(auto d=imports;d->Name;++d){wchar_t name[260];auto narrow=(char*)(base+d->Name);unsigned n=0;while(n<259 && narrow[n]){name[n]=(wchar_t)(unsigned char)narrow[n];++n;}name[n]=0;
        HMODULE module=library(name);if(!module)return nullptr;
        auto source=(IMAGE_THUNK_DATA64*)(base+d->OriginalFirstThunk);auto dest=(IMAGE_THUNK_DATA64*)(base+d->FirstThunk);
        for(;source->u1.AddressOfData;++source,++dest){LPCSTR symbol=IMAGE_SNAP_BY_ORDINAL64(source->u1.Ordinal)?(LPCSTR)IMAGE_ORDINAL64(source->u1.Ordinal):(LPCSTR)((IMAGE_IMPORT_BY_NAME*)(base+source->u1.AddressOfData))->Name;
            dest->u1.Function=(ULONGLONG)proc(module,symbol);if(!dest->u1.Function)return nullptr;}
    }
    auto exceptions=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if(exceptions.Size && !functions((PRUNTIME_FUNCTION)(base+exceptions.VirtualAddress),exceptions.Size/sizeof(RUNTIME_FUNCTION),(DWORD64)base))return nullptr;
    for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i){DWORD bits=section[i].Characteristics;
        DWORD mode=(bits&IMAGE_SCN_MEM_EXECUTE)?((bits&IMAGE_SCN_MEM_WRITE)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ):((bits&IMAGE_SCN_MEM_WRITE)?PAGE_READWRITE:PAGE_READONLY);
        DWORD old;protect(base+section[i].VirtualAddress,section[i].Misc.VirtualSize,mode,&old);}
    flush((HANDLE)-1,base,nt->OptionalHeader.SizeOfImage);
    // The undo runtime uses TlsAlloc rather than compiler TLS. Run its CRT initializers.
    using Entry=BOOL(WINAPI*)(HINSTANCE,DWORD,void*);
    if(!((Entry)(base+nt->OptionalHeader.AddressOfEntryPoint))((HINSTANCE)base,DLL_PROCESS_ATTACH,nullptr))return nullptr;
    auto exports=(IMAGE_EXPORT_DIRECTORY*)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto names=(DWORD*)(base+exports->AddressOfNames);auto ordinals=(WORD*)(base+exports->AddressOfNameOrdinals);auto addresses=(DWORD*)(base+exports->AddressOfFunctions);
    for(DWORD i=0;i<exports->NumberOfNames;++i)if(equal((char*)(base+names[i]),"HistoryInitialize")){
        if(!((BOOL(WINAPI*)(BYTE*))(base+addresses[ordinals[i]]))(host))return nullptr;return base;}
    return nullptr;
}
extern "C" __declspec(dllexport) void UndoEntry(){
    BYTE* host=*(BYTE**)(__readgsqword(0x60)+0x10);
    if(!load(host)){
        auto library=*(decltype(&LoadLibraryW)*)(host+UndoBindings.loadLibraryRva);auto proc=*(decltype(&GetProcAddress)*)(host+UndoBindings.getProcRva);
        auto message=(decltype(&MessageBoxW))proc(library(L"user32.dll"),"MessageBoxW");
        message(nullptr,L"The embedded undo runtime could not start. File Pilot will continue without file undo.",L"File Pilot undo",MB_OK|MB_ICONERROR);
    }
    ((void(*)())(host+UndoBindings.originalRva))();
}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID){return TRUE;}

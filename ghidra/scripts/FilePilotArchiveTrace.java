// Read-only archive integration research.
//@category Reverse Engineering
import java.io.*;
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class FilePilotArchiveTrace extends GhidraScript {
    PrintWriter out;
    Set<Function> selected = new TreeSet<>(Comparator.comparing(f -> f.getEntryPoint()));
    void refs(Address a) {
        for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
            Function f = getFunctionContaining(r.getFromAddress());
            out.println("  " + r.getFromAddress() + " " + r.getReferenceType() + " " + (f == null ? "data" : f.getName()+" @ "+f.getEntryPoint()));
            if (f != null) selected.add(f);
        }
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(args[0])))) {
            out = writer;
            out.println("Program="+currentProgram.getName()+" SHA256="+currentProgram.getExecutableSHA256()+" base="+currentProgram.getImageBase());
            if (args.length == 1) {
                String[] names = {"ShellExecuteExW", "ShellExecuteW", "FindFirstFileExW", "FindFirstFileW", "FindNextFileW", "NtQueryDirectoryFile", "GetFileAttributesW", "ReadDirectoryChangesW", "SHParseDisplayName", "SHCreateItemFromParsingName", "SHBindToParent", "SetClipboardData", "OpenClipboard", "SHCreateShellItem", "RegisterDragDrop"};
                for (String name : names) {
                    out.println("SYMBOL "+name);
                    for (Symbol s : currentProgram.getSymbolTable().getSymbols(name)) {out.println(s.getAddress()); refs(s.getAddress());}
                }
                for (Data d : currentProgram.getListing().getDefinedData(true)) {
                    if (!d.hasStringValue()) continue;
                    String s = String.valueOf(d.getValue());
                    if (s.toLowerCase().matches("(?s).*(archive|\\.zip|\\.rar|\\.7z|extract|open in|open file|compressed|dragdropstart).*")) {
                        out.println("STRING "+d.getAddress()+" "+s); refs(d.getAddress());
                    }
                }
            } else {
                for(int i=1;i<args.length;i++) {
                    if(args[i].startsWith("text:")) {String term=args[i].substring(5).toLowerCase();for(Data d:currentProgram.getListing().getDefinedData(true))if(d.hasStringValue()&&String.valueOf(d.getValue()).toLowerCase().contains(term)){out.println("STRING "+d.getAddress()+" "+d.getValue());refs(d.getAddress());}continue;}
                    if(args[i].startsWith("symbol:")) {for(Symbol s:currentProgram.getSymbolTable().getSymbols(args[i].substring(7))) {out.println("SYMBOL "+s.getName()+" "+s.getAddress());refs(s.getAddress());}continue;}
                    boolean exact=args[i].startsWith("only:");
                    Address a=toAddr(exact?args[i].substring(5):args[i]);
                    Function f=getFunctionContaining(a);
                    if(f!=null) {selected.add(f); if(!exact) {out.println("CALLERS "+f.getEntryPoint()); refs(f.getEntryPoint());}}
                    else {out.println("ADDRESS "+a); refs(a);}
                }
            }
            DecompInterface dec = new DecompInterface(); dec.openProgram(currentProgram);
            try {
                for(Function f : selected) {
                    monitor.checkCancelled(); out.println("\nFUNCTION "+f.getEntryPoint()+" "+f.getName()+" size="+f.getBody().getNumAddresses());
                    if(f.getBody().getNumAddresses()>100000) {out.println("Skipped oversized function; inspect call-site disassembly separately."); continue;}
                    DecompileResults r=dec.decompileFunction(f,60,monitor);
                    out.println(r.decompileCompleted()?r.getDecompiledFunction().getC():r.getErrorMessage()); out.flush();
                }
            } finally {dec.dispose();}
        }
    }
}

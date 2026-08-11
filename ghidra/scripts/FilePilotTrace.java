// Dumps FilePilot's command-line, navigation, and selection-related call sites.
//@category Reverse Engineering

import java.io.*;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FilePilotTrace extends GhidraScript {
    private PrintWriter out;
    private Set<Function> functions = new TreeSet<>(Comparator.comparing(f -> f.getEntryPoint()));

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: FilePilotTrace.java <output-file>");
        }
        out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), "UTF-8"));
        out.printf("Program: %s%nImage base: %s%nLanguage: %s%nCompiler: %s%n%n",
            currentProgram.getName(), currentProgram.getImageBase(), currentProgram.getLanguageID(),
            currentProgram.getCompilerSpec().getCompilerSpecID());

        String[] symbols = {
            "GetCommandLineW", "CommandLineToArgvW", "LocalFree", "GetFileAttributesW",
            "GetFullPathNameW", "PathRemoveFileSpecW", "PathFindFileNameW",
            "SHParseDisplayName", "SHBindToParent", "FindWindowW", "SendMessageW",
            "SendMessageTimeoutW", "PostMessageW", "SetForegroundWindow", "ShowWindow",
            "SetFocus", "SetActiveWindow", "CreateMutexW", "GetLastError",
            "RegisterWindowMessageW", "CreateWindowExW", "SetWindowLongPtrW",
            "SetWindowLongW", "SetPropW", "GetPropW", "SetTimer", "KillTimer"
        };
        for (String name : symbols) {
            dumpSymbolRefs(name);
        }

        String[] stringTerms = {
            "FilePilot-OpenWindowFormat", "explorer.exe", "<folder>", "<file>",
            "Open in File Pilot", "File Pilot here", "FilePilot_Config_Mutex"
        };
        for (String term : stringTerms) {
            dumpStringRefs(term);
        }

        out.println("\n================ DECOMPILATION ================");
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            out.println("Decompiler initialization failed: " + decompiler.getLastMessage());
        } else {
            for (Function f : functions) {
                monitor.checkCancelled();
                out.printf("%n----- %s @ %s (size 0x%x) -----%n", f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
                DecompileResults result = decompiler.decompileFunction(f, 120, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    out.println(result.getDecompiledFunction().getC());
                } else {
                    out.println("[decompile failed] " + result.getErrorMessage());
                }
            }
        }
        decompiler.dispose();
        out.close();
    }

    private void dumpSymbolRefs(String name) {
        out.printf("\n=== SYMBOL %s ===%n", name);
        boolean found = false;
        SymbolIterator it = currentProgram.getSymbolTable().getSymbols(name);
        while (it.hasNext()) {
            found = true;
            Symbol s = it.next();
            out.printf("symbol %s @ %s type=%s external=%s%n", s.getName(true), s.getAddress(), s.getSymbolType(), s.isExternal());
            collectRefs(s.getAddress());
        }
        if (!found) out.println("[not found]");
    }

    private void dumpStringRefs(String needle) {
        out.printf("\n=== STRING %s ===%n", needle);
        boolean found = false;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (!d.hasStringValue()) continue;
            Object value = d.getValue();
            if (value != null && value.toString().contains(needle)) {
                found = true;
                out.printf("string @ %s: %s%n", d.getAddress(), value);
                collectRefs(d.getAddress());
            }
        }
        if (!found) out.println("[not found as defined data]");
    }

    private void collectRefs(Address target) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
        while (refs.hasNext()) {
            Reference r = refs.next();
            Address from = r.getFromAddress();
            Function f = currentProgram.getFunctionManager().getFunctionContaining(from);
            out.printf("  ref %s -> %s (%s)%n", from, target, f == null ? "no function" : f.getName() + " @ " + f.getEntryPoint());
            if (f != null) functions.add(f);
        }
    }
}

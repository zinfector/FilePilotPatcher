// Dumps the native File Pilot render-command seams used by the Unicode patch.
//@category Reverse Engineering

import java.io.*;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class UnicodeNativeTrace extends GhidraScript {
    private PrintWriter out;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: UnicodeNativeTrace.java <output-file>");
        }
        out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), "UTF-8"));
        long[] targets = {
            0x1401b82f0L, // native text command emitter
            0x1401b99c0L, // native draw-command node allocator
            0x1401b9b50L, // shared render-command allocator/linker
            0x1401b91c0L, // native texture/resource registration
            0x1401b9400L, // native texture/resource lookup
            0x140049350L, // D3D render-command dispatcher
            0x14004a690L  // native textured/glyph draw helper
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(decompiler.getLastMessage());
        }
        for (long target : targets) {
            Address address = toAddr(target);
            Function function = getFunctionContaining(address);
            out.printf("%n================ %s @ %s ================%n",
                function == null ? "[no function]" : function.getName(), address);
            if (function == null) continue;
            out.printf("prototype: %s%nbody: %s%n%n", function.getPrototypeString(false, false),
                function.getBody());
            out.println("-- references to entry --");
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(
                function.getEntryPoint());
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function caller = getFunctionContaining(ref.getFromAddress());
                out.printf("%s %s from %s%n", ref.getFromAddress(), ref.getReferenceType(),
                    caller == null ? "[no function]" : caller.getName() + " @ " + caller.getEntryPoint());
            }
            out.println("-- decompilation --");
            DecompileResults result = decompiler.decompileFunction(function, 180, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                out.println(result.getDecompiledFunction().getC());
            } else {
                out.println("[decompile failed] " + result.getErrorMessage());
            }
            out.println("-- listing --");
            InstructionIterator instructions = currentProgram.getListing().getInstructions(
                function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                out.printf("%s  %-8s %s%n", instruction.getAddress(), instruction.getMnemonicString(),
                    instruction.toString().substring(instruction.getMnemonicString().length()).trim());
            }
        }
        decompiler.dispose();
        out.close();
    }
}

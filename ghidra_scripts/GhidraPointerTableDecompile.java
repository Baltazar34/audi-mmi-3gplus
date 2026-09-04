// Resolve 32-bit pointers stored at supplied addresses and decompile their targets.
// Arguments: output path, then pointer-slot addresses in hexadecimal.
// @category MMI3G

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class GhidraPointerTableDecompile extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + pointer-slot addresses required");
        }
        PrintWriter out = new PrintWriter(args[0]);
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        for (int index = 1; index < args.length; index++) {
            Address slot = toAddr(Long.parseUnsignedLong(args[index], 16));
            long pointer = Integer.toUnsignedLong(getInt(slot));
            Address target = toAddr(pointer);
            Function function = currentProgram.getFunctionManager().getFunctionAt(target);
            if (function == null) {
                function = currentProgram.getFunctionManager().getFunctionContaining(target);
            }
            out.printf("%n===== slot=%s pointer=%s function=%s =====%n",
                slot, target, function == null ? "-" : function.getName(true));
            if (function == null) {
                continue;
            }
            DecompileResults result = decompiler.decompileFunction(function, 180, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                out.println(result.getDecompiledFunction().getC());
            }
            else {
                out.println("DECOMPILE FAILED: " + result.getErrorMessage());
            }
        }
        decompiler.dispose();
        out.close();
    }
}

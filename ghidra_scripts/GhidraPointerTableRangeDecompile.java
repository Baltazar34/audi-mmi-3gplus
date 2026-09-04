// Resolve/decompile consecutive 32-bit pointer slots in a bounded table range.
// Arguments: output path, hexadecimal start slot, hexadecimal exclusive end.
// @category MHI2

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;

public class GhidraPointerTableRangeDecompile extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("output, start slot, exclusive end required");
        }
        long start = Long.parseUnsignedLong(args[1], 16);
        long end = Long.parseUnsignedLong(args[2], 16);
        if (Long.compareUnsigned(end, start) <= 0 || ((end - start) & 3) != 0) {
            throw new IllegalArgumentException("invalid aligned pointer-table range");
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        Set<Long> emitted = new HashSet<>();
        int slots = 0;
        int functions = 0;

        try (PrintWriter out = new PrintWriter(args[0])) {
            for (long offset = start; Long.compareUnsigned(offset, end) < 0; offset += 4) {
                slots++;
                Address slot = toAddr(offset);
                long pointer = Integer.toUnsignedLong(getInt(slot));
                Address target = toAddr(pointer);
                Function function = currentProgram.getFunctionManager().getFunctionAt(target);
                if (function == null) {
                    function = currentProgram.getFunctionManager().getFunctionContaining(target);
                }
                out.printf("%n===== slot=%s index=%d pointer=%s function=%s =====%n",
                    slot, (offset - start) / 4, target,
                    function == null ? "-" : function.getName(true));
                if (function == null || !emitted.add(function.getEntryPoint().getOffset())) {
                    continue;
                }
                functions++;
                DecompileResults result = decompiler.decompileFunction(function, 180, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    out.println(result.getDecompiledFunction().getC());
                }
                else {
                    out.println("DECOMPILE FAILED: " + result.getErrorMessage());
                }
            }
            out.printf("%nSUMMARY slots=%d unique_functions=%d%n", slots, functions);
        }
        decompiler.dispose();
        println("GhidraPointerTableRangeDecompile slots " + slots +
            " unique functions " + functions);
    }
}

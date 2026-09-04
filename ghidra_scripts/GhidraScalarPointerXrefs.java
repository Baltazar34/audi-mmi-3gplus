// Find raw 32-bit pointer constants and decompile the nearest owning function.
// Arguments: output path, then target addresses in hexadecimal.
// @category MMI3G

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class GhidraScalarPointerXrefs extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + target addresses required");
        }
        Map<Long, String> targets = new LinkedHashMap<>();
        for (int index = 1; index < args.length; index++) {
            long value = Long.parseUnsignedLong(args[index], 16) & 0xffffffffL;
            targets.put(value, args[index]);
        }

        PrintWriter out = new PrintWriter(args[0]);
        Memory memory = currentProgram.getMemory();
        Set<Function> functions = new LinkedHashSet<>();
        int matches = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isRead()) {
                continue;
            }
            Address cursor = block.getStart();
            long remainder = cursor.getOffset() & 3L;
            if (remainder != 0) {
                cursor = cursor.add(4L - remainder);
            }
            while (cursor.compareTo(block.getEnd()) <= 0 && !monitor.isCancelled()) {
                if (block.getEnd().subtract(cursor) < 3) {
                    break;
                }
                long value = Integer.toUnsignedLong(memory.getInt(cursor));
                String requested = targets.get(value);
                if (requested != null) {
                    Address target = toAddr(value);
                    Function owner = currentProgram.getFunctionManager().getFunctionContaining(cursor);
                    FunctionIterator backwards = currentProgram.getFunctionManager()
                        .getFunctions(cursor, false);
                    Function previous = backwards.hasNext() ? backwards.next() : null;
                    long previousDistance = previous == null
                        ? -1 : cursor.subtract(previous.getBody().getMaxAddress());
                    out.printf("POINTER slot=%s target=%s requested=%s owner=%s previous=%s distance=%d%n",
                        cursor, target, requested,
                        owner == null ? "-" : owner.getName(true),
                        previous == null ? "-" : previous.getName(true), previousDistance);
                    if (owner != null) {
                        functions.add(owner);
                    }
                    else if (previous != null && previousDistance >= 0 && previousDistance <= 0x100) {
                        functions.add(previous);
                    }
                    matches++;
                }
                cursor = cursor.add(4);
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        for (Function function : functions) {
            out.printf("%n===== %s %s size=%d =====%n", function.getEntryPoint(),
                function.getName(true), function.getBody().getNumAddresses());
            DecompileResults result = decompiler.decompileFunction(function, 180, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                out.println(result.getDecompiledFunction().getC());
            }
            else {
                out.println("DECOMPILE FAILED: " + result.getErrorMessage());
            }
        }
        decompiler.dispose();
        out.printf("%nSUMMARY matches=%d functions=%d%n", matches, functions.size());
        out.close();
    }
}

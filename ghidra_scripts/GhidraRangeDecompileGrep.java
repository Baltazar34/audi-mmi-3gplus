// Decompile a bounded function range and retain C containing supplied needles.
// Arguments: output path, hexadecimal start, hexadecimal end, then needles.
// @category MHI2

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class GhidraRangeDecompileGrep extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4) {
            throw new IllegalArgumentException("output, start, end, and needles required");
        }
        long start = Long.parseUnsignedLong(args[1], 16);
        long end = Long.parseUnsignedLong(args[2], 16);
        List<String> needles = new ArrayList<>();
        for (int index = 3; index < args.length; index++) {
            needles.add(args[index].toLowerCase(Locale.ROOT));
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        int visited = 0;
        int matched = 0;
        try (PrintWriter out = new PrintWriter(args[0])) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                long address = function.getEntryPoint().getOffset();
                if (Long.compareUnsigned(address, start) < 0) {
                    continue;
                }
                if (Long.compareUnsigned(address, end) >= 0) {
                    break;
                }
                visited++;
                if (visited % 250 == 0) {
                    println("GhidraRangeDecompileGrep visited " + visited + " matched " + matched);
                }
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    continue;
                }
                String c = result.getDecompiledFunction().getC();
                String lower = c.toLowerCase(Locale.ROOT);
                List<String> hits = new ArrayList<>();
                for (int index = 0; index < needles.size(); index++) {
                    if (lower.contains(needles.get(index))) {
                        hits.add(args[index + 3]);
                    }
                }
                if (hits.isEmpty()) {
                    continue;
                }
                matched++;
                out.printf("%n===== %s %s size=%d needles=%s =====%n",
                    function.getEntryPoint(), function.getName(true),
                    function.getBody().getNumAddresses(), String.join(",", hits));
                out.println(c);
            }
            out.printf("%nSUMMARY visited=%d matched=%d%n", visited, matched);
        }
        decompiler.dispose();
        println("GhidraRangeDecompileGrep visited " + visited + " matched " + matched);
    }
}

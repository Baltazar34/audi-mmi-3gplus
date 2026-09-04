// Decompile every function and retain functions whose C contains a supplied needle.
// Arguments: output path, then one or more case-insensitive needles.
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

public class GhidraDecompileGrep extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + decompiler needles required");
        }
        List<String> needles = new ArrayList<>();
        for (int index = 1; index < args.length; index++) {
            needles.add(args[index].toLowerCase(Locale.ROOT));
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        int visited = 0;
        int matched = 0;
        PrintWriter out = new PrintWriter(args[0]);
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            visited++;
            DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                continue;
            }
            String c = result.getDecompiledFunction().getC();
            String lower = c.toLowerCase(Locale.ROOT);
            List<String> hits = new ArrayList<>();
            for (int index = 0; index < needles.size(); index++) {
                if (lower.contains(needles.get(index))) {
                    hits.add(args[index + 1]);
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
        out.close();
        decompiler.dispose();
        println("GhidraDecompileGrep visited " + visited + " matched " + matched);
    }
}

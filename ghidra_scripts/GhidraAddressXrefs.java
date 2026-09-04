// Print xrefs to supplied addresses, their containing functions, and decompile them.
// First argument is output path; remaining args are hex addresses.
// @category MHI2

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class GhidraAddressXrefs extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + addresses required");
        }
        PrintWriter out = new PrintWriter(args[0]);
        Set<Function> functions = new LinkedHashSet<>();
        for (int index = 1; index < args.length; index++) {
            Address target = toAddr(Long.parseUnsignedLong(args[index], 16));
            Function targetFunction = currentProgram.getFunctionManager().getFunctionAt(target);
            out.printf("%nTARGET %s function=%s%n", target,
                targetFunction == null ? "-" : targetFunction.getName(true));
            ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(target);
            while (references.hasNext()) {
                Reference reference = references.next();
                Function function = currentProgram.getFunctionManager()
                    .getFunctionContaining(reference.getFromAddress());
                out.printf("  %s type=%s source=%s function=%s%n",
                    reference.getFromAddress(), reference.getReferenceType(),
                    reference.getSource(), function == null ? "-" : function.getName(true));
                if (function != null) {
                    functions.add(function);
                }
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
        out.close();
        println("GhidraAddressXrefs wrote " + functions.size() + " functions");
    }
}

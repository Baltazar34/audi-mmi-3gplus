// Find defined strings containing supplied needles, print xrefs, and decompile callers.
// First argument is output path; remaining arguments are case-insensitive needles.
// @category MHI2

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class GhidraStringXrefs extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + string needles required");
        }
        List<String> needles = new ArrayList<>();
        for (int index = 1; index < args.length; index++) {
            needles.add(args[index].toLowerCase(Locale.ROOT));
        }

        PrintWriter out = new PrintWriter(args[0]);
        Set<Function> callers = new LinkedHashSet<>();
        boolean[] matched = new boolean[needles.size()];
        DataIterator dataItems = currentProgram.getListing().getDefinedData(true);
        while (dataItems.hasNext() && !monitor.isCancelled()) {
            Data data = dataItems.next();
            Object value = data.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            String stringValue = (String)value;
            String lower = stringValue.toLowerCase(Locale.ROOT);
            for (int needleIndex = 0; needleIndex < needles.size(); needleIndex++) {
                if (!lower.contains(needles.get(needleIndex))) {
                    continue;
                }
                matched[needleIndex] = true;
                out.printf("%nSTRING %s needle=%s value=%s%n", data.getAddress(),
                    args[needleIndex + 1], stringValue.replace("\n", "\\n"));
                ReferenceIterator references = currentProgram.getReferenceManager()
                    .getReferencesTo(data.getAddress());
                while (references.hasNext()) {
                    Reference reference = references.next();
                    Function function = currentProgram.getFunctionManager()
                        .getFunctionContaining(reference.getFromAddress());
                    out.printf("  %s type=%s source=%s function=%s%n",
                        reference.getFromAddress(), reference.getReferenceType(),
                        reference.getSource(), function == null ? "-" : function.getName(true));
                    if (function != null) {
                        callers.add(function);
                    }
                }
            }
        }
        for (int index = 0; index < needles.size(); index++) {
            if (!matched[index]) {
                out.printf("%nMISSING needle=%s%n", args[index + 1]);
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        for (Function function : callers) {
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
        println("GhidraStringXrefs matched " + callers.size() + " caller functions");
    }
}

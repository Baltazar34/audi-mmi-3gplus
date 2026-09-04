// List defined strings referenced by supplied functions, including instruction sites.
// Arguments: output path, then hexadecimal function entry addresses.
// @category MHI2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class GhidraFunctionStringRefs extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + function addresses required");
        }
        int found = 0;
        try (PrintWriter out = new PrintWriter(args[0])) {
            for (int index = 1; index < args.length; index++) {
                Address entry = toAddr(Long.parseUnsignedLong(args[index], 16));
                Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                out.printf("%n===== %s function=%s =====%n", entry,
                    function == null ? "-" : function.getName(true));
                if (function == null) {
                    continue;
                }
                Set<Address> emitted = new LinkedHashSet<>();
                InstructionIterator instructions = currentProgram.getListing()
                    .getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    for (Reference reference : instruction.getReferencesFrom()) {
                        Address target = reference.getToAddress();
                        Data data = currentProgram.getListing().getDataAt(target);
                        if (data == null || !(data.getValue() instanceof String) ||
                            !emitted.add(target)) {
                            continue;
                        }
                        String value = ((String)data.getValue())
                            .replace("\n", "\\n").replace("\r", "\\r");
                        out.printf("%s -> %s type=%s value=%s%n",
                            instruction.getAddress(), target,
                            reference.getReferenceType(), value);
                        found++;
                    }
                }
            }
            out.printf("%nSUMMARY strings=%d%n", found);
        }
        println("GhidraFunctionStringRefs strings " + found);
    }
}

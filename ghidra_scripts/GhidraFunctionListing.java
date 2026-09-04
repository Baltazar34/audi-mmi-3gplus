// Dump instruction listings for supplied function entry addresses.
// Arguments: output path, then hexadecimal function addresses.
// @category MHI2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;

public class GhidraFunctionListing extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + function addresses required");
        }
        try (PrintWriter out = new PrintWriter(args[0])) {
            for (int index = 1; index < args.length; index++) {
                Address address = toAddr(Long.parseUnsignedLong(args[index], 16));
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                out.printf("%n===== %s function=%s =====%n", address,
                    function == null ? "-" : function.getName(true));
                if (function == null) {
                    continue;
                }
                InstructionIterator instructions = currentProgram.getListing()
                    .getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    StringBuilder bytes = new StringBuilder();
                    for (byte value : instruction.getBytes()) {
                        if (bytes.length() != 0) bytes.append(' ');
                        bytes.append(String.format("%02x", value & 0xff));
                    }
                    out.printf("%s  %-23s  %s", instruction.getAddress(), bytes,
                        instruction.toString());
                    Reference[] references = instruction.getReferencesFrom();
                    if (references.length != 0) {
                        out.print("  refs=");
                        for (int refIndex = 0; refIndex < references.length; refIndex++) {
                            if (refIndex != 0) out.print(",");
                            out.print(references[refIndex].getToAddress());
                        }
                    }
                    out.println();
                }
            }
        }
    }
}

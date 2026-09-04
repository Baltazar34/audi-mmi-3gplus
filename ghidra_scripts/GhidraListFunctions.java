// List functions in an address range. Arguments: output, start, end.
// @category MHI2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;

public class GhidraListFunctions extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("output, start, end required");
        }
        long start = Long.parseUnsignedLong(args[1], 16);
        long end = Long.parseUnsignedLong(args[2], 16);
        PrintWriter out = new PrintWriter(args[0]);
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            long address = function.getEntryPoint().getOffset();
            if (Long.compareUnsigned(address, start) >= 0
                    && Long.compareUnsigned(address, end) < 0) {
                out.printf("%s %s size=%d%n", function.getEntryPoint(),
                    function.getName(true), function.getBody().getNumAddresses());
            }
        }
        out.close();
    }
}

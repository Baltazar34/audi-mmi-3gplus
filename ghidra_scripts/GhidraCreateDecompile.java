// Disassemble/create functions at supplied code-pointer addresses, then decompile.
// First argument is output path; remaining args are hex addresses.
// @category MHI2

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class GhidraCreateDecompile extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + addresses required");
        }
        PrintWriter out = new PrintWriter(args[0]);
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        for (int index = 1; index < args.length; index++) {
            Address address = toAddr(Long.parseUnsignedLong(args[index], 16));
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                disassemble(address);
                try {
                    function = createFunction(address, null);
                }
                catch (Exception error) {
                    out.println("CREATE " + address + " failed: " + error);
                }
            }
            out.printf("%n===== %s function=%s =====%n", address,
                function == null ? "-" : function.getName(true));
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

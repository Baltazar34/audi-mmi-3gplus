// atlas_dec — CDecompression::create i prvi bitovni citac.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.util.*;

public class atlas_dec extends GhidraScript {
    static final long[] P = {0x08331ac0L, 0x08331c18L, 0x08331d8cL};
    static final String[] N = {"CDecompression::create", "citac 1", "citac 2"};
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_dec.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < P.length; i++) {
            Function f = getFunctionBefore(toAddr(P[i] + 1));
            out.printf("%n%n########## %s (pool 0x%08x) ##########%n", N[i], P[i]);
            if (f == null) { out.println("<nema>"); continue; }
            out.printf("# %s @ %s (%d B)%n", f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
            if (!seen.add(f.getEntryPoint().toString())) { out.println("(ista)"); continue; }
            DecompileResults r = dec.decompileFunction(f, 240, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("atlas_dec: gotovo");
    }
}

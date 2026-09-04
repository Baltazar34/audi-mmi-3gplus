// atlas_cbase — COrionContainerBase metode preko pool adresa.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.util.*;

public class atlas_cbase extends GhidraScript {
    static final long[] P = {0x0832f468L,0x0832f018L,0x0832e6ecL,0x0832e744L,
                             0x0832dc60L,0x0832d888L,0x0832c224L};
    static final String[] N = {"uncompress","calculateOffsets","readString","readBinary",
                               "loadIndexArray","createTables","parseDescriptions"};
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_cbase.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < P.length; i++) {
            Function f = getFunctionBefore(toAddr(P[i] + 1));
            out.printf("%n%n################ %s  (pool 0x%08x) ################%n", N[i], P[i]);
            if (f == null) { out.println("<nema funkcije>"); continue; }
            out.printf("# %s @ %s  (%d B)%n", f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
            if (!seen.add(f.getEntryPoint().toString())) { out.println("(ista funkcija kao ranije)"); continue; }
            DecompileResults r = dec.decompileFunction(f, 300, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("atlas_cbase: gotovo");
    }
}

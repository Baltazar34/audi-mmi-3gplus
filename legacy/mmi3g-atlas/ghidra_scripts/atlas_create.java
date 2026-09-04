// atlas_create — dekompilacija COrionDatabase::create/validate i DataBaseInfo ispisa.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class atlas_create extends GhidraScript {
    static final long[] F = {0x08322504L, 0x0809876cL, 0x083221ecL};
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_create.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        for (long a : F) {
            Function f = getFunctionAt(toAddr(a));
            if (f == null) f = getFunctionBefore(toAddr(a + 1));
            out.printf("%n%n======== %s @ %s ========%n", f.getName(), f.getEntryPoint());
            DecompileResults r = dec.decompileFunction(f, 300, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("atlas_create: gotovo");
    }
}

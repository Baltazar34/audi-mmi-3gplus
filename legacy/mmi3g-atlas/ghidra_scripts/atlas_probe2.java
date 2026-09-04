// atlas_probe2 — dekompilacija konkretnih funkcija .ATLAS lanca.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class atlas_probe2 extends GhidraScript {
    static final long[] FUNCS = { 0x081b3a4cL, 0x081b1710L, 0x08343f08L };
    static final String[] NOTE = {
        "handler koji prima .ATLAS unos", "getter kontejnera", "lock" };

    public void run() throws Exception {
        java.io.PrintWriter out =
            new java.io.PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_probe2.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        for (int i = 0; i < FUNCS.length; i++) {
            Address a = toAddr(FUNCS[i]);
            Function f = getFunctionContaining(a);
            out.println("\n======== " + NOTE[i] + " @ " + a + " ========");
            if (f == null) { out.println("  (nema funkcije na toj adresi)"); continue; }
            DecompileResults r = dec.decompileFunction(f, 180, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("atlas_probe2: gotovo");
    }
}

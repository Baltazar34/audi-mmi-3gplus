// atlas_modes — tri rukovaoca kompresije iz CDecompression::create.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class atlas_modes extends GhidraScript {
    static final long[] F = {0x08330224L, 0x08331050L, 0x08331740L};
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_modes.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        for (int i = 0; i < F.length; i++) {
            Function f = getFunctionAt(toAddr(F[i]));
            if (f == null) f = getFunctionBefore(toAddr(F[i] + 1));
            out.printf("%n%n########## tip %d -> %s @ %s (%d B) ##########%n",
                       i + 1, f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
            DecompileResults r = dec.decompileFunction(f, 240, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("atlas_modes: gotovo");
    }
}

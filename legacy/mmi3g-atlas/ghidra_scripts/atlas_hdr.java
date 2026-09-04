// atlas_hdr — funkcije koje validiraju/ispisuju Orion heder.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.util.*;

public class atlas_hdr extends GhidraScript {
    static final long[] POOL = {
        0x080987b0L, 0x083226acL, 0x083226e0L, 0x08322874L, 0x0832288cL, 0x08322dfcL
    };
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_hdr.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        LinkedHashMap<Address, Function> fs = new LinkedHashMap<>();
        for (long p : POOL) {
            Function f = getFunctionContaining(toAddr(p));
            out.printf("pool 0x%08x -> %s%n", p, f == null ? "<van funkcije>" : f.getName() + " @ " + f.getEntryPoint());
            if (f != null) fs.put(f.getEntryPoint(), f);
        }
        for (Function f : fs.values()) {
            out.printf("%n%n======== %s @ %s  (%d B) ========%n",
                       f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
            DecompileResults r = dec.decompileFunction(f, 300, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("atlas_hdr: gotovo, funkcija=" + fs.size());
    }
}

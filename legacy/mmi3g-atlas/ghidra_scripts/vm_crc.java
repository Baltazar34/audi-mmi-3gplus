// vm_crc — funkcije provere u vdev-logvolmgr.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.util.*;

public class vm_crc extends GhidraScript {
    static final long[] P = {0x08045744L, 0x08046248L, 0x080532dcL, 0x080537e8L};
    static final String[] N = {"CRC of file", "CRC mismatch u conf", "CRC32 mismatch u fajlu", "md5 provera"};
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_vm.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < P.length; i++) {
            Function f = getFunctionBefore(toAddr(P[i] + 1));
            out.printf("%n%n########## %s (pool 0x%08x) ##########%n", N[i], P[i]);
            if (f == null) { out.println("<nema>"); continue; }
            out.printf("# %s @ %s (%d B)%n", f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
            if (!seen.add(f.getEntryPoint().toString())) { out.println("(ista funkcija)"); continue; }
            DecompileResults r = dec.decompileFunction(f, 240, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("vm_crc: gotovo");
    }
}

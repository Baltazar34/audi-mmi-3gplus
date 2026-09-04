// atlas_probe — headless probe nad NavCore (MMI 3G+).
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;
import java.util.*;

public class atlas_probe extends GhidraScript {

    static final long[] ADDRS = {
        0x083CCBE0L, 0x083CCAA4L, 0x081B2350L, 0x081B2388L, 0x084860D8L
    };
    static final String[] LABELS = {
        "assertion: 0 == (file_offset & (CDM_CD_SECTOR_SIZE()-1))",
        "string: ISO9660 volume descriptor on sector",
        "tabela ekstenzija (pocetak, .PI2)",
        "tabela ekstenzija (kraj, .ATLAS)",
        "string: .ATLAS"
    };

    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_probe.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<Address> seen = new HashSet<>();

        for (int i = 0; i < ADDRS.length; i++) {
            Address a = toAddr(ADDRS[i]);
            out.println();
            out.println("========================================================");
            out.printf("%s%n0x%08x%n", LABELS[i], ADDRS[i]);
            out.println("========================================================");

            List<Reference> refs = new ArrayList<>();
            for (Reference r : getReferencesTo(a)) refs.add(r);

            if (refs.isEmpty()) {
                out.println("  (nema direktnih referenci — adresa se verovatno racuna)");
                continue;
            }
            for (Reference r : refs) {
                Function f = getFunctionContaining(r.getFromAddress());
                out.printf("  ref sa %s  u  %s%n", r.getFromAddress(),
                           f != null ? f.getName() : "<van funkcije>");
            }
            for (Reference r : refs) {
                Function f = getFunctionContaining(r.getFromAddress());
                if (f == null || !seen.add(f.getEntryPoint())) continue;
                out.printf("%n--- dekompilacija %s @ %s ---%n", f.getName(), f.getEntryPoint());
                DecompileResults res = dec.decompileFunction(f, 180, monitor);
                out.println(res != null && res.decompileCompleted()
                            ? res.getDecompiledFunction().getC()
                            : "<dekompilacija nije uspela>");
            }
        }
        out.close();
        println("atlas_probe: gotovo");
    }
}

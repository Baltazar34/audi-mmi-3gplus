// atlas_reader — dvostepeni xref do funkcija citaca Orion formata.
// Referenca na string cesto pada u literal pool; tada se trazi ko cita taj slot.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;
import java.util.*;

public class atlas_reader extends GhidraScript {
    static final long[] STR = {
        0x084ff640L, 0x08500094L, 0x08500228L, 0x084fff10L,
        0x084fff60L, 0x084ff46cL, 0x084ffa48L, 0x084ffadcL,
    };
    static final String[] NM = {
        "parseDescriptions", "calculateOffsets", "uncompress", "readString",
        "readBinary", "resolveIndex", "createTables", "loadIndexArray",
    };

    Set<Address> done = new HashSet<>();

    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_reader.txt");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        for (int i = 0; i < STR.length; i++) {
            Address a = toAddr(STR[i]);
            out.printf("%n%n################ %s  (string @ %s) ################%n", NM[i], a);
            LinkedHashSet<Function> fs = new LinkedHashSet<>();
            for (Reference r : getReferencesTo(a)) collect(r.getFromAddress(), fs, 0);
            if (fs.isEmpty()) { out.println("  (nema referenci)"); continue; }
            for (Function f : fs) {
                out.printf("%n--- %s @ %s  (%d B) ---%n",
                           f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
                if (!done.add(f.getEntryPoint())) { out.println("(vec ispisano ranije)"); continue; }
                DecompileResults r = dec.decompileFunction(f, 240, monitor);
                out.println(r != null && r.decompileCompleted()
                            ? r.getDecompiledFunction().getC() : "<neuspelo>");
            }
        }
        out.close();
        println("atlas_reader: gotovo");
    }

    void collect(Address from, LinkedHashSet<Function> fs, int depth) {
        Function f = getFunctionContaining(from);
        if (f != null) { fs.add(f); return; }
        if (depth >= 2) return;                       // pool slot -> ko ga cita
        for (Reference r : getReferencesTo(from)) collect(r.getFromAddress(), fs, depth + 1);
    }
}

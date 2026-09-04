// atlas_map — inventar NavCore-a: koliko funkcija, koje nose imena,
// i gde su funkcije koje diraju Atlas/Orion/Terrain/tile logiku.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.data.StringDataInstance;
import java.io.PrintWriter;
import java.util.*;

public class atlas_map extends GhidraScript {
    static final String[] KEYS = {
        "Atlas","ATLAS","Orion","Terrain","Tile","tile","pkgdb","DBInfo",
        "metainfo","Heights","Radia","SoarTerrain","WGS","Longitude","index"
    };

    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_map.txt");
        FunctionManager fm = currentProgram.getFunctionManager();

        int total = 0, named = 0;
        for (Function f : fm.getFunctions(true)) {
            total++;
            if (!f.getName().startsWith("FUN_")) named++;
        }
        out.printf("funkcija ukupno: %d, sa imenom iz simbola: %d%n%n", total, named);

        Listing lst = currentProgram.getListing();
        Map<String, TreeSet<String>> hits = new LinkedHashMap<>();
        for (String k : KEYS) hits.put(k, new TreeSet<>());

        DataIterator it = lst.getDefinedData(true);
        int nstr = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            if (!(d.getValue() instanceof String)) continue;
            String s = (String) d.getValue();
            nstr++;
            for (String k : KEYS) {
                if (!s.contains(k)) continue;
                for (Reference r : getReferencesTo(d.getAddress())) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    if (f != null) hits.get(k).add(f.getName() + " @ " + f.getEntryPoint());
                }
            }
        }
        out.printf("definisanih stringova: %d%n%n", nstr);
        for (String k : KEYS) {
            TreeSet<String> v = hits.get(k);
            out.printf("== \"%s\" -> %d funkcija%n", k, v.size());
            int n = 0;
            for (String f : v) { out.println("   " + f); if (++n >= 12) { out.println("   ..."); break; } }
        }
        out.close();
        println("atlas_map: gotovo");
    }
}

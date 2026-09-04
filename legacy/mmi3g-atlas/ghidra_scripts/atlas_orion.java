// atlas_orion — dekompilacija Orion klastera (engine .ATLAS formata).
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;
import java.util.*;

public class atlas_orion extends GhidraScript {
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_orion.txt");
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();
        DecompInterface dec = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        dec.setOptions(opts);
        dec.openProgram(currentProgram);

        // 1. sve funkcije u opsegu klastera + sve koje referenciraju "Orion" string
        TreeMap<Long, Function> targets = new TreeMap<>();
        DataIterator it = lst.getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            if (!(d.getValue() instanceof String)) continue;
            String s = (String) d.getValue();
            if (!s.contains("Orion")) continue;
            out.println("string \"" + s + "\" @ " + d.getAddress());
            for (Reference r : getReferencesTo(d.getAddress())) {
                Function f = fm.getFunctionContaining(r.getFromAddress());
                if (f != null) targets.put(f.getEntryPoint().getOffset(), f);
            }
        }
        // dodaj poznatu ulaznu tacku iz .ATLAS registracije
        Function known = getFunctionContaining(toAddr(0x083221ecL));
        if (known != null) targets.put(known.getEntryPoint().getOffset(), known);

        out.printf("%n== ciljanih funkcija: %d ==%n", targets.size());
        for (Map.Entry<Long, Function> e : targets.entrySet()) {
            Function f = e.getValue();
            out.printf("  %s @ %s  (%d B)%n", f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
        }

        for (Map.Entry<Long, Function> e : targets.entrySet()) {
            Function f = e.getValue();
            out.printf("%n%n======== %s @ %s ========%n", f.getName(), f.getEntryPoint());
            DecompileResults r = dec.decompileFunction(f, 240, monitor);
            out.println(r != null && r.decompileCompleted()
                        ? r.getDecompiledFunction().getC() : "<neuspelo>");
        }
        out.close();
        println("atlas_orion: gotovo, ciljeva=" + targets.size());
    }
}

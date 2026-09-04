// atlas_near — sta je oko pool adresa: najbliza funkcija pre/posle.
// @category MMI3G
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import java.io.PrintWriter;

public class atlas_near extends GhidraScript {
    static final long[] POOL = {0x080987b0L,0x083226acL,0x083226e0L,0x08322874L,0x0832288cL,0x08322dfcL};
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(System.getProperty("user.home") + "/mmi3g-atlas/ghidra_near.txt");
        for (long p : POOL) {
            Address a = toAddr(p);
            Function before = getFunctionBefore(a);
            Function after  = getFunctionAfter(a);
            Instruction ins = getInstructionContaining(a);
            Data dat = getDataContaining(a);
            out.printf("0x%08x%n", p);
            out.printf("   pre : %s%n", before == null ? "-" :
                String.format("%s @ %s  kraj %s", before.getName(), before.getEntryPoint(),
                              before.getBody().getMaxAddress()));
            out.printf("   posle: %s%n", after == null ? "-" :
                String.format("%s @ %s", after.getName(), after.getEntryPoint()));
            out.printf("   instrukcija=%s  podatak=%s%n%n",
                       ins == null ? "-" : ins.toString(), dat == null ? "-" : dat.getDataType().getName());
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        out.println("== funkcije u 0x08321000-0x08324000 ==");
        FunctionIterator it = fm.getFunctions(toAddr(0x08321000L), true);
        int n = 0;
        while (it.hasNext() && n < 30) {
            Function f = it.next();
            if (f.getEntryPoint().getOffset() > 0x08324000L) break;
            out.printf("   %s @ %s  (%d B)%n", f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses());
            n++;
        }
        out.close();
        println("atlas_near: gotovo");
    }
}

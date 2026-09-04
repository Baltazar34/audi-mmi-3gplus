// TraceIndirectCalls.java — resolve pointer-pool references used by one function.
// @category AudiMMI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import java.io.PrintWriter;
import java.util.Map;
import java.util.TreeMap;

public class TraceIndirectCalls extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: TraceIndirectCalls <function-address> <output>");
        }
        Address entry = toAddr(args[0]);
        Function function = getFunctionAt(entry);
        if (function == null) {
            function = getFunctionContaining(entry);
        }
        if (function == null) {
            throw new IllegalArgumentException("function not found at " + entry);
        }

        Map<Address, String> pools = new TreeMap<>();
        for (Instruction insn : currentProgram.getListing().getInstructions(function.getBody(), true)) {
            for (Reference ref : insn.getReferencesFrom()) {
                Address target = ref.getToAddress();
                if (target != null && target.isMemoryAddress()) {
                    Symbol symbol = getSymbolAt(target);
                    if (symbol != null && symbol.getName().startsWith("PTR_")) {
                        pools.put(target, symbol.getName());
                    }
                }
            }
        }

        try (PrintWriter out = new PrintWriter(args[1])) {
            out.printf("function=%s entry=%s size=%d%n", function.getName(),
                function.getEntryPoint(), function.getBody().getNumAddresses());
            for (Map.Entry<Address, String> item : pools.entrySet()) {
                Address pool = item.getKey();
                long raw = Integer.toUnsignedLong(getInt(pool));
                Address target = toAddr(raw);
                Symbol primary = getSymbolAt(target);
                Function called = getFunctionAt(target);
                out.printf("%s %-36s -> %s", pool, item.getValue(), target);
                if (primary != null) out.printf(" symbol=%s", primary.getName(true));
                if (called != null) out.printf(" function=%s", called.getName(true));
                out.println();
                for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(target)) {
                    out.printf("    alias=%s source=%s%n", symbol.getName(true), symbol.getSource());
                }
            }
        }
        println("TraceIndirectCalls wrote " + args[1]);
    }
}

// Dump exact bytes at supplied address:length ranges.
// Arguments: output path, then hexadecimal address:length pairs.
// @category MMI3G

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.io.PrintWriter;

public class GhidraMemoryBytes extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("output + address:length ranges required");
        }
        try (PrintWriter out = new PrintWriter(args[0])) {
            for (int index = 1; index < args.length; index++) {
                String[] fields = args[index].split(":", 2);
                Address address = toAddr(Long.parseUnsignedLong(fields[0], 16));
                int length = Integer.parseInt(fields[1]);
                byte[] bytes = new byte[length];
                currentProgram.getMemory().getBytes(address, bytes);
                out.printf("%s:", address);
                for (byte value : bytes) {
                    out.printf(" %02x", value & 0xff);
                }
                out.println();
            }
        }
    }
}

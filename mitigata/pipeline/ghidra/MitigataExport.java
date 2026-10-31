// Headless export for the MITIGATA pipeline: program name, functions, decompiled C, imports and defined strings.
// Every payload is URL-encoded and prefixed with MITIGATA_ so the Python side can split lines reliably.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class MitigataExport extends GhidraScript {

    private static String enc(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    @Override
    protected void run() throws Exception {
        println("MITIGATA_PROGRAM|" + enc(currentProgram.getName()));

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int decompiled = 0;
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            if (function.isExternal()) {
                println("MITIGATA_IMP|" + enc(function.getName()));
                continue;
            }
            println("MITIGATA_FUNC|" + enc(function.getName()) + "|" + function.getEntryPoint()
                    + "|" + function.getBody().getNumAddresses());
            if (decompiled >= 300) {
                continue;
            }
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            decompiled++;
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                println("MITIGATA_DEC|" + enc(function.getName()) + "|"
                        + enc(results.getDecompiledFunction().getC()));
            }
        }
        decompiler.dispose();

        DataIterator data = currentProgram.getListing().getDefinedData(true);
        int strings = 0;
        while (data.hasNext() && strings < 5000 && !monitor.isCancelled()) {
            Data item = data.next();
            if (item.hasStringValue()) {
                Object value = item.getValue();
                if (value != null) {
                    strings++;
                    println("MITIGATA_STR|" + item.getAddress() + "|" + enc(value.toString()));
                }
            }
        }
        println("MITIGATA_END|" + decompiled + "|" + strings);
    }
}

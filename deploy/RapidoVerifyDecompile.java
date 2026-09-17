/* ###
 * IP: GHIDRA
 */
// Verify the final-image Ghidra decompiler bridge with recovered semantics.
//@category Rapido

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class RapidoVerifyDecompile extends GhidraScript {
	@Override
	public void run() throws Exception {
		Function main = null;
		FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function candidate = functions.next();
			if (candidate.getName().equals("main")) {
				main = candidate;
				break;
			}
		}
		if (main == null) {
			throw new AssertionError("main missing");
		}
		DecompInterface decompiler = new DecompInterface();
		try {
			if (!decompiler.openProgram(currentProgram)) {
				throw new AssertionError("open failed");
			}
			DecompileResults result = decompiler.decompileFunction(main, 30, monitor);
			if (!result.decompileCompleted()) {
				throw new AssertionError(result.getErrorMessage());
			}
			String code = result.getDecompiledFunction().getC();
			if (!code.contains("puts") || !code.contains("tiny-exec-ok")) {
				throw new AssertionError("expected recovered semantics missing");
			}
			println("RAPIDO_DECOMPILE_OK");
		}
		finally {
			decompiler.dispose();
		}
	}
}

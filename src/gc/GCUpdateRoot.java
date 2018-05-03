package gc;

import com.oblivm.backend.circuits.arithmetic.IntegerLib;
import com.oblivm.backend.flexsc.CompEnv;

public class GCUpdateRoot<T> extends IntegerLib<T> {

	private int d;
	private int sw;
	private int logSW;

	// d: tree depth
	// sw: root bucket width
	public GCUpdateRoot(CompEnv<T> e, int d, int sw) {
		super(e);
		this.d = d;
		this.sw = sw;
		logSW = (int) Math.ceil(Math.log(sw) / Math.log(2));
	}

	private void zerosFollowedByOnes(T[] input) {
		for (int i = input.length - 2; i >= 0; i--) {
			input[i] = or(input[i], input[i + 1]);
		}
	}

	public T[][] rootFindDeepestAndEmpty(T[] j1, T[] pathLabel, T[] E_feBits, T[] C_feBits, T[][] E_tupleLabels,
			T[][] C_tupleLabels) {
		T[] feBits = xor(E_feBits, C_feBits);
		T[][] tupleLabels = env.newTArray(sw, 0);
		for (int j = 0; j < sw; j++)
			tupleLabels[j] = xor(E_tupleLabels[j], C_tupleLabels[j]);

		T[] l = padSignal(ones(d - 1), d); // has sign bit
		T[] j2 = zeros(logSW); // no sign bit

		for (int j = 0; j < sw; j++) {
			T[] tupleIndex = toSignals(j, logSW);
			T[] lz = xor(pathLabel, tupleLabels[j]);
			zerosFollowedByOnes(lz);
			lz = padSignal(lz, d); // add sign bit

			T firstIf = and(feBits[j], less(lz, l));
			l = mux(l, lz, firstIf);
			j1 = mux(j1, tupleIndex, firstIf);

			j2 = mux(tupleIndex, j2, feBits[j]);
		}

		T[][] output = env.newTArray(2, 0);
		output[0] = j1;
		output[1] = j2;
		return output;
	}
}

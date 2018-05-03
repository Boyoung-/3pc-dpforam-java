package gc;

import java.util.Arrays;

import com.oblivm.backend.circuits.arithmetic.IntegerLib;
import com.oblivm.backend.flexsc.CompEnv;

public class GCRoute<T> extends IntegerLib<T> {

	private int d;
	private int w;
	private int logD;
	private int logW;

	// d: tree depth
	// w: non-root bucket width
	public GCRoute(CompEnv<T> e, int d, int w) {
		super(e);
		this.d = d;
		this.w = w;
		logD = (int) Math.ceil(Math.log(d) / Math.log(2));
		logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2)); // includes fake
																// empty tuple
	}

	public T[][][] routing(T[] Li, T[][] E_feBits, T[][] C_feBits, T[][][] E_tupleLabels, T[][][] C_tupleLabels,
			T[][] delta) {
		T[][] feBits = env.newTArray(d, 0);
		T[][][] tupleLabels = env.newTArray(d, w, 0);
		for (int i = 0; i < d; i++) {
			feBits[i] = xor(E_feBits[i], C_feBits[i]);
			for (int j = 0; j < w; j++) {
				tupleLabels[i][j] = xor(E_tupleLabels[i][j], C_tupleLabels[i][j]);
			}
		}

		T[][][] pd = prepareDeepest(Li, feBits, tupleLabels);
		T[][][] ptai = prepareTargetAndIndex(pd[0], pd[1], pd[2], pd[3], delta);
		T[][] target = makeCycle(ptai[0], ptai[2][0], ptai[2][1], ptai[2][2], ptai[2][3]);

		T[][][] output = env.newTArray(2, 0, 0);
		output[0] = target;
		output[1] = ptai[1];

		// rm sign bit
		for (int i = 0; i < output[0].length; i++) {
			output[0][i] = Arrays.copyOfRange(output[0][i], 0, logD);
			output[1][i] = Arrays.copyOfRange(output[1][i], 0, logW);
		}

		return output;
	}

	private void zerosFollowedByOnes(T[] input) {
		for (int i = input.length - 2; i >= 0; i--) {
			input[i] = or(input[i], input[i + 1]);
		}
	}

	public T[][] findDeepestAndEmpty(int i, T[] pathLabel, T[] feBits, T[][] tupleLabels) {
		T[] l = padSignal(ones(d - 1 - i), d); // has sign bit
		T[] j1 = zeros(logW); // no sign bit
		T[] j2 = zeros(logW);
		T[] et = zeros(1);

		for (int j = 0; j < w; j++) {
			T[] tupleIndex = toSignals(j, logW);
			T[] lz = xor(pathLabel, tupleLabels[j]);
			zerosFollowedByOnes(lz);
			lz = padSignal(lz, d); // add sign bit

			T firstIf = and(feBits[j], less(lz, l));
			l = mux(l, lz, firstIf);
			j1 = mux(j1, tupleIndex, firstIf);

			et = mux(ones(1), et, feBits[j]);
			j2 = mux(tupleIndex, j2, feBits[j]);
		}

		T[] l_p = numberOfOnes(not(Arrays.copyOfRange(l, 0, d - 1))); // has
																		// sign
																		// bit

		T[][] output = env.newTArray(4, 0);
		output[0] = l_p;
		output[1] = padSignal(j1, logW + 1); // add sign bit
		output[2] = padSignal(j2, logW + 1);
		output[3] = et;
		return output;
	}

	public T[][][] prepareDeepest(T[] Li, T[][] feBits, T[][][] tupleLabels) {
		T[] perpD = ones(logD + 1);
		T[][][] output = env.newTArray(4, d, 0);

		T[][] deepest = env.newTArray(d, 0);
		for (int j = 0; j < d; j++)
			deepest[j] = perpD;
		T[] src = perpD;
		T[] goal = perpD; // \perp = -1 in 2's complement form

		for (int i = 0; i < d; i++) {
			T[] index = toSignals(i, logD + 1);
			deepest[i] = mux(deepest[i], src, geq(goal, index));

			T[][] dae = findDeepestAndEmpty(i, Li, feBits[i], tupleLabels[i]);
			T[] l = dae[0];
			output[1][i] = dae[1];
			output[2][i] = dae[2];
			output[3][i] = dae[3];

			T lGreaterGoal = greater(l, goal);
			goal = mux(goal, l, lGreaterGoal);
			src = mux(src, index, lGreaterGoal);
		}

		output[0] = deepest;
		return output;
	}

	public T[][][] prepareTargetAndIndex(T[][] deepest, T[][] j1, T[][] j2, T[][] et, T[][] delta) {
		T[] ft = toSignals(w, logW + 1);
		T[] perpD = ones(logD + 1);
		T[] perpW = ones(logW + 1);
		T[][][] output = env.newTArray(3, 4, 0);

		T[] nTop = perpD;
		T[] nBot = perpD;
		T[] eTop = perpD;
		T[] eBot = perpD;
		T[] src = perpD;
		T[] dest = perpD;
		T[][] target = env.newTArray(d, 0);
		T[][] f = env.newTArray(d, 0);
		for (int i = 0; i < d; i++) {
			target[i] = perpD;
			f[i] = perpW;
		}

		for (int i = d - 1; i >= 0; i--) {
			T[] index = toSignals(i, logD + 1);

			T iEqSrc = eq(index, src);
			target[i] = mux(target[i], dest, iEqSrc);
			f[i] = mux(f[i], j1[i], iEqSrc);
			src = mux(src, perpD, iEqSrc);

			T deepestEqPerp = eq(deepest[i], perpD);
			dest = mux(dest, index, and(iEqSrc, deepestEqPerp));
			dest = mux(dest, perpD, and(iEqSrc, not(deepestEqPerp)));

			T destEqPerp = eq(dest, perpD);
			T srcEqPerp = eq(src, perpD);
			T fourthIf = and(not(deepestEqPerp), and(not(destEqPerp), srcEqPerp));
			target[i] = mux(target[i], dest, fourthIf);
			f[i] = mux(f[i], j2[i], fourthIf);

			T targetEqPerp = eq(target[i], perpD);
			T fifthIf = and(not(deepestEqPerp), or(and(destEqPerp, et[i][0]), not(targetEqPerp)));
			src = mux(src, deepest[i], fifthIf);
			dest = mux(dest, index, fifthIf);
			eTop = mux(eTop, src, fifthIf);

			T eBotEqPerp = eq(eBot, perpD);
			T sixthIf = and(fifthIf, eBotEqPerp);
			eBot = mux(eBot, dest, sixthIf);
			f[i] = mux(f[i], j2[i], sixthIf);

			T fEqPerp = eq(f[i], perpW);
			f[i] = mux(f[i], ft, fEqPerp);
			nTop = mux(nTop, index, fEqPerp);

			T nBotEqPerp = eq(nBot, perpD);
			nBot = mux(nBot, index, and(fEqPerp, nBotEqPerp));

			f[i] = xor(f[i], padSignal(delta[i], logW + 1));
		}

		output[0] = target;
		output[1] = f;
		output[2][0] = nTop;
		output[2][1] = nBot;
		output[2][2] = eTop;
		output[2][3] = eBot;
		return output;
	}

	public T[][] makeCycle(T[][] target, T[] nTop, T[] nBot, T[] eTop, T[] eBot) {
		T[] perpD = ones(logD + 1);
		T[] nPrev = perpD;

		for (int i = 0; i < d; i++) {
			T[] index = toSignals(i, logD + 1);

			T nTopEqPerp = eq(nTop, perpD);
			T iEqEBot = eq(index, eBot);
			target[i] = mux(target[i], eTop, and(nTopEqPerp, iEqEBot));

			T thirdIf = and(not(nTopEqPerp), iEqEBot);
			target[i] = mux(target[i], nBot, thirdIf);

			T fourthIf = and(not(or(nTopEqPerp, iEqEBot)), eq(target[i], perpD));
			T iEqNTop = eq(index, nTop);
			T fifthIf = and(fourthIf, iEqNTop);
			T eTopEqPerp = eq(eTop, perpD);
			target[i] = mux(target[i], nBot, and(fifthIf, eTopEqPerp));
			target[i] = mux(target[i], eTop, and(fifthIf, not(eTopEqPerp)));

			target[i] = mux(target[i], nPrev, and(fourthIf, not(iEqNTop)));

			nPrev = mux(nPrev, index, fourthIf);
		}

		return target;
	}
}

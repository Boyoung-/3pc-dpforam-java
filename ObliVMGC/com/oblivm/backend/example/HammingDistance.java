package com.oblivm.backend.example;

import com.oblivm.backend.circuits.arithmetic.IntegerLib;
import com.oblivm.backend.flexsc.CompEnv;
import com.oblivm.backend.gc.BadLabelException;
import com.oblivm.backend.util.EvaRunnable;
import com.oblivm.backend.util.GenRunnable;

public class HammingDistance {

	static int totalLength = 100;

	private static int countOnes(boolean[] in) {
		int cnt = 0;
		for (int i = 0; i < in.length; i++)
			if (in[i])
				cnt++;
		return cnt;
	}

	private static int booleansToInt(boolean[] arr) {
		int n = 0;
		for (int i = arr.length - 1; i >= 0; i--)
			n = (n << 1) | (arr[i] ? 1 : 0);
		return n;
	}

	public static class Generator<T> extends GenRunnable<T> {

		T[] inputA;
		T[] inputB;
		T[] scResult;
		int cnt;

		@Override
		public void prepareInput(CompEnv<T> gen) {
			boolean[] in = new boolean[totalLength];
			for (int i = 0; i < in.length; ++i)
				in[i] = CompEnv.rnd.nextBoolean();
			inputA = gen.inputOfAlice(in);
			gen.flush();
			inputB = gen.inputOfBob(new boolean[totalLength]);

			cnt = countOnes(in);
		}

		@Override
		public void secureCompute(CompEnv<T> gen) {
			scResult = compute(gen, inputA, inputB);
		}

		private T[] compute(CompEnv<T> gen, T[] inputA, T[] inputB) {
			return new IntegerLib<T>(gen).hammingDistance(inputA, inputB);
		}

		@Override
		public void prepareOutput(CompEnv<T> gen) throws BadLabelException {
			boolean[] out = gen.outputToAlice(scResult);
			int outValue = booleansToInt(out);
			System.out.println((outValue == cnt) + " " + cnt + " " + outValue);
		}

	}

	public static class Evaluator<T> extends EvaRunnable<T> {
		T[] inputA;
		T[] inputB;
		T[] scResult;

		@Override
		public void prepareInput(CompEnv<T> gen) {
			boolean[] in = new boolean[totalLength];
			// for(int i = 0; i < in.length; ++i)
			// in[i] = CompEnv.rnd.nextBoolean();
			inputA = gen.inputOfAlice(new boolean[totalLength]);
			gen.flush();
			inputB = gen.inputOfBob(in);
		}

		@Override
		public void secureCompute(CompEnv<T> gen) {
			scResult = compute(gen, inputA, inputB);
		}

		private T[] compute(CompEnv<T> gen, T[] inputA, T[] inputB) {
			IntegerLib<T> il = new IntegerLib<T>(gen);
			il.hammingDistance(inputB, inputB);
			gen.setEvaluate();
			return il.hammingDistance(inputA, inputB);
		}

		@Override
		public void prepareOutput(CompEnv<T> gen) throws BadLabelException {
			gen.outputToAlice(scResult);
		}
	}
}

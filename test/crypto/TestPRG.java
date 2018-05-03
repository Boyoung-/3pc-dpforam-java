package crypto;

import java.math.BigInteger;

public class TestPRG {

	public static void main(String[] args) {
		// PRG.generateKey(Crypto.sr);

		int n = 10;
		int outBits = 1000;
		int outBytes = (outBits + 7) / 8;
		byte[][] input = new byte[n][16];
		byte[][] output = new byte[n][];
		PRG G = new PRG(outBits);

		for (int i = 0; i < n; i++) {
			Crypto.sr.nextBytes(input[i]);
			output[i] = G.compute(input[i]);
			System.out.println(new BigInteger(1, output[i]).toString(16));
		}

		for (int i = 0; i < n; i++) {
			byte[] tmp = G.compute(input[i]);
			System.out.println(
					"deterministic:\t" + (new BigInteger(1, tmp).compareTo(new BigInteger(1, output[i])) == 0));
			System.out.println("right length:\t" + (output[i].length == outBytes));
		}
	}

}

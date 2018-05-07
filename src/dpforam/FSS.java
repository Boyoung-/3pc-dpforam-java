package dpforam;

import java.math.BigInteger;
import java.util.Arrays;

import crypto.Crypto;
import crypto.PRG;
import util.Util;

// TODO: 1-bit output and early termination
public class FSS {

	int seedBytes;
	PRG prg;

	public FSS(int seedBytes) {
		this.seedBytes = seedBytes;
		prg = new PRG();
	}

	public FSSKey[] Gen(long alpha, int m, byte[] beta) {
		int mPlus1 = m + 1;
		byte[][] s_a_p = new byte[mPlus1][];
		byte[][] s_b_p = new byte[mPlus1][];
		byte[] t_a = new byte[mPlus1];
		byte[] t_b = new byte[mPlus1];
		byte[][][] s_a = new byte[2][mPlus1][seedBytes];
		byte[][][] s_b = new byte[2][mPlus1][seedBytes];
		byte[][] sigma = new byte[mPlus1][];
		byte[][] tau = new byte[2][mPlus1];

		s_a_p[0] = Util.nextBytes(seedBytes, Crypto.sr);
		s_b_p[0] = Util.nextBytes(seedBytes, Crypto.sr);
		t_a[0] = (byte) Crypto.sr.nextInt(2);
		t_b[0] = (byte) (1 - t_a[0]);

		for (int j = 1; j <= m; j++) {
			byte[] twoSeeds = prg.compute(s_a_p[j - 1], seedBytes * 2);
			System.arraycopy(twoSeeds, 0, s_a[0][j], 0, seedBytes);
			System.arraycopy(twoSeeds, seedBytes, s_a[1][j], 0, seedBytes);
			twoSeeds = prg.compute(s_b_p[j - 1], seedBytes * 2);
			System.arraycopy(twoSeeds, 0, s_b[0][j], 0, seedBytes);
			System.arraycopy(twoSeeds, seedBytes, s_b[1][j], 0, seedBytes);

			int alpha_j = (int) (alpha >>> (j - 1)) & 1;
			sigma[j] = Util.xor(s_a[1 - alpha_j][j], s_b[1 - alpha_j][j]);

			tau[0][j] = (byte) ((s_a[0][j][seedBytes - 1] ^ s_b[0][j][seedBytes - 1] ^ alpha_j ^ 1) & 1);
			tau[1][j] = (byte) ((s_a[1][j][seedBytes - 1] ^ s_b[1][j][seedBytes - 1] ^ alpha_j) & 1);

			s_a_p[j] = s_a[alpha_j][j];
			t_a[j] = (byte) (s_a[alpha_j][j][seedBytes - 1] & 1);
			if (t_a[j - 1] == 1) {
				s_a_p[j] = Util.xor(s_a_p[j], sigma[j]);
				t_a[j] = (byte) (t_a[j] ^ tau[alpha_j][j]);
			}
			s_b_p[j] = s_b[alpha_j][j];
			t_b[j] = (byte) (s_b[alpha_j][j][seedBytes - 1] & 1);
			if (t_b[j - 1] == 1) {
				s_b_p[j] = Util.xor(s_b_p[j], sigma[j]);
				t_b[j] = (byte) (t_b[j] ^ tau[alpha_j][j]);
			}
		}

		byte[] gamma = null;
		if (beta.length > seedBytes) {
			gamma = prg.compute(s_a_p[m], beta.length);
			Util.setXor(gamma, prg.compute(s_b_p[m], beta.length));
		} else {
			gamma = Util.xor(s_a_p[m], s_b_p[m]);
			if (gamma.length > beta.length)
				gamma = Arrays.copyOfRange(gamma, 0, beta.length);
		}
		Util.setXor(gamma, beta);

		FSSKey[] keys = new FSSKey[2];
		keys[0] = new FSSKey(s_a_p[0], t_a[0], sigma, tau, gamma);
		keys[1] = new FSSKey(s_b_p[0], t_b[0], sigma, tau, gamma);

		return keys;
	}

	public byte[][] Eval(FSSKey key, long x, int m) {
		byte[] s_p = key.s;
		byte[][] s = new byte[2][seedBytes];
		byte t = key.t;

		for (int j = 1; j <= m; j++) {
			byte[] twoSeeds = prg.compute(s_p, seedBytes * 2);
			System.arraycopy(twoSeeds, 0, s[0], 0, seedBytes);
			System.arraycopy(twoSeeds, seedBytes, s[1], 0, seedBytes);

			int x_j = (int) (x >>> (j - 1)) & 1;
			s_p = (t == 0) ? s[x_j] : Util.xor(s[x_j], key.sigma[j]);
			t = (t == 0) ? 0 : key.tau[x_j][j];
			t = (byte) ((s[x_j][seedBytes - 1] ^ t) & 1);
		}

		byte[][] out = new byte[2][];
		if (key.gamma.length > seedBytes) {
			out[0] = (t == 0) ? prg.compute(s_p, key.gamma.length)
					: Util.xor(prg.compute(s_p, key.gamma.length), key.gamma);
		} else {
			out[0] = (seedBytes == key.gamma.length) ? s_p : Arrays.copyOfRange(s_p, 0, key.gamma.length);
			if (t == 1)
				out[0] = Util.xor(out[0], key.gamma);
		}
		out[1] = new byte[] { t };

		return out;
	}

	// testing
	public static void main(String[] args) {
		int m = 10;
		long range = (long) Math.pow(2, m);

		for (int i = 0; i < 100; i++) {
			boolean pass = true;

			long alpha = Util.nextLong(range, Crypto.sr);
			byte[] beta = Util.padArray(new BigInteger(m, Crypto.sr).toByteArray(),
					Crypto.sr.nextInt(Crypto.prgSeedBytes) + Crypto.prgSeedBytes / 2);

			FSS fss = new FSS(Crypto.prgSeedBytes);
			FSSKey[] keys = fss.Gen(alpha, m, beta);

			for (long x = 0; x < range; x++) {
				byte[][] share0 = fss.Eval(keys[0], x, m);
				byte[][] share1 = fss.Eval(keys[1], x, m);
				byte[] output = Util.xor(share0[0], share1[0]);
				byte outbit = (byte) (share0[1][0] ^ share1[1][0]);

				long outValue = new BigInteger(1, output).longValue();
				long betaValue = new BigInteger(1, beta).longValue();
				if (x == alpha) {
					if (!Util.equal(beta, output) || outbit != 1) {
						System.err.println("Failed: alpha=" + alpha + ", beta=" + betaValue + ", x=" + x + ", outValue="
								+ outValue + ", outbit=" + outbit);
						pass = false;
					}
				} else {
					if (outValue != 0 || outbit != 0) {
						System.err.println("Failed: alpha=" + alpha + ", beta=" + betaValue + ", x=" + x + ", outValue="
								+ outValue + ", outbit=" + outbit);
						pass = false;
					}
				}
			}

			if (pass)
				System.out.println("i=" + i + ", betaBytes=" + beta.length + ": passed");
			else
				System.err.println("i=" + i + ", betaBytes=" + beta.length + ": passed");
		}
	}

}

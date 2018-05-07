package dpforam;

import java.math.BigInteger;

import crypto.Crypto;
import crypto.PRG;
import util.Util;

// TODO: EvalAll
public class FSS1Bit {

	int seedBytes;
	int ETBits;
	PRG prg;

	public FSS1Bit(int seedBytes) {
		this.seedBytes = seedBytes;
		ETBits = earlyTermBits(seedBytes * 8);
		prg = new PRG();
	}

	private int earlyTermBits(int n) {
		return (int) Math.floor(Math.log(n) / Math.log(2));
	}

	public FSSKey[] Gen(long alpha, int m) {
		long mask = (1 << m) - 1;
		alpha &= mask;
		int old_m = m;
		m = Math.max(1, m - ETBits);

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

			int alpha_j = (int) (alpha & 1);
			alpha = alpha >>> 1;
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
		FSSKey[] keys = new FSSKey[2];
		keys[0] = new FSSKey(s_a_p[0], t_a[0], sigma, tau, gamma);
		keys[1] = new FSSKey(s_b_p[0], t_b[0], sigma, tau, gamma);

		if (old_m == 1) {
			return keys;
		}

		gamma = Util.padArray(BigInteger.ZERO.setBit((int) alpha).toByteArray(), seedBytes);
		Util.setXor(gamma, s_a_p[m]);
		Util.setXor(gamma, s_b_p[m]);
		keys[0].gamma = gamma;
		keys[1].gamma = gamma;

		return keys;
	}

	public byte Eval(FSSKey key, long x, int m) {
		long mask = (1 << m) - 1;
		x &= mask;
		int old_m = m;
		m = Math.max(1, m - ETBits);

		byte[] s_p = key.s;
		byte[][] s = new byte[2][seedBytes];
		byte t = key.t;

		for (int j = 1; j <= m; j++) {
			byte[] twoSeeds = prg.compute(s_p, seedBytes * 2);
			System.arraycopy(twoSeeds, 0, s[0], 0, seedBytes);
			System.arraycopy(twoSeeds, seedBytes, s[1], 0, seedBytes);

			int x_j = (int) (x & 1);
			x = x >>> 1;
			s_p = (t == 0) ? s[x_j] : Util.xor(s[x_j], key.sigma[j]);
			t = (t == 0) ? 0 : key.tau[x_j][j];
			t = (byte) ((s[x_j][seedBytes - 1] ^ t) & 1);
		}

		if (old_m == 1) {
			return t;
		}

		byte[] y = (t == 0) ? s_p : Util.xor(s_p, key.gamma);
		t = (byte) (new BigInteger(1, y).testBit((int) x) ? 1 : 0);

		return t;
	}

	// testing
	public static void main(String[] args) {
		for (int m = 1; m <= 10; m++) {
			long range = (long) Math.pow(2, m);

			for (int i = 0; i < 100; i++) {
				boolean pass = true;

				long alpha = Util.nextLong(range, Crypto.sr);

				FSS1Bit fss = new FSS1Bit(Crypto.prgSeedBytes);
				FSSKey[] keys = fss.Gen(alpha, m);

				for (long x = 0; x < range; x++) {
					byte share0 = fss.Eval(keys[0], x, m);
					byte share1 = fss.Eval(keys[1], x, m);
					int output = share0 ^ share1;

					if (x == alpha) {
						if (output != 1) {
							System.err.println("Failed: alpha=" + alpha + ", x=" + x + ", outValue=" + output);
							pass = false;
						}
					} else {
						if (output != 0) {
							System.err.println("Failed: alpha=" + alpha + ", x=" + x + ", outValue=" + output);
							pass = false;
						}
					}
				}

				if (pass)
					System.out.println("m=" + m + ", i=" + i + ": passed");
				else
					System.err.println("m=" + m + ", i=" + i + ": failed");
			}
			System.out.println();
		}
	}

}

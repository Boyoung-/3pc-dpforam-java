package subprotocols;

import java.security.SecureRandom;

import communication.Communication;
import crypto.Crypto;
import util.Util;

public class InsLbl {

	Communication con1;
	Communication con2;
	SecureRandom sr1;
	SecureRandom sr2;

	public InsLbl(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public void runP1(int dN1, byte[] L1, int ttp) {
		int l = L1.length;

		byte[] p = Util.nextBytes(ttp * l, sr1);
		byte[] a = Util.nextBytes(ttp * l, sr1);
		byte[] b = Util.nextBytes(ttp * l, sr1);
		int v = sr1.nextInt(ttp);
		int w = sr1.nextInt(ttp);

		int alpha1 = Crypto.sr.nextInt(ttp);
		int u1 = alpha1 ^ v;
		byte[] pstar = Util.xor(p, Util.xorRotate(a, u1, ttp, l));

		con2.write(u1);
		con2.write(pstar);

		// ----------------------------------------- //

		int m = dN1 ^ alpha1;

		con1.write(m);

		m = con1.readInt();

		int beta1 = m ^ dN1;

		int index = beta1 ^ w;
		for (int i = 0; i < l; i++) {
			b[index * l + i] = (byte) (b[index * l + i] ^ L1[i]);
		}

		con2.write(b);

		return;
	}

	public byte[] runP2(int dN2, byte[] L2, int ttp) {
		int l = L2.length;

		byte[] p = Util.nextBytes(ttp * l, sr1);
		byte[] a = Util.nextBytes(ttp * l, sr1);
		byte[] b = Util.nextBytes(ttp * l, sr1);
		int v = sr1.nextInt(ttp);
		int w = sr1.nextInt(ttp);

		int beta2 = Crypto.sr.nextInt(ttp);
		int u2 = beta2 ^ w;
		byte[] z2 = Util.xor(p, Util.xorRotate(b, u2, ttp, l));

		con2.write(u2);

		// ----------------------------------------- //

		int m = beta2 ^ dN2;

		con1.write(m);

		m = con1.readInt();

		int alpha2 = m ^ dN2;

		int index = alpha2 ^ v;
		for (int i = 0; i < l; i++) {
			a[index * l + i] = (byte) (a[index * l + i] ^ L2[i]);
		}

		con2.write(a);

		return z2;
	}

	public byte[] runP3(int ttp, int l) {
		int u1 = con1.readInt();
		byte[] pstar = con1.read();
		int u2 = con2.readInt();

		// ----------------------------------------- //

		byte[] s1 = con1.read();
		byte[] s2 = con2.read();

		s2 = Util.xorRotate(s2, u1, ttp, l);
		s1 = Util.xorRotate(s1, u2, ttp, l);
		Util.setXor(pstar, s1);
		Util.setXor(pstar, s2);

		return pstar;
	}
}

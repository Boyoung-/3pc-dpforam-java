package subprotocols;

import communication.Communication;
import crypto.Crypto;
import util.Util;

public class SSOT {

	Communication con1;
	Communication con2;

	public SSOT(Communication con1, Communication con2) {
		this.con1 = con1;
		this.con2 = con2;
	}

	public byte[] runE(int b1, byte[][] v01) {
		int mBytes = v01[0].length;
		byte[][] y01 = new byte[2][];
		y01[0] = Util.nextBytes(mBytes, Crypto.sr_DE);
		y01[1] = Util.nextBytes(mBytes, Crypto.sr_DE);
		int e = Crypto.sr_DE.nextInt(2);
		byte[] x = con1.read();

		/////////////////////////////////////////////

		int t = b1 ^ e;
		con2.write(t);
		int s = con2.readInt();

		byte[][] v01_p = new byte[2][];
		v01_p[0] = Util.xor(v01[b1], y01[s]);
		v01_p[1] = Util.xor(v01[1 - b1], y01[1 - s]);
		con2.write(v01_p);
		byte[][] u01_p = con2.readDoubleByteArray();

		byte[] p1 = Util.xor(u01_p[b1], x);

		return p1;
	}

	public void runD(int mBytes) {
		byte[][] x01 = new byte[2][];
		x01[0] = Util.nextBytes(mBytes, Crypto.sr_CD);
		x01[1] = Util.nextBytes(mBytes, Crypto.sr_CD);
		byte[][] y01 = new byte[2][];
		y01[0] = Util.nextBytes(mBytes, Crypto.sr_DE);
		y01[1] = Util.nextBytes(mBytes, Crypto.sr_DE);
		byte[] delta = Util.nextBytes(mBytes, Crypto.sr);
		int c = Crypto.sr_CD.nextInt(2);
		int e = Crypto.sr_DE.nextInt(2);
		byte[] x = Util.xor(x01[e], delta);
		byte[] y = Util.xor(y01[c], delta);
		con2.write(y);
		con1.write(x);

		/////////////////////////////////////////////
	}

	public byte[] runC(int b0, byte[][] u01) {
		int mBytes = u01[0].length;
		byte[][] x01 = new byte[2][];
		x01[0] = Util.nextBytes(mBytes, Crypto.sr_CD);
		x01[1] = Util.nextBytes(mBytes, Crypto.sr_CD);
		int c = Crypto.sr_CD.nextInt(2);
		byte[] y = con2.read();

		/////////////////////////////////////////////

		int s = b0 ^ c;
		con1.write(s);
		int t = con1.readInt();

		byte[][] u01_p = new byte[2][];
		u01_p[0] = Util.xor(u01[b0], x01[t]);
		u01_p[1] = Util.xor(u01[1 - b0], x01[1 - t]);
		con1.write(u01_p);
		byte[][] v01_p = con1.readDoubleByteArray();

		byte[] p0 = Util.xor(v01_p[b0], y);

		return p0;
	}
}

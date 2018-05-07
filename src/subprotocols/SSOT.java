package subprotocols;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.Party;
import util.Util;

public class SSOT extends Protocol {

	public SSOT(Communication con1, Communication con2) {
		super(con1, con2);
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

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 1000; j++) {
			int mBytes = 100;
			int b0 = Crypto.sr.nextInt(2);
			int b1 = Crypto.sr.nextInt(2);
			byte[][] u01 = new byte[2][];
			byte[][] v01 = new byte[2][];
			u01[0] = Util.nextBytes(mBytes, Crypto.sr);
			u01[1] = Util.nextBytes(mBytes, Crypto.sr);
			v01[0] = Util.nextBytes(mBytes, Crypto.sr);
			v01[1] = Util.nextBytes(mBytes, Crypto.sr);

			if (party == Party.Eddie) {
				byte[] p1 = this.runE(b1, v01);

				b0 = con2.readInt();
				u01 = con2.readDoubleByteArray();
				byte[] p0 = con2.read();

				byte[][] m01 = new byte[2][];
				m01[0] = Util.xor(u01[0], v01[0]);
				m01[1] = Util.xor(u01[1], v01[1]);
				int b = b0 ^ b1;
				byte[] p = Util.xor(p0, p1);

				if (Util.equal(p, m01[b])) {
					System.out.println("j = " + j + ": SSOT Passed");
				} else {
					System.err.println("j = " + j + ": SSOT Failed");
				}

			} else if (party == Party.Debbie) {
				this.runD(mBytes);

			} else if (party == Party.Charlie) {
				byte[] p0 = this.runC(b0, u01);

				con1.write(b0);
				con1.write(u01);
				con1.write(p0);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

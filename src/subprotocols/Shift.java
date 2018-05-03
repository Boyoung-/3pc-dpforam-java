package subprotocols;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.Party;
import util.M;
import util.Util;

public class Shift extends Protocol {

	public Shift(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.Shift_on;
		offline_band = all.Shift_off;
		timer = all.Shift;
	}

	public byte[][] runE(byte[][] x, int s) {
		timer.start(M.offline_comp);

		int n = x.length;
		int l = x[0].length;

		byte[][] q = new byte[n][];
		for (int i = 0; i < n; i++)
			q[i] = Util.nextBytes(l, Crypto.sr_CE);

		byte[][] r = new byte[n][];
		for (int i = 0; i < n; i++)
			r[i] = Util.nextBytes(l, Crypto.sr_DE);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		timer.start(M.online_read);
		byte[][] z = con2.readDoubleByteArrayAndDec();
		timer.stop(M.online_read);

		byte[][] b = new byte[n][];
		for (int i = 0; i < n; i++) {
			Util.setXor(z[i], r[i]);
			Util.setXor(z[i], x[i]);
		}
		for (int i = 0; i < n; i++) {
			b[i] = z[(i + s) % n];
			Util.setXor(b[i], q[i]);
		}

		timer.stop(M.online_comp);
		return b;
	}

	public void runD(int s, int n, int l) {
		timer.start(M.offline_comp);

		byte[][] r = new byte[n][];
		for (int i = 0; i < n; i++)
			r[i] = Util.nextBytes(l, Crypto.sr_DE);

		byte[][] p = new byte[n][];
		for (int i = 0; i < n; i++)
			p[i] = Util.nextBytes(l, Crypto.sr_CD);

		for (int i = 0; i < n; i++)
			Util.setXor(p[i], r[i]);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		byte[][] a = new byte[n][];
		for (int i = 0; i < n; i++)
			a[i] = p[(i + s) % n];

		timer.start(M.online_write);
		con2.write(online_band, a);
		timer.stop(M.online_write);

		timer.stop(M.online_comp);
		return;
	}

	public byte[][] runC(byte[][] x) {
		timer.start(M.offline_comp);

		int n = x.length;
		int l = x[0].length;

		byte[][] p = new byte[n][];
		for (int i = 0; i < n; i++)
			p[i] = Util.nextBytes(l, Crypto.sr_CD);

		byte[][] q = new byte[n][];
		for (int i = 0; i < n; i++)
			q[i] = Util.nextBytes(l, Crypto.sr_CE);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		for (int i = 0; i < n; i++)
			Util.setXor(p[i], x[i]);

		timer.start(M.online_write);
		con1.write(online_band, p);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		byte[][] a = con2.readDoubleByteArrayAndDec();
		timer.stop(M.online_read);

		for (int i = 0; i < n; i++)
			Util.setXor(a[i], q[i]);

		timer.stop(M.online_comp);
		return a;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int n = 500;
			int l = 50;
			byte[][] x = new byte[n][l];
			for (int i = 0; i < n; i++) {
				Crypto.sr.nextBytes(x[i]);
			}
			int s = Crypto.sr.nextInt(n);

			if (party == Party.Eddie) {
				con1.write(s);
				byte[][] y1 = this.runE(x, s);

				byte[][] x2 = con2.readDoubleByteArray();
				byte[][] y2 = con2.readDoubleByteArray();
				for (int i = 0; i < n; i++) {
					Util.setXor(x2[i], x[i]);
					Util.setXor(y2[i], y1[i]);
				}
				boolean fail = false;
				for (int i = 0; i < n; i++) {
					if (!Util.equal(y2[i], x2[(i + s) % n])) {
						System.err.println(j + ": Shift test failed");
						fail = true;
						break;
					}
				}
				if (!fail)
					System.out.println(j + ": Shift test passed");

			} else if (party == Party.Debbie) {
				s = con1.readInt();
				this.runD(s, n, l);

			} else if (party == Party.Charlie) {
				byte[][] y2 = this.runC(x);

				con1.write(x);
				con1.write(y2);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

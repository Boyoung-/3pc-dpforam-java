package subprotocols;

import java.security.SecureRandom;
import java.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.Party;
import util.M;
import util.Util;

public class ShiftXorPIR extends Protocol {

	SecureRandom sr1;
	SecureRandom sr2;

	public ShiftXorPIR(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.ShiftXorPIR_on;
		offline_band = all.ShiftXorPIR_off;
		timer = all.ShiftXorPIR;
	}

	public ShiftXorPIR(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		super(con1, con2);
		this.sr1 = sr1;
		this.sr2 = sr2;

		online_band = all.ShiftXorPIR_on;
		offline_band = all.ShiftXorPIR_off;
		timer = all.ShiftXorPIR;
	}

	public void reinit(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public byte[] runP1(byte[][] x, int s1, int s2, int m) {
		timer.start(M.online_comp);

		int n = x.length;
		int l = x[0].length / m;

		byte[][] xp = new byte[n * m][];
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < m; j++) {
				xp[i * m + j] = Arrays.copyOfRange(x[(i + s1) % n], (j ^ s2) * l, ((j ^ s2) + 1) * l);
			}
		}

		SSPIR sspir = new SSPIR(con1, con2, sr1, sr2);
		byte[] z = sspir.runP1(xp);

		timer.stop(M.online_comp);
		return z;
	}

	public byte[] runP2(byte[][] x, int s1, int s2, int m) {
		timer.start(M.online_comp);

		int n = x.length;
		int l = x[0].length / m;

		byte[][] xp = new byte[n * m][];
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < m; j++) {
				xp[i * m + j] = Arrays.copyOfRange(x[(i + s1) % n], (j ^ s2) * l, ((j ^ s2) + 1) * l);
			}
		}

		SSPIR sspir = new SSPIR(con1, con2, sr1, sr2);
		byte[] z = sspir.runP2(xp);

		timer.stop(M.online_comp);
		return z;
	}

	public void runP3(int t1, int t2, int n, int m) {
		timer.start(M.online_comp);

		int t = t1 * m + t2;

		SSPIR sspir = new SSPIR(con1, con2, sr1, sr2);
		sspir.runP3(n * m, t);

		timer.stop(M.online_comp);
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int n = 500;
			int m = 16;
			int l = 4;
			byte[][] x = new byte[n][m * l];
			for (int i = 0; i < n; i++) {
				Crypto.sr.nextBytes(x[i]);
			}
			int s1 = Crypto.sr.nextInt(n);
			int t1 = Crypto.sr.nextInt(n);
			int s2 = Crypto.sr.nextInt(m);
			int t2 = Crypto.sr.nextInt(m);

			if (party == Party.Eddie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CE);

				con1.write(x);
				con1.write(s1);
				con1.write(s2);
				con2.write(t1);
				con2.write(t2);
				byte[] e = this.runP1(x, s1, s2, m);

				byte[] d = con1.read();
				Util.setXor(e, d);

				int i1 = (s1 + t1) % n;
				int i2 = s2 ^ t2;
				byte[] expect = Arrays.copyOfRange(x[i1], i2 * l, (i2 + 1) * l);

				if (!Util.equal(e, expect))
					System.err.println(j + ": ShiftXorPIR test failed");
				else
					System.out.println(j + ": ShiftXorPIR test passed");

			} else if (party == Party.Debbie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CD);

				x = con1.readDoubleByteArray();
				s1 = con1.readInt();
				s2 = con1.readInt();
				byte[] d = this.runP2(x, s1, s2, m);

				con1.write(d);

			} else if (party == Party.Charlie) {
				this.reinit(con1, con2, Crypto.sr_CE, Crypto.sr_CD);

				t1 = con1.readInt();
				t2 = con1.readInt();
				this.runP3(t1, t2, n, m);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

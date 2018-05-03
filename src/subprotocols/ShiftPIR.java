package subprotocols;

import java.security.SecureRandom;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.Party;
import util.M;
import util.Util;

public class ShiftPIR extends Protocol {

	SecureRandom sr1;
	SecureRandom sr2;

	public ShiftPIR(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.ShiftPIR_on;
		offline_band = all.ShiftPIR_off;
		timer = all.ShiftPIR;
	}

	public ShiftPIR(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		super(con1, con2);
		this.sr1 = sr1;
		this.sr2 = sr2;

		online_band = all.ShiftPIR_on;
		offline_band = all.ShiftPIR_off;
		timer = all.ShiftPIR;
	}

	public void reinit(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public byte[] runP1(byte[][] x, int s) {
		timer.start(M.online_comp);

		// TODO: do in place shift
		byte[][] xp = new byte[x.length][];
		for (int i = 0; i < x.length; i++) {
			xp[i] = x[(i + s) % x.length];
		}

		SSPIR sspir = new SSPIR(con1, con2, sr1, sr2);
		byte[] z = sspir.runP1(xp);

		timer.stop(M.online_comp);
		return z;
	}

	public byte[] runP2(byte[][] x, int s) {
		timer.start(M.online_comp);

		byte[][] xp = new byte[x.length][];
		for (int i = 0; i < x.length; i++) {
			xp[i] = x[(i + s) % x.length];
		}

		SSPIR sspir = new SSPIR(con1, con2, sr1, sr2);
		byte[] z = sspir.runP2(xp);

		timer.stop(M.online_comp);
		return z;
	}

	public void runP3(int l, int t) {
		timer.start(M.online_comp);

		SSPIR sspir = new SSPIR(con1, con2, sr1, sr2);
		sspir.runP3(l, t);

		timer.stop(M.online_comp);
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int l = 100;
			int m = 50;
			byte[][] x = new byte[l][m];
			for (int i = 0; i < l; i++) {
				Crypto.sr.nextBytes(x[i]);
			}
			int s = Crypto.sr.nextInt(l);
			int t = Crypto.sr.nextInt(l);

			if (party == Party.Eddie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CE);

				con1.write(x);
				con1.write(s);
				byte[] out = this.runP1(x, s);
				con2.write(out);
				con2.write(x);
				con2.write(s);

			} else if (party == Party.Debbie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CD);

				x = con1.readDoubleByteArray();
				s = con1.readInt();
				byte[] out = this.runP2(x, s);
				con2.write(out);

			} else if (party == Party.Charlie) {
				this.reinit(con1, con2, Crypto.sr_CE, Crypto.sr_CD);

				this.runP3(l, t);
				byte[] out1 = con1.read();
				x = con1.readDoubleByteArray();
				s = con1.readInt();
				byte[] out2 = con2.read();
				Util.setXor(out1, out2);
				int index = (s + t) % l;

				if (!Util.equal(out1, x[index]))
					System.err.println(j + ": ShiftPIR test failed");
				else
					System.out.println(j + ": ShiftPIR test passed");

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

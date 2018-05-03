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

public class SSPIR extends Protocol {

	SecureRandom sr1;
	SecureRandom sr2;

	public SSPIR(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.SSPIR_on;
		offline_band = all.SSPIR_off;
		timer = all.SSPIR;
	}

	public SSPIR(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		super(con1, con2);
		this.sr1 = sr1;
		this.sr2 = sr2;

		online_band = all.SSPIR_on;
		offline_band = all.SSPIR_off;
		timer = all.SSPIR;
	}

	public void reinit(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public byte[] runP1(byte[][] x) {
		timer.start(M.offline_comp);

		int l = x.length;
		int m = x[0].length;
		byte[] a1 = new byte[l];
		byte[] r = new byte[m];
		sr2.nextBytes(a1);
		sr1.nextBytes(r);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		byte[] z = Util.xorSelect(x, a1);
		Util.setXor(z, r);

		timer.stop(M.online_comp);
		return z;
	}

	public byte[] runP2(byte[][] x) {
		timer.start(M.offline_comp);

		int m = x[0].length;
		byte[] r = new byte[m];
		sr1.nextBytes(r);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		timer.start(M.online_read);
		byte[] a2 = con2.readAndDec();
		timer.stop(M.online_read);

		byte[] z = Util.xorSelect(x, a2);
		Util.setXor(z, r);

		timer.stop(M.online_comp);
		return z;
	}

	public void runP3(int l, int t) {
		timer.start(M.offline_comp);

		byte[] a = new byte[l];
		sr1.nextBytes(a);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		a[t] = (byte) (a[t] ^ 1);

		timer.start(M.online_write);
		con2.write(online_band, a);
		timer.stop(M.online_write);

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

			if (party == Party.Eddie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CE);

				con1.write(x);
				byte[] out = this.runP1(x);
				con2.write(out);
				con2.write(x);

			} else if (party == Party.Debbie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CD);

				x = con1.readDoubleByteArray();
				byte[] out = this.runP2(x);
				con2.write(out);

			} else if (party == Party.Charlie) {
				this.reinit(con1, con2, Crypto.sr_CE, Crypto.sr_CD);

				int index = Crypto.sr.nextInt(l);
				this.runP3(l, index);
				byte[] out1 = con1.read();
				x = con1.readDoubleByteArray();
				byte[] out2 = con2.read();
				Util.setXor(out1, out2);

				if (!Util.equal(out1, x[index]))
					System.err.println(j + ": SSPIR test failed");
				else
					System.out.println(j + ": SSPIR test passed");

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

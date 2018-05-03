package subprotocols;

import java.security.SecureRandom;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.OutPIRCOT;
import struct.Party;
import struct.TwoThreeXorByte;
import util.M;
import util.Util;

public class ThreeShiftPIR extends Protocol {

	SecureRandom sr1;
	SecureRandom sr2;

	public ThreeShiftPIR(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.ThreeShiftPIR_on;
		offline_band = all.ThreeShiftPIR_off;
		timer = all.ThreeShiftPIR;
	}

	public ThreeShiftPIR(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		super(con1, con2);
		this.sr1 = sr1;
		this.sr2 = sr2;

		online_band = all.ThreeShiftPIR_on;
		offline_band = all.ThreeShiftPIR_off;
		timer = all.ThreeShiftPIR;
	}

	public void reinit(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public TwoThreeXorByte runE(byte[][] x_DE, byte[][] x_CE, OutPIRCOT i) {
		timer.start(M.online_comp);

		int l = x_DE.length;
		ShiftPIR sftpir = new ShiftPIR(con1, con2, sr1, sr2);
		byte[] e1 = sftpir.runP1(x_DE, i.s_DE);
		sftpir.reinit(con2, con1, sr2, sr1);
		byte[] e2 = sftpir.runP2(x_CE, i.s_CE);
		sftpir.reinit(con1, con2, sr1, sr2);
		sftpir.runP3(l, i.t_E);
		Util.setXor(e1, e2);

		TwoThreeXorByte X = new TwoThreeXorByte();
		X.DE = e1;

		timer.start(M.online_write);
		con1.write(online_band, X.DE);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		X.CE = con2.readAndDec();
		timer.stop(M.online_read);

		timer.stop(M.online_comp);
		return X;
	}

	public TwoThreeXorByte runD(byte[][] x_DE, byte[][] x_CD, OutPIRCOT i) {
		timer.start(M.online_comp);

		int l = x_DE.length;
		ShiftPIR sftpir = new ShiftPIR(con1, con2, sr1, sr2);
		byte[] d1 = sftpir.runP2(x_DE, i.s_DE);
		sftpir.reinit(con2, con1, sr2, sr1);
		sftpir.runP3(l, i.t_D);
		sftpir.reinit(con2, con1, sr2, sr1);
		byte[] d2 = sftpir.runP1(x_CD, i.s_CD);
		Util.setXor(d1, d2);

		TwoThreeXorByte X = new TwoThreeXorByte();
		X.CD = d1;

		timer.start(M.online_write);
		con2.write(online_band, X.CD);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		X.DE = con1.readAndDec();
		timer.stop(M.online_read);

		timer.stop(M.online_comp);
		return X;
	}

	public TwoThreeXorByte runC(byte[][] x_CD, byte[][] x_CE, OutPIRCOT i) {
		timer.start(M.online_comp);

		int l = x_CD.length;
		ShiftPIR sftpir = new ShiftPIR(con1, con2, sr1, sr2);
		sftpir.runP3(l, i.t_C);
		sftpir.reinit(con1, con2, sr1, sr2);
		byte[] c1 = sftpir.runP1(x_CE, i.s_CE);
		sftpir.reinit(con2, con1, sr2, sr1);
		byte[] c2 = sftpir.runP2(x_CD, i.s_CD);
		Util.setXor(c1, c2);

		TwoThreeXorByte X = new TwoThreeXorByte();
		X.CE = c1;

		timer.start(M.online_write);
		con1.write(online_band, X.CE);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		X.CD = con2.readAndDec();
		timer.stop(M.online_read);

		timer.stop(M.online_comp);
		return X;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int l = 500;
			int m = 50;
			byte[][] x_CD = new byte[l][m];
			byte[][] x_CE = new byte[l][m];
			byte[][] x_DE = new byte[l][m];
			for (int i = 0; i < l; i++) {
				Crypto.sr.nextBytes(x_CD[i]);
				Crypto.sr.nextBytes(x_DE[i]);
				Crypto.sr.nextBytes(x_CE[i]);
			}
			int index = Crypto.sr.nextInt(l);
			OutPIRCOT ks = new OutPIRCOT();
			ks.t_C = Crypto.sr.nextInt(l);
			ks.t_D = Crypto.sr.nextInt(l);
			ks.t_E = Crypto.sr.nextInt(l);
			ks.s_DE = (index - ks.t_C + l) % l;
			ks.s_CE = (index - ks.t_D + l) % l;
			ks.s_CD = (index - ks.t_E + l) % l;

			TwoThreeXorByte X = new TwoThreeXorByte();

			if (party == Party.Eddie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CE);

				con1.write(x_CD);
				con1.write(x_DE);
				con2.write(x_CD);
				con2.write(x_CE);
				con1.write(ks.t_D);
				con1.write(ks.s_DE);
				con1.write(ks.s_CD);
				con2.write(ks.t_C);
				con2.write(ks.s_CE);
				con2.write(ks.s_CD);

				X = this.runE(x_DE, x_CE, ks);
				X.CD = con1.read();
				byte[] e = X.CE;
				Util.setXor(e, X.CD);
				Util.setXor(e, X.DE);
				byte[] x = x_DE[index];
				Util.setXor(x, x_CE[index]);
				Util.setXor(x, x_CD[index]);

				if (!Util.equal(x, e))
					System.err.println(j + ": 3ShiftPIR test failed");
				else
					System.out.println(j + ": 3ShiftPIR test passed");

			} else if (party == Party.Debbie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CD);

				x_CD = con1.readDoubleByteArray();
				x_DE = con1.readDoubleByteArray();
				ks.t_D = con1.readInt();
				ks.s_DE = con1.readInt();
				ks.s_CD = con1.readInt();

				X = this.runD(x_DE, x_CD, ks);
				con1.write(X.CD);

			} else if (party == Party.Charlie) {
				this.reinit(con1, con2, Crypto.sr_CE, Crypto.sr_CD);

				x_CD = con1.readDoubleByteArray();
				x_CE = con1.readDoubleByteArray();
				ks.t_C = con1.readInt();
				ks.s_CE = con1.readInt();
				ks.s_CD = con1.readInt();

				this.runC(x_CD, x_CE, ks);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

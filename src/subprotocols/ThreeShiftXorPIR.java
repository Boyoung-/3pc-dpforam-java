package subprotocols;

import java.security.SecureRandom;
import java.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.OutPIRCOT;
import struct.Party;
import struct.TwoOneXor;
import struct.TwoThreeXorByte;
import util.M;
import util.Util;

public class ThreeShiftXorPIR extends Protocol {

	SecureRandom sr1;
	SecureRandom sr2;

	public ThreeShiftXorPIR(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.ThreeShiftXorPIR_on;
		offline_band = all.ThreeShiftXorPIR_off;
		timer = all.ThreeShiftXorPIR;
	}

	public ThreeShiftXorPIR(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		super(con1, con2);
		this.sr1 = sr1;
		this.sr2 = sr2;

		online_band = all.ThreeShiftXorPIR_on;
		offline_band = all.ThreeShiftXorPIR_off;
		timer = all.ThreeShiftXorPIR;
	}

	public void reinit(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public TwoThreeXorByte runE(byte[][] x_DE, byte[][] x_CE, OutPIRCOT i, TwoOneXor dN, int ttp) {
		timer.start(M.online_comp);

		int n = x_DE.length;
		ShiftXorPIR sftpir = new ShiftXorPIR(con1, con2, sr1, sr2);
		byte[] e1 = sftpir.runP1(x_DE, i.s_DE, dN.s_DE, ttp);
		sftpir.reinit(con2, con1, sr2, sr1);
		byte[] e2 = sftpir.runP2(x_CE, i.s_CE, dN.s_CE, ttp);
		sftpir.reinit(con1, con2, sr1, sr2);
		sftpir.runP3(i.t_E, dN.t_E, n, ttp);
		Util.setXor(e1, e2);

		timer.start(M.online_write);
		con1.write(online_band, e1);
		con2.write(online_band, e1);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		byte[] d = con1.readAndDec();
		byte[] c = con2.readAndDec();
		timer.stop(M.online_read);

		TwoThreeXorByte nextL = new TwoThreeXorByte();
		nextL.DE = e1;
		nextL.CD = d;
		nextL.CE = c;

		timer.stop(M.online_comp);
		return nextL;
	}

	public TwoThreeXorByte runD(byte[][] x_DE, byte[][] x_CD, OutPIRCOT i, TwoOneXor dN, int ttp) {
		timer.start(M.online_comp);

		int n = x_DE.length;
		ShiftXorPIR sftpir = new ShiftXorPIR(con1, con2, sr1, sr2);
		byte[] d1 = sftpir.runP2(x_DE, i.s_DE, dN.s_DE, ttp);
		sftpir.reinit(con2, con1, sr2, sr1);
		sftpir.runP3(i.t_D, dN.t_D, n, ttp);
		sftpir.reinit(con2, con1, sr2, sr1);
		byte[] d2 = sftpir.runP1(x_CD, i.s_CD, dN.s_CD, ttp);
		Util.setXor(d1, d2);

		timer.start(M.online_write);
		con1.write(online_band, d1);
		con2.write(online_band, d1);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		byte[] e = con1.readAndDec();
		byte[] c = con2.readAndDec();
		timer.stop(M.online_read);

		TwoThreeXorByte nextL = new TwoThreeXorByte();
		nextL.DE = e;
		nextL.CD = d1;
		nextL.CE = c;

		timer.stop(M.online_comp);
		return nextL;
	}

	public TwoThreeXorByte runC(byte[][] x_CD, byte[][] x_CE, OutPIRCOT i, TwoOneXor dN, int ttp) {
		timer.start(M.online_comp);

		int n = x_CD.length;
		ShiftXorPIR sftpir = new ShiftXorPIR(con1, con2, sr1, sr2);
		sftpir.runP3(i.t_C, dN.t_C, n, ttp);
		sftpir.reinit(con1, con2, sr1, sr2);
		byte[] c1 = sftpir.runP1(x_CE, i.s_CE, dN.s_CE, ttp);
		sftpir.reinit(con2, con1, sr2, sr1);
		byte[] c2 = sftpir.runP2(x_CD, i.s_CD, dN.s_CD, ttp);
		Util.setXor(c1, c2);

		timer.start(M.online_write);
		con1.write(online_band, c1);
		con2.write(online_band, c1);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		byte[] e = con1.readAndDec();
		byte[] d = con2.readAndDec();
		timer.stop(M.online_read);

		TwoThreeXorByte nextL = new TwoThreeXorByte();
		nextL.DE = e;
		nextL.CD = d;
		nextL.CE = c1;

		timer.stop(M.online_comp);
		return nextL;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int n = 500;
			int m = 16;
			int l = 4;
			byte[][] x_CD = new byte[n][m * l];
			byte[][] x_CE = new byte[n][m * l];
			byte[][] x_DE = new byte[n][m * l];
			for (int i = 0; i < n; i++) {
				Crypto.sr.nextBytes(x_CD[i]);
				Crypto.sr.nextBytes(x_DE[i]);
				Crypto.sr.nextBytes(x_CE[i]);
			}
			int i1 = Crypto.sr.nextInt(n);
			OutPIRCOT ks = new OutPIRCOT();
			ks.t_C = Crypto.sr.nextInt(n);
			ks.t_D = Crypto.sr.nextInt(n);
			ks.t_E = Crypto.sr.nextInt(n);
			ks.s_DE = (i1 - ks.t_C + n) % n;
			ks.s_CE = (i1 - ks.t_D + n) % n;
			ks.s_CD = (i1 - ks.t_E + n) % n;

			int i2 = Crypto.sr.nextInt(m);
			TwoOneXor tox = new TwoOneXor();
			tox.t_C = Crypto.sr.nextInt(m);
			tox.t_D = Crypto.sr.nextInt(m);
			tox.t_E = Crypto.sr.nextInt(m);
			tox.s_DE = i2 ^ tox.t_C;
			tox.s_CE = i2 ^ tox.t_D;
			tox.s_CD = i2 ^ tox.t_E;

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
				con1.write(tox.t_D);
				con1.write(tox.s_DE);
				con1.write(tox.s_CD);
				con2.write(tox.t_C);
				con2.write(tox.s_CE);
				con2.write(tox.s_CD);

				TwoThreeXorByte nextL = this.runE(x_DE, x_CE, ks, tox, m);
				byte[] e = Util.xor(Util.xor(nextL.DE, nextL.CE), nextL.CD);
				byte[] d = con1.read();
				byte[] c = con2.read();

				byte[] x = x_DE[i1];
				Util.setXor(x, x_CE[i1]);
				Util.setXor(x, x_CD[i1]);
				byte[] expect = Arrays.copyOfRange(x, i2 * l, (i2 + 1) * l);

				if (!Util.equal(expect, e) || !Util.equal(expect, d) || !Util.equal(expect, c))
					System.err.println(j + ": 3ShiftXorPIR test failed");
				else
					System.out.println(j + ": 3ShiftXorPIR test passed");

			} else if (party == Party.Debbie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CD);

				x_CD = con1.readDoubleByteArray();
				x_DE = con1.readDoubleByteArray();
				ks.t_D = con1.readInt();
				ks.s_DE = con1.readInt();
				ks.s_CD = con1.readInt();
				tox.t_D = con1.readInt();
				tox.s_DE = con1.readInt();
				tox.s_CD = con1.readInt();

				TwoThreeXorByte nextL = this.runD(x_DE, x_CD, ks, tox, m);
				byte[] d = Util.xor(Util.xor(nextL.DE, nextL.CE), nextL.CD);
				con1.write(d);

			} else if (party == Party.Charlie) {
				this.reinit(con1, con2, Crypto.sr_CE, Crypto.sr_CD);

				x_CD = con1.readDoubleByteArray();
				x_CE = con1.readDoubleByteArray();
				ks.t_C = con1.readInt();
				ks.s_CE = con1.readInt();
				ks.s_CD = con1.readInt();
				tox.t_C = con1.readInt();
				tox.s_CE = con1.readInt();
				tox.s_CD = con1.readInt();

				TwoThreeXorByte nextL = this.runC(x_CD, x_CE, ks, tox, m);
				byte[] c = Util.xor(Util.xor(nextL.DE, nextL.CE), nextL.CD);
				con1.write(c);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

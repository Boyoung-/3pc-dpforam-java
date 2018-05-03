package protocols;

import java.security.SecureRandom;
import java.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import oram.Tuple;
import struct.OutULiT;
import struct.Party;
import struct.TwoThreeXorByte;
import struct.TwoThreeXorInt;
import subprotocols.InsLbl;
import util.M;
import util.Util;

public class ULiT extends Protocol {

	SecureRandom sr1;
	SecureRandom sr2;

	public ULiT(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.ULiT_on;
		offline_band = all.ULiT_off;
		timer = all.ULiT;
	}

	public ULiT(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		super(con1, con2);
		this.sr1 = sr1;
		this.sr2 = sr2;

		online_band = all.ULiT_on;
		offline_band = all.ULiT_off;
		timer = all.ULiT;
	}

	public void reinit(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public OutULiT runE(TwoThreeXorByte X, TwoThreeXorByte N, TwoThreeXorInt dN, TwoThreeXorByte Lp,
			TwoThreeXorByte Lpi, TwoThreeXorByte Li, int ttp) {
		timer.start(M.offline_comp);

		int l = Li.CE.length;

		byte[] x2 = Util.nextBytes(X.DE.length, sr1);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		int dN_E = dN.CE;
		byte[] xorLi_E = Util.xor(Lpi.CE, Li.CE);

		InsLbl inslbl = new InsLbl(con1, con2, sr1, sr2);
		inslbl.runP1(dN_E, xorLi_E, ttp);

		inslbl.reinit(con2, con1, sr2, sr1);
		byte[] b1 = inslbl.runP3(ttp, l);

		timer.start(M.online_read);
		byte[] me = con1.readAndDec();
		timer.stop(M.online_read);

		byte[] x3 = Util.xor(me, b1);

		Util.setXor(X.CE, x3);
		Util.setXor(X.DE, x2);

		OutULiT out = new OutULiT();
		out.CE = new Tuple(new byte[] { 1 }, N.CE, Lp.CE, X.CE);
		out.DE = new Tuple(new byte[] { 1 }, N.DE, Lp.DE, X.DE);

		timer.stop(M.online_comp);
		return out;
	}

	public OutULiT runD(TwoThreeXorByte X, TwoThreeXorByte N, TwoThreeXorInt dN, TwoThreeXorByte Lp,
			TwoThreeXorByte Lpi, TwoThreeXorByte Li, int ttp) {
		timer.start(M.offline_comp);

		byte[] x1 = Util.nextBytes(X.CD.length, sr2);
		byte[] x2 = Util.nextBytes(X.CD.length, sr1);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		int dN_D = dN.CD ^ dN.DE;
		byte[] xorLi_D = Util.xor(Util.xor(Lpi.CD, Li.CD), Util.xor(Lpi.DE, Li.DE));

		InsLbl inslbl = new InsLbl(con1, con2, sr1, sr2);
		byte[] a2 = inslbl.runP2(dN_D, xorLi_D, ttp);

		inslbl.reinit(con2, con1, sr2, sr1);
		byte[] a1 = inslbl.runP2(dN_D, xorLi_D, ttp);

		Util.setXor(a1, x1);
		Util.setXor(a1, x2);
		Util.setXor(a2, x1);
		Util.setXor(a2, x2);

		timer.start(M.online_write);
		con1.write(online_band, a1);
		con2.write(online_band, a2);
		timer.stop(M.online_write);

		Util.setXor(X.CD, x1);
		Util.setXor(X.DE, x2);

		OutULiT out = new OutULiT();
		out.CD = new Tuple(new byte[] { 1 }, N.CD, Lp.CD, X.CD);
		out.DE = new Tuple(new byte[] { 1 }, N.DE, Lp.DE, X.DE);

		timer.stop(M.online_comp);
		return out;
	}

	public OutULiT runC(TwoThreeXorByte X, TwoThreeXorByte N, TwoThreeXorInt dN, TwoThreeXorByte Lp,
			TwoThreeXorByte Lpi, TwoThreeXorByte Li, int ttp) {
		timer.start(M.offline_comp);

		int l = Li.CE.length;

		byte[] x1 = Util.nextBytes(X.CD.length, sr2);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		int dN_C = dN.CE;
		byte[] xorLi_C = Util.xor(Lpi.CE, Li.CE);

		InsLbl inslbl = new InsLbl(con1, con2, sr1, sr2);
		byte[] b2 = inslbl.runP3(ttp, l);

		inslbl.reinit(con2, con1, sr2, sr1);
		inslbl.runP1(dN_C, xorLi_C, ttp);

		timer.start(M.online_read);
		byte[] mc = con2.readAndDec();
		timer.stop(M.online_read);

		byte[] x3 = Util.xor(mc, b2);

		Util.setXor(X.CD, x1);
		Util.setXor(X.CE, x3);

		OutULiT out = new OutULiT();
		out.CD = new Tuple(new byte[] { 1 }, N.CD, Lp.CD, X.CD);
		out.CE = new Tuple(new byte[] { 1 }, N.CE, Lp.CE, X.CE);

		timer.stop(M.online_comp);
		return out;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int ttp = (int) Math.pow(2, 8);
			int l = 10;
			int Llen = 9;
			int Nlen = 20;
			int Xlen = ttp * l;

			TwoThreeXorInt dN = new TwoThreeXorInt();
			dN.CD = Crypto.sr.nextInt(ttp);
			dN.DE = Crypto.sr.nextInt(ttp);
			dN.CE = Crypto.sr.nextInt(ttp);
			int trueDN = dN.CD ^ dN.CE ^ dN.DE;

			TwoThreeXorByte X = new TwoThreeXorByte();
			X.CD = Util.nextBytes(Xlen, Crypto.sr);
			X.DE = Util.nextBytes(Xlen, Crypto.sr);
			X.CE = Util.nextBytes(Xlen, Crypto.sr);
			TwoThreeXorByte N = new TwoThreeXorByte();
			N.CD = Util.nextBytes(Nlen, Crypto.sr);
			N.DE = Util.nextBytes(Nlen, Crypto.sr);
			N.CE = Util.nextBytes(Nlen, Crypto.sr);
			TwoThreeXorByte Lp = new TwoThreeXorByte();
			Lp.CD = Util.nextBytes(Llen, Crypto.sr);
			Lp.DE = Util.nextBytes(Llen, Crypto.sr);
			Lp.CE = Util.nextBytes(Llen, Crypto.sr);
			TwoThreeXorByte Lpi = new TwoThreeXorByte();
			Lpi.CD = Util.nextBytes(l, Crypto.sr);
			Lpi.DE = Util.nextBytes(l, Crypto.sr);
			Lpi.CE = Util.nextBytes(l, Crypto.sr);

			byte[] trueX = Util.xor(X.CD, X.CE);
			Util.setXor(trueX, X.DE);

			TwoThreeXorByte Li = new TwoThreeXorByte();
			Li.CD = Util.nextBytes(l, Crypto.sr);
			Li.DE = Util.nextBytes(l, Crypto.sr);
			Li.CE = Arrays.copyOfRange(trueX, trueDN * l, trueDN * l + l);
			Util.setXor(Li.CE, Li.CD);
			Util.setXor(Li.CE, Li.DE);

			if (party == Party.Eddie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CE);

				con1.write(X.CD);
				con1.write(X.DE);
				con1.write(N.CD);
				con1.write(N.DE);
				con1.write(Lp.CD);
				con1.write(Lp.DE);
				con1.write(Lpi.CD);
				con1.write(Lpi.DE);
				con1.write(Li.CD);
				con1.write(Li.DE);
				con1.write(dN.CD);
				con1.write(dN.DE);

				con2.write(X.CD);
				con2.write(X.CE);
				con2.write(N.CD);
				con2.write(N.CE);
				con2.write(Lp.CD);
				con2.write(Lp.CE);
				con2.write(Lpi.CD);
				con2.write(Lpi.CE);
				con2.write(Li.CD);
				con2.write(Li.CE);
				con2.write(dN.CD);
				con2.write(dN.CE);

				OutULiT out = this.runE(X, N, dN, Lp, Lpi, Li, ttp);
				out.CD = con1.readTuple();
				Tuple T = out.CD.xor(out.CE);
				T.setXor(out.DE);
				byte[] trueN = Util.xor(N.CD, N.CE);
				Util.setXor(trueN, N.DE);
				byte[] trueLp = Util.xor(Lp.CD, Lp.CE);
				Util.setXor(trueLp, Lp.DE);
				byte[] trueLpi = Util.xor(Lpi.CD, Lpi.CE);
				Util.setXor(trueLpi, Lpi.DE);
				byte[] expectLpi = Arrays.copyOfRange(T.getA(), trueDN * l, trueDN * l + l);
				byte[] expectX = T.getA();

				boolean fail = false;
				if ((T.getF()[0] & 1) != 1) {
					System.err.println(j + ": ULiT test failed on F");
					fail = true;
				}
				if (!Util.equal(T.getN(), trueN)) {
					System.err.println(j + ": ULiT test failed on N");
					fail = true;
				}
				if (!Util.equal(T.getL(), trueLp)) {
					System.err.println(j + ": ULiT test failed on Lp");
					fail = true;
				}
				if (!Util.equal(expectLpi, trueLpi)) {
					System.err.println(j + ": ULiT test failed on Lpi");
					fail = true;
				}
				for (int i = 0; i < trueDN * l; i++) {
					if (expectX[i] != trueX[i]) {
						System.err.println(j + ": ULiT test failed 1");
						fail = true;
						break;
					}
				}
				for (int i = trueDN * l + l; i < trueX.length; i++) {
					if (expectX[i] != trueX[i]) {
						System.err.println(j + ": ULiT test failed 2");
						fail = true;
						break;
					}
				}
				if (!fail)
					System.out.println(j + ": ULiT test passed");

			} else if (party == Party.Debbie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CD);

				X.CD = con1.read();
				X.DE = con1.read();
				N.CD = con1.read();
				N.DE = con1.read();
				Lp.CD = con1.read();
				Lp.DE = con1.read();
				Lpi.CD = con1.read();
				Lpi.DE = con1.read();
				Li.CD = con1.read();
				Li.DE = con1.read();
				dN.CD = con1.readInt();
				dN.DE = con1.readInt();

				OutULiT out = this.runD(X, N, dN, Lp, Lpi, Li, ttp);
				con1.write(out.CD);

			} else if (party == Party.Charlie) {
				this.reinit(con1, con2, Crypto.sr_CE, Crypto.sr_CD);

				X.CD = con1.read();
				X.CE = con1.read();
				N.CD = con1.read();
				N.CE = con1.read();
				Lp.CD = con1.read();
				Lp.CE = con1.read();
				Lpi.CD = con1.read();
				Lpi.CE = con1.read();
				Li.CD = con1.read();
				Li.CE = con1.read();
				dN.CD = con1.readInt();
				dN.CE = con1.readInt();

				this.runC(X, N, dN, Lp, Lpi, Li, ttp);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

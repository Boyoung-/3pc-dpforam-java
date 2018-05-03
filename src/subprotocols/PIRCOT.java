package subprotocols;

import communication.Communication;
import crypto.Crypto;
import crypto.PRF;
import exceptions.NoSuchPartyException;
import exceptions.PIRCOTException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.OutPIRCOT;
import struct.Party;
import util.M;
import util.Util;

// KSearch
public class PIRCOT extends Protocol {

	public PIRCOT(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.KSearch_on;
		offline_band = all.KSearch_off;
		timer = all.KSearch;
	}

	public OutPIRCOT runE(byte[][] u, byte[] v) {
		timer.start(M.offline_comp);

		int l = u.length;
		byte[] k = PRF.generateKey(Crypto.sr_DE);
		byte[][] r = new byte[l][];
		for (int i = 0; i < l; i++) {
			r[i] = new byte[Crypto.secParamBytes];
			Crypto.sr_DE.nextBytes(r[i]);
		}
		int s_DE = Crypto.sr_DE.nextInt(l);

		int s_CE = Crypto.sr_CE.nextInt(l);

		PRF F_k = new PRF(Crypto.secParam);
		F_k.init(k);

		timer.stop(M.offline_comp);

		//////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		byte[][] a = new byte[l][];
		for (int j = 0; j < l; j++) {
			a[j] = Util.xor(u[(j + s_DE) % l], v);
			a[j] = Util.padArray(a[j], r[j].length);
			Util.setXor(a[j], r[j]);
			a[j] = F_k.compute(a[j]);
		}

		timer.start(M.online_write);
		con2.write(online_band, a);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		int delta = con2.readIntAndDec();
		timer.stop(M.online_read);

		int t_E = (s_DE + delta) % l;

		OutPIRCOT out = new OutPIRCOT();
		out.t_E = t_E;
		out.s_DE = s_DE;
		out.s_CE = s_CE;

		timer.stop(M.online_comp);
		return out;
	}

	public OutPIRCOT runD(byte[][] u, byte[] v) {
		timer.start(M.offline_comp);

		int l = u.length;
		byte[] k = PRF.generateKey(Crypto.sr_DE);
		byte[][] r = new byte[l][];
		for (int i = 0; i < l; i++) {
			r[i] = new byte[Crypto.secParamBytes];
			Crypto.sr_DE.nextBytes(r[i]);
		}
		int s_DE = Crypto.sr_DE.nextInt(l);

		int s_CD = Crypto.sr_CD.nextInt(l);

		PRF F_k = new PRF(Crypto.secParam);
		F_k.init(k);

		timer.stop(M.offline_comp);

		///////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		byte[][] a = new byte[l][];
		for (int j = 0; j < l; j++) {
			a[j] = Util.xor(u[(j + s_DE) % l], v);
			a[j] = Util.padArray(a[j], r[j].length);
			Util.setXor(a[j], r[j]);
			a[j] = F_k.compute(a[j]);
		}

		timer.start(M.online_write);
		con2.write(online_band, a);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		int delta = con2.readIntAndDec();
		timer.stop(M.online_read);

		int t_D = (s_DE + delta) % l;

		OutPIRCOT out = new OutPIRCOT();
		out.t_D = t_D;
		out.s_DE = s_DE;
		out.s_CD = s_CD;

		timer.stop(M.online_comp);
		return out;
	}

	public OutPIRCOT runC(int l) {
		timer.start(M.offline_comp);

		int s_CE = Crypto.sr_CE.nextInt(l);
		int s_CD = Crypto.sr_CD.nextInt(l);

		timer.stop(M.offline_comp);

		/////////////////////////////////////////////////

		timer.start(M.online_comp);

		timer.start(M.online_read);
		byte[][] x = con1.readDoubleByteArrayAndDec();
		byte[][] y = con2.readDoubleByteArrayAndDec();
		timer.stop(M.online_read);

		int count = 0;
		int t_C = 0;
		for (int i = 0; i < l; i++) {
			if (Util.equal(x[i], y[i])) {
				t_C = i;
				count++;
			}
		}

		if (count != 1) {
			throw new PIRCOTException("Invariant error: " + count);
		}

		int delta_D = (t_C - s_CE + l) % l;
		int delta_E = (t_C - s_CD + l) % l;

		timer.start(M.online_write);
		con2.write(online_band, delta_D);
		con1.write(online_band, delta_E);
		timer.stop(M.online_write);

		OutPIRCOT out = new OutPIRCOT();
		out.t_C = t_C;
		out.s_CE = s_CE;
		out.s_CD = s_CD;

		timer.stop(M.online_comp);
		return out;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int n = 500;
			int FN = 5;
			byte[][] a = new byte[n][FN];
			byte[][] b = new byte[n][FN];
			for (int i = 0; i < n; i++) {
				Crypto.sr.nextBytes(a[i]);
			}
			int index = Crypto.sr.nextInt(n);
			byte[] v = a[index].clone();

			OutPIRCOT output;

			if (party == Party.Eddie) {
				con2.write(index);
				output = runE(a, v);

				con2.write(output.t_E);
				con2.write(output.s_CE);
				con2.write(output.s_DE);

			} else if (party == Party.Debbie) {
				output = runD(b, new byte[FN]);

				con2.write(output.t_D);
				con2.write(output.s_DE);
				con2.write(output.s_CD);

			} else if (party == Party.Charlie) {
				index = con1.readInt();
				output = runC(n);

				int t_E = con1.readInt();
				int s_CE = con1.readInt();
				int s_DE = con1.readInt();
				if ((t_E + output.s_CD) % n != index)
					System.err.println(j + ": PIRCOT test failed 1");
				else if (s_CE != output.s_CE)
					System.err.println(j + ": PIRCOT test failed 2");
				else if ((s_DE + output.t_C) % n != index)
					System.err.println(j + ": PIRCOT test failed 3");
				else
					System.out.println(j + ": PIRCOT first half test passed");

				int t_D = con2.readInt();
				s_DE = con2.readInt();
				int s_CD = con2.readInt();
				if ((t_D + output.s_CE) % n != index)
					System.err.println(j + ": PIRCOT test failed 4");
				else if (s_CD != output.s_CD)
					System.err.println(j + ": PIRCOT test failed 5");
				else if ((s_DE + output.t_C) % n != index)
					System.err.println(j + ": PIRCOT test failed 6");
				else
					System.out.println(j + ": PIRCOT all test passed");

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	// for testing correctness
	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

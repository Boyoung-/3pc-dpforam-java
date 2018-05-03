package subprotocols;

import java.math.BigInteger;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import oram.Tuple;
import protocols.Protocol;
import struct.Party;
import util.M;
import util.Util;

// TODO: change XOT to do 2 rounds and 2|path| bndw

public class SSXOT extends Protocol {

	public SSXOT(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.SSXOT_on;
		offline_band = all.SSXOT_off;
		timer = all.SSXOT;
	}

	public Tuple[] runE(Tuple[] m, int[] tupleParam) {
		timer.start(M.offline_comp);

		int n = m.length;

		int[] E_pi = Util.randomPermutation(n, Crypto.sr_DE);

		Tuple[] E_r = new Tuple[n];
		for (int i = 0; i < n; i++) {
			E_r[i] = new Tuple(tupleParam[0], tupleParam[1], tupleParam[2], tupleParam[3], Crypto.sr_DE);
		}

		timer.stop(M.offline_comp);

		/////////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// step 1
		Tuple[] a = new Tuple[m.length];
		for (int i = 0; i < m.length; i++)
			a[i] = m[E_pi[i]].xor(E_r[i]);

		timer.start(M.online_write);
		con2.write(online_band, a);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		a = con2.readTupleArrayAndDec();

		// step 2
		int[] j = con1.readIntArrayAndDec();
		Tuple[] p = con1.readTupleArrayAndDec();
		timer.stop(M.online_read);

		// step 3
		Tuple[] z = new Tuple[j.length];
		for (int i = 0; i < j.length; i++)
			z[i] = a[j[i]].xor(p[i]);

		timer.stop(M.online_comp);
		return z;
	}

	public void runD(int n, int k, int[] tupleParam, int[] index) {
		timer.start(M.offline_comp);

		Tuple[] delta = new Tuple[k];
		for (int i = 0; i < k; i++)
			delta[i] = new Tuple(tupleParam[0], tupleParam[1], tupleParam[2], tupleParam[3], Crypto.sr);

		int[] E_pi = Util.randomPermutation(n, Crypto.sr_DE);
		int[] C_pi = Util.randomPermutation(n, Crypto.sr_CD);
		int[] E_pi_ivs = Util.inversePermutation(E_pi);
		int[] C_pi_ivs = Util.inversePermutation(C_pi);

		Tuple[] E_r = new Tuple[n];
		Tuple[] C_r = new Tuple[n];
		for (int i = 0; i < n; i++) {
			E_r[i] = new Tuple(tupleParam[0], tupleParam[1], tupleParam[2], tupleParam[3], Crypto.sr_DE);
			C_r[i] = new Tuple(tupleParam[0], tupleParam[1], tupleParam[2], tupleParam[3], Crypto.sr_CD);
		}

		timer.stop(M.offline_comp);

		////////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// step 2
		k = index.length;
		int[] E_j = new int[k];
		int[] C_j = new int[k];
		Tuple[] E_p = new Tuple[k];
		Tuple[] C_p = new Tuple[k];
		for (int i = 0; i < k; i++) {
			E_j[i] = E_pi_ivs[index[i]];
			C_j[i] = C_pi_ivs[index[i]];
			E_p[i] = E_r[E_j[i]].xor(delta[i]);
			C_p[i] = C_r[C_j[i]].xor(delta[i]);
		}

		timer.start(M.online_write);
		con2.write(online_band, E_j);
		con2.write(online_band, E_p);
		con1.write(online_band, C_j);
		con1.write(online_band, C_p);
		timer.stop(M.online_write);

		timer.stop(M.online_comp);
	}

	public Tuple[] runC(Tuple[] m, int[] tupleParam) {
		timer.start(M.offline_comp);

		int n = m.length;

		int[] C_pi = Util.randomPermutation(n, Crypto.sr_CD);

		Tuple[] C_r = new Tuple[n];
		for (int i = 0; i < n; i++) {
			C_r[i] = new Tuple(tupleParam[0], tupleParam[1], tupleParam[2], tupleParam[3], Crypto.sr_CD);
		}

		timer.stop(M.offline_comp);

		////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// step 1
		Tuple[] a = new Tuple[m.length];
		for (int i = 0; i < m.length; i++)
			a[i] = m[C_pi[i]].xor(C_r[i]);

		timer.start(M.online_write);
		con1.write(online_band, a);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		a = con1.readTupleArrayAndDec();

		// step 2
		int[] j = con2.readIntArrayAndDec();
		Tuple[] p = con2.readTupleArrayAndDec();
		timer.stop(M.online_read);

		// step 3
		Tuple[] z = new Tuple[j.length];
		for (int i = 0; i < j.length; i++)
			z[i] = a[j[i]].xor(p[i]);

		timer.stop(M.online_comp);
		return z;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int n = 100;
			int k = Crypto.sr.nextInt(50) + 50;
			int[] index = Util.randomPermutation(k, Crypto.sr);
			int[] tupleParam = new int[] { 1, 2, 3, 4 };
			Tuple[] E_m = new Tuple[n];
			Tuple[] C_m = new Tuple[n];
			for (int i = 0; i < n; i++) {
				E_m[i] = new Tuple(tupleParam[0], tupleParam[1], tupleParam[2], tupleParam[3], Crypto.sr);
				C_m[i] = new Tuple(tupleParam[0], tupleParam[1], tupleParam[2], tupleParam[3], null);
			}

			if (party == Party.Eddie) {
				Tuple[] E_out_m = runE(E_m, tupleParam);

				con2.write(E_m);
				con2.write(E_out_m);

			} else if (party == Party.Debbie) {
				runD(n, k, tupleParam, index);

				con2.write(index);

			} else if (party == Party.Charlie) {
				Tuple[] C_out_m = runC(C_m, tupleParam);

				index = con2.readIntArray();
				E_m = con1.readTupleArray();
				Tuple[] E_out_m = con1.readTupleArray();

				boolean pass = true;
				for (int i = 0; i < index.length; i++) {
					int input = new BigInteger(1, E_m[index[i]].getA()).intValue();
					int output = new BigInteger(1, Util.xor(E_out_m[i].getA(), C_out_m[i].getA())).intValue();
					if (input != output) {
						System.err.println("SSXOT test failed");
						pass = false;
						break;
					}
				}
				if (pass)
					System.out.println("SSXOT test passed");

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

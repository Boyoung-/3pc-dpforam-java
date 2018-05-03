package subprotocols;

import java.math.BigInteger;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.Party;
import util.M;
import util.Util;

public class PermuteIndex extends Protocol {

	public PermuteIndex(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.PermTuple_on;
		offline_band = all.PermTuple_off;
		timer = all.PermTuple;
	}

	public void runE(int w, int[] evict_pi) {
		timer.start(M.offline_comp);

		int d = evict_pi.length;
		int logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2));

		byte[][] p = new byte[d][(logW + 7) / 8];
		byte[][] r = new byte[d][(logW + 7) / 8];
		byte[][] a = new byte[d][];
		for (int i = 0; i < d; i++) {
			Crypto.sr_DE.nextBytes(p[i]);
			Crypto.sr_CE.nextBytes(r[i]);
			a[i] = Util.xor(p[i], r[i]);
		}
		a = Util.permute(a, evict_pi);

		timer.start(M.offline_write);
		con1.write(offline_band, a);
		timer.stop(M.offline_write);

		timer.stop(M.offline_comp);
	}

	public int[] runD(boolean firstTree, byte[][] ti, int w) {
		if (firstTree)
			return null;

		timer.start(M.offline_comp);

		int logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2));

		timer.start(M.offline_read);
		byte[][] a = con1.readDoubleByteArrayAndDec();
		timer.stop(M.offline_read);

		int d = a.length;

		byte[][] p = new byte[d][(logW + 7) / 8];
		for (int i = 0; i < d; i++) {
			Crypto.sr_DE.nextBytes(p[i]);
		}

		timer.stop(M.offline_comp);

		////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		byte[][] z = Util.xor(ti, p);

		timer.start(M.online_write);
		con2.write(online_band, z);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		byte[][] g = con2.readDoubleByteArrayAndDec();
		timer.stop(M.online_read);

		ti = Util.xor(a, g);

		int[] ti_pp = new int[ti.length];
		for (int i = 0; i < ti.length; i++)
			ti_pp[i] = Util.getSubBits(new BigInteger(ti[i]), logW, 0).intValue();

		timer.stop(M.online_comp);
		return ti_pp;
	}

	public void runC(boolean firstTree, int w, int[] evict_pi, byte[][] evict_rho) {
		if (firstTree)
			return;

		timer.start(M.offline_comp);

		int d = evict_pi.length;
		int logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2));

		byte[][] r = new byte[d][(logW + 7) / 8];
		for (int i = 0; i < d; i++) {
			Crypto.sr_CE.nextBytes(r[i]);
		}

		timer.stop(M.offline_comp);

		////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		timer.start(M.online_read);
		byte[][] z = con2.readDoubleByteArrayAndDec();
		timer.stop(M.online_read);

		z = Util.xor(z, r);
		z = Util.permute(z, evict_pi);
		byte[][] g = Util.xor(evict_rho, z);

		timer.start(M.online_write);
		con2.write(online_band, g);
		timer.stop(M.online_write);

		timer.stop(M.online_comp);
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int i = 0; i < 100; i++) {

			System.out.println("i=" + i);

			if (party == Party.Eddie) {
				int d = Crypto.sr.nextInt(15) + 5;
				int w = Crypto.sr.nextInt(15) + 5;
				int logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2));

				byte[][] ti = new byte[d][];
				int[] evict_pi = Util.randomPermutation(d, Crypto.sr);
				byte[][] evict_rho = new byte[d][];
				for (int j = 0; j < d; j++) {
					ti[j] = Util.nextBytes((logW + 7) / 8, Crypto.sr);
					evict_rho[j] = Util.nextBytes((logW + 7) / 8, Crypto.sr);
				}

				con1.write(ti);
				con1.write(w);

				con2.write(w);
				con2.write(evict_pi);
				con2.write(evict_rho);

				runE(w, evict_pi);

				int[] ti_pp = con1.readIntArray();
				ti = Util.permute(ti, evict_pi);
				int j = 0;
				for (; j < d; j++) {
					int tmp = Util.getSubBits(new BigInteger(Util.xor(evict_rho[j], ti[j])), logW, 0).intValue();
					if (tmp != ti_pp[j]) {
						System.err.println("PermuteIndex test failed");
						break;
					}
				}
				if (j == d)
					System.out.println("PermuteIndex test passed");

			} else if (party == Party.Debbie) {
				byte[][] ti = con1.readDoubleByteArray();
				int w = con1.readInt();

				int[] ti_pp = runD(false, ti, w);
				con1.write(ti_pp);

			} else if (party == Party.Charlie) {
				int w = con1.readInt();
				int[] evict_pi = con1.readIntArray();
				byte[][] evict_rho = con1.readDoubleByteArray();

				runC(false, w, evict_pi, evict_rho);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

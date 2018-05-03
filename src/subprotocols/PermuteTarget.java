package subprotocols;

import java.math.BigInteger;

import com.oblivm.backend.gc.GCSignal;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import gc.GCUtil;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.Party;
import util.M;
import util.Util;

public class PermuteTarget extends Protocol {

	public PermuteTarget(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.PermBucket_on;
		offline_band = all.PermBucket_off;
		timer = all.PermBucket;
	}

	public void runE(int d, int[] evict_pi, GCSignal[][][] evict_targetOutKeyPairs) {
		timer.start(M.offline_comp);

		// PermuteTargetI
		int logD = (int) Math.ceil(Math.log(d) / Math.log(2));

		byte[][][] keyT = new byte[d][d][];
		byte[][][] targetT = new byte[d][d][];
		byte[][][] maskT = new byte[d][d][];

		for (int i = 0; i < d; i++) {
			for (int j = 0; j < d; j++) {
				GCSignal[] keys = GCUtil.revSelectKeys(evict_targetOutKeyPairs[i], BigInteger.valueOf(j).toByteArray());
				keyT[i][j] = GCUtil.hashAll(keys);

				maskT[i][j] = Util.nextBytes((logD + 7) / 8, Crypto.sr);

				targetT[i][j] = Util.xor(Util.padArray(BigInteger.valueOf(evict_pi[j]).toByteArray(), (logD + 7) / 8),
						maskT[i][j]);
			}

			int[] randPerm = Util.randomPermutation(d, Crypto.sr);
			keyT[i] = Util.permute(keyT[i], randPerm);
			maskT[i] = Util.permute(maskT[i], randPerm);
			targetT[i] = Util.permute(targetT[i], randPerm);
		}

		timer.start(M.offline_write);
		con1.write(offline_band, keyT);
		con1.write(offline_band, targetT);
		con2.write(offline_band, maskT);
		timer.stop(M.offline_write);

		// PermuteTargetII
		byte[][] p = new byte[d][(logD + 7) / 8];
		byte[][] r = new byte[d][(logD + 7) / 8];
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

	public int[] runD(boolean firstTree, GCSignal[][] targetOutKeys) {
		if (firstTree)
			return null;

		timer.start(M.offline_comp);

		int d = targetOutKeys.length;
		int logD = (int) Math.ceil(Math.log(d) / Math.log(2));

		timer.start(M.offline_read);
		// PermuteTargetI
		byte[][][] keyT = con1.readTripleByteArrayAndDec();
		byte[][][] targetT = con1.readTripleByteArrayAndDec();

		// PermuteTargetII
		byte[][] a = con1.readDoubleByteArrayAndDec();
		timer.stop(M.offline_read);

		byte[][] p = new byte[d][(logD + 7) / 8];
		for (int i = 0; i < d; i++) {
			Crypto.sr_DE.nextBytes(p[i]);
		}

		timer.stop(M.offline_comp);

		//////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// PermuteTargetI
		int I[] = new int[d];
		byte[][] target = new byte[d][];

		for (int i = 0; i < d; i++) {
			byte[] hashKeys = GCUtil.hashAll(targetOutKeys[i]);
			for (int j = 0; j < d; j++) {
				if (Util.equal(hashKeys, keyT[i][j])) {
					I[i] = j;
					target[i] = targetT[i][j];
					break;
				}
			}
		}

		// PermuteTargetII
		byte[][] z = Util.xor(target, p);

		timer.start(M.online_write);
		con2.write(online_band, z);
		con2.write(online_band, I);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		byte[][] g = con2.readDoubleByteArrayAndDec();
		timer.stop(M.online_read);

		target = Util.xor(a, g);

		int[] target_pp = new int[d];
		for (int i = 0; i < d; i++)
			target_pp[i] = Util.getSubBits(new BigInteger(target[i]), logD, 0).intValue();

		timer.stop(M.online_comp);
		return target_pp;
	}

	public void runC(boolean firstTree, int d, int[] evict_pi) {
		if (firstTree)
			return;

		timer.start(M.offline_comp);

		int logD = (int) Math.ceil(Math.log(d) / Math.log(2));

		timer.start(M.offline_read);
		// PermuteTargetI
		byte[][][] maskT = con1.readTripleByteArrayAndDec();
		timer.stop(M.offline_read);

		// PermuteTargetII
		byte[][] r = new byte[d][(logD + 7) / 8];
		for (int i = 0; i < d; i++) {
			Crypto.sr_CE.nextBytes(r[i]);
		}

		timer.stop(M.offline_comp);

		//////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// PermuteTargetII
		timer.start(M.online_read);
		byte[][] z = con2.readDoubleByteArrayAndDec();
		int[] I = con2.readIntArrayAndDec();
		timer.stop(M.online_read);

		byte[][] mk = new byte[z.length][];
		for (int i = 0; i < mk.length; i++) {
			mk[i] = Util.xor(maskT[i][I[i]], z[i]);
			mk[i] = Util.xor(r[i], mk[i]);
		}
		byte[][] g = Util.permute(mk, evict_pi);

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
				int d = Crypto.sr.nextInt(20) + 5;
				int logD = (int) Math.ceil(Math.log(d) / Math.log(2));
				int[] target = Util.randomPermutation(d, Crypto.sr);

				int[] evict_pi = Util.randomPermutation(d, Crypto.sr);
				GCSignal[][][] evict_targetOutKeyPairs = new GCSignal[d][][];
				GCSignal[][] targetOutKeys = new GCSignal[d][];
				for (int j = 0; j < d; j++) {
					evict_targetOutKeyPairs[j] = GCUtil.genKeyPairs(logD);
					targetOutKeys[j] = GCUtil.revSelectKeys(evict_targetOutKeyPairs[j],
							BigInteger.valueOf(target[j]).toByteArray());
				}

				con1.write(targetOutKeys);
				con2.write(d);
				con2.write(evict_pi);

				runE(d, evict_pi, evict_targetOutKeyPairs);

				int[] target_pp = con1.readIntArray();
				int[] pi_ivs = Util.inversePermutation(evict_pi);
				int[] piTargetPiIvs = new int[d];

				int j = 0;
				for (; j < d; j++) {
					piTargetPiIvs[j] = evict_pi[target[pi_ivs[j]]];
					if (piTargetPiIvs[j] != target_pp[j]) {
						System.err.println("PermuteTarget test failed");
						break;
					}
				}
				if (j == d)
					System.out.println("PermuteTarget test passed");

			} else if (party == Party.Debbie) {
				GCSignal[][] targetOutKeys = con1.readDoubleGCSignalArray();

				int[] target_pp = runD(false, targetOutKeys);
				con1.write(target_pp);

			} else if (party == Party.Charlie) {
				int d = con1.readInt();
				int[] evict_pi = con1.readIntArray();

				runC(false, d, evict_pi);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

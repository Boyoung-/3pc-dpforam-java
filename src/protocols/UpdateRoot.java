package protocols;

import java.math.BigInteger;

import org.apache.commons.lang3.ArrayUtils;

import com.oblivm.backend.flexsc.CompEnv;
import com.oblivm.backend.gc.GCSignal;
import com.oblivm.backend.gc.regular.GCEva;
import com.oblivm.backend.gc.regular.GCGen;
import com.oblivm.backend.network.Network;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import gc.GCUpdateRoot;
import gc.GCUtil;
import oram.Forest;
import oram.Metadata;
import oram.Tuple;
import struct.Party;
import subprotocols.SSXOT;
import util.M;
import util.Util;

public class UpdateRoot extends Protocol {

	public UpdateRoot(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.UpdateRoot_on;
		offline_band = all.UpdateRoot_off;
		timer = all.UpdateRoot;
	}

	public Tuple[] runE(boolean firstTree, int sw, int lBits, int[] tupleParam, byte[] Li, Tuple[] R, Tuple Ti) {
		if (firstTree)
			return R;

		timer.start(M.offline_comp);

		int sLogW = (int) Math.ceil(Math.log(sw) / Math.log(2));
		GCSignal[][] j1KeyPairs = GCUtil.genKeyPairs(sLogW);
		GCSignal[][] LiKeyPairs = GCUtil.genKeyPairs(lBits);
		GCSignal[][] E_feKeyPairs = GCUtil.genKeyPairs(sw);
		GCSignal[][] C_feKeyPairs = GCUtil.genKeyPairs(sw);
		GCSignal[] j1ZeroKeys = GCUtil.getZeroKeys(j1KeyPairs);
		GCSignal[] LiZeroKeys = GCUtil.getZeroKeys(LiKeyPairs);
		GCSignal[] E_feZeroKeys = GCUtil.getZeroKeys(E_feKeyPairs);
		GCSignal[] C_feZeroKeys = GCUtil.getZeroKeys(C_feKeyPairs);
		GCSignal[][][] E_labelKeyPairs = new GCSignal[sw][][];
		GCSignal[][][] C_labelKeyPairs = new GCSignal[sw][][];
		GCSignal[][] E_labelZeroKeys = new GCSignal[sw][];
		GCSignal[][] C_labelZeroKeys = new GCSignal[sw][];
		for (int i = 0; i < sw; i++) {
			E_labelKeyPairs[i] = GCUtil.genKeyPairs(lBits);
			C_labelKeyPairs[i] = GCUtil.genKeyPairs(lBits);
			E_labelZeroKeys[i] = GCUtil.getZeroKeys(E_labelKeyPairs[i]);
			C_labelZeroKeys[i] = GCUtil.getZeroKeys(C_labelKeyPairs[i]);
		}

		Network channel = new Network(null, con1);
		CompEnv<GCSignal> gen = new GCGen(channel, timer, offline_band, M.offline_write);
		GCSignal[][] outZeroKeys = new GCUpdateRoot<GCSignal>(gen, lBits + 1, sw).rootFindDeepestAndEmpty(j1ZeroKeys,
				LiZeroKeys, E_feZeroKeys, C_feZeroKeys, E_labelZeroKeys, C_labelZeroKeys);
		((GCGen) gen).sendLastSetGTT();

		byte[][][] outKeyHashes = new byte[outZeroKeys.length][][];
		for (int i = 0; i < outZeroKeys.length; i++)
			outKeyHashes[i] = GCUtil.genOutKeyHashes(outZeroKeys[i]);

		timer.start(M.offline_write);
		con2.write(offline_band, C_feKeyPairs);
		con2.write(offline_band, C_labelKeyPairs);
		con1.write(offline_band, outKeyHashes);
		timer.stop(M.offline_write);

		timer.stop(M.offline_comp);

		//////////////////////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// step 1
		int j1 = Crypto.sr.nextInt(R.length);
		GCSignal[] j1InputKeys = GCUtil.revSelectKeys(j1KeyPairs, BigInteger.valueOf(j1).toByteArray());
		GCSignal[] LiInputKeys = GCUtil.revSelectKeys(LiKeyPairs, Li);
		GCSignal[] E_feInputKeys = GCUtil.selectFeKeys(E_feKeyPairs, R);
		GCSignal[][] E_labelInputKeys = GCUtil.selectLabelKeys(E_labelKeyPairs, R);

		timer.start(M.online_write);
		con1.write(online_band, j1InputKeys);
		con1.write(online_band, LiInputKeys);
		con1.write(online_band, E_feInputKeys);
		con1.write(online_band, E_labelInputKeys);
		timer.stop(M.online_write);

		// step 4
		R = ArrayUtils.addAll(R, new Tuple[] { Ti });
		SSXOT ssxot = new SSXOT(con1, con2);
		R = ssxot.runE(R, tupleParam);

		timer.stop(M.online_comp);
		return R;
	}

	public void runD(boolean firstTree, int sw, int lBits, int[] tupleParam, byte[] Li, int w) {
		if (firstTree)
			return;

		timer.start(M.offline_comp);

		int logSW = (int) Math.ceil(Math.log(sw) / Math.log(2));
		GCSignal[] j1ZeroKeys = GCUtil.genEmptyKeys(logSW);
		GCSignal[] LiZeroKeys = GCUtil.genEmptyKeys(lBits);
		GCSignal[] E_feZeroKeys = GCUtil.genEmptyKeys(sw);
		GCSignal[] C_feZeroKeys = GCUtil.genEmptyKeys(sw);
		GCSignal[][] E_labelZeroKeys = new GCSignal[sw][];
		GCSignal[][] C_labelZeroKeys = new GCSignal[sw][];
		for (int i = 0; i < sw; i++) {
			E_labelZeroKeys[i] = GCUtil.genEmptyKeys(lBits);
			C_labelZeroKeys[i] = GCUtil.genEmptyKeys(lBits);
		}

		Network channel = new Network(con1, null);
		CompEnv<GCSignal> eva = new GCEva(channel, timer, M.offline_read);
		GCUpdateRoot<GCSignal> gcur = new GCUpdateRoot<GCSignal>(eva, lBits + 1, sw);
		gcur.rootFindDeepestAndEmpty(j1ZeroKeys, LiZeroKeys, E_feZeroKeys, C_feZeroKeys, E_labelZeroKeys,
				C_labelZeroKeys);
		((GCEva) eva).receiveLastSetGTT();
		eva.setEvaluate();

		timer.start(M.offline_read);
		byte[][][] outKeyHashes = con1.readTripleByteArrayAndDec();
		timer.stop(M.offline_read);

		timer.stop(M.offline_comp);

		///////////////////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// step 1
		timer.start(M.online_read);
		GCSignal[] j1InputKeys = con1.readGCSignalArrayAndDec();
		GCSignal[] LiInputKeys = con1.readGCSignalArrayAndDec();
		GCSignal[] E_feInputKeys = con1.readGCSignalArrayAndDec();
		GCSignal[][] E_labelInputKeys = con1.readDoubleGCSignalArrayAndDec();
		GCSignal[] C_feInputKeys = con2.readGCSignalArrayAndDec();
		GCSignal[][] C_labelInputKeys = con2.readDoubleGCSignalArrayAndDec();
		timer.stop(M.online_read);

		// step 2
		GCSignal[][] outKeys = gcur.rootFindDeepestAndEmpty(j1InputKeys, LiInputKeys, E_feInputKeys, C_feInputKeys,
				E_labelInputKeys, C_labelInputKeys);
		int j1 = GCUtil.evaOutKeys(outKeys[0], outKeyHashes[0]).intValue();
		int j2 = GCUtil.evaOutKeys(outKeys[1], outKeyHashes[1]).intValue();

		// step 3
		int r = Crypto.sr.nextInt(w);
		int[] I = new int[E_feInputKeys.length];
		for (int i = 0; i < I.length; i++)
			I[i] = i;
		I[j2] = I.length;
		int tmp = I[r];
		I[r] = I[j1];
		I[j1] = tmp;

		// step 4
		SSXOT ssxot = new SSXOT(con1, con2);
		ssxot.runD(sw + 1, sw, tupleParam, I);

		timer.stop(M.online_comp);
	}

	public Tuple[] runC(boolean firstTree, int[] tupleParam, Tuple[] R, Tuple Ti) {
		if (firstTree)
			return R;

		timer.start(M.offline_comp);

		timer.start(M.offline_read);
		GCSignal[][] C_feKeyPairs = con1.readDoubleGCSignalArrayAndDec();
		GCSignal[][][] C_labelKeyPairs = con1.readTripleGCSignalArrayAndDec();
		timer.stop(M.offline_read);

		timer.stop(M.offline_comp);

		////////////////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		// step 1
		GCSignal[] C_feInputKeys = GCUtil.selectFeKeys(C_feKeyPairs, R);
		GCSignal[][] C_labelInputKeys = GCUtil.selectLabelKeys(C_labelKeyPairs, R);

		timer.start(M.online_write);
		con2.write(online_band, C_feInputKeys);
		con2.write(online_band, C_labelInputKeys);
		timer.stop(M.online_write);

		// step 4
		R = ArrayUtils.addAll(R, new Tuple[] { Ti });
		SSXOT ssxot = new SSXOT(con1, con2);
		R = ssxot.runC(R, tupleParam);

		timer.stop(M.online_comp);
		return R;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int i = 0; i < 100; i++) {

			System.out.println("i=" + i);

			if (party == Party.Eddie) {
				int sw = Crypto.sr.nextInt(15) + 10;
				int lBits = Crypto.sr.nextInt(20) + 5;
				byte[] Li = Util.nextBytes((lBits + 7) / 8, Crypto.sr);
				Tuple[] R = new Tuple[sw];
				for (int j = 0; j < sw; j++)
					R[j] = new Tuple(1, 2, (lBits + 7) / 8, 3, Crypto.sr);
				Tuple Ti = new Tuple(1, 2, (lBits + 7) / 8, 3, Crypto.sr);
				int[] tupleParam = new int[] { 1, 2, (lBits + 7) / 8, 3 };

				con1.write(sw);
				con1.write(lBits);
				con1.write(Li);
				con1.write(tupleParam);
				con2.write(sw);
				con2.write(lBits);
				con2.write(tupleParam);

				Tuple[] newR = runE(false, sw, lBits, tupleParam, Li, R, Ti);

				Tuple[] R_C = con2.readTupleArray();
				int cnt = 0;
				int[] index = new int[3];
				for (int j = 0; j < sw; j++) {
					newR[j].setXor(R_C[j]);
					if (!R[j].equals(newR[j])) {
						index[cnt] = j;
						cnt++;
					}
				}

				if (cnt == 1) {
					if (newR[index[0]].equals(Ti) && (R[index[0]].getF()[0] & 1) == 0)
						System.out.println("UpdateRoot test passed");
					else
						System.err.println("UpdateRoot test failed 1");
				} else if (cnt == 2) {
					int u = -1;
					for (int k = 0; k < cnt; k++) {
						if (newR[index[k]].equals(Ti)) {
							u = k;
							break;
						}
					}
					if (u == -1)
						System.err.println("UpdateRoot test failed 2");
					else {
						int a1 = index[u];
						int a2 = index[1 - u];
						if (!R[a1].equals(newR[a2]) || (R[u].getF()[0] & 1) == 1)
							System.err.println("UpdateRoot test failed 3");
						else
							System.out.println("UpdateRoot test passed");
					}
				} else if (cnt == 3) {
					int u = -1;
					for (int k = 0; k < cnt; k++) {
						if (newR[index[k]].equals(Ti)) {
							u = k;
							break;
						}
					}
					if (u == -1)
						System.err.println("UpdateRoot test failed 4");
					else {
						int a1, a2;
						if (u == 0) {
							a1 = 1;
							a2 = 2;
						} else if (u == 1) {
							a1 = 0;
							a2 = 2;
						} else {
							a1 = 0;
							a2 = 1;
						}
						u = index[u];
						a1 = index[a1];
						a2 = index[a2];
						if ((R[u].getF()[0] & 1) == 1)
							System.err.println("UpdateRoot test failed 5");
						else if (!R[a1].equals(newR[a2]))
							System.err.println("UpdateRoot test failed 6");
						else if (!R[a1].equals(newR[a2]) || !R[a2].equals(newR[a1]))
							System.err.println("UpdateRoot test failed 7");
						else
							System.out.println("UpdateRoot test passed");
					}
				} else {
					System.err.println("UpdateRoot test failed 8");
				}

			} else if (party == Party.Debbie) {
				int sw = con1.readInt();
				int lBits = con1.readInt();
				byte[] Li = con1.read();
				int[] tupleParam = con1.readIntArray();

				runD(false, sw, lBits, tupleParam, Li, md.getW());

			} else if (party == Party.Charlie) {
				int sw = con1.readInt();
				int lBits = con1.readInt();
				int[] tupleParam = con1.readIntArray();

				Tuple[] R = new Tuple[sw];
				for (int j = 0; j < sw; j++)
					R[j] = new Tuple(1, 2, (lBits + 7) / 8, 3, null);
				Tuple Ti = new Tuple(1, 2, (lBits + 7) / 8, 3, null);

				R = runC(false, tupleParam, R, Ti);

				con1.write(R);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}

	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

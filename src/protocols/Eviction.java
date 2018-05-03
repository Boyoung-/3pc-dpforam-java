package protocols;

import java.util.Arrays;

import com.oblivm.backend.flexsc.CompEnv;
import com.oblivm.backend.gc.GCSignal;
import com.oblivm.backend.gc.regular.GCEva;
import com.oblivm.backend.gc.regular.GCGen;
import com.oblivm.backend.network.Network;

import communication.Communication;
import crypto.Crypto;
import gc.GCRoute;
import gc.GCUtil;
import oram.Bucket;
import oram.Forest;
import oram.Metadata;
import oram.Tree;
import oram.Tuple;
import struct.Party;
import subprotocols.PermuteIndex;
import subprotocols.PermuteTarget;
import subprotocols.SSXOT;
import util.M;
import util.Util;

// TODO: set bucket on path

public class Eviction extends Protocol {

	public Eviction(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.Eviction_on;
		offline_band = all.Eviction_off;
		timer = all.Eviction;
	}

	private int[] prepareEviction(int[] target, int[] ti, int W) {
		int d = ti.length;
		int[] evict = new int[W * d];
		for (int r = 0; r < d; r++) {
			int tupleIndex = r * W + ti[r];
			for (int c = 0; c < W; c++) {
				int currIndex = r * W + c;
				if (currIndex == tupleIndex) {
					int targetIndex = target[r] * W + ti[target[r]];
					evict[targetIndex] = currIndex;
				} else
					evict[currIndex] = currIndex;
			}
		}
		return evict;
	}

	public void runE(boolean firstTree, int[] tupleParam, byte[] Li, Tuple[] originalPath, Tree OTi) {
		if (firstTree) {
			// OTi.setBucketsOnPath(new BigInteger(1, Li).longValue(), new Bucket[] { new
			// Bucket(originalPath) });
			return;
		}

		timer.start(M.offline_comp);

		// GC
		int d = OTi.getD();
		int sw = OTi.getStashSize();
		int w = OTi.getW();
		int logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2));

		GCSignal[][] evict_LiKeyPairs = GCUtil.genKeyPairs(d - 1);
		GCSignal[] LiZeroKeys = GCUtil.getZeroKeys(evict_LiKeyPairs);

		GCSignal[][][] evict_E_feKeyPairs = new GCSignal[d][][];
		GCSignal[][][] evict_C_feKeyPairs = new GCSignal[d][][];
		GCSignal[][] E_feZeroKeys = new GCSignal[d][];
		GCSignal[][] C_feZeroKeys = new GCSignal[d][];

		GCSignal[][][][] evict_E_labelKeyPairs = new GCSignal[d][w][][];
		GCSignal[][][][] evict_C_labelKeyPairs = new GCSignal[d][w][][];
		GCSignal[][][] E_labelZeroKeys = new GCSignal[d][w][];
		GCSignal[][][] C_labelZeroKeys = new GCSignal[d][w][];

		GCSignal[][][] evict_deltaKeyPairs = new GCSignal[d][][];
		GCSignal[][] deltaZeroKeys = new GCSignal[d][];

		for (int i = 0; i < d; i++) {
			evict_E_feKeyPairs[i] = GCUtil.genKeyPairs(w);
			evict_C_feKeyPairs[i] = GCUtil.genKeyPairs(w);
			E_feZeroKeys[i] = GCUtil.getZeroKeys(evict_E_feKeyPairs[i]);
			C_feZeroKeys[i] = GCUtil.getZeroKeys(evict_C_feKeyPairs[i]);

			evict_deltaKeyPairs[i] = GCUtil.genKeyPairs(logW);
			deltaZeroKeys[i] = GCUtil.getZeroKeys(evict_deltaKeyPairs[i]);

			for (int j = 0; j < w; j++) {
				evict_E_labelKeyPairs[i][j] = GCUtil.genKeyPairs(d - 1);
				evict_C_labelKeyPairs[i][j] = GCUtil.genKeyPairs(d - 1);
				E_labelZeroKeys[i][j] = GCUtil.getZeroKeys(evict_E_labelKeyPairs[i][j]);
				C_labelZeroKeys[i][j] = GCUtil.getZeroKeys(evict_C_labelKeyPairs[i][j]);
			}
		}

		Network channel = new Network(null, con1);
		CompEnv<GCSignal> gen = new GCGen(channel, timer, offline_band, M.offline_write);
		GCSignal[][][] outZeroKeys = new GCRoute<GCSignal>(gen, d, w).routing(LiZeroKeys, E_feZeroKeys, C_feZeroKeys,
				E_labelZeroKeys, C_labelZeroKeys, deltaZeroKeys);
		((GCGen) gen).sendLastSetGTT();

		byte[][][] evict_tiOutKeyHashes = new byte[d][][];
		GCSignal[][][] evict_targetOutKeyPairs = new GCSignal[d][][];
		for (int i = 0; i < d; i++) {
			evict_tiOutKeyHashes[i] = GCUtil.genOutKeyHashes(outZeroKeys[1][i]);
			evict_targetOutKeyPairs[i] = GCUtil.recoverOutKeyPairs(outZeroKeys[0][i]);
		}

		timer.start(M.offline_write);
		con2.write(offline_band, evict_C_feKeyPairs);
		con2.write(offline_band, evict_C_labelKeyPairs);

		con1.write(offline_band, evict_tiOutKeyHashes);
		timer.stop(M.offline_write);

		// Permutation
		int[] evict_pi = Util.randomPermutation(d, Crypto.sr_CE);
		byte[][] evict_delta = new byte[d][(logW + 7) / 8];
		byte[][] evict_rho = new byte[d][(logW + 7) / 8];
		int[][] evict_delta_p = new int[d][];
		int[][] evict_rho_p = new int[d][];

		for (int i = 0; i < d; i++) {
			Crypto.sr_CE.nextBytes(evict_delta[i]);
			Crypto.sr_CE.nextBytes(evict_rho[i]);
			evict_delta_p[i] = Util.getXorPermutation(evict_delta[i], logW);
			evict_rho_p[i] = Util.getXorPermutation(evict_rho[i], logW);
		}

		timer.stop(M.offline_comp);

		///////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		Tuple[] pathTuples = new Tuple[d * w];
		System.arraycopy(originalPath, 0, pathTuples, 0, w);
		System.arraycopy(originalPath, sw, pathTuples, w, (d - 1) * w);

		Bucket[] pathBuckets = Bucket.tuplesToBuckets(pathTuples, d, w, w);

		GCSignal[] LiInputKeys = GCUtil.revSelectKeys(evict_LiKeyPairs, Li);
		GCSignal[][] E_feInputKeys = new GCSignal[d][];
		GCSignal[][][] E_labelInputKeys = new GCSignal[d][][];
		GCSignal[][] deltaInputKeys = new GCSignal[d][];
		for (int i = 0; i < d; i++) {
			E_feInputKeys[i] = GCUtil.selectFeKeys(evict_E_feKeyPairs[i], pathBuckets[i].getTuples());
			E_labelInputKeys[i] = GCUtil.selectLabelKeys(evict_E_labelKeyPairs[i], pathBuckets[i].getTuples());
			deltaInputKeys[i] = GCUtil.revSelectKeys(evict_deltaKeyPairs[i], evict_delta[i]);
		}

		timer.start(M.online_write);
		con1.write(online_band, LiInputKeys);
		con1.write(online_band, E_feInputKeys);
		con1.write(online_band, E_labelInputKeys);
		con1.write(online_band, deltaInputKeys);
		timer.stop(M.online_write);

		PermuteTarget permutetarget = new PermuteTarget(con1, con2);
		permutetarget.runE(d, evict_pi, evict_targetOutKeyPairs);

		PermuteIndex permuteindex = new PermuteIndex(con1, con2);
		permuteindex.runE(w, evict_pi);

		int W = (int) Math.pow(2, logW);
		for (int i = 0; i < d; i++) {
			pathBuckets[i].expand(W);
			pathBuckets[i].permute(evict_delta_p[i]);
		}
		pathBuckets = Util.permute(pathBuckets, evict_pi);
		for (int i = 0; i < d; i++) {
			pathBuckets[i].permute(evict_rho_p[i]);
		}
		pathTuples = Bucket.bucketsToTuples(pathBuckets);

		SSXOT ssxot = new SSXOT(con1, con2);
		pathTuples = ssxot.runE(pathTuples, tupleParam);

		pathBuckets = Bucket.tuplesToBuckets(pathTuples, d, W, W);
		for (int i = 0; i < d; i++) {
			int[] rho_ivs = Util.inversePermutation(evict_rho_p[i]);
			pathBuckets[i].permute(rho_ivs);
		}
		int[] pi_ivs = Util.inversePermutation(evict_pi);
		pathBuckets = Util.permute(pathBuckets, pi_ivs);
		for (int i = 0; i < d; i++) {
			int[] delta_ivs = Util.inversePermutation(evict_delta_p[i]);
			pathBuckets[i].permute(delta_ivs);
			pathBuckets[i].shrink(w);
		}

		pathBuckets[0].expand(Arrays.copyOfRange(originalPath, w, sw));
		// OTi.setBucketsOnPath(new BigInteger(1, Li).longValue(), pathBuckets);

		timer.stop(M.online_comp);
	}

	public void runD(boolean firstTree, int[] tupleParam, byte[] Li, Tree OTi) {
		if (firstTree) {
			timer.start(M.online_read);
			// Tuple[] originalPath = con2.readTupleArrayAndDec();
			timer.stop(M.online_read);

			// OTi.setBucketsOnPath(new BigInteger(1, Li).longValue(), new Bucket[] { new
			// Bucket(originalPath) });
			return;
		}

		timer.start(M.offline_comp);

		// GC
		int d = OTi.getD();
		int w = OTi.getW();
		int logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2));

		GCSignal[] LiZeroKeys = GCUtil.genEmptyKeys(d - 1);
		GCSignal[][] E_feZeroKeys = new GCSignal[d][];
		GCSignal[][] C_feZeroKeys = new GCSignal[d][];
		GCSignal[][][] E_labelZeroKeys = new GCSignal[d][w][];
		GCSignal[][][] C_labelZeroKeys = new GCSignal[d][w][];
		GCSignal[][] deltaZeroKeys = new GCSignal[d][];

		for (int i = 0; i < d; i++) {
			E_feZeroKeys[i] = GCUtil.genEmptyKeys(w);
			C_feZeroKeys[i] = GCUtil.genEmptyKeys(w);
			deltaZeroKeys[i] = GCUtil.genEmptyKeys(logW);

			for (int j = 0; j < w; j++) {
				E_labelZeroKeys[i][j] = GCUtil.genEmptyKeys(d - 1);
				C_labelZeroKeys[i][j] = GCUtil.genEmptyKeys(d - 1);
			}
		}

		Network channel = new Network(con1, null);
		CompEnv<GCSignal> eva = new GCEva(channel, timer, M.offline_read);
		GCRoute<GCSignal> evict_gcroute = new GCRoute<GCSignal>(eva, d, w);
		evict_gcroute.routing(LiZeroKeys, E_feZeroKeys, C_feZeroKeys, E_labelZeroKeys, C_labelZeroKeys, deltaZeroKeys);
		((GCEva) eva).receiveLastSetGTT();
		eva.setEvaluate();

		timer.start(M.offline_read);
		byte[][][] evict_tiOutKeyHashes = con1.readTripleByteArrayAndDec();
		timer.stop(M.offline_read);

		timer.stop(M.offline_comp);

		//////////////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		timer.start(M.online_read);
		GCSignal[] LiInputKeys = con1.readGCSignalArrayAndDec();
		GCSignal[][] E_feInputKeys = con1.readDoubleGCSignalArrayAndDec();
		GCSignal[][][] E_labelInputKeys = con1.readTripleGCSignalArrayAndDec();
		GCSignal[][] deltaInputKeys = con1.readDoubleGCSignalArrayAndDec();

		GCSignal[][] C_feInputKeys = con2.readDoubleGCSignalArrayAndDec();
		GCSignal[][][] C_labelInputKeys = con2.readTripleGCSignalArrayAndDec();
		timer.stop(M.online_read);

		GCSignal[][][] outKeys = evict_gcroute.routing(LiInputKeys, E_feInputKeys, C_feInputKeys, E_labelInputKeys,
				C_labelInputKeys, deltaInputKeys);

		byte[][] ti_p = new byte[deltaInputKeys.length][];
		for (int i = 0; i < ti_p.length; i++) {
			ti_p[i] = Util.padArray(GCUtil.evaOutKeys(outKeys[1][i], evict_tiOutKeyHashes[i]).toByteArray(),
					(logW + 7) / 8);
		}

		PermuteTarget permutetarget = new PermuteTarget(con1, con2);
		int[] target_pp = permutetarget.runD(firstTree, outKeys[0]);

		PermuteIndex permuteindex = new PermuteIndex(con1, con2);
		int[] ti_pp = permuteindex.runD(firstTree, ti_p, w);

		int W = (int) Math.pow(2, logW);
		int[] evict = prepareEviction(target_pp, ti_pp, W);

		SSXOT ssxot = new SSXOT(con1, con2);
		ssxot.runD(evict.length, evict.length, tupleParam, evict);

		timer.start(M.online_read);
		// Bucket[] pathBuckets = con2.readBucketArrayAndDec();
		timer.stop(M.online_read);

		// OTi.setBucketsOnPath(new BigInteger(1, Li).longValue(), pathBuckets);

		timer.stop(M.online_comp);
	}

	public void runC(boolean firstTree, int[] tupleParam, Tuple[] originalPath, int d, int sw, int w) {
		if (firstTree) {
			timer.start(M.online_write);
			// con2.write(online_band, originalPath);
			timer.stop(M.online_write);
			return;
		}

		timer.start(M.offline_comp);

		// GC
		timer.start(M.offline_read);
		GCSignal[][][] evict_C_feKeyPairs = con1.readTripleGCSignalArrayAndDec();
		GCSignal[][][][] evict_C_labelKeyPairs = con1.readQuadGCSignalArrayAndDec();
		timer.stop(M.offline_read);

		// Permutation
		int logW = (int) Math.ceil(Math.log(w + 1) / Math.log(2));
		int[] evict_pi = Util.randomPermutation(d, Crypto.sr_CE);
		byte[][] evict_delta = new byte[d][(logW + 7) / 8];
		byte[][] evict_rho = new byte[d][(logW + 7) / 8];
		int[][] evict_delta_p = new int[d][];
		int[][] evict_rho_p = new int[d][];

		for (int i = 0; i < d; i++) {
			Crypto.sr_CE.nextBytes(evict_delta[i]);
			Crypto.sr_CE.nextBytes(evict_rho[i]);
			evict_delta_p[i] = Util.getXorPermutation(evict_delta[i], logW);
			evict_rho_p[i] = Util.getXorPermutation(evict_rho[i], logW);
		}

		timer.stop(M.offline_comp);

		///////////////////////////////////////////////////////////////

		timer.start(M.online_comp);

		Tuple[] pathTuples = new Tuple[d * w];
		System.arraycopy(originalPath, 0, pathTuples, 0, w);
		System.arraycopy(originalPath, sw, pathTuples, w, (d - 1) * w);

		Bucket[] pathBuckets = Bucket.tuplesToBuckets(pathTuples, d, w, w);

		GCSignal[][] C_feInputKeys = new GCSignal[d][];
		GCSignal[][][] C_labelInputKeys = new GCSignal[d][][];
		for (int i = 0; i < d; i++) {
			C_feInputKeys[i] = GCUtil.selectFeKeys(evict_C_feKeyPairs[i], pathBuckets[i].getTuples());
			C_labelInputKeys[i] = GCUtil.selectLabelKeys(evict_C_labelKeyPairs[i], pathBuckets[i].getTuples());
		}

		timer.start(M.online_write);
		con2.write(online_band, C_feInputKeys);
		con2.write(online_band, C_labelInputKeys);
		timer.stop(M.online_write);

		PermuteTarget permutetarget = new PermuteTarget(con1, con2);
		permutetarget.runC(firstTree, d, evict_pi);

		PermuteIndex permuteindex = new PermuteIndex(con1, con2);
		permuteindex.runC(firstTree, w, evict_pi, evict_rho);

		int W = (int) Math.pow(2, logW);
		for (int i = 0; i < d; i++) {
			pathBuckets[i].expand(W);
			pathBuckets[i].permute(evict_delta_p[i]);
		}
		pathBuckets = Util.permute(pathBuckets, evict_pi);
		for (int i = 0; i < d; i++) {
			pathBuckets[i].permute(evict_rho_p[i]);
		}
		pathTuples = Bucket.bucketsToTuples(pathBuckets);

		SSXOT ssxot = new SSXOT(con1, con2);
		pathTuples = ssxot.runC(pathTuples, tupleParam);

		pathBuckets = Bucket.tuplesToBuckets(pathTuples, d, W, W);
		for (int i = 0; i < d; i++) {
			int[] rho_ivs = Util.inversePermutation(evict_rho_p[i]);
			pathBuckets[i].permute(rho_ivs);
		}
		int[] pi_ivs = Util.inversePermutation(evict_pi);
		pathBuckets = Util.permute(pathBuckets, pi_ivs);
		for (int i = 0; i < d; i++) {
			int[] delta_ivs = Util.inversePermutation(evict_delta_p[i]);
			pathBuckets[i].permute(delta_ivs);
			pathBuckets[i].shrink(w);
		}

		pathBuckets[0].expand(Arrays.copyOfRange(originalPath, w, sw));

		timer.start(M.online_write);
		// con2.write(online_band, pathBuckets);
		timer.stop(M.online_write);

		timer.stop(M.online_comp);
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {
		System.out.println("Use PIRRetrieve to test Eviction");
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

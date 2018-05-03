package protocols;

import java.math.BigInteger;

import org.apache.commons.lang3.ArrayUtils;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Bucket;
import oram.Forest;
import oram.Metadata;
import oram.Tree;
import oram.Tuple;
import struct.OutPIRAccess;
import struct.OutPIRCOT;
import struct.Party;
import struct.TwoOneXor;
import struct.TwoThreeXorByte;
import struct.TwoThreeXorInt;
import subprotocols.PIRCOT;
import subprotocols.ThreeShiftPIR;
import subprotocols.ThreeShiftXorPIR;
import util.M;
import util.Util;

public class PIRAccess extends Protocol {

	public PIRAccess(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.Access_on;
		offline_band = all.Access_off;
		timer = all.Access;
	}

	public OutPIRAccess runE(Metadata md, Tree tree_DE, Tree tree_CE, byte[] Li, TwoThreeXorByte L, TwoThreeXorByte N,
			TwoThreeXorInt dN) {
		timer.start(M.online_comp);

		Bucket[] pathBuckets_DE = tree_DE.getBucketsOnPath(Li);
		Tuple[] pathTuples_DE = Bucket.bucketsToTuples(pathBuckets_DE);
		Bucket[] pathBuckets_CE = tree_CE.getBucketsOnPath(Li);
		Tuple[] pathTuples_CE = Bucket.bucketsToTuples(pathBuckets_CE);

		int pathTuples = pathTuples_CE.length;
		int ttp = md.getTwoTauPow();
		int treeIndex = tree_DE.getTreeIndex();
		boolean isLastTree = treeIndex == md.getNumTrees() - 1;
		boolean isFirstTree = treeIndex == 0;

		byte[][] x_DE = new byte[pathTuples][];
		byte[][] x_CE = new byte[pathTuples][];
		for (int i = 0; i < pathTuples; i++) {
			x_DE[i] = pathTuples_DE[i].getA();
			x_CE[i] = pathTuples_CE[i].getA();
		}
		OutPIRCOT j = new OutPIRCOT();
		TwoOneXor dN21 = new TwoOneXor();
		TwoThreeXorByte X = new TwoThreeXorByte();

		if (isFirstTree) {
			X.DE = x_DE[0];
			X.CE = x_CE[0];
		} else {

			byte[][] u = new byte[pathTuples][];
			for (int i = 0; i < pathTuples; i++) {
				u[i] = ArrayUtils.addAll(pathTuples_CE[i].getF(), pathTuples_CE[i].getN());
			}
			byte[] v = ArrayUtils.addAll(new byte[] { 1 }, N.CE);

			PIRCOT ksearch = new PIRCOT(con1, con2);
			j = ksearch.runE(u, v);

			ThreeShiftPIR threeshiftpir = new ThreeShiftPIR(con1, con2, Crypto.sr_DE, Crypto.sr_CE);
			X = threeshiftpir.runE(x_DE, x_CE, j);

			dN21.t_E = dN.CE ^ dN.DE;
			dN21.s_CE = dN.CE;
			dN21.s_DE = dN.DE;
		}

		TwoThreeXorByte nextL = null;
		byte[] Lip1 = null;
		if (!isLastTree) {
			ThreeShiftXorPIR threeshiftxorpir = new ThreeShiftXorPIR(con1, con2, Crypto.sr_DE, Crypto.sr_CE);
			nextL = threeshiftxorpir.runE(x_DE, x_CE, j, dN21, ttp);
			Lip1 = Util.xor(Util.xor(nextL.DE, nextL.CE), nextL.CD);
		}

		OutPIRAccess out = new OutPIRAccess(null, pathTuples_CE, pathTuples_DE, j, X, nextL, Lip1);

		timer.stop(M.online_comp);
		return out;
	}

	public OutPIRAccess runD(Metadata md, Tree tree_DE, Tree tree_CD, byte[] Li, TwoThreeXorByte L, TwoThreeXorByte N,
			TwoThreeXorInt dN) {
		timer.start(M.online_comp);

		Bucket[] pathBuckets_DE = tree_DE.getBucketsOnPath(Li);
		Tuple[] pathTuples_DE = Bucket.bucketsToTuples(pathBuckets_DE);
		Bucket[] pathBuckets_CD = tree_CD.getBucketsOnPath(Li);
		Tuple[] pathTuples_CD = Bucket.bucketsToTuples(pathBuckets_CD);

		int pathTuples = pathTuples_CD.length;
		int ttp = md.getTwoTauPow();
		int treeIndex = tree_DE.getTreeIndex();
		boolean isLastTree = treeIndex == md.getNumTrees() - 1;
		boolean isFirstTree = treeIndex == 0;

		byte[][] x_DE = new byte[pathTuples][];
		byte[][] x_CD = new byte[pathTuples][];
		for (int i = 0; i < pathTuples; i++) {
			x_DE[i] = pathTuples_DE[i].getA();
			x_CD[i] = pathTuples_CD[i].getA();
		}
		OutPIRCOT j = new OutPIRCOT();
		TwoOneXor dN21 = new TwoOneXor();
		TwoThreeXorByte X = new TwoThreeXorByte();

		if (isFirstTree) {
			X.DE = x_DE[0];
			X.CD = x_CD[0];
		} else {

			byte[][] u = new byte[pathTuples][];
			for (int i = 0; i < pathTuples; i++) {
				u[i] = ArrayUtils.addAll(pathTuples_DE[i].getF(), pathTuples_DE[i].getN());
				Util.setXor(u[i], ArrayUtils.addAll(pathTuples_CD[i].getF(), pathTuples_CD[i].getN()));
			}
			byte[] v = ArrayUtils.addAll(new byte[] { 1 }, N.CE);
			Util.setXor(v, ArrayUtils.addAll(new byte[] { 1 }, N.CD));

			PIRCOT ksearch = new PIRCOT(con1, con2);
			j = ksearch.runD(u, v);

			ThreeShiftPIR threeshiftpir = new ThreeShiftPIR(con1, con2, Crypto.sr_DE, Crypto.sr_CD);
			X = threeshiftpir.runD(x_DE, x_CD, j);

			dN21.t_D = dN.CD ^ dN.DE;
			dN21.s_CD = dN.CD;
			dN21.s_DE = dN.DE;
		}

		TwoThreeXorByte nextL = null;
		byte[] Lip1 = null;
		if (!isLastTree) {
			ThreeShiftXorPIR threeshiftxorpir = new ThreeShiftXorPIR(con1, con2, Crypto.sr_DE, Crypto.sr_CD);
			nextL = threeshiftxorpir.runD(x_DE, x_CD, j, dN21, ttp);
			Lip1 = Util.xor(Util.xor(nextL.DE, nextL.CE), nextL.CD);
		}

		OutPIRAccess out = new OutPIRAccess(pathTuples_CD, null, pathTuples_DE, j, X, nextL, Lip1);

		timer.stop(M.online_comp);
		return out;
	}

	public OutPIRAccess runC(Metadata md, Tree tree_CD, Tree tree_CE, byte[] Li, TwoThreeXorByte L, TwoThreeXorByte N,
			TwoThreeXorInt dN) {
		timer.start(M.online_comp);

		Bucket[] pathBuckets_CD = tree_CD.getBucketsOnPath(Li);
		Tuple[] pathTuples_CD = Bucket.bucketsToTuples(pathBuckets_CD);
		Bucket[] pathBuckets_CE = tree_CE.getBucketsOnPath(Li);
		Tuple[] pathTuples_CE = Bucket.bucketsToTuples(pathBuckets_CE);

		int pathTuples = pathTuples_CE.length;
		int ttp = md.getTwoTauPow();
		int treeIndex = tree_CE.getTreeIndex();
		boolean isLastTree = treeIndex == md.getNumTrees() - 1;
		boolean isFirstTree = treeIndex == 0;

		byte[][] x_CE = new byte[pathTuples][];
		byte[][] x_CD = new byte[pathTuples][];
		for (int i = 0; i < pathTuples; i++) {
			x_CE[i] = pathTuples_CE[i].getA();
			x_CD[i] = pathTuples_CD[i].getA();
		}
		OutPIRCOT j = new OutPIRCOT();
		TwoOneXor dN21 = new TwoOneXor();
		TwoThreeXorByte X = new TwoThreeXorByte();

		if (isFirstTree) {
			X.CE = x_CE[0];
			X.CD = x_CD[0];
		} else {

			PIRCOT ksearch = new PIRCOT(con1, con2);
			j = ksearch.runC(pathTuples);

			ThreeShiftPIR threeshiftpir = new ThreeShiftPIR(con1, con2, Crypto.sr_CE, Crypto.sr_CD);
			X = threeshiftpir.runC(x_CD, x_CE, j);

			dN21.t_C = dN.CD ^ dN.CE;
			dN21.s_CD = dN.CD;
			dN21.s_CE = dN.CE;
		}

		TwoThreeXorByte nextL = null;
		byte[] Lip1 = null;
		if (!isLastTree) {
			ThreeShiftXorPIR threeshiftxorpir = new ThreeShiftXorPIR(con1, con2, Crypto.sr_CE, Crypto.sr_CD);
			nextL = threeshiftxorpir.runC(x_CD, x_CE, j, dN21, ttp);
			Lip1 = Util.xor(Util.xor(nextL.DE, nextL.CE), nextL.CD);
		}

		OutPIRAccess out = new OutPIRAccess(pathTuples_CD, pathTuples_CE, null, j, X, nextL, Lip1);

		timer.stop(M.online_comp);
		return out;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		Tree tree_CD = null;
		Tree tree_DE = null;
		Tree tree_CE = null;

		for (int test = 0; test < 100; test++) {

			for (int treeIndex = 0; treeIndex < md.getNumTrees(); treeIndex++) {
				if (party == Party.Eddie) {
					tree_DE = forest[0].getTree(treeIndex);
					tree_CE = forest[1].getTree(treeIndex);
				} else if (party == Party.Debbie) {
					tree_DE = forest[0].getTree(treeIndex);
					tree_CD = forest[1].getTree(treeIndex);
				} else if (party == Party.Charlie) {
					tree_CE = forest[0].getTree(treeIndex);
					tree_CD = forest[1].getTree(treeIndex);
				} else {
					throw new NoSuchPartyException(party + "");
				}

				int Llen = md.getLBytesOfTree(treeIndex);
				int Nlen = md.getNBytesOfTree(treeIndex);

				TwoThreeXorInt dN = new TwoThreeXorInt();

				TwoThreeXorByte N = new TwoThreeXorByte();
				N.CD = new byte[Nlen];
				N.DE = new byte[Nlen];
				N.CE = new byte[Nlen];
				TwoThreeXorByte L = new TwoThreeXorByte();
				L.CD = new byte[Llen];
				L.DE = new byte[Llen];
				L.CE = new byte[Llen];
				byte[] Li = new byte[Llen];

				if (party == Party.Eddie) {
					OutPIRAccess out = this.runE(md, tree_DE, tree_CE, Li, L, N, dN);
					out.j.t_D = con1.readInt();
					out.j.t_C = con2.readInt();
					out.X.CD = con1.read();
					int pathTuples = out.pathTuples_CE.length;
					int index = (out.j.t_D + out.j.s_CE) % pathTuples;
					byte[] X = Util.xor(Util.xor(out.X.DE, out.X.CE), out.X.CD);

					boolean fail = false;
					if (index != 0) {
						System.err.println(test + " " + treeIndex + ": PIRAcc test failed on KSearch index");
						fail = true;
					}
					if (new BigInteger(1, X).intValue() != 0) {
						System.err.println(test + " " + treeIndex + ": PIRAcc test failed on 3ShiftPIR X");
						fail = true;
					}
					if (treeIndex < md.getNumTrees() - 1 && new BigInteger(1, out.Lip1).intValue() != 0) {
						System.err.println(test + " " + treeIndex + ": PIRAcc test failed on 3ShiftXorPIR Lip1");
						fail = true;
					}
					if (!fail)
						System.out.println(test + " " + treeIndex + ": PIRAcc test passed");

				} else if (party == Party.Debbie) {
					OutPIRAccess out = this.runD(md, tree_DE, tree_CD, Li, L, N, dN);
					con1.write(out.j.t_D);
					con1.write(out.X.CD);

				} else if (party == Party.Charlie) {
					OutPIRAccess out = this.runC(md, tree_CD, tree_CE, Li, L, N, dN);
					con1.write(out.j.t_C);

				} else {
					throw new NoSuchPartyException(party + "");
				}
			}

		}
	}

	// TODO: add Access on second path

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

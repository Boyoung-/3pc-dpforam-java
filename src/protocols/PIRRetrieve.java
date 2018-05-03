package protocols;

import java.math.BigInteger;
import java.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Global;
import oram.Metadata;
import oram.Tree;
import oram.Tuple;
import struct.OutFF;
import struct.OutPIRAccess;
import struct.OutULiT;
import struct.Party;
import struct.TwoThreeXorByte;
import struct.TwoThreeXorInt;
import util.Bandwidth;
import util.M;
import util.StopWatch;
import util.Timer;
import util.Util;

// TODO: really FlipFlag on path, and update path in Eviction
// TODO: fix simulation

public class PIRRetrieve extends Protocol {

	Communication[] cons1;
	Communication[] cons2;

	public PIRRetrieve(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = new Bandwidth();
		offline_band = new Bandwidth();
		timer = new Timer();
	}

	public void setCons(Communication[] a, Communication[] b) {
		cons1 = a;
		cons2 = b;
	}

	public OutPIRAccess runE(Metadata md, Tree tree_DE, Tree tree_CE, byte[] Li, TwoThreeXorByte L, TwoThreeXorByte N,
			TwoThreeXorInt dN) {
		timer.start(M.online_comp);

		int treeIndex = tree_DE.getTreeIndex();
		boolean isLastTree = treeIndex == md.getNumTrees() - 1;
		boolean isFirstTree = treeIndex == 0;

		PIRAccess piracc = new PIRAccess(con1, con2);
		OutPIRAccess outpiracc = piracc.runE(md, tree_DE, tree_CE, Li, L, N, dN);

		OutULiT T = new OutULiT();
		if (!isLastTree) {
			TwoThreeXorByte Lp = new TwoThreeXorByte(md.getLBytesOfTree(treeIndex));
			TwoThreeXorByte Lpi = new TwoThreeXorByte(md.getLBytesOfTree(treeIndex + 1));
			ULiT ulit = new ULiT(con1, con2, Crypto.sr_DE, Crypto.sr_CE);
			T = ulit.runE(outpiracc.X, N, dN, Lp, Lpi, outpiracc.nextL, md.getTwoTauPow());
		} else {
			T.DE = outpiracc.pathTuples_DE[0];
			T.CE = outpiracc.pathTuples_CE[0];
		}

		int pathTuples = outpiracc.pathTuples_CE.length;

		if (!isFirstTree) {
			byte[][] fb_DE = new byte[pathTuples][];
			byte[][] fb_CE = new byte[pathTuples][];
			for (int i = 0; i < pathTuples; i++) {
				fb_DE[i] = outpiracc.pathTuples_DE[i].getF();
				fb_CE[i] = outpiracc.pathTuples_CE[i].getF();
			}
			FlipFlag ff = new FlipFlag(con1, con2);
			OutFF outff = ff.runE(fb_DE, fb_CE, outpiracc.j.s_DE);
			for (int i = 0; i < pathTuples; i++) {
				// outpiracc.pathTuples_DE[i].setF(outff.fb_DE[i]);
				// outpiracc.pathTuples_CE[i].setF(outff.fb_CE[i]);
			}
		}

		int stashSize = tree_DE.getStashSize();
		int[] tupleParam = new int[] { treeIndex == 0 ? 0 : 1, md.getNBytesOfTree(treeIndex),
				md.getLBytesOfTree(treeIndex), md.getABytesOfTree(treeIndex) };

		Tuple[] path = new Tuple[pathTuples];
		for (int i = 0; i < pathTuples; i++) {
			path[i] = outpiracc.pathTuples_DE[i].xor(outpiracc.pathTuples_CE[i]);
		}
		Tuple[] R = Arrays.copyOfRange(path, 0, stashSize);
		UpdateRoot updateroot = new UpdateRoot(con1, con2);
		R = updateroot.runE(isFirstTree, stashSize, md.getLBitsOfTree(treeIndex), tupleParam, Li, R, T.DE.xor(T.CE));
		System.arraycopy(R, 0, path, 0, R.length);

		Eviction eviction = new Eviction(con1, con2);
		eviction.runE(isFirstTree, tupleParam, Li, path, tree_DE);

		// simulation of Reshare
		timer.start(M.online_write);
		con2.write(online_band, path);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		con2.readTupleArrayAndDec();
		timer.stop(M.online_read);

		// second eviction sim
		for (int i = 0; i < pathTuples; i++) {
			path[i] = outpiracc.pathTuples_DE[i].xor(outpiracc.pathTuples_CE[i]);
		}
		R = Arrays.copyOfRange(path, 0, stashSize);
		R = updateroot.runE(isFirstTree, stashSize, md.getLBitsOfTree(treeIndex), tupleParam, Li, R, T.DE.xor(T.CE));
		System.arraycopy(R, 0, path, 0, R.length);

		eviction.runE(isFirstTree, tupleParam, Li, path, tree_DE);

		// simulation of Reshare
		timer.start(M.online_write);
		con2.write(online_band, path);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		con2.readTupleArrayAndDec();
		timer.stop(M.online_read);

		timer.stop(M.online_comp);
		return outpiracc;
	}

	public OutPIRAccess runD(Metadata md, Tree tree_DE, Tree tree_CD, byte[] Li, TwoThreeXorByte L, TwoThreeXorByte N,
			TwoThreeXorInt dN) {
		timer.start(M.online_comp);

		int treeIndex = tree_DE.getTreeIndex();
		boolean isLastTree = treeIndex == md.getNumTrees() - 1;
		boolean isFirstTree = treeIndex == 0;

		PIRAccess piracc = new PIRAccess(con1, con2);
		OutPIRAccess outpiracc = piracc.runD(md, tree_DE, tree_CD, Li, L, N, dN);

		OutULiT T = new OutULiT();
		if (!isLastTree) {
			TwoThreeXorByte Lp = new TwoThreeXorByte(md.getLBytesOfTree(treeIndex));
			TwoThreeXorByte Lpi = new TwoThreeXorByte(md.getLBytesOfTree(treeIndex + 1));
			ULiT ulit = new ULiT(con1, con2, Crypto.sr_DE, Crypto.sr_CD);
			T = ulit.runD(outpiracc.X, N, dN, Lp, Lpi, outpiracc.nextL, md.getTwoTauPow());
		} else {
			T.CD = outpiracc.pathTuples_CD[0];
			T.DE = outpiracc.pathTuples_DE[0];
		}

		int pathTuples = outpiracc.pathTuples_CD.length;

		if (!isFirstTree) {
			byte[][] fb_DE = new byte[pathTuples][];
			byte[][] fb_CD = new byte[pathTuples][];
			for (int i = 0; i < pathTuples; i++) {
				fb_DE[i] = outpiracc.pathTuples_DE[i].getF();
				fb_CD[i] = outpiracc.pathTuples_CD[i].getF();
			}
			FlipFlag ff = new FlipFlag(con1, con2);
			OutFF outff = ff.runD(fb_DE, fb_CD, outpiracc.j.s_DE);
			for (int i = 0; i < pathTuples; i++) {
				// outpiracc.pathTuples_DE[i].setF(outff.fb_DE[i]);
				// outpiracc.pathTuples_CD[i].setF(outff.fb_CD[i]);
			}
		}

		int stashSize = tree_DE.getStashSize();
		int[] tupleParam = new int[] { treeIndex == 0 ? 0 : 1, md.getNBytesOfTree(treeIndex),
				md.getLBytesOfTree(treeIndex), md.getABytesOfTree(treeIndex) };

		UpdateRoot updateroot = new UpdateRoot(con1, con2);
		updateroot.runD(isFirstTree, stashSize, md.getLBitsOfTree(treeIndex), tupleParam, Li, tree_DE.getW());

		Eviction eviction = new Eviction(con1, con2);
		eviction.runD(isFirstTree, tupleParam, Li, tree_DE);

		// second eviction sim
		updateroot.runD(isFirstTree, stashSize, md.getLBitsOfTree(treeIndex), tupleParam, Li, tree_DE.getW());

		eviction.runD(isFirstTree, tupleParam, Li, tree_DE);

		timer.stop(M.online_comp);
		return outpiracc;
	}

	public OutPIRAccess runC(Metadata md, Tree tree_CD, Tree tree_CE, byte[] Li, TwoThreeXorByte L, TwoThreeXorByte N,
			TwoThreeXorInt dN) {
		timer.start(M.online_comp);

		int treeIndex = tree_CE.getTreeIndex();
		boolean isLastTree = treeIndex == md.getNumTrees() - 1;
		boolean isFirstTree = treeIndex == 0;

		PIRAccess piracc = new PIRAccess(con1, con2);
		OutPIRAccess outpiracc = piracc.runC(md, tree_CD, tree_CE, Li, L, N, dN);

		OutULiT T = new OutULiT();
		if (!isLastTree) {
			TwoThreeXorByte Lp = new TwoThreeXorByte(md.getLBytesOfTree(treeIndex));
			TwoThreeXorByte Lpi = new TwoThreeXorByte(md.getLBytesOfTree(treeIndex + 1));
			ULiT ulit = new ULiT(con1, con2, Crypto.sr_CE, Crypto.sr_CD);
			T = ulit.runC(outpiracc.X, N, dN, Lp, Lpi, outpiracc.nextL, md.getTwoTauPow());
		} else {
			T.CD = outpiracc.pathTuples_CD[0];
			T.CE = outpiracc.pathTuples_CE[0];
		}

		int pathTuples = outpiracc.pathTuples_CD.length;

		if (!isFirstTree) {
			byte[][] fb_CE = new byte[pathTuples][];
			byte[][] fb_CD = new byte[pathTuples][];
			for (int i = 0; i < pathTuples; i++) {
				fb_CE[i] = outpiracc.pathTuples_CE[i].getF();
				fb_CD[i] = outpiracc.pathTuples_CD[i].getF();
			}
			FlipFlag ff = new FlipFlag(con1, con2);
			OutFF outff = ff.runC(fb_CD, fb_CE, outpiracc.j.t_C);
			for (int i = 0; i < pathTuples; i++) {
				// outpiracc.pathTuples_CD[i].setF(outff.fb_CD[i]);
				// outpiracc.pathTuples_CE[i].setF(outff.fb_CE[i]);
			}
		}

		int stashSize = tree_CE.getStashSize();
		int[] tupleParam = new int[] { treeIndex == 0 ? 0 : 1, md.getNBytesOfTree(treeIndex),
				md.getLBytesOfTree(treeIndex), md.getABytesOfTree(treeIndex) };

		Tuple[] path = outpiracc.pathTuples_CD;
		Tuple[] R = Arrays.copyOfRange(path, 0, stashSize);

		UpdateRoot updateroot = new UpdateRoot(con1, con2);
		R = updateroot.runC(isFirstTree, tupleParam, R, T.CD);
		System.arraycopy(R, 0, path, 0, R.length);

		Eviction eviction = new Eviction(con1, con2);
		eviction.runC(isFirstTree, tupleParam, path, tree_CD.getD(), stashSize, tree_CD.getW());

		// simulation of Reshare
		timer.start(M.online_write);
		con1.write(online_band, path);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		con1.readTupleArrayAndDec();
		timer.stop(M.online_read);

		// second eviction sim
		R = Arrays.copyOfRange(path, 0, stashSize);

		R = updateroot.runC(isFirstTree, tupleParam, R, T.CD);
		System.arraycopy(R, 0, path, 0, R.length);

		eviction.runC(isFirstTree, tupleParam, path, tree_CD.getD(), stashSize, tree_CD.getW());

		// simulation of Reshare
		timer.start(M.online_write);
		con1.write(online_band, path);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		con1.readTupleArrayAndDec();
		timer.stop(M.online_read);

		timer.stop(M.online_comp);
		return outpiracc;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		StopWatch ete = new StopWatch("ETE");

		Tree tree_CD = null;
		Tree tree_DE = null;
		Tree tree_CE = null;

		int iterations = 100;
		int reset = 20;

		for (int test = 0; test < iterations; test++) {

			if (test == reset) {
				timer.reset();
				ete.reset();
			}
			if (test == 1) {
				Global.bandSwitch = false;
			}

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
					ete.start();
					OutPIRAccess out = this.runE(md, tree_DE, tree_CE, Li, L, N, dN);
					ete.stop();

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
					ete.start();
					OutPIRAccess out = this.runD(md, tree_DE, tree_CD, Li, L, N, dN);
					ete.stop();

					con1.write(out.j.t_D);
					con1.write(out.X.CD);

				} else if (party == Party.Charlie) {
					ete.start();
					OutPIRAccess out = this.runC(md, tree_CD, tree_CE, Li, L, N, dN);
					ete.stop();

					con1.write(out.j.t_C);

				} else {
					throw new NoSuchPartyException(party + "");
				}
			}

		}

		// Bandwidth total = new Bandwidth("Total Online");
		// for (int i = 0; i < P.size; i++) {
		// for (int j = 0; j < cons1.length; j++)
		// total.add(cons1[j].bandwidth[i].add(cons2[j].bandwidth[i]).bandwidth);
		// }
		// System.out.println(total.toString());

		// timer.divideBy(iterations - reset);
		// timer.print();

		System.out.println(ete.toMS());

		sanityCheck();
	}

	// for testing correctness
	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

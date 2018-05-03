package protocols;

import java.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Metadata;
import oram.Tree;
import oram.Tuple;
import struct.Party;
import util.Timer;
import util.Util;

public class Pipeline extends Thread {

	// private Communication con1;
	// private Communication con2;
	// private Party party;
	// private PreData[] predata;
	// private Tree OTi;
	// private int h;
	// private Timer timer;
	// private Metadata md;
	// private int treeIndex;
	// private byte[] Li;
	// private OutAccess outaccess;
	//
	// public Pipeline(Communication con1, Communication con2, Party party,
	// PreData[] predata, Tree OTi, int h,
	// Timer timer, Metadata md, int treeIndex, byte[] Li, OutAccess outaccess) {
	// this.con1 = con1;
	// this.con2 = con2;
	// this.party = party;
	// this.predata = predata;
	// this.OTi = OTi;
	// this.h = h;
	// this.timer = timer;
	// this.md = md;
	// this.treeIndex = treeIndex;
	// this.Li = Li;
	// this.outaccess = outaccess;
	// }
	//
	// public void runE(PreData[] predata, Tree OTi, int h, Timer timer) {
	// // 1st eviction
	// Access access = new Access(con1, con2);
	// Reshuffle reshuffle = new Reshuffle(con1, con2);
	// PostProcessT postprocesst = new PostProcessT(con1, con2);
	// UpdateRoot updateroot = new UpdateRoot(con1, con2);
	// Eviction eviction = new Eviction(con1, con2);
	//
	// Tuple[] path = reshuffle.runE(predata[0], outaccess.E_P, OTi.getTreeIndex()
	// == 0, timer);
	// Tuple Ti = postprocesst.runE(predata[0], outaccess.E_Ti, OTi.getTreeIndex()
	// == h - 1, timer);
	// Tuple[] root = Arrays.copyOfRange(path, 0, OTi.getStashSize());
	// root = updateroot.runE(predata[0], OTi.getTreeIndex() == 0, outaccess.Li,
	// root, Ti, timer);
	// System.arraycopy(root, 0, path, 0, root.length);
	// eviction.runE(predata[0], OTi.getTreeIndex() == 0, outaccess.Li,
	// OTi.getTreeIndex() == 0 ? new Tuple[] { Ti } : path, OTi, timer);
	//
	// // 2nd eviction
	// OutAccess outaccess2 = access.runE2(OTi, timer);
	// Tuple[] path2 = outaccess2.E_P;
	// Tuple Ti2 = outaccess2.E_Ti;
	// Tuple[] root2 = Arrays.copyOfRange(path2, 0, OTi.getStashSize());
	// root2 = updateroot.runE(predata[1], OTi.getTreeIndex() == 0, outaccess2.Li,
	// root2, Ti2, timer);
	// System.arraycopy(root2, 0, path2, 0, root2.length);
	// eviction.runE(predata[1], OTi.getTreeIndex() == 0, outaccess2.Li,
	// OTi.getTreeIndex() == 0 ? new Tuple[] { Ti2 } : path2, OTi, timer);
	// }
	//
	// public void runD(PreData predata[], Tree OTi, Timer timer) {
	// // 1st eviction
	// Access access = new Access(con1, con2);
	// Reshuffle reshuffle = new Reshuffle(con1, con2);
	// PostProcessT postprocesst = new PostProcessT(con1, con2);
	// UpdateRoot updateroot = new UpdateRoot(con1, con2);
	// Eviction eviction = new Eviction(con1, con2);
	//
	// reshuffle.runD();
	// postprocesst.runD();
	// updateroot.runD(predata[0], OTi.getTreeIndex() == 0, Li, OTi.getW(), timer);
	// eviction.runD(predata[0], OTi.getTreeIndex() == 0, Li, OTi, timer);
	//
	// // 2nd eviction
	// byte[] Li2 = access.runD2(OTi, timer);
	// updateroot.runD(predata[1], OTi.getTreeIndex() == 0, Li2, OTi.getW(), timer);
	// eviction.runD(predata[1], OTi.getTreeIndex() == 0, Li2, OTi, timer);
	// }
	//
	// public OutAccess runC(PreData[] predata, Metadata md, int ti, byte[] Li,
	// Timer timer) {
	// // 1st eviction
	// Access access = new Access(con1, con2);
	// Reshuffle reshuffle = new Reshuffle(con1, con2);
	// PostProcessT postprocesst = new PostProcessT(con1, con2);
	// UpdateRoot updateroot = new UpdateRoot(con1, con2);
	// Eviction eviction = new Eviction(con1, con2);
	//
	// Tuple[] path = reshuffle.runC(predata[0], outaccess.C_P, ti == 0, timer);
	// Tuple Ti = postprocesst.runC(predata[0], outaccess.C_Ti, Li,
	// outaccess.C_Lip1, outaccess.C_j2,
	// ti == md.getNumTrees() - 1, timer);
	// Tuple[] root = Arrays.copyOfRange(path, 0, md.getStashSizeOfTree(ti));
	// root = updateroot.runC(predata[0], ti == 0, root, Ti, timer);
	// System.arraycopy(root, 0, path, 0, root.length);
	// eviction.runC(predata[0], ti == 0, ti == 0 ? new Tuple[] { Ti } : path,
	// md.getLBitsOfTree(ti) + 1,
	// md.getStashSizeOfTree(ti), md.getW(), timer);
	//
	// // 2nd eviction
	// byte[] Li2 = Util.nextBytes(md.getLBytesOfTree(ti), Crypto.sr);
	// OutAccess outaccess2 = access.runC2(md, ti, Li2, timer);
	// Tuple[] path2 = outaccess2.C_P;
	// Tuple Ti2 = outaccess2.C_Ti;
	// Tuple[] root2 = Arrays.copyOfRange(path2, 0, md.getStashSizeOfTree(ti));
	// root2 = updateroot.runC(predata[1], ti == 0, root2, Ti2, timer);
	// System.arraycopy(root2, 0, path2, 0, root2.length);
	// eviction.runC(predata[1], ti == 0, ti == 0 ? new Tuple[] { Ti2 } : path2,
	// md.getLBitsOfTree(ti) + 1,
	// md.getStashSizeOfTree(ti), md.getW(), timer);
	//
	// return outaccess;
	// }
	//
	// public void run() {
	// if (party == Party.Eddie) {
	// runE(predata, OTi, h, timer);
	//
	// } else if (party == Party.Debbie) {
	// runD(predata, OTi, timer);
	//
	// } else if (party == Party.Charlie) {
	// runC(predata, md, treeIndex, Li, timer);
	//
	// } else {
	// throw new NoSuchPartyException(party + "");
	// }
	// }

}

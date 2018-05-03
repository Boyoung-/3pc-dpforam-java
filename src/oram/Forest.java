package oram;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;

import crypto.Crypto;
import exceptions.LengthNotMatchException;
import util.Util;

public class Forest implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static String folderName = "data/";
	private String forestFileName;

	private int tau;
	private int addrBits;
	private long numInsertRecords;

	private long numBytes;
	private Tree[] trees;

	// build empty forest and insert records according to config file
	public Forest() {
		Metadata md = new Metadata();
		init(md);
		initTrees(md, null);
		insertRecords(md);
	}

	public Forest(Metadata md) {
		init(md);
		initTrees(md, null);
		insertRecords(md);
	}

	// build empty/random content forest
	public Forest(Random rand) {
		Metadata md = new Metadata();
		init(md);
		initTrees(md, rand);
	}

	public Forest(Metadata md, Random rand) {
		init(md);
		initTrees(md, rand);
	}

	// only used in xor operation
	// does not shallow/deep copy trees
	private Forest(Forest f) {
		forestFileName = f.getForestFileName();
		tau = f.getTau();
		addrBits = f.getAddrBits();
		numInsertRecords = f.getNumInsertRecords();
		numBytes = f.getNumBytes();
		trees = new Tree[f.getNumTrees()];
	}

	private void init(Metadata md) {
		forestFileName = md.getDefaultForestFileName();
		tau = md.getTau();
		addrBits = md.getAddrBits();
		numInsertRecords = md.getNumInsertRecords();
		numBytes = md.getForestBytes();
	}

	public String getForestFileName() {
		return forestFileName;
	}

	public int getTau() {
		return tau;
	}

	public int getAddrBits() {
		return addrBits;
	}

	public long getNumInsertRecords() {
		return numInsertRecords;
	}

	public long getNumBytes() {
		return numBytes;
	}

	public int getNumTrees() {
		return trees.length;
	}

	public Tree getTree(int i) {
		return trees[i];
	}

	public void setTree(int i, Tree tree) {
		if (!trees[i].sameLength(tree))
			throw new LengthNotMatchException(trees[i].getNumBytes() + " != " + tree.getNumBytes());
		trees[i] = tree;
	}

	// init trees
	private void initTrees(Metadata md, Random rand) {
		trees = new Tree[md.getNumTrees()];
		for (int i = 0; i < trees.length; i++)
			trees[i] = new Tree(i, md, rand);
	}

	// insert records into ORAM forest
	private void insertRecords(Metadata md) {
		int numTrees = trees.length;
		int tau = md.getTau();
		int w = md.getW();
		int lastNBits = md.getAddrBits() - tau * (numTrees - 2);
		// mapping between address N and leaf tuple
		@SuppressWarnings("unchecked")
		HashMap<Long, Long>[] addrToTuple = new HashMap[numTrees];
		for (int i = 1; i < numTrees; i++)
			addrToTuple[i] = new HashMap<Long, Long>();
		// keep track of each(current) inserted tuple's N and L for each tree
		long[] N = new long[numTrees];
		long[] L = new long[numTrees];

		// start inserting records with address addr
		for (long addr = 0; addr < md.getNumInsertRecords(); addr++) {
			// for each tree (from last to first)
			for (int i = numTrees - 1; i >= 0; i--) {
				long numBuckets = trees[i].getNumBuckets();
				// index of bucket that contains the tuple we will insert/update
				long bucketIndex = 0;
				// index of tuple within the bucket
				int tupleIndex = 0;
				// set correct bucket/tuple index on trees after the first one
				if (i > 0) {
					// set N of the tuple
					if (i == numTrees - 1)
						N[i] = addr;
					else if (i == numTrees - 2)
						N[i] = N[i + 1] >> lastNBits;
					else
						N[i] = N[i + 1] >> tau;
					// find the corresponding leaf tuple index using N
					Long leafTupleIndex = addrToTuple[i].get(N[i]);
					// if N is a new address, then find an unused leaf tuple
					if (leafTupleIndex == null) {
						do {
							leafTupleIndex = Util.nextLong((numBuckets / 2 + 1) * w, Crypto.sr);
						} while (addrToTuple[i].containsValue(leafTupleIndex));
						addrToTuple[i].put(N[i], leafTupleIndex);
					}
					// get leaf tuple label and set bucket/tuple index
					L[i] = leafTupleIndex / (long) w;
					bucketIndex = L[i] + numBuckets / 2;
					tupleIndex = (int) (leafTupleIndex % w);
				}
				// retrieve the tuple that needs to be updated
				Tuple targetTuple = trees[i].getBucket(bucketIndex).getTuple(tupleIndex);

				// for all trees except the last one,
				// update only one label bits in the A field of the target tuple
				if (i < numTrees - 1) {
					int indexN;
					if (i == numTrees - 2)
						indexN = (int) Util.getSubBits(N[i + 1], lastNBits, 0);
					else
						indexN = (int) Util.getSubBits(N[i + 1], tau, 0);
					int start = indexN * trees[i].getAlBytes();
					int end = start + trees[i].getAlBytes();
					targetTuple.setSubA(start, end, Util.rmSignBit(BigInteger.valueOf(L[i + 1]).toByteArray()));
				}
				// for the last tree, update the whole A field of the target
				// tuple
				else
					targetTuple.setA(Util.rmSignBit(BigInteger.valueOf(addr).toByteArray()));

				// for all trees except the first one,
				// also update F, N, L fields
				// no need to update F, N, L for the first tree
				if (i > 0) {
					targetTuple.setF(new byte[] { 1 });
					targetTuple.setN(Util.rmSignBit(BigInteger.valueOf(N[i]).toByteArray()));
					targetTuple.setL(Util.rmSignBit(BigInteger.valueOf(L[i]).toByteArray()));
				}
			}
		}
	}

	public Forest xor(Forest f) {
		if (!this.sameLength(f))
			throw new LengthNotMatchException(numBytes + " != " + f.getNumBytes());
		Forest newForest = new Forest(f);
		for (int i = 0; i < trees.length; i++)
			newForest.trees[i] = trees[i].xor(f.getTree(i));
		return newForest;
	}

	public void setXor(Forest f) {
		if (!this.sameLength(f))
			throw new LengthNotMatchException(numBytes + " != " + f.getNumBytes());
		for (int i = 0; i < trees.length; i++)
			trees[i].setXor(f.getTree(i));
	}

	public boolean sameLength(Forest f) {
		return numBytes == f.getNumBytes();
	}

	public void print() {
		System.out.println("===== ORAM Forest =====");
		System.out.println();

		for (int i = 0; i < trees.length; i++) {
			System.out.println("***** Tree " + i + " *****");
			for (int j = 0; j < trees[i].getNumBuckets(); j++)
				System.out.println(trees[i].getBucket(j));
			System.out.println();
		}

		System.out.println("===== End of Forest =====");
		System.out.println();
	}

	public void writeToFile() {
		writeToFile(forestFileName);
	}

	public void writeToFile(String filename) {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = new FileOutputStream(folderName + filename);
			oos = new ObjectOutputStream(fos);
			oos.writeObject(this);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (oos != null)
				try {
					oos.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
	}

	public static Forest readFromFile(String filename) {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		Forest forest = null;
		try {
			fis = new FileInputStream(folderName + filename);
			ois = new ObjectInputStream(fis);
			forest = (Forest) ois.readObject();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		} finally {
			if (ois != null)
				try {
					ois.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
		forest.forestFileName = filename;
		return forest;
	}
}

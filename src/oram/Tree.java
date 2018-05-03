package oram;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

import exceptions.LengthNotMatchException;
import util.Array64;
import util.Util;

public class Tree implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private int tau;
	private int twoTauPow;
	private int treeIndex;
	private int w;
	private int stashSize;
	private int nBits;
	private int lBits;
	private int alBits;
	private int nBytes;
	private int lBytes;
	private int alBytes;
	private int aBytes;
	private int tupleBytes;
	private long numBuckets;
	private long numBytes;
	private int d;
	private int h;

	private Array64<Bucket> buckets;

	// only for cheat
	private Bucket[] pathBuckets;

	public Tree(int index, Metadata md, Random rand) {
		tau = md.getTau();
		twoTauPow = md.getTwoTauPow();
		treeIndex = index;
		w = md.getW();
		stashSize = md.getStashSizeOfTree(treeIndex);
		nBits = md.getNBitsOfTree(treeIndex);
		lBits = md.getLBitsOfTree(treeIndex);
		alBits = md.getAlBitsOfTree(treeIndex);
		nBytes = md.getNBytesOfTree(treeIndex);
		lBytes = md.getLBytesOfTree(treeIndex);
		alBytes = md.getAlBytesOfTree(treeIndex);
		aBytes = md.getABytesOfTree(treeIndex);
		tupleBytes = md.getTupleBytesOfTree(treeIndex);
		numBuckets = md.getNumBucketsOfTree(treeIndex);
		numBytes = md.getTreeBytesOfTree(treeIndex);
		d = lBits + 1;
		h = md.getNumTrees();

		int fBytes = treeIndex == 0 ? 0 : 1;
		int[] tupleParams = new int[] { fBytes, nBytes, lBytes, aBytes };
		if (!Global.cheat) {
			buckets = new Array64<Bucket>(numBuckets);
			buckets.set(0, new Bucket(stashSize, tupleParams, rand));
			for (int i = 1; i < numBuckets; i++)
				buckets.set(i, new Bucket(w, tupleParams, rand));
		} else {
			pathBuckets = new Bucket[d];
			pathBuckets[0] = new Bucket(stashSize, tupleParams, null);
			for (int i = 1; i < d; i++)
				pathBuckets[i] = new Bucket(w, tupleParams, null);
			if (rand != null && treeIndex > 0)
				pathBuckets[0].getTuple(0).setF(new byte[] { 1 });
		}
	}

	// only used for xor operation
	// does not shallow/deep copy buckets
	private Tree(Tree t) {
		tau = t.getTau();
		twoTauPow = t.getTwoTauPow();
		treeIndex = t.getTreeIndex();
		w = t.getW();
		stashSize = t.getStashSize();
		nBits = t.getNBits();
		lBits = t.getLBits();
		alBits = t.getAlBits();
		nBytes = t.getNBytes();
		lBytes = t.getLBytes();
		alBytes = t.getAlBytes();
		aBytes = t.getABytes();
		tupleBytes = t.getTupleBytes();
		numBuckets = t.getNumBuckets();
		numBytes = t.getNumBytes();
		d = t.getD();
		h = t.getH();
		buckets = new Array64<Bucket>(numBuckets);
	}

	public Bucket getBucket(long i) {
		return buckets.get(i);
	}

	public void setBucket(long i, Bucket bucket) {
		if (!buckets.get(i).sameLength(bucket))
			throw new LengthNotMatchException(buckets.get(i).getNumBytes() + " != " + bucket.getNumBytes());
		buckets.set(i, bucket);
	}

	public Tree xor(Tree t) {
		if (!this.sameLength(t))
			throw new LengthNotMatchException(numBytes + " != " + t.getNumBytes());
		Tree newTree = new Tree(t);
		for (long i = 0; i < numBuckets; i++)
			// cannot use newTree.setBucket() here
			newTree.buckets.set(i, buckets.get(i).xor(t.getBucket(i)));
		return newTree;
	}

	public void setXor(Tree t) {
		if (!this.sameLength(t))
			throw new LengthNotMatchException(numBytes + " != " + t.getNumBytes());
		for (long i = 0; i < numBuckets; i++)
			buckets.get(i).setXor(t.getBucket(i));
	}

	public boolean sameLength(Tree t) {
		return numBytes == t.getNumBytes();
	}

	private long[] getBucketIndicesOnPath(BigInteger L) {
		if (treeIndex == 0)
			return new long[] { 0 };

		L = Util.getSubBits(L, lBits, 0);
		long[] indices = new long[d];
		for (int i = 1; i < d; i++) {
			if (L.testBit(d - i - 1))
				indices[i] = indices[i - 1] * 2 + 2;
			else
				indices[i] = indices[i - 1] * 2 + 1;
		}
		return indices;
	}

	public Bucket[] getBucketsOnPath(BigInteger L) {
		if (Global.cheat)
			return pathBuckets;

		long[] indices = getBucketIndicesOnPath(L);
		Bucket[] buckets = new Bucket[indices.length];
		for (int i = 0; i < indices.length; i++)
			buckets[i] = getBucket(indices[i]);
		return buckets;
	}

	public Bucket[] getBucketsOnPath(byte[] L) {
		return getBucketsOnPath(new BigInteger(1, L));
	}

	public Bucket[] getBucketsOnPath(long L) {
		return getBucketsOnPath(BigInteger.valueOf(L));
	}

	public void setBucketsOnPath(BigInteger L, Bucket[] buckets) {
		if (Global.cheat) {
			pathBuckets = buckets;
			return;
		}

		long[] indices = getBucketIndicesOnPath(L);
		if (indices.length != buckets.length)
			throw new LengthNotMatchException(indices.length + " != " + buckets.length);
		for (int i = 0; i < indices.length; i++)
			setBucket(indices[i], buckets[i]);
	}

	public void setBucketsOnPath(byte[] L, Bucket[] buckets) {
		setBucketsOnPath(new BigInteger(1, L), buckets);
	}

	public void setBucketsOnPath(long L, Bucket[] buckets) {
		setBucketsOnPath(BigInteger.valueOf(L), buckets);
	}

	public int getTau() {
		return tau;
	}

	public int getTwoTauPow() {
		return twoTauPow;
	}

	public int getTreeIndex() {
		return treeIndex;
	}

	public int getW() {
		return w;
	}

	public int getStashSize() {
		return stashSize;
	}

	public int getFBytes() {
		return treeIndex == 0 ? 0 : 1;
	}

	public int getNBits() {
		return nBits;
	}

	public int getLBits() {
		return lBits;
	}

	public int getAlBits() {
		return alBits;
	}

	public int getNBytes() {
		return nBytes;
	}

	public int getLBytes() {
		return lBytes;
	}

	public int getAlBytes() {
		return alBytes;
	}

	public int getABytes() {
		return aBytes;
	}

	public int getTupleBytes() {
		return tupleBytes;
	}

	public long getNumBuckets() {
		return numBuckets;
	}

	public long getNumBytes() {
		return numBytes;
	}

	public int getD() {
		return d;
	}

	public int getH() {
		return h;
	}
}

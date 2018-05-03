package oram;

import java.math.BigInteger;

import util.Util;

public class TestTree {

	public static void main(String[] args) {
		Metadata md = new Metadata();
		Tree tree = new Tree(2, md, null);
		long tupleCounter = 0;
		for (long i = 0; i < tree.getNumBuckets(); i++) {
			Bucket bucket = tree.getBucket(i);
			for (int j = 0; j < bucket.getNumTuples(); j++) {
				bucket.getTuple(j).setA(Util.rmSignBit(BigInteger.valueOf(tupleCounter).toByteArray()));
				tupleCounter++;
			}
		}

		BigInteger L = new BigInteger("0110011", 2);
		System.out.println(L.toString(2));
		Bucket[] pathBuckets = tree.getBucketsOnPath(L.longValue());
		for (int i = 0; i < pathBuckets.length; i++)
			System.out.println(pathBuckets[i]);
	}

}

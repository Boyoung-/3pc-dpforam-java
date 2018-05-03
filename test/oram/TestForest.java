package oram;

import java.math.BigInteger;

import crypto.Crypto;
import util.Util;

public class TestForest {

	public static void main(String[] args) {
		Metadata md = new Metadata();
		// Forest forest = new Forest(md);
		Forest forest = Forest.readFromFile(md.getDefaultForestFileName());
		int tau = md.getTau();
		int addrBits = md.getAddrBits();
		long numRecords = md.getNumInsertRecords();
		int numTrees = forest.getNumTrees();

		long numTests = 100;
		// long numTests = numRecords;
		for (long n = 0; n < numTests; n++) {
			// address of record we want to test
			long testAddr = Util.nextLong(numRecords, Crypto.sr);
			// long testAddr = n;
			long L = 0;
			long outRecord = 0;

			for (int i = 0; i < numTrees; i++) {
				// set address of tuple and index of label for searching
				long N;
				int indexN;
				if (i == 0) {
					N = 0;
					indexN = Util.getSubBits(BigInteger.valueOf(testAddr), addrBits, addrBits - tau).intValue();
				} else if (i < numTrees - 1) {
					N = Util.getSubBits(testAddr, addrBits, addrBits - i * tau);
					indexN = Util.getSubBits(BigInteger.valueOf(testAddr), addrBits - i * tau,
							Math.max(addrBits - (i + 1) * tau, 0)).intValue();
				} else {
					N = testAddr;
					indexN = 0;
				}

				// get the path buckets and search for the tuple
				Tree tree = forest.getTree(i);
				Bucket[] pathBuckets = tree.getBucketsOnPath(L);
				Tuple targetTuple = null;
				if (i == 0) {
					targetTuple = pathBuckets[0].getTuple(0);
				} else {
					for (int j = 0; j < pathBuckets.length; j++) {
						for (int k = 0; k < pathBuckets[j].getNumTuples(); k++) {
							Tuple tuple = pathBuckets[j].getTuple(k);
							if (tuple.getF()[0] == 1 && new BigInteger(1, tuple.getL()).longValue() == L
									&& new BigInteger(1, tuple.getN()).longValue() == N) {
								targetTuple = tuple;
								break;
							}
						}
						if (targetTuple != null)
							break;
					}
				}

				// retrieve the next label or record from the tuple
				if (i < numTrees - 1)
					L = new BigInteger(1,
							targetTuple.getSubA(indexN * tree.getAlBytes(), (indexN + 1) * tree.getAlBytes()))
									.longValue();
				else
					outRecord = new BigInteger(1, targetTuple.getA()).longValue();
			}

			// verify correctness
			if (testAddr == outRecord)
				System.out.println("Success on address " + BigInteger.valueOf(testAddr).toString(2));
			else
				System.err.println("Error on address " + BigInteger.valueOf(testAddr).toString(2));
		}
	}

}

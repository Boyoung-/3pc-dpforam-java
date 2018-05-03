package oram;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.lang3.ArrayUtils;

import crypto.Crypto;
import exceptions.LengthNotMatchException;
import util.Util;

public class Bucket implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private Tuple[] tuples;

	public Bucket(int numTuples, int[] tupleParams, Random rand) {
		if (tupleParams.length != 4)
			throw new LengthNotMatchException(tupleParams.length + " != 4");
		tuples = new Tuple[numTuples];
		for (int i = 0; i < numTuples; i++)
			tuples[i] = new Tuple(tupleParams[0], tupleParams[1], tupleParams[2], tupleParams[3], rand);
	}

	public Bucket(Tuple[] tuples) {
		this.tuples = tuples;
	}

	// deep copy
	public Bucket(Bucket b) {
		tuples = new Tuple[b.getNumTuples()];
		for (int i = 0; i < tuples.length; i++)
			tuples[i] = new Tuple(b.getTuple(i));
	}

	public int getNumBytes() {
		return tuples.length * tuples[0].getNumBytes();
	}

	public int getNumTuples() {
		return tuples.length;
	}

	public Tuple[] getTuples() {
		return tuples;
	}

	public Tuple getTuple(int i) {
		return tuples[i];
	}

	public void setTuple(int i, Tuple tuple) {
		if (!tuples[i].sameLength(tuple))
			throw new LengthNotMatchException(tuples[i].getNumBytes() + " != " + tuple.getNumBytes());
		tuples[i] = tuple;
	}

	public void permute(int[] p) {
		tuples = Util.permute(tuples, p);
	}

	public Bucket xor(Bucket b) {
		if (!this.sameLength(b))
			throw new LengthNotMatchException(getNumBytes() + " != " + b.getNumBytes());
		Tuple[] newTuples = new Tuple[tuples.length];
		for (int i = 0; i < tuples.length; i++)
			newTuples[i] = tuples[i].xor(b.getTuple(i));
		return new Bucket(newTuples);
	}

	public void setXor(Bucket b) {
		if (!this.sameLength(b))
			throw new LengthNotMatchException(getNumBytes() + " != " + b.getNumBytes());
		for (int i = 0; i < tuples.length; i++)
			tuples[i].setXor(b.getTuple(i));
	}

	public boolean sameLength(Bucket b) {
		return getNumBytes() == b.getNumBytes();
	}

	public static Tuple[] bucketsToTuples(Bucket[] buckets) {
		int numTuples = 0;
		for (int i = 0; i < buckets.length; i++)
			numTuples += buckets[i].getNumTuples();

		Tuple[] tuples = new Tuple[numTuples];
		int tupleCnt = 0;
		for (int i = 0; i < buckets.length; i++)
			for (int j = 0; j < buckets[i].getNumTuples(); j++) {
				tuples[tupleCnt] = buckets[i].getTuple(j);
				tupleCnt++;
			}

		return tuples;
	}

	public static Bucket[] tuplesToBuckets(Tuple[] tuples, int d, int sw, int w) {
		if (tuples.length != sw + (d - 1) * w)
			throw new LengthNotMatchException(tuples.length + " != " + (sw + (d - 1) * w));

		Bucket[] buckets = new Bucket[d];
		for (int i = 0; i < d; i++) {
			int start = i == 0 ? 0 : sw + (i - 1) * w;
			int end = i == 0 ? sw : start + w;
			buckets[i] = new Bucket(Arrays.copyOfRange(tuples, start, end));
		}

		return buckets;
	}

	public void expand(Tuple[] ts) {
		if (!tuples[0].sameLength(ts[0]))
			throw new LengthNotMatchException(tuples[0].getNumBytes() + " != " + ts[0].getNumBytes());

		tuples = ArrayUtils.addAll(tuples, ts);
	}

	// append empty random content tuples
	public void expand(int numTuples) {
		if (tuples.length >= numTuples)
			return;

		int f = tuples[0].getF().length;
		int n = tuples[0].getN().length;
		int l = tuples[0].getL().length;
		int a = tuples[0].getA().length;

		Tuple[] newTuples = new Tuple[numTuples];
		System.arraycopy(tuples, 0, newTuples, 0, tuples.length);
		for (int i = tuples.length; i < numTuples; i++) {
			newTuples[i] = new Tuple(f, n, l, a, Crypto.sr);
			newTuples[i].setF(new byte[f]);
		}

		tuples = newTuples;
	}

	public void shrink(int numTuples) {
		if (numTuples >= tuples.length)
			return;
		tuples = Arrays.copyOfRange(tuples, 0, numTuples);
	}

	public byte[] toByteArray() {
		int tupleBytes = tuples[0].getNumBytes();
		byte[] bucket = new byte[getNumBytes()];
		for (int i = 0; i < tuples.length; i++) {
			byte[] tuple = tuples[i].toByteArray();
			System.arraycopy(tuple, 0, bucket, i * tupleBytes, tupleBytes);
		}
		return bucket;
	}

	@Override
	public String toString() {
		String str = "Bucket:";
		for (int i = 0; i < tuples.length; i++)
			str += ("\n  " + tuples[i]);
		return str;
	}
}

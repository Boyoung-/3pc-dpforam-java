package oram;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import exceptions.LengthNotMatchException;
import util.Util;

public class Tuple implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private byte[] F;
	private byte[] N;
	private byte[] L;
	private byte[] A;

	public Tuple(int fs, int ns, int ls, int as, Random rand) {
		F = new byte[fs];
		N = new byte[ns];
		L = new byte[ls];
		A = new byte[as];
		if (rand != null) {
			rand.nextBytes(F);
			rand.nextBytes(N);
			rand.nextBytes(L);
			rand.nextBytes(A);
		}
	}

	public Tuple(byte[] f, byte[] n, byte[] l, byte[] a) {
		F = f;
		N = n;
		L = l;
		A = a;
	}

	// deep copy
	public Tuple(Tuple t) {
		F = t.getF().clone();
		N = t.getN().clone();
		L = t.getL().clone();
		A = t.getA().clone();
	}

	public int getNumBytes() {
		return F.length + N.length + L.length + A.length;
	}

	public byte[] getF() {
		return F;
	}

	public void setF(byte[] f) {
		if (F.length < f.length)
			throw new LengthNotMatchException(F.length + " < " + f.length);
		else if (F.length > f.length) {
			for (int i = 0; i < F.length - f.length; i++)
				F[i] = 0;
			System.arraycopy(f, 0, F, F.length - f.length, f.length);
		} else
			F = f;
	}

	public byte[] getN() {
		return N;
	}

	public void setN(byte[] n) {
		if (N.length < n.length)
			throw new LengthNotMatchException(N.length + " < " + n.length);
		else if (N.length > n.length) {
			for (int i = 0; i < N.length - n.length; i++)
				N[i] = 0;
			System.arraycopy(n, 0, N, N.length - n.length, n.length);
		} else
			N = n;
	}

	public byte[] getL() {
		return L;
	}

	public void setL(byte[] l) {
		if (L.length < l.length)
			throw new LengthNotMatchException(L.length + " < " + l.length);
		else if (L.length > l.length) {
			for (int i = 0; i < L.length - l.length; i++)
				L[i] = 0;
			System.arraycopy(l, 0, L, L.length - l.length, l.length);
		} else
			L = l;
	}

	public byte[] getA() {
		return A;
	}

	public void setA(byte[] a) {
		if (A.length < a.length)
			throw new LengthNotMatchException(A.length + " < " + a.length);
		else if (A.length > a.length) {
			for (int i = 0; i < A.length - a.length; i++)
				A[i] = 0;
			System.arraycopy(a, 0, A, A.length - a.length, a.length);
		} else
			A = a;
	}

	public byte[] getSubA(int start, int end) {
		return Arrays.copyOfRange(A, start, end);
	}

	public void setSubA(int start, int end, byte[] label) {
		if (start < 0)
			throw new IllegalArgumentException(start + " < 0");
		if (start > end)
			throw new IllegalArgumentException(start + " > " + end);
		int len = end - start;
		if (len < label.length)
			throw new LengthNotMatchException(len + " < " + label.length);
		else if (len > label.length) {
			for (int i = 0; i < len - label.length; i++)
				A[start + i] = 0;
		}
		System.arraycopy(label, 0, A, end - label.length, label.length);
	}

	public Tuple xor(Tuple t) {
		if (!this.sameLength(t))
			throw new LengthNotMatchException(this.getNumBytes() + " != " + t.getNumBytes());
		byte[] newF = Util.xor(F, t.getF());
		byte[] newN = Util.xor(N, t.getN());
		byte[] newL = Util.xor(L, t.getL());
		byte[] newA = Util.xor(A, t.getA());
		return new Tuple(newF, newN, newL, newA);
	}

	public void setXor(Tuple t) {
		if (!this.sameLength(t))
			throw new LengthNotMatchException(this.getNumBytes() + " != " + t.getNumBytes());
		Util.setXor(F, t.getF());
		Util.setXor(N, t.getN());
		Util.setXor(L, t.getL());
		Util.setXor(A, t.getA());
	}

	public boolean sameLength(Tuple t) {
		return getNumBytes() == t.getNumBytes();
	}

	public boolean equals(Tuple t) {
		if (!sameLength(t))
			return false;
		return Util.equal(toByteArray(), t.toByteArray());
	}

	public byte[] toByteArray() {
		byte[] tuple = new byte[getNumBytes()];
		int offset = 0;
		System.arraycopy(F, 0, tuple, offset, F.length);
		offset += F.length;
		System.arraycopy(N, 0, tuple, offset, N.length);
		offset += N.length;
		System.arraycopy(L, 0, tuple, offset, L.length);
		offset += L.length;
		System.arraycopy(A, 0, tuple, offset, A.length);
		return tuple;
	}

	@Override
	public String toString() {
		String str = "Tuple: ";
		str += ("F=" + new BigInteger(1, getF()).toString(2) + ", ");
		str += ("N=" + new BigInteger(1, getN()).toString(2) + ", ");
		str += ("L=" + new BigInteger(1, getL()).toString(2) + ", ");
		str += ("A=" + new BigInteger(1, getA()).toString(2));
		return str;
	}

}

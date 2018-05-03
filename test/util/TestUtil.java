package util;

import java.math.BigInteger;

public class TestUtil {

	public static void main(String[] args) {
		long a = new BigInteger("110101100", 2).longValue();
		long subBits = Util.getSubBits(a, 4, 1);
		System.out.println(BigInteger.valueOf(subBits).toString(2));
		long b = Util.setSubBits(a, subBits, 5, 2);
		System.out.println(BigInteger.valueOf(b).toString(2));

		byte[] aa = new byte[] { 0 };
		byte[] bb = new byte[] { 1 };
		Util.setXor(aa, bb);
		System.out.println(aa[0]);
	}

}

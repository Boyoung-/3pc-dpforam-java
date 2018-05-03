package util;

import util.Array64;

public class TestArray64 {

	public static void main(String[] args) {
		long size = (long) Math.pow(2, 20);
		Array64<Integer> arr = new Array64<Integer>(size);
		long pos = (long) Math.pow(2, 19);

		Integer a = 1;
		arr.set(pos, a);
		Integer b = arr.get(pos);
		a++;
		System.out.println(a + " " + b);
	}

}

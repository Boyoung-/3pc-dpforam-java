package oram;

import java.util.Random;

public class TestBucket {

	public static void main(String[] args) {
		int[] tupleParams = new int[] { 1, 2, 3, 4 };
		Random rand = new Random();
		Bucket bucket = new Bucket(6, tupleParams, null);
		System.out.println(bucket);
		bucket = new Bucket(6, tupleParams, rand);
		System.out.println(bucket);
	}

}

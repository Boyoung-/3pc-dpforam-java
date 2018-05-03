package oram;

import java.util.Random;

public class TestTuple {

	public static void main(String[] args) {
		Random rand = new Random();
		Tuple tuple = new Tuple(1, 2, 3, 4, null);
		System.out.println(tuple);
		tuple = new Tuple(1, 2, 3, 4, rand);
		System.out.println(tuple);
		tuple = new Tuple(0, 0, 0, 4, rand);
		System.out.println(tuple);
	}

}

package ui;

import oram.Forest;
import oram.Metadata;

public class InitForest {

	public static void main(String[] args) {
		Metadata md = new Metadata();
		md.print();

		Forest forest = new Forest(md);
		forest.writeToFile(md.getDefaultSharesName1());

		forest = new Forest(md, null);
		forest.writeToFile(md.getDefaultSharesName2());
	}

}

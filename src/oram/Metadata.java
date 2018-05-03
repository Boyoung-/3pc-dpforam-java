package oram;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

public class Metadata {
	private String configFolder = "config/";
	private String configFileName = "config.yaml";
	private String defaultForestFileName;

	private String TAU = "tau";
	private String ADDRBITS = "addrBits";
	private String W = "w";
	private String DBYTES = "dBytes";
	private String INSERT = "insert";
	private String STASH = "stash";

	private int tau;
	private int twoTauPow;
	private int addrBits;
	private int w;
	private int dBytes;
	private int stashSize;
	private int numTrees;
	private long maxNumRecords;
	private long numInsertRecords;

	private int[] nBits;
	private int[] lBits;
	private int[] alBits;

	private int[] nBytes;
	private int[] lBytes;
	private int[] alBytes;
	private int[] aBytes;
	private int[] tupleBytes;

	private int[] stashSizes;
	private long[] numBuckets;
	private long[] treeBytes;

	private long forestBytes;

	public Metadata() {
		setup(configFileName);
	}

	public Metadata(String filename) {
		setup(filename);
	}

	private void setup(String filename) {
		Yaml yaml = new Yaml();
		InputStream input = null;
		try {
			input = new FileInputStream(new File(configFolder + filename));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		@SuppressWarnings("unchecked")
		Map<String, Object> configMap = (Map<String, Object>) yaml.load(input);

		tau = Integer.parseInt(configMap.get(TAU).toString());
		addrBits = Integer.parseInt(configMap.get(ADDRBITS).toString());
		w = Integer.parseInt(configMap.get(W).toString());
		dBytes = Integer.parseInt(configMap.get(DBYTES).toString());
		numInsertRecords = Long.parseLong(configMap.get(INSERT).toString(), 10);
		stashSize = Integer.parseInt(configMap.get(STASH).toString());

		init();
		setDefaultForestFileName();
	}

	private void init() {
		twoTauPow = (int) Math.pow(2, tau);
		numTrees = (addrBits - 1) / tau + 2;
		maxNumRecords = (long) Math.pow(2, addrBits);
		if (numInsertRecords < 0 || numInsertRecords > maxNumRecords)
			numInsertRecords = maxNumRecords;

		lBits = new int[numTrees];
		nBits = new int[numTrees];
		alBits = new int[numTrees];
		lBytes = new int[numTrees];
		nBytes = new int[numTrees];
		alBytes = new int[numTrees];
		aBytes = new int[numTrees];
		tupleBytes = new int[numTrees];

		stashSizes = new int[numTrees];
		numBuckets = new long[numTrees];
		treeBytes = new long[numTrees];

		forestBytes = 0;

		for (int i = numTrees - 1; i >= 0; i--) {
			if (i == 0) {
				nBits[i] = 0;
				lBits[i] = 0;
				alBits[i] = lBits[i + 1];
			} else if (i < numTrees - 1) {
				nBits[i] = i * tau;
				lBits[i] = nBits[i] + 1;
				alBits[i] = lBits[i + 1];
			} else {
				nBits[i] = addrBits;
				lBits[i] = nBits[i] + 1;
				alBits[i] = 0;
			}

			nBytes[i] = (nBits[i] + 7) / 8;
			lBytes[i] = (lBits[i] + 7) / 8;
			alBytes[i] = (alBits[i] + 7) / 8;
			aBytes[i] = (i < numTrees - 1) ? (alBytes[i] * twoTauPow) : dBytes;

			numBuckets[i] = (long) Math.pow(2, lBits[i] + 1) - 1;
			if (i == 0) {
				tupleBytes[i] = aBytes[i];
				stashSizes[i] = 1;
				treeBytes[i] = tupleBytes[i];
			} else {
				tupleBytes[i] = 1 + nBytes[i] + lBytes[i] + aBytes[i];
				stashSizes[i] = stashSize;
				treeBytes[i] = ((numBuckets[i] - 1) * w + stashSizes[i]) * tupleBytes[i];
			}

			forestBytes += treeBytes[i];
		}
	}

	public void print() {
		System.out.println("===== ORAM Forest Metadata =====");
		System.out.println();
		System.out.println("tau:				" + tau);
		System.out.println("address bits:		" + addrBits);
		System.out.println("w:					" + w);
		System.out.println("D bytes:			" + dBytes);
		System.out.println();
		System.out.println("max records:		" + maxNumRecords);
		System.out.println("inserted records:	" + numInsertRecords);
		System.out.println("trees:				" + numTrees);
		System.out.println("forest bytes:		" + forestBytes);
		System.out.println();

		for (int i = 0; i < numTrees; i++) {
			System.out.println("[Tree " + i + "]");
			System.out.println("	nBits		-> " + nBits[i]);
			System.out.println("	lBits		-> " + lBits[i]);
			System.out.println("	alBits		-> " + alBits[i]);
			System.out.println("	nBytes		-> " + nBytes[i]);
			System.out.println("	lBytes		-> " + lBytes[i]);
			System.out.println("	alBytes		-> " + alBytes[i]);
			System.out.println("	aBytes		-> " + aBytes[i]);
			System.out.println("	tupleBytes	-> " + tupleBytes[i]);
			System.out.println("	stashSize	-> " + stashSizes[i]);
			System.out.println("	numBuckets	-> " + numBuckets[i]);
			System.out.println("	treeBytes	-> " + treeBytes[i]);
			System.out.println();
		}
		System.out.println("===== End of Metadata =====");
		System.out.println();
	}

	public void writeToFile(String filename) {
		Yaml yaml = new Yaml();
		FileWriter writer = null;
		try {
			writer = new FileWriter(configFolder + filename);
		} catch (IOException e) {
			e.printStackTrace();
		}

		Map<String, String> configMap = new HashMap<String, String>();
		configMap.put(TAU, "" + tau);
		configMap.put(ADDRBITS, "" + addrBits);
		configMap.put(W, "" + w);
		configMap.put(DBYTES, "" + dBytes);
		configMap.put(INSERT, "" + numInsertRecords);
		configMap.put(STASH, "" + stashSize);

		yaml.dump(configMap, writer);
	}

	public void writeToFile() {
		writeToFile(configFileName);
	}

	private void setDefaultForestFileName() {
		defaultForestFileName = "forest_";
		defaultForestFileName += "t" + tau;
		defaultForestFileName += "m" + addrBits;
		defaultForestFileName += "s" + stashSize;
		defaultForestFileName += "w" + w;
		defaultForestFileName += "d" + dBytes;
		defaultForestFileName += "_i" + numInsertRecords;
		defaultForestFileName += ".bin";
	}

	public String getDefaultForestFileName() {
		return defaultForestFileName;
	}

	public String getDefaultSharesName1() {
		return defaultForestFileName + ".share1";
	}

	public String getDefaultSharesName2() {
		return defaultForestFileName + ".share2";
	}

	public int getTau() {
		return tau;
	}

	public int getTwoTauPow() {
		return twoTauPow;
	}

	public int getAddrBits() {
		return addrBits;
	}

	public int getW() {
		return w;
	}

	public int getDBytes() {
		return dBytes;
	}

	public int getTempStashSize() {
		return stashSize;
	}

	public int getNumTrees() {
		return numTrees;
	}

	public long getMaxNumRecords() {
		return maxNumRecords;
	}

	public long getNumInsertRecords() {
		return numInsertRecords;
	}

	public int getNBitsOfTree(int i) {
		return nBits[i];
	}

	public int getLBitsOfTree(int i) {
		return lBits[i];
	}

	public int getAlBitsOfTree(int i) {
		return alBits[i];
	}

	public int getNBytesOfTree(int i) {
		return nBytes[i];
	}

	public int getLBytesOfTree(int i) {
		return lBytes[i];
	}

	public int getAlBytesOfTree(int i) {
		return alBytes[i];
	}

	public int getABytesOfTree(int i) {
		return aBytes[i];
	}

	public int getTupleBytesOfTree(int i) {
		return tupleBytes[i];
	}

	public int getStashSizeOfTree(int i) {
		return stashSizes[i];
	}

	public long getNumBucketsOfTree(int i) {
		return numBuckets[i];
	}

	public long getTreeBytesOfTree(int i) {
		return treeBytes[i];
	}

	public long getForestBytes() {
		return forestBytes;
	}
}

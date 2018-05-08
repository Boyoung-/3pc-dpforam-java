package crypto;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Crypto {
	public static final int prgSeedBits = 128;
	public static final int prgSeedBytes = (prgSeedBits + 7) / 8;

	public static SecureRandom sr;
	public static SecureRandom sr_DE;
	public static SecureRandom sr_CE;
	public static SecureRandom sr_CD;

	static {
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");

			sr_DE = SecureRandom.getInstance("SHA1PRNG");
			sr_DE.setSeed("abcdefghijklmnop".getBytes("us-ascii"));

			sr_CE = SecureRandom.getInstance("SHA1PRNG");
			sr_CE.setSeed("qrstuvwxyzabcdef".getBytes("us-ascii"));

			sr_CD = SecureRandom.getInstance("SHA1PRNG");
			sr_CD.setSeed("ghijklmnopqrstuv".getBytes("us-ascii"));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
}

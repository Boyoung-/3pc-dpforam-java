package crypto;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Crypto {
	public static SecureRandom sr;
	public static SecureRandom sr_DE;
	public static SecureRandom sr_CE;
	public static SecureRandom sr_CD;
	public static MessageDigest sha1;
	public static int secParam;
	public static int secParamBytes;
	public static int KSearchRerunParam;
	public static int KSearchRerunParamBytes;

	static {
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");

			sr_DE = SecureRandom.getInstance("SHA1PRNG");
			sr_DE.setSeed("abcdefghijklmnop".getBytes("us-ascii"));

			sr_CE = SecureRandom.getInstance("SHA1PRNG");
			sr_CE.setSeed("qrstuvwxyzabcdef".getBytes("us-ascii"));

			sr_CD = SecureRandom.getInstance("SHA1PRNG");
			sr_CD.setSeed("ghijklmnopqrstuv".getBytes("us-ascii"));

			sha1 = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		secParam = 80;
		secParamBytes = (secParam + 7) / 8;
		KSearchRerunParam = 32;
		KSearchRerunParamBytes = (KSearchRerunParam + 7) / 8;
	}
}

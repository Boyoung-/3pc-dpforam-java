package crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import exceptions.IllegalInputException;
import exceptions.LengthNotMatchException;
import util.Util;

public class PRF {

	private Cipher cipher;
	private int l; // output bit length

	private int maxInputBytes = 12;

	public PRF(int l) {
		try {
			cipher = Cipher.getInstance("AES/ECB/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
		this.l = l;
	}

	public void init(byte[] key) {
		if (key.length != 16)
			throw new LengthNotMatchException(key.length + " != 16");

		SecretKeySpec skey = new SecretKeySpec(key, "AES");
		try {
			cipher.init(Cipher.ENCRYPT_MODE, skey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	public synchronized byte[] compute(byte[] input) {
		if (input.length > maxInputBytes)
			throw new IllegalInputException(input.length + " > " + maxInputBytes);

		byte[] in = new byte[16];
		System.arraycopy(input, 0, in, in.length - input.length, input.length);
		byte[] output = null;
		if (l <= 128)
			output = leq128(in, l);
		else
			output = g128(in);

		return output;
	}

	private byte[] leq128(byte[] input, int np) {
		byte[] ctext = null;
		try {
			ctext = cipher.doFinal(input);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

		int outBytes = (np + 7) / 8;
		if (ctext.length == outBytes)
			return ctext;
		else
			return Arrays.copyOfRange(ctext, ctext.length - outBytes, ctext.length);
	}

	private byte[] g128(byte[] input) {
		int n = l / 128;
		int outBytes = (l + 7) / 8;
		byte[] output = new byte[outBytes];

		int len = Math.min(16 - maxInputBytes, 4);
		for (int i = 0; i < n; i++) {
			byte[] index = Util.intToBytes(i + 1);
			System.arraycopy(index, 4 - len, input, 16 - maxInputBytes - len, len);
			byte[] seg = leq128(input, 128);
			System.arraycopy(seg, 0, output, i * seg.length, seg.length);
		}
		int np = l % 128;
		if (np == 0)
			return output;

		byte[] index = Util.intToBytes(n + 1);
		System.arraycopy(index, 4 - len, input, 16 - maxInputBytes - len, len);
		byte[] last = leq128(input, np);
		System.arraycopy(last, 0, output, outBytes - last.length, last.length);
		return output;
	}

	public static byte[] generateKey(Random rand) {
		byte[] key = new byte[16];
		rand.nextBytes(key);
		return key;
	}
}

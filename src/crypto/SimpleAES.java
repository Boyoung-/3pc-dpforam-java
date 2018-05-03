package crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class SimpleAES {
	private Cipher cipherEnc;
	private Cipher cipherDec;

	public SimpleAES() {
		SecretKeySpec skey = readKey();
		try {
			cipherEnc = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipherDec = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipherEnc.init(Cipher.ENCRYPT_MODE, skey);
			cipherDec.init(Cipher.DECRYPT_MODE, skey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	public synchronized byte[] encrypt(byte[] in) {
		byte[] out = null;
		try {
			out = cipherEnc.doFinal(in);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return out;
	}

	public synchronized byte[] decrypt(byte[] in) {
		byte[] out = null;
		try {
			out = cipherDec.doFinal(in);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return out;
	}

	public static void generateKey(Random rand) {
		byte[] key = new byte[16];
		rand.nextBytes(key);
		SecretKeySpec skey = new SecretKeySpec(key, "AES");
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = new FileOutputStream("key/aes.key");
			oos = new ObjectOutputStream(fos);
			oos.writeObject(skey);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (oos != null) {
				try {
					oos.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public SecretKeySpec readKey() {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		SecretKeySpec skey = null;
		try {
			fis = new FileInputStream("key/aes.key");
			ois = new ObjectInputStream(fis);
			skey = (SecretKeySpec) ois.readObject();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		} finally {
			if (ois != null) {
				try {
					ois.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return skey;
	}

	// test
	public static void main(String[] args) {
		SimpleAES aes = new SimpleAES();
		byte[] plain = new byte[10240 * 8];
		Crypto.sr.nextBytes(plain);
		byte[] enc = aes.encrypt(plain);
		byte[] tmp = new byte[plain.length];
		Crypto.sr.nextBytes(tmp);
		aes.decrypt(aes.encrypt(tmp));
		byte[] dec = aes.decrypt(enc);
		long in = new BigInteger(plain).longValue();
		long cipher = new BigInteger(enc).longValue();
		long out = new BigInteger(dec).longValue();
		System.out.println(in != cipher);
		System.out.println(in == out);
		System.out.println(plain.length == dec.length);
	}
}

package crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import exceptions.IllegalInputException;

public class PRG {
	private Cipher cipher;
	private SecretKeySpec skey;
	private int l; // output bit length

	public PRG(int l) {
		try {
			cipher = Cipher.getInstance("AES/CTR/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
		readKey();
		this.l = l;
	}

	public synchronized byte[] compute(byte[] seed) {
		byte[] input;
		if (seed.length > 16) {
			throw new IllegalInputException(seed.length + " > 16");
		} else if (seed.length == 16) {
			input = seed;
		} else {
			input = new byte[16];
			System.arraycopy(seed, 0, input, input.length - seed.length, seed.length);
		}

		IvParameterSpec IV = new IvParameterSpec(input);
		byte[] msg = new byte[(l + 7) / 8];
		byte[] output = null;

		try {
			cipher.init(Cipher.ENCRYPT_MODE, skey, IV);
			output = cipher.doFinal(msg);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}

		return output;
	}

	public static void generateKey(Random rand) {
		byte[] key = new byte[16];
		rand.nextBytes(key);
		SecretKeySpec skey = new SecretKeySpec(key, "AES");
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = new FileOutputStream("key/prg.key");
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

	public void readKey() {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream("key/prg.key");
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
	}
}

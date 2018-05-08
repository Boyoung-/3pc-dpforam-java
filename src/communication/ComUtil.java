package communication;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import fss.FSSKey;

public class ComUtil {
	public static byte[] serialize(FSSKey key) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			int seedBytes = key.s.length;
			int mPlus1 = key.sigma.length;
			dos.writeInt(seedBytes);
			dos.writeInt(mPlus1);
			dos.write(key.s);
			dos.writeByte(key.t);
			for (int i = 1; i < mPlus1; i++) {
				dos.write(key.sigma[i]);
			}
			dos.write(key.tau[0]);
			dos.write(key.tau[1]);
			if (key.gamma == null) {
				dos.writeInt(-1);
			} else {
				dos.writeInt(key.gamma.length);
				dos.write(key.gamma);
			}
			out = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dos.close();
				baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static FSSKey toFSSKey(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		FSSKey out = null;
		try {
			int seedBytes = dis.readInt();
			int mPlus1 = dis.readInt();
			byte[] s = new byte[seedBytes];
			dis.read(s);
			byte t = dis.readByte();
			byte[][] sigma = new byte[mPlus1][seedBytes];
			for (int i = 1; i < mPlus1; i++) {
				dis.read(sigma[i]);
			}
			byte[][] tau = new byte[2][mPlus1];
			dis.read(tau[0]);
			dis.read(tau[1]);
			byte[] gamma = null;
			int gammaLen = dis.readInt();
			if (gammaLen > -1) {
				gamma = new byte[gammaLen];
				dis.read(gamma);
			}
			out = new FSSKey(s, t, sigma, tau, gamma);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
				bais.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static byte[] serialize(byte[][] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			dos.writeInt(in[0].length);
			for (int i = 0; i < in.length; i++)
				dos.write(in[i]);
			out = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dos.close();
				baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static byte[][] toDoubleByteArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		byte[][] out = null;
		try {
			int len1 = dis.readInt();
			int len2 = dis.readInt();
			out = new byte[len1][len2];
			for (int i = 0; i < len1; i++)
				dis.read(out[i]);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
				bais.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static byte[] serialize(byte[][][] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			dos.writeInt(in[0].length);
			dos.writeInt(in[0][0].length);
			for (int i = 0; i < in.length; i++)
				for (int j = 0; j < in[i].length; j++)
					dos.write(in[i][j]);
			out = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dos.close();
				baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static byte[][][] toTripleByteArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		byte[][][] out = null;
		try {
			int len1 = dis.readInt();
			int len2 = dis.readInt();
			int len3 = dis.readInt();
			out = new byte[len1][len2][len3];
			for (int i = 0; i < len1; i++)
				for (int j = 0; j < len2; j++)
					dis.read(out[i][j]);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
				bais.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static byte[] serialize(int[] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			for (int i = 0; i < in.length; i++)
				dos.writeInt(in[i]);
			out = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dos.close();
				baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static int[] toIntArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		int[] out = null;
		try {
			int len1 = dis.readInt();
			out = new int[len1];
			for (int i = 0; i < len1; i++)
				out[i] = dis.readInt();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
				bais.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static byte[] serialize(int[][] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			dos.writeInt(in[0].length);
			for (int i = 0; i < in.length; i++)
				for (int j = 0; j < in[i].length; j++)
					dos.writeInt(in[i][j]);
			out = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dos.close();
				baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static int[][] toDoubleIntArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		int[][] out = null;
		try {
			int len1 = dis.readInt();
			int len2 = dis.readInt();
			out = new int[len1][len2];
			for (int i = 0; i < len1; i++)
				for (int j = 0; j < len2; j++)
					out[i][j] = dis.readInt();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
				bais.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static byte[] serialize(ArrayList<byte[]> in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.size());
			dos.writeInt(in.get(0).length);
			for (int i = 0; i < in.size(); i++)
				dos.write(in.get(i));
			out = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dos.close();
				baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}

	public static ArrayList<byte[]> toArrayList(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		ArrayList<byte[]> out = null;
		try {
			int len = dis.readInt();
			int bytes = dis.readInt();
			out = new ArrayList<byte[]>(len);
			for (int i = 0; i < len; i++) {
				byte[] b = new byte[bytes];
				dis.read(b);
				out.add(b);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
				bais.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return out;
	}
}

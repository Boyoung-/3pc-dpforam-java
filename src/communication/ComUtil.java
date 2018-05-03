package communication;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import com.oblivm.backend.gc.GCSignal;

import oram.Bucket;
import oram.Tuple;

public class ComUtil {
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

	public static byte[] serialize(Tuple in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.getF().length);
			dos.writeInt(in.getN().length);
			dos.writeInt(in.getL().length);
			dos.writeInt(in.getA().length);
			dos.write(in.getF());
			dos.write(in.getN());
			dos.write(in.getL());
			dos.write(in.getA());
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

	public static Tuple toTuple(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		Tuple out = null;
		try {
			int f = dis.readInt();
			int n = dis.readInt();
			int l = dis.readInt();
			int a = dis.readInt();
			byte[] F = new byte[f];
			byte[] N = new byte[n];
			byte[] L = new byte[l];
			byte[] A = new byte[a];
			dis.read(F);
			dis.read(N);
			dis.read(L);
			dis.read(A);
			out = new Tuple(F, N, L, A);
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

	public static byte[] serialize(Tuple[] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			dos.writeInt(in[0].getF().length);
			dos.writeInt(in[0].getN().length);
			dos.writeInt(in[0].getL().length);
			dos.writeInt(in[0].getA().length);
			for (int i = 0; i < in.length; i++) {
				dos.write(in[i].getF());
				dos.write(in[i].getN());
				dos.write(in[i].getL());
				dos.write(in[i].getA());
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

	public static Tuple[] toTupleArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		Tuple[] out = null;
		try {
			int len = dis.readInt();
			int f = dis.readInt();
			int n = dis.readInt();
			int l = dis.readInt();
			int a = dis.readInt();
			out = new Tuple[len];
			for (int i = 0; i < len; i++) {
				byte[] F = new byte[f];
				byte[] N = new byte[n];
				byte[] L = new byte[l];
				byte[] A = new byte[a];
				dis.read(F);
				dis.read(N);
				dis.read(L);
				dis.read(A);
				out[i] = new Tuple(F, N, L, A);
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

	public static byte[] serialize(GCSignal[] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			for (int i = 0; i < in.length; i++)
				dos.write(in[i].bytes);
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

	public static GCSignal[] toGCSignalArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		GCSignal[] out = null;
		try {
			int len1 = dis.readInt();
			out = new GCSignal[len1];
			for (int i = 0; i < len1; i++) {
				out[i] = new GCSignal(new byte[GCSignal.len]);
				dis.read(out[i].bytes);
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

	public static byte[] serialize(GCSignal[][] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			dos.writeInt(in[0].length);
			for (int i = 0; i < in.length; i++)
				for (int j = 0; j < in[i].length; j++)
					dos.write(in[i][j].bytes);
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

	public static GCSignal[][] toDoubleGCSignalArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		GCSignal[][] out = null;
		try {
			int len1 = dis.readInt();
			int len2 = dis.readInt();
			out = new GCSignal[len1][len2];
			for (int i = 0; i < len1; i++)
				for (int j = 0; j < len2; j++) {
					out[i][j] = new GCSignal(new byte[GCSignal.len]);
					dis.read(out[i][j].bytes);
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

	public static byte[] serialize(GCSignal[][][] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			dos.writeInt(in[0].length);
			dos.writeInt(in[0][0].length);
			for (int i = 0; i < in.length; i++)
				for (int j = 0; j < in[i].length; j++)
					for (int k = 0; k < in[i][j].length; k++)
						dos.write(in[i][j][k].bytes);
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

	public static GCSignal[][][] toTripleGCSignalArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		GCSignal[][][] out = null;
		try {
			int len1 = dis.readInt();
			int len2 = dis.readInt();
			int len3 = dis.readInt();
			out = new GCSignal[len1][len2][len3];
			for (int i = 0; i < len1; i++)
				for (int j = 0; j < len2; j++)
					for (int k = 0; k < len3; k++) {
						out[i][j][k] = new GCSignal(new byte[GCSignal.len]);
						dis.read(out[i][j][k].bytes);
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

	public static byte[] serialize(GCSignal[][][][] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			dos.writeInt(in.length);
			dos.writeInt(in[0].length);
			dos.writeInt(in[0][0].length);
			dos.writeInt(in[0][0][0].length);
			for (int i = 0; i < in.length; i++)
				for (int j = 0; j < in[i].length; j++)
					for (int k = 0; k < in[i][j].length; k++)
						for (int l = 0; l < in[i][j][k].length; l++)
							dos.write(in[i][j][k][l].bytes);
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

	public static GCSignal[][][][] toQuadGCSignalArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		GCSignal[][][][] out = null;
		try {
			int len1 = dis.readInt();
			int len2 = dis.readInt();
			int len3 = dis.readInt();
			int len4 = dis.readInt();
			out = new GCSignal[len1][len2][len3][len4];
			for (int i = 0; i < len1; i++)
				for (int j = 0; j < len2; j++)
					for (int k = 0; k < len3; k++)
						for (int l = 0; l < len4; l++) {
							out[i][j][k][l] = new GCSignal(new byte[GCSignal.len]);
							dis.read(out[i][j][k][l].bytes);
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

	public static byte[] serialize(Bucket[] in) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] out = null;
		try {
			byte[] b = serialize(Bucket.bucketsToTuples(in));
			dos.writeInt(in.length);
			dos.writeInt(in[0].getNumTuples());
			dos.writeInt(in[1].getNumTuples());
			dos.writeInt(b.length);
			dos.write(b);
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

	public static Bucket[] toBucketArray(byte[] in) {
		ByteArrayInputStream bais = new ByteArrayInputStream(in);
		DataInputStream dis = new DataInputStream(bais);
		Bucket[] out = null;
		try {
			int d = dis.readInt();
			int sw = dis.readInt();
			int w = dis.readInt();
			int bytes = dis.readInt();
			byte[] b = new byte[bytes];
			dis.read(b);
			Tuple[] tuples = toTupleArray(b);
			out = Bucket.tuplesToBuckets(tuples, d, sw, w);
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

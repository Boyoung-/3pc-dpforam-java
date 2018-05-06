package dpforam;

import java.io.Serializable;

// TODO: customize serialization

public class FSSKey implements Serializable {
	private static final long serialVersionUID = 4522976008505295658L;

	public byte[] s;
	public byte t;
	public byte[][] sigma;
	public byte[][] tau;
	byte[] gamma;

	public FSSKey(byte[] s, byte t, byte[][] sigma, byte[][] tau, byte[] gamma) {
		this.s = s;
		this.t = t;
		this.sigma = sigma;
		this.tau = tau;
		this.gamma = gamma;
	}
}

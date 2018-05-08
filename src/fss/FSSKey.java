package fss;

public class FSSKey {
	public byte[] s;
	public byte t;
	public byte[][] sigma;
	public byte[][] tau;
	public byte[] gamma;

	public FSSKey(byte[] s, byte t, byte[][] sigma, byte[][] tau, byte[] gamma) {
		this.s = s;
		this.t = t;
		this.sigma = sigma;
		this.tau = tau;
		this.gamma = gamma;
	}
}

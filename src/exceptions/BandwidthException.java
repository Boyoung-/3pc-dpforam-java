package exceptions;

public class BandwidthException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public BandwidthException() {
		super();
	}

	public BandwidthException(String message) {
		super(message);
	}
}

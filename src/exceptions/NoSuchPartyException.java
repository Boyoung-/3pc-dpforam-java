package exceptions;

public class NoSuchPartyException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public NoSuchPartyException() {
		super();
	}

	public NoSuchPartyException(String message) {
		super(message);
	}
}

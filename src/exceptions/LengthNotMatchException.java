package exceptions;

public class LengthNotMatchException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public LengthNotMatchException() {
		super();
	}

	public LengthNotMatchException(String message) {
		super(message);
	}
}

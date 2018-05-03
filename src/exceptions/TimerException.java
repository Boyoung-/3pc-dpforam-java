package exceptions;

public class TimerException extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public TimerException() {
		super();
	}

	public TimerException(String message) {
		super(message);
	}
}

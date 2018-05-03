package struct;

public enum Party {
	Charlie("charlie"), Debbie("debbie"), Eddie("eddie");

	private final String str;

	private Party(String str) {
		this.str = str;
	}

	@Override
	public String toString() {
		return str;
	}
}

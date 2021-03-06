package util;

public class Array64<T> {

	private final int CHUNK_SIZE = 1024 * 1024;

	private long size;
	public T[][] data;

	@SuppressWarnings("unchecked")
	public Array64(long s) {
		size = (s > 0) ? s : 0;
		int chunks = (int) (size / CHUNK_SIZE);
		int remainder = (int) (size % CHUNK_SIZE);
		data = (T[][]) new Object[chunks + (remainder == 0 ? 0 : 1)][];
		for (int i = 0; i < chunks; i++)
			data[i] = (T[]) new Object[CHUNK_SIZE];
		if (remainder != 0)
			data[chunks] = (T[]) new Object[remainder];
	}

	@SuppressWarnings("unchecked")
	public Array64(long size, Object[][] data) {
		this.size = size;
		this.data = (T[][]) data;
	}

	public long size() {
		return size;
	}

	public int numChunks() {
		return data.length;
	}

	public T[] getChunk(int i) {
		return data[i];
	}

	public T get(long index) {
		if (index < 0 || index >= size)
			throw new ArrayIndexOutOfBoundsException("" + index);
		int chunk = (int) (index / CHUNK_SIZE);
		int offset = (int) (index % CHUNK_SIZE);
		return data[chunk][offset];
	}

	public void set(long index, T item) {
		if (index < 0 || index >= size)
			throw new ArrayIndexOutOfBoundsException("" + index);
		int chunk = (int) (index / CHUNK_SIZE);
		int offset = (int) (index % CHUNK_SIZE);
		data[chunk][offset] = item;
	}
}

package util;

import java.io.Serializable;

import exceptions.BandwidthException;

public class Bandwidth implements Serializable {

	private static final long serialVersionUID = -5318086786286085625L;

	public String task;
	public long bandwidth;

	public Bandwidth() {
		task = "";
		bandwidth = 0;
	}

	public Bandwidth(String t) {
		task = t;
		bandwidth = 0;
	}

	public Bandwidth(Bandwidth b) {
		task = b.task;
		bandwidth = b.bandwidth;
	}

	public void reset() {
		bandwidth = 0;
	}

	public void add(long n) {
		bandwidth += n;
	}

	public Bandwidth addAndReturn(Bandwidth b) {
		if (!task.equals(b.task))
			throw new BandwidthException("Task: " + task + " != " + b.task);
		Bandwidth total = new Bandwidth(task);
		total.bandwidth = bandwidth + b.bandwidth;
		return total;
	}

	public void add(Bandwidth b) {
		if (!task.equals(b.task))
			throw new BandwidthException("Task: " + task + " != " + b.task);
		bandwidth += b.bandwidth;
	}

	public String noPreToString() {
		return "" + bandwidth;
	}

	@Override
	public String toString() {
		return task + "(bytes): " + bandwidth;
	}
}

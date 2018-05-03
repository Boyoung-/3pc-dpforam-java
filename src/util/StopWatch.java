package util;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;

import exceptions.StopWatchException;

public class StopWatch {

	private String task;
	private long startWC;
	private long startCPU;
	public long elapsedWC;
	public long elapsedCPU;
	private boolean isOn;

	public StopWatch() {
		task = "";
		startWC = 0;
		startCPU = 0;
		elapsedWC = 0;
		elapsedCPU = 0;
		isOn = false;
	}

	public StopWatch(String t) {
		task = t;
		startWC = 0;
		startCPU = 0;
		elapsedWC = 0;
		elapsedCPU = 0;
		isOn = false;
	}

	public void reset() {
		if (isOn) {
			try {
				throw new StopWatchException("StopWatch is still running");
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		startWC = 0;
		startCPU = 0;
		elapsedWC = 0;
		elapsedCPU = 0;
	}

	public void start() {
		if (isOn) {
			try {
				throw new StopWatchException("StopWatch is already running");
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		isOn = true;
		startWC = System.nanoTime();
		startCPU = getCPUTime();
	}

	public void stop() {
		if (!isOn) {
			try {
				throw new StopWatchException("StopWatch is not running");
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		isOn = false;
		elapsedCPU += getCPUTime() - startCPU;
		elapsedWC += System.nanoTime() - startWC;
	}

	private long getCPUTime() {
		ThreadMXBean bean = ManagementFactory.getThreadMXBean();
		return bean.isCurrentThreadCpuTimeSupported() ? bean.getCurrentThreadCpuTime() : 0L;
	}

	public String toMS() {
		String out = "  WC(ms): " + elapsedWC / 1000000;
		out += "\n  CPU(ms): " + elapsedCPU / 1000000;
		if (task.length() == 0)
			return out;
		else
			return task + "\n" + out;
	}

	public String noPreToMS() {
		return "\n" + (elapsedWC / 1000000) + "\n" + (elapsedCPU / 1000000);
	}

	public StopWatch divideBy(int n) {
		if (isOn) {
			try {
				throw new StopWatchException("StopWatch is still running");
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		StopWatch sw = new StopWatch(task);
		sw.elapsedWC = elapsedWC / n;
		sw.elapsedCPU = elapsedCPU / n;
		return sw;
	}

	public StopWatch addAndReturn(StopWatch s) {
		if (isOn || s.isOn) {
			try {
				throw new StopWatchException("StopWatch is still running");
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		if (!task.equals(s.task)) {
			try {
				throw new StopWatchException("Tasks don't match: " + task + " != " + s.task);
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		StopWatch sw = new StopWatch(task);
		sw.elapsedWC = elapsedWC + s.elapsedWC;
		sw.elapsedCPU = elapsedCPU + s.elapsedCPU;
		return sw;
	}

	public void add(StopWatch s) {
		if (isOn || s.isOn) {
			try {
				throw new StopWatchException("StopWatch is still running");
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		if (!task.equals(s.task)) {
			try {
				throw new StopWatchException("Tasks don't match: " + task + " != " + s.task);
			} catch (StopWatchException e) {
				e.printStackTrace();
			}
		}

		elapsedWC += s.elapsedWC;
		elapsedCPU += s.elapsedCPU;
	}
}

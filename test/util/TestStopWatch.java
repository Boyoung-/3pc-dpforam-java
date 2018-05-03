package util;

public class TestStopWatch {

	public static void main(String[] args) {
		StopWatch sw = new StopWatch();
		sw.start();
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		sw.stop();
		System.out.println(sw.toMS());

		sw.start();
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		sw.stop();
		System.out.println(sw.toMS());
	}

}

package subprotocols;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;

public class TestShift_C {

	public static void main(String[] args) {
		Runtime runTime = Runtime.getRuntime();
		Process process = null;
		String dir = System.getProperty("user.dir");
		String binDir = dir + "\\bin";
		String libs = dir + "\\lib\\*";
		try {
			process = runTime.exec("java -classpath " + binDir + ";" + libs + " ui.CLI -protocol shift charlie");

		} catch (IOException e) {
			e.printStackTrace();
		}
		InputStream inputStream = process.getInputStream();
		InputStreamReader isr = new InputStreamReader(inputStream);
		InputStream errorStream = process.getErrorStream();
		InputStreamReader esr = new InputStreamReader(errorStream);

		System.out.println("STANDARD OUTPUT:");
		int n1;
		char[] c1 = new char[1024];
		try {
			while ((n1 = isr.read(c1)) > 0) {
				System.out.print(new String(Arrays.copyOfRange(c1, 0, n1)));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println("STANDARD ERROR:");
		int n2;
		char[] c2 = new char[1024];
		try {
			while ((n2 = esr.read(c2)) > 0) {
				System.err.print(new String(Arrays.copyOfRange(c2, 0, n2)));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}

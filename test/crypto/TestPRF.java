package crypto;

import java.math.BigInteger;

public class TestPRF {

	public static void main(String[] args) {
		try {
			for (int l = 1; l < 5000; l++) {
				System.out.println("Round: l=" + l);
				PRF f1 = new PRF(l);
				PRF f2 = new PRF(l);
				byte[] k = new byte[16];
				Crypto.sr.nextBytes(k);
				byte[] input = new byte[Crypto.sr.nextInt(12) + 1];
				Crypto.sr.nextBytes(input);
				f1.init(k);
				f2.init(k);
				byte[] output1 = f1.compute(input);
				byte[] output2 = f2.compute(input);
				for (int i = 0; i < output2.length; i++)
					System.out.print(String.format("%02X", output2[i]));
				System.out.println("");
				boolean test1 = new BigInteger(1, output1).compareTo(new BigInteger(1, output2)) == 0;
				boolean test2 = output1.length == (l + 7) / 8;
				if (!test1 || !test2) {
					System.out.println("Fail: l=" + l + "  " + test1 + "  " + test2);
					break;
				}
			}

			System.out.println("done");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

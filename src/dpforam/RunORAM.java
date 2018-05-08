package dpforam;

import java.math.BigInteger;

import communication.Communication;
import crypto.Crypto;
import struct.Global;
import struct.Party;
import util.Bandwidth;
import util.StopWatch;
import util.Util;

public class RunORAM {

	public static void testAccess(int tau, int logN, int DBytes, Party party, Communication[] cons) {
		System.out.println("tau=" + tau + ", logN=" + logN + ", DBytes=" + DBytes);

		StopWatch timer = new StopWatch("Runtime");
		Bandwidth bandwidth = new Bandwidth("Bandwidth");

		DPFORAM dpforam = new DPFORAM(tau, logN, DBytes, true, party, cons, bandwidth);
		dpforam.printMetadata();

		int numTestAddr = 11;
		int eachAddrIter = 100;

		for (int t = 0; t < numTestAddr; t++) {
			if (t == 1)
				timer.reset();

			long addr = Util.nextLong(dpforam.N, Crypto.sr);
			if (party == Party.Eddie) {
				cons[0].write(addr);
				cons[1].write(addr);
			} else if (party == Party.Debbie) {
				addr = cons[1].readLong();
			} else if (party == Party.Charlie) {
				addr = cons[0].readLong();
			} else {
			}

			BigInteger expected = BigInteger.valueOf(addr % DPFORAM.prime);

			for (int i = 0; i < eachAddrIter; i++) {
				if (i == 1)
					Global.bandSwitch = false;

				BigInteger newVal = BigInteger.valueOf(Crypto.sr.nextInt(DPFORAM.prime));
				if (party == Party.Eddie) {
					cons[0].write(newVal);
					cons[1].write(newVal);
				} else if (party == Party.Debbie) {
					newVal = cons[1].readBigInteger();
				} else if (party == Party.Charlie) {
					newVal = cons[0].readBigInteger();
				} else {
				}

				byte[][] newRec = new byte[2][];
				newRec[0] = Util.padArray(newVal.toByteArray(), dpforam.DBytes);
				newRec[1] = newRec[0].clone();

				timer.start();
				byte[][] rec_23 = dpforam.access(new long[] { addr, addr }, newRec, false);
				timer.stop();

				if (party == Party.Eddie) {
					byte[] rec = Util.xor(rec_23[0], rec_23[1]);
					Util.setXor(rec, cons[0].read());
					BigInteger output = new BigInteger(1, rec);
					if (output.compareTo(expected) != 0) {
						System.err.println("ERROR: t=" + t + ", addr=" + addr + ", i=" + i + ", expected="
								+ expected.longValue() + ", output=" + output.longValue());
					} else {
						System.out.println("PASSED: t=" + t + ", addr=" + addr + ", i=" + i + ", expected="
								+ expected.longValue() + ", output=" + output.longValue());
					}

					expected = newVal;

				} else if (party == Party.Debbie) {
					cons[1].write(rec_23[0]);
				} else if (party == Party.Charlie) {
				} else {
				}
			}
		}

		System.out.println("Test access() done.");
		// TODO: not test on same addr twice when access = write
		System.out.println("Note: if some addr is tested twice,");
		System.out.println("then the first read of the second test run will print ERROR,");
		System.out.println("which is correct, becasue we are doing access = write");
		System.out.println();

		cons[0].write(bandwidth);
		cons[0].write(timer);
		cons[1].write(bandwidth);
		cons[1].write(timer);
		Bandwidth bandwidth1 = cons[0].readObject();
		StopWatch timer1 = cons[0].readObject();
		Bandwidth bandwidth2 = cons[1].readObject();
		StopWatch timer2 = cons[1].readObject();

		bandwidth2.add(bandwidth1);
		bandwidth2.add(bandwidth);
		timer2.elapsedCPU += timer1.elapsedCPU + timer.elapsedCPU;
		timer2.elapsedWC = Math.max(Math.max(timer2.elapsedWC, timer1.elapsedWC), timer.elapsedWC);

		int iterations = (numTestAddr - 1) * eachAddrIter;
		System.out.println("tau=" + tau + ", logN=" + logN + ", DBytes=" + DBytes);
		System.out.println("Runtime is total of " + iterations + " accesses.");
		System.out.println("Bandwidth is 1 access.");
		System.out.println("===== this party only =====");
		System.out.println(timer.toMS());
		System.out.println(bandwidth.toString());
		System.out.println("===== all parties =====");
		System.out.println(timer2.toMS());
		System.out.println(bandwidth2.toString());
		System.out.println();
	}

}

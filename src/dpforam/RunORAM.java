package dpforam;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import communication.Communication;
import crypto.Crypto;
import struct.Global;
import struct.Party;
import util.Bandwidth;
import util.StopWatch;
import util.Util;

public class RunORAM {

	// oram access testing
	public static void testAccess(int tau, int logN, int DBytes, int eachAddrIter, Party party, Communication[] cons) {
		StopWatch timer = new StopWatch("Runtime");
		Bandwidth bandwidth = new Bandwidth("Bandwidth");

		DPFORAM dpforam = new DPFORAM(tau, logN, DBytes, true, party, cons, bandwidth);
		dpforam.printMetadata();

		// sync all parties before test
		byte[] zero = new byte[] { 0 };
		cons[0].write(zero);
		cons[1].write(zero);
		cons[0].read();
		cons[1].read();

		int numTestAddr = 11;
		if (numTestAddr > dpforam.N) {
			System.err.println("Doesn't have " + numTestAddr + " different addr to test");
			return;
		}

		// not test same address twice because of testing access = write
		Set<Long> testedAddr = new HashSet<Long>();

		for (int t = 0; t < numTestAddr; t++) {
			// not count timing for the first address because JVM needs to warm up
			if (t == 1)
				timer.reset();

			long addr = 0;
			// generate a random addr to test, and let all parties know; this can be done
			// with (2,3)-sharing, but here it's just for simplicity
			if (party == Party.Eddie) {
				addr = Util.nextLong(dpforam.N, Crypto.sr);
				while (testedAddr.contains(addr))
					addr = Util.nextLong(dpforam.N, Crypto.sr);
				testedAddr.add(addr);
				cons[0].write(addr);
				cons[1].write(addr);
			} else if (party == Party.Debbie) {
				addr = cons[1].readLong();
			} else if (party == Party.Charlie) {
				addr = cons[0].readLong();
			} else {
			}

			// expected payload = address % prime
			BigInteger expected = BigInteger.valueOf(addr % DPFORAM.prime);

			// test this many writes for the same address
			for (int i = 0; i < eachAddrIter; i++) {
				// only measure bandwidth once
				if (i == 1)
					Global.bandSwitch = false;

				// new payload value for write; again for simplicity, can do (2,3)-sharing but
				// not yet
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

				// access = write
				timer.start();
				byte[][] rec_23 = dpforam.access(new long[] { addr, addr }, newRec, false);
				timer.stop();

				// verify correctness
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

					// need to change expected value because of write
					expected = newVal;

				} else if (party == Party.Debbie) {
					cons[1].write(rec_23[0]);
				} else if (party == Party.Charlie) {
				} else {
				}
			}
		}

		System.out.println("Test access() done.");
		System.out.println();

		// generate time and bandwidth output
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
		System.out.println("Number of threads: " + Global.numThreads);
		System.out.println("Runtime is total of " + iterations + " accesses.");
		System.out.println("Bandwidth is 1 access.");
		System.out.println("===== this party only =====");
		System.out.println((Global.numThreads < 2 ? timer.toMS() : timer.WCtoMS()));
		System.out.println(bandwidth.toString());
		System.out.println("===== all parties =====");
		System.out.println((Global.numThreads < 2 ? timer2.toMS() : timer2.WCtoMS()));
		System.out.println(bandwidth2.toString());
		System.out.println();
	}

}

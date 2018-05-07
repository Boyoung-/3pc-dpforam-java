package dpforam;

import java.math.BigInteger;

import communication.Communication;
import crypto.Crypto;
import struct.Party;
import util.Util;

public class RunORAM {

	public static void testAccess(Party party, Communication[] cons) {
		DPFORAM dpforam = new DPFORAM(3, 9, 4, true, party, cons);
		dpforam.printMetadata();

		for (int t = 0; t < 10; t++) {
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
			for (int i = 0; i < 100; i++) {
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
				byte[] rec_13 = dpforam.access(addr, newRec, false);

				if (party == Party.Eddie) {
					Util.setXor(rec_13, cons[0].read());
					Util.setXor(rec_13, cons[1].read());
					BigInteger output = new BigInteger(1, rec_13);
					if (output.compareTo(expected) != 0)
						System.err.println("ERROR: " + t + " " + addr + " " + i);
					else
						System.out.println("Passed: " + t + " " + addr + " " + i);

					expected = newVal;

				} else if (party == Party.Debbie) {
					cons[1].write(rec_13);
				} else if (party == Party.Charlie) {
					cons[0].write(rec_13);
				} else {
				}
			}
		}

		System.out.println("Test access() done.");
	}

	public static void testAccessFirst(Party party, Communication[] cons) {
		DPFORAM dpforam = new DPFORAM(3, 6, 4, true, party, cons);
		dpforam.printMetadata();

		for (int t = 0; t < 10; t++) {
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
			int mask = (1 << dpforam.tau) - 1;
			long addrPre = (addr >>> dpforam.tau);
			int addrSuf = ((int) addr & mask);

			BigInteger expected = BigInteger.ZERO;
			for (int i = 0; i < 100; i++) {
				BigInteger newVal = new BigInteger(dpforam.logN, Crypto.sr);
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
				newRec[0] = Util.padArray(newVal.toByteArray(), dpforam.logNBytes);
				newRec[1] = newRec[0].clone();
				byte[] rec_13 = dpforam.getPosMap().accessFirst(addrPre, addrSuf, newRec)[0];

				if (party == Party.Eddie) {
					Util.setXor(rec_13, cons[0].read());
					Util.setXor(rec_13, cons[1].read());
					BigInteger output = new BigInteger(1, rec_13);
					if (output.compareTo(expected) != 0)
						System.err.println("ERROR: " + t + " " + addr + " " + i);
					else
						System.out.println("Passed: " + t + " " + addr + " " + i);
					expected = newVal;

				} else if (party == Party.Debbie) {
					cons[1].write(rec_13);
				} else if (party == Party.Charlie) {
					cons[0].write(rec_13);
				} else {
				}
			}
		}

		System.out.println("Test accessFirst() done.");
	}

	public static void testAccessFirstAndLast(Party party, Communication[] cons) {
		DPFORAM dpforam = new DPFORAM(3, 3, 4, true, party, cons);
		dpforam.printMetadata();

		for (int t = 0; t < 10; t++) {
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

			long expected = addr % DPFORAM.prime;
			for (int i = 0; i < 100; i++) {
				int newVal = Crypto.sr.nextInt(DPFORAM.prime);
				if (party == Party.Eddie) {
					cons[0].write(newVal);
					cons[1].write(newVal);
				} else if (party == Party.Debbie) {
					newVal = cons[1].readInt();
				} else if (party == Party.Charlie) {
					newVal = cons[0].readInt();
				} else {
				}

				byte[][] newRec = new byte[2][];
				newRec[0] = Util.padArray(BigInteger.valueOf(newVal).toByteArray(), dpforam.DBytes);
				newRec[1] = newRec[0].clone();
				byte[] rec_13 = dpforam.accessFirstAndLast(addr, newRec, false)[0];

				if (party == Party.Eddie) {
					Util.setXor(rec_13, cons[0].read());
					Util.setXor(rec_13, cons[1].read());
					long output = new BigInteger(1, rec_13).longValue();
					if (output != expected)
						System.err.println("ERROR: " + t + " " + addr + " " + i);
					else
						System.out.println("Passed: " + t + " " + addr + " " + i);
					expected = newVal;

				} else if (party == Party.Debbie) {
					cons[1].write(rec_13);
				} else if (party == Party.Charlie) {
					cons[0].write(rec_13);
				} else {
				}
			}
		}

		System.out.println("Test accessFirstAndLast() done.");
		System.out.println(
				"Note: if some addr is tested twice, the first read of the second test run will be error, which is correct");
	}
}

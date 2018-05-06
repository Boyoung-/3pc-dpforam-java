package dpforam;

import java.math.BigInteger;

import communication.Communication;
import crypto.Crypto;
import struct.Party;
import util.Util;

public class RunORAM {

	public static void run(int tau, int logN, int DBytes, Party party, Communication[] cons) {
		DPFORAM dpforam = new DPFORAM(tau, logN, DBytes, true, party, cons);
		// dpforam.printMetadata();

		for (int t = 0; t < 10; t++) {////
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
			for (int i = 0; i < 1000; i++) {/////
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

				////
				byte[] rec_13 = dpforam.accessFirstAndLast(addr,
						Util.padArray(BigInteger.valueOf(newVal).toByteArray(), dpforam.DBytes), false);

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
	}
}

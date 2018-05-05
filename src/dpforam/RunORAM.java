package dpforam;

import communication.Communication;
import struct.Party;

public class RunORAM {
	
	public static void run(int tau, int logN, int DBytes, Party party, Communication[] cons) {
		DPFORAM dpforam = new DPFORAM(tau, logN, DBytes, true, party, cons);
		dpforam.printMetadata();
	}
}

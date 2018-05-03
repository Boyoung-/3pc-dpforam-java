package protocols;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Global;
import oram.Metadata;
import struct.Party;
import struct.TimeAndBandwidth;
import util.Bandwidth;
import util.Timer;

public abstract class Protocol {
	protected Communication con1;
	protected Communication con2;
	public Timer timer;
	public Bandwidth online_band;
	public Bandwidth offline_band;

	public static TimeAndBandwidth all;

	static {
		all = new TimeAndBandwidth();
	}

	public synchronized void addTime(Timer from, Timer to) {
		to.add(from);
	}

	public synchronized void addBand(Bandwidth from, Bandwidth to) {
		to.add(from);
	}

	/*
	 * Connections are alphabetized so:
	 * 
	 * For Eddie con1 = debbie con2 = charlie
	 * 
	 * For Debbie con1 = eddie con2 = charlie
	 * 
	 * For Charlie con1 = eddie con2 = debbie
	 */
	public Protocol(Communication con1, Communication con2) {
		this.con1 = con1;
		this.con2 = con2;
		// timer = new Timer();
		// online_band = new Bandwidth();
		// offline_band = new Bandwidth();
	}

	private static final boolean ENSURE_SANITY = true;

	public boolean ifSanityCheck() {
		return ENSURE_SANITY;
	}

	// Utility function will test for synchrony between the parties.
	public void sanityCheck() {
		if (ENSURE_SANITY) {

			// System.out.println("Sanity check");
			con1.write("sanity");
			con2.write("sanity");

			if (!con1.readString().equals("sanity")) {
				System.out.println("Sanity check failed for con1");
			}
			if (!con2.readString().equals("sanity")) {
				System.out.println("Sanity check failed for con2");
			}
		}
	}

	public void run(Party party, Metadata md, String forestFile) {
		Forest forest = null;
		if (party == Party.Eddie) {
			if (Global.cheat)
				forest = new Forest(md, Crypto.sr);
			else if (forestFile == null)
				forest = Forest.readFromFile(md.getDefaultSharesName1());
			else
				forest = Forest.readFromFile(forestFile);

		} else if (party == Party.Debbie) {
			if (Global.cheat)
				forest = new Forest(md, null);
			else if (forestFile == null)
				forest = Forest.readFromFile(md.getDefaultSharesName2());
			else
				forest = Forest.readFromFile(forestFile);
		} else if (party == Party.Charlie) {
			if (Global.cheat)
				forest = new Forest(md, null);

		} else {
			throw new NoSuchPartyException(party.toString());
		}

		run(party, md, forest);
	}

	// a simulation using a path instead of building whole tree
	public void run(Party party, Metadata md) {
		// System.err.println("Check");
		assert Global.cheat;
		Forest[] forests = new Forest[2];
		// Eddie has x1, x2
		// Debbie has x1, x3
		// Charlie has x2, x3
		// only x1 should have content
		if (party == Party.Eddie) {
			forests[0] = new Forest(md, Crypto.sr);
			forests[1] = new Forest(md, null);

		} else if (party == Party.Debbie) {
			forests[0] = new Forest(md, Crypto.sr);
			forests[1] = new Forest(md, null);

		} else if (party == Party.Charlie) {
			forests[0] = new Forest(md, null);
			forests[1] = new Forest(md, null);

		} else {
			throw new NoSuchPartyException(party.toString());
		}

		run(party, md, forests);
	}

	/*
	 * This is mostly just testing code and may need to change for the purpose of an
	 * actual execution
	 */
	public abstract void run(Party party, Metadata md, Forest forest);

	public abstract void run(Party party, Metadata md, Forest[] forests);
}

package ui;

import java.net.InetSocketAddress;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import communication.Communication;
import dpforam.RunORAM;
import exceptions.NoSuchPartyException;
import struct.Party;

public class CLI {
	public static final int DEFAULT_PORT = 8000;
	public static final String DEFAULT_IP = "localhost";

	public static void main(String[] args) {
		// Setup command line argument parser
		Options options = new Options();
		options.addOption("eddie_ip", true, "IP to look for eddie");
		options.addOption("debbie_ip", true, "IP to look for debbie");

		// Parse the command line arguments
		CommandLineParser cmdParser = new GnuParser();
		CommandLine cmd = null;
		try {
			cmd = cmdParser.parse(options, args);
		} catch (ParseException e1) {
			e1.printStackTrace();
		}

		String party = null;
		String[] positionalArgs = cmd.getArgs();
		if (positionalArgs.length > 0) {
			party = positionalArgs[0];
		} else {
			try {
				throw new ParseException("No party specified");
			} catch (ParseException e) {
				e.printStackTrace();
				System.exit(-1);
			}
		}

		int extra_port = 1;
		int eddiePort1 = DEFAULT_PORT;
		int eddiePort2 = eddiePort1 + extra_port;
		int debbiePort = eddiePort2 + extra_port;

		String eddieIp = cmd.getOptionValue("eddie_ip", DEFAULT_IP);
		String debbieIp = cmd.getOptionValue("debbie_ip", DEFAULT_IP);

		int tau = 3;
		int logN = 12;
		int DBytes = 4;

		// For now all logic happens here. Eventually this will get wrapped
		// up in party specific classes.
		System.out.println("Starting " + party + "...");

		Communication con1 = new Communication();
		Communication con2 = new Communication();
		Party partyEnum;

		if (party.equals("eddie")) {
			partyEnum = Party.Eddie;

			System.out.print("Waiting to establish debbie connections...");
			con1.start(eddiePort1);
			while (con1.getState() != Communication.STATE_CONNECTED)
				;
			System.out.println(" done!");

			System.out.print("Waiting to establish charlie connections...");
			con2.start(eddiePort2);
			while (con2.getState() != Communication.STATE_CONNECTED)
				;
			System.out.println(" done!");

		} else if (party.equals("debbie")) {
			partyEnum = Party.Debbie;

			System.out.print("Waiting to establish eddie connections...");
			InetSocketAddress addr = new InetSocketAddress(eddieIp, eddiePort1);
			con2.connect(addr);
			while (con2.getState() != Communication.STATE_CONNECTED)
				;

			System.out.println(" done!");

			System.out.print("Waiting to establish charlie connections...");
			con1.start(debbiePort);
			while (con1.getState() != Communication.STATE_CONNECTED)
				;

			System.out.println(" done!");

		} else if (party.equals("charlie")) {
			partyEnum = Party.Charlie;

			System.out.print("Waiting to establish eddie connections...");
			InetSocketAddress addr = new InetSocketAddress(eddieIp, eddiePort2);
			con1.connect(addr);
			while (con1.getState() != Communication.STATE_CONNECTED)
				;

			System.out.println(" done!");

			System.out.print("Waiting to establish debbie connections...");
			addr = new InetSocketAddress(debbieIp, debbiePort);
			con2.connect(addr);
			while (con2.getState() != Communication.STATE_CONNECTED)
				;

			System.out.println(" done!");

		} else {
			throw new NoSuchPartyException(party);
		}

		con1.setTcpNoDelay(true);
		con2.setTcpNoDelay(true);

		RunORAM.testAccess(tau, logN, DBytes, partyEnum, new Communication[] { con1, con2 });

		//////////////////////////////////////////////////////////////

		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		con1.stop();
		con2.stop();

		System.out.println(party + " exiting...");
	}
}

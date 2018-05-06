package dpforam;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import struct.Party;
import subprotocols.InsLbl;
import util.Array64;
import util.Util;

// TODO: measure bandwidth

public class DPFORAM {

	public static final int prime = 251;
	
	public static final FSS fss = new FSS(Crypto.prgSeedBytes);

	public final int logN;
	public final int logNBytes;
	public final int nextLogN;
	public final int nextLogNBytes;
	public final int tau;
	public final int ttp;
	public final int DBytes;
	public final long N;
	public final boolean isFirst;
	public final boolean isLast;
	public final Party party;
	public final Communication[] cons;

	private Array64<byte[]>[] ROM;
	private Array64<byte[]> WOM;
	private Array64<byte[]>[] stash;
	private DPFORAM posMap;
	private long stashCtr;

	@SuppressWarnings("unchecked")
	public DPFORAM(int tau, int logN, int DBytes, boolean isLast, Party party, Communication[] cons) {
		this.tau = tau;
		this.logN = logN;
		this.isLast = isLast;
		this.party = party;
		this.cons = cons;

		ttp = (int) Math.pow(2, tau);
		logNBytes = (logN + 7) / 8;
		nextLogN = isLast ? 0 : logN + tau;
		nextLogNBytes = (nextLogN + 7) / 8;
		this.DBytes = isLast ? DBytes : nextLogNBytes * ttp;
		N = (long) Math.pow(2, logN);
		isFirst = logN - tau < tau;

		ROM = (Array64<byte[]>[]) new Array64[] {new Array64<byte[]>(N), new Array64<byte[]>(N)};
		WOM = isFirst ? null : new Array64<byte[]>(N);
		stash = isFirst ? null : ((Array64<byte[]>[]) new Array64[] {new Array64<byte[]>(N), new Array64<byte[]>(N)});

		posMap = isFirst ? null : new DPFORAM(tau, logN - tau, 0, false, party, cons);

		if (isLast)
			init();
	}

	private void init() {
		initCtr();

		if (isLast) {
			initROM();
			initWOM();
		} else {
			initEmpty(ROM[0]);
			initEmpty(ROM[1]);
			initEmpty(WOM);
		}
		if (stash != null) {
			initEmpty(stash[0]);
			initEmpty(stash[1]);
		}

		if (!isFirst)
			posMap.init();
	}
	
	private void initROM() {
		if (ROM == null)
			return;

		if (party == Party.Eddie) {
			for (long i = 0; i < N; i++) {
				ROM[0].set(i, Util.padArray(BigInteger.valueOf(i % prime).toByteArray(), DBytes));
			}
			initEmpty(ROM[1]);
		}
		else if (party == Party.Debbie) {
			initEmpty(ROM[0]);
			for (long i = 0; i < N; i++) {
				ROM[1].set(i, Util.padArray(BigInteger.valueOf(i % prime).toByteArray(), DBytes));
			}
		}
		else if (party == Party.Charlie) {
			initEmpty(ROM[0]);
			initEmpty(ROM[1]);
		}
		else {
		}
	}

	private void initWOM() {
		if (WOM == null)
			return;

		for (long i = 0; i < WOM.size(); i++) {
			WOM.set(i, Util.padArray(BigInteger.valueOf(i % prime).toByteArray(), DBytes));
		}
	}

	private void initEmpty(Array64<byte[]> mem) {
		if (mem == null)
			return;

		for (long i = 0; i < mem.size(); i++) {
			mem.set(i, new byte[DBytes]);
		}
	}

	private void initCtr() {
		stashCtr = 1;
	}

//	private void WOMtoROM() {
//		if (isFirst)
//			return;
//
//		for (long i = 0; i < N; i++) {
//			ROM.set(i, WOM.get(i).clone());
//		}
//	}

//	public byte[] access(long addr, byte[] newRec, boolean isRead) {
//		assert (newRec.length == (isLast ? DBytes : nextLogNBytes));
//
//		if (isFirst && isLast)
//			return accessFirstAndLast(addr, newRec, isRead);
//
//		int mask = (1 << tau) - 1;
//		long addrPre = isLast ? addr : (addr >>> tau);
//		int addrSuf = isLast ? 0 : ((int) addr & mask);
//		if (isFirst) {
//			return accessFirst(addrPre, addrSuf, newRec);
//		}
//
//		byte[] newPos = Util.padArray(BigInteger.valueOf(stashCtr).toByteArray(), logNBytes);
//		byte[] pos = posMap.access(addrPre, newPos, false);
//		long stashAddrPre = new BigInteger(1, pos).longValue();
//		byte[] block = (stashAddrPre == 0) ? ROM.get(addrPre).clone() : stash.get(stashAddrPre).clone();
//		byte[] rec = Arrays.copyOfRange(block, addrSuf * newRec.length, (addrSuf + 1) * newRec.length);
//		newRec = isRead ? rec : newRec;
//		System.arraycopy(newRec, 0, block, addrSuf * newRec.length, newRec.length);
//
//		WOM.set(addrPre, block);
//		stash.set(stashCtr, block.clone());
//		stashCtr++;
//
//		if (stashCtr == N) {
//			WOMtoROM();
//			initEmpty(stash);
//			initCtr();
//			posMap.init();
//		}
//
//		return rec;
//	}
//
//	private byte[] accessFirst(long addrPre, int addrSuf, byte[] newRec) {
//		byte[] rec = Arrays.copyOfRange(ROM.get(addrPre), addrSuf * nextLogNBytes, (addrSuf + 1) * nextLogNBytes);
//		System.arraycopy(newRec, 0, ROM.get(addrPre), addrSuf * nextLogNBytes, nextLogNBytes);
//		return rec;
//	}
//
	
	// TODO: change below to private
	public byte[] accessFirstAndLast(long addr, byte[] newRec_13, boolean isRead) {
//		byte[] rec = ROM.get(addr).clone();
		FSSKey[] keys = fss.Gen(addr, logN, new byte[DBytes]);
		cons[0].write(keys[0]);
		cons[1].write(keys[1]);
		keys[1] = (FSSKey) cons[0].readObject();
		keys[0] = (FSSKey) cons[1].readObject();
		byte[] rec_13 = new byte[DBytes];
		@SuppressWarnings("unchecked")
		Array64<byte[][]>[] fssOut = (Array64<byte[][]>[]) new Array64[] {new Array64<byte[][]>(N), new Array64<byte[][]>(N)};
		for (int i=0; i<2; i++) {
			for (long j=0; j<N; j++) {
				fssOut[i].set(j, fss.Eval(keys[i], j, logN));
				if (fssOut[i].get(j)[1][0] == 1) {
					Util.setXor(rec_13, ROM[i].get(j));
				}
			}
		}
		
//		newRec = isRead ? rec : newRec;
		byte[] delta_13 = isRead ? new byte[DBytes] : Util.xor(rec_13, newRec_13);
		
//		ROM.set(addr, newRec.clone());
		InsLbl inslbl = null;
		byte[][] rom = new byte[2][];
		int romBytes = (int) N * DBytes;
		if (party == Party.Eddie) {
			Util.setXor(delta_13, cons[1].read());
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_DE, Crypto.sr_CE);
			inslbl.runP1((int) addr, delta_13, (int) N);
			
			rom[0] = Util.nextBytes(romBytes, Crypto.sr_DE);
			rom[1] = Util.nextBytes(romBytes, Crypto.sr_CE);
		} else if (party == Party.Debbie) {
			inslbl = new InsLbl(cons[1], cons[0], Crypto.sr_DE, Crypto.sr_CD);
			byte[] rom_12 = inslbl.runP2(0, delta_13, (int) N);
			
			rom[1] = Util.nextBytes(romBytes, Crypto.sr_DE);
			rom[0] = Util.xor(rom_12, rom[1]);
			cons[0].write(rom[0]);
			Util.setXor(rom[0], cons[0].read());
		} else if (party == Party.Charlie) {
			cons[0].write(delta_13);
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_CE, Crypto.sr_CD);
			byte[] rom_12 = inslbl.runP3((int) N, DBytes);
			
			rom[0] = Util.nextBytes(romBytes, Crypto.sr_CE);
			rom[1] = Util.xor(rom_12, rom[0]);
			cons[1].write(rom[1]);
			Util.setXor(rom[1], cons[1].read());
		} else {
		}
		
		for (int i=0; i<2; i++) {
			for (long j=0; j<N; j++) {
				Util.setXor(ROM[i].get(j), Arrays.copyOfRange(rom[i], (int) j * DBytes, (int) (j+1) * DBytes));
			}
		}
		
//		return rec;
		return rec_13;
	}

	public void printMetadata() {
		System.out.println("===================");
		System.out.println("Party: " + party);
		System.out.println("tau: " + tau);
		System.out.println("2^tau: " + ttp);
		System.out.println("Last level: " + isLast);
		System.out.println("First level: " + isFirst);
		System.out.println("N: " + N);
		System.out.println("logN: " + logN);
		System.out.println("logNBytes: " + logNBytes);
		System.out.println("nextLogN: " + nextLogN);
		System.out.println("nextLogNBytes: " + nextLogNBytes);
		System.out.println("DBytes: " + DBytes);
		System.out.println("Stash counter: " + stashCtr);
		System.out.println("ROM null: " + (ROM == null));
		System.out.println("WOM null: " + (WOM == null));
		System.out.println("stash null: " + (stash == null));
		System.out.println("posMap null: " + (posMap == null));
		System.out.println("cons null: " + (cons == null));
		System.out.println("===================\n");

		if (!isFirst)
			posMap.printMetadata();
	}

//	public static void main(String[] args) {
//		DPFORAM dpforam = new DPFORAM(3, 12, 4, true, Party.Eddie, null);
//		dpforam.printMetadata();
//
//		Set<Long> tested = new HashSet<Long>();
//		for (int t = 0; t < 100; t++) {
//			long addr = Util.nextLong(dpforam.N, Crypto.sr);
//			while (tested.contains(addr))
//				addr = Util.nextLong(dpforam.N, Crypto.sr);
//			tested.add(addr);
//
//			long expected = addr % prime;
//			for (int i = 0; i < 1000; i++) {
//				int newVal = Crypto.sr.nextInt(prime);
//				byte[] rec = dpforam.access(addr,
//						Util.padArray(BigInteger.valueOf(newVal).toByteArray(), dpforam.DBytes), false);
//				long output = new BigInteger(1, rec).longValue();
//				if (output != expected)
//					System.err.println("ERROR: " + t + " " + addr + " " + i);
//				expected = newVal;
//			}
//		}
//	}

}

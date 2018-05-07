package dpforam;

import java.math.BigInteger;

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

	private final Communication[] cons;
	private final Array64<byte[]>[] ROM;
	private final Array64<byte[]> WOM;
	private final Array64<byte[]>[] stash;
	private final DPFORAM posMap;

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

		ROM = (Array64<byte[]>[]) new Array64[] { new Array64<byte[]>(N), new Array64<byte[]>(N) };
		WOM = isFirst ? null : new Array64<byte[]>(N);
		stash = isFirst ? null : ((Array64<byte[]>[]) new Array64[] { new Array64<byte[]>(N), new Array64<byte[]>(N) });

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
		} else if (party == Party.Debbie) {
			initEmpty(ROM[0]);
			for (long i = 0; i < N; i++) {
				ROM[1].set(i, Util.padArray(BigInteger.valueOf(i % prime).toByteArray(), DBytes));
			}
		} else if (party == Party.Charlie) {
			initEmpty(ROM[0]);
			initEmpty(ROM[1]);
		} else {
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

	private void WOMtoROM() {
		if (isFirst)
			return;

		for (long i = 0; i < N; i++) {
			ROM[0].set(i, WOM.get(i).clone());
		}
		cons[0].write(WOM);
		ROM[1] = cons[1].readArray64ByteArray();
	}

	// TODO: secret-shared isRead??
	public byte[][] access(long addr, byte[][] newRec_23, boolean isRead) {
		assert (newRec_23[0].length == (isLast ? DBytes : nextLogNBytes));

		if (isFirst && isLast)
			return accessFirstAndLast(addr, newRec_23, isRead);

		int mask = (1 << tau) - 1;
		long addrPre = isLast ? addr : (addr >>> tau);
		int addrSuf = isLast ? 0 : ((int) addr & mask);
		if (isFirst) {
			return accessFirst(addrPre, addrSuf, newRec_23);
		}

		byte[] newStashPtr = Util.padArray(BigInteger.valueOf(stashCtr).toByteArray(), logNBytes);
		byte[][] stashPtr_23 = posMap.access(addrPre, new byte[][] { newStashPtr, newStashPtr }, false);

		// TODO: access on addr sharing
		cons[0].write(stashPtr_23[1]);
		byte[] stashPtr = cons[1].read();
		Util.setXor(stashPtr, stashPtr_23[0]);
		Util.setXor(stashPtr, stashPtr_23[1]);

		long stashAddrPre = new BigInteger(1, stashPtr).longValue();
		PIROut romPirOut = blockPIR(addrPre, ROM);
		PIROut stashPirOut = blockPIR(stashAddrPre, stash);
		// TODO: 3pc selection
		byte[][] block_23 = (stashAddrPre == 0) ? romPirOut.rec_23 : stashPirOut.rec_23;

		if (isLast) {
			byte[][] deltaBlock_23 = isRead ? new byte[][] { new byte[DBytes], new byte[DBytes] }
					: new byte[][] { Util.xor(block_23[0], newRec_23[0]), Util.xor(block_23[1], newRec_23[1]) };

			updateStashAndWOM(block_23, deltaBlock_23, romPirOut.t);

			return block_23;
		}

		// TODO: pir on shared idx
		byte[][] ptr_23 = ptrPIR(addrSuf, block_23);
		byte[][] ptrDelta_23 = isRead ? new byte[][] { new byte[nextLogNBytes], new byte[nextLogNBytes] }
				: new byte[][] { Util.xor(ptr_23[0], newRec_23[0]), Util.xor(ptr_23[1], newRec_23[1]) };
		byte[][] deltaBlock_23 = genBlockOrArrayDelta(addrSuf, ttp, nextLogNBytes, ptrDelta_23);

		updateStashAndWOM(block_23, deltaBlock_23, romPirOut.t);

		return ptr_23;
	}

	private void updateStashAndWOM(byte[][] block_23, byte[][] deltaBlock_23, Array64<byte[]> fssout) {
		byte[][] newBlock_23 = new byte[2][];
		newBlock_23[0] = Util.xor(block_23[0], deltaBlock_23[0]);
		newBlock_23[1] = Util.xor(block_23[1], deltaBlock_23[1]);

		for (int i = 0; i < 2; i++) {
			for (long j = 0; j < N; j++) {
				if (fssout.get(j)[i] == 1) {
					Util.setXor(WOM.get(j), deltaBlock_23[i]);
				}
			}
		}

		stash[0].set(stashCtr, newBlock_23[0]);
		stash[1].set(stashCtr, newBlock_23[1]);
		stashCtr++;

		if (stashCtr == N) {
			WOMtoROM();
			initEmpty(stash[0]);
			initEmpty(stash[1]);
			initCtr();
			posMap.init();
		}
	}

	// TODO: clean InsLbl, change below to private
	public byte[][] accessFirst(long addrPre, int addrSuf, byte[][] newPtr_23) {
		PIROut blockPirOut = blockPIR(addrPre, ROM);
		byte[][] block_23 = blockPirOut.rec_23;

		byte[][] ptr_23 = ptrPIR(addrSuf, block_23);
		byte[][] deltaPtr_23 = new byte[][] { Util.xor(ptr_23[0], newPtr_23[0]), Util.xor(ptr_23[1], newPtr_23[1]) };
		byte[][] deltaBlock_23 = genBlockOrArrayDelta(addrSuf, ttp, nextLogNBytes, deltaPtr_23);
		byte[][] rom = genBlockOrArrayDelta((int) addrPre, (int) N, DBytes, deltaBlock_23);

		for (int i = 0; i < 2; i++) {
			for (long j = 0; j < N; j++) {
				Util.setXor(ROM[i].get(j), Arrays.copyOfRange(rom[i], (int) j * DBytes, (int) (j + 1) * DBytes));
			}
		}

		return ptr_23;
	}

	// TODO: change below to private
	public byte[][] accessFirstAndLast(long addr, byte[][] newRec_23, boolean isRead) {
		PIROut pirout = blockPIR(addr, ROM);
		byte[][] rec_23 = pirout.rec_23;

		byte[][] delta_23 = isRead ? new byte[][] { new byte[DBytes], new byte[DBytes] }
				: new byte[][] { Util.xor(rec_23[0], newRec_23[0]), Util.xor(rec_23[1], newRec_23[1]) };

		byte[][] rom = genBlockOrArrayDelta((int) addr, (int) N, DBytes, delta_23);
		for (int i = 0; i < 2; i++) {
			for (long j = 0; j < N; j++) {
				Util.setXor(ROM[i].get(j), Arrays.copyOfRange(rom[i], (int) j * DBytes, (int) (j + 1) * DBytes));
			}
		}

		return rec_23;
	}

	class PIROut {
		Array64<byte[]> t;
		public byte[][] rec_23;

		public PIROut(Array64<byte[]> t, byte[][] rec_23) {
			this.t = t;
			this.rec_23 = rec_23;
		}
	}

	private PIROut blockPIR(long addr, Array64<byte[]>[] mem) {
		FSSKey[] keys = fss.Gen(addr, logN, new byte[1]);
		cons[0].write(keys[0]);
		cons[1].write(keys[1]);
		keys[1] = (FSSKey) cons[0].readObject();
		keys[0] = (FSSKey) cons[1].readObject();

		byte[] rec_13 = new byte[DBytes];
		Array64<byte[]> t = new Array64<byte[]>(N);
		for (long j = 0; j < N; j++) {
			t.set(j, new byte[2]);
			for (int i = 0; i < 2; i++) {
				t.get(j)[i] = fss.Eval(keys[i], j, logN)[1][0];
				if (t.get(j)[i] == 1) {
					Util.setXor(rec_13, mem[i].get(j));
				}
			}
		}

		byte[][] rec_23 = new byte[2][];
		rec_23[0] = rec_13;
		cons[0].write(rec_23[0]);
		rec_23[1] = cons[1].read();

		return new PIROut(t, rec_23);
	}

	private byte[][] ptrPIR(int idx, byte[][] block_23) {
		FSSKey[] keys = fss.Gen(idx, tau, new byte[1]);
		cons[0].write(keys[0]);
		cons[1].write(keys[1]);
		keys[1] = (FSSKey) cons[0].readObject();
		keys[0] = (FSSKey) cons[1].readObject();

		byte[] rec_13 = new byte[nextLogNBytes];
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < ttp; j++) {
				byte[][] fssout = fss.Eval(keys[i], j, tau);
				if (fssout[1][0] == 1) {
					Util.setXor(rec_13, Arrays.copyOfRange(block_23[i], j * nextLogNBytes, (j + 1) * nextLogNBytes));
				}
			}
		}

		byte[][] rec_23 = new byte[2][];
		rec_23[0] = rec_13;
		cons[0].write(rec_23[0]);
		rec_23[1] = cons[1].read();

		return rec_23;
	}

	private byte[][] genBlockOrArrayDelta(int idx, int numChunk, int chunkBytes, byte[][] delta_23) {
		InsLbl inslbl = null;
		byte[][] mem = new byte[2][];
		int memBytes = numChunk * chunkBytes;

		if (party == Party.Eddie) {
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_DE, Crypto.sr_CE);
			inslbl.runP1(idx, Util.xor(delta_23[0], delta_23[1]), numChunk);

			mem[0] = Util.nextBytes(memBytes, Crypto.sr_DE);
			mem[1] = Util.nextBytes(memBytes, Crypto.sr_CE);

		} else if (party == Party.Debbie) {
			inslbl = new InsLbl(cons[1], cons[0], Crypto.sr_DE, Crypto.sr_CD);
			byte[] mem_12 = inslbl.runP2(0, delta_23[0], numChunk);

			mem[1] = Util.nextBytes(memBytes, Crypto.sr_DE);
			mem[0] = Util.xor(mem_12, mem[1]);
			cons[0].write(mem[0]);
			Util.setXor(mem[0], cons[0].read());

		} else if (party == Party.Charlie) {
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_CE, Crypto.sr_CD);
			byte[] mem_12 = inslbl.runP3(numChunk, chunkBytes);

			mem[0] = Util.nextBytes(memBytes, Crypto.sr_CE);
			mem[1] = Util.xor(mem_12, mem[0]);
			cons[1].write(mem[1]);
			Util.setXor(mem[1], cons[1].read());

		} else {
		}

		return mem;
	}

	public DPFORAM getPosMap() {
		return posMap;
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

}

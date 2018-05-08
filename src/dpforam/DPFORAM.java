package dpforam;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import fss.FSS1Bit;
import fss.FSSKey;
import struct.Party;
import subprotocols.InsLbl;
import subprotocols.SSOT;
import util.Array64;
import util.Bandwidth;
import util.Util;

// TODO: link encryption, add comments

public class DPFORAM {

	public static final int prime = 251;

	public static final FSS1Bit fss = new FSS1Bit(Crypto.prgSeedBytes);

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
	public final Bandwidth bandwidth;

	private final Communication[] cons;
	private final Array64<byte[]>[] ROM;
	private final Array64<byte[]> WOM;
	private final Array64<byte[]>[] stash;
	private final DPFORAM posMap;

	private long stashCtr;

	@SuppressWarnings("unchecked")
	public DPFORAM(int tau, int logN, int DBytes, boolean isLast, Party party, Communication[] cons,
			Bandwidth bandwidth) {
		this.tau = tau;
		this.logN = logN;
		this.isLast = isLast;
		this.party = party;
		this.cons = cons;
		this.bandwidth = bandwidth;

		ttp = (int) Math.pow(2, tau);
		logNBytes = (logN + 7) / 8 + 1;
		nextLogN = isLast ? 0 : logN + tau;
		nextLogNBytes = (nextLogN + 7) / 8 + 1;
		this.DBytes = isLast ? DBytes : nextLogNBytes * ttp;
		N = (long) Math.pow(2, logN);
		isFirst = logN - tau < tau;

		ROM = (Array64<byte[]>[]) new Array64[] { new Array64<byte[]>(N), new Array64<byte[]>(N) };
		WOM = isFirst ? null : new Array64<byte[]>(N);
		stash = isFirst ? null : ((Array64<byte[]>[]) new Array64[] { new Array64<byte[]>(N), new Array64<byte[]>(N) });

		posMap = isFirst ? null : new DPFORAM(tau, logN - tau, 0, false, party, cons, bandwidth);

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
		cons[0].write(bandwidth, WOM);
		ROM[1] = cons[1].readArray64ByteArray();
	}

	public byte[][] access(long[] addr_23, byte[][] newRec_23, boolean isRead) {
		assert (newRec_23[0].length == (isLast ? DBytes : nextLogNBytes));

		if (isFirst && isLast)
			return accessFirstAndLast(addr_23, newRec_23, isRead);

		int mask = (1 << tau) - 1;
		long[] addrPre_23 = new long[2];
		int[] addrSuf_23 = new int[2];
		for (int i = 0; i < 2; i++) {
			addrPre_23[i] = isLast ? addr_23[i] : (addr_23[i] >>> tau);
			addrSuf_23[i] = isLast ? 0 : ((int) addr_23[i] & mask);
		}

		if (isFirst) {
			return accessFirst(addrPre_23, addrSuf_23, newRec_23);
		}

		byte[] newStashPtr = Util.padArray(BigInteger.valueOf(stashCtr).toByteArray(), logNBytes);
		newStashPtr[0] = 1;
		byte[][] stashPtr_23 = posMap.access(addrPre_23, new byte[][] { newStashPtr, newStashPtr }, false);
		long[] stashAddrPre_23 = new long[2];
		stashAddrPre_23[0] = new BigInteger(1, stashPtr_23[0]).longValue();
		stashAddrPre_23[1] = new BigInteger(1, stashPtr_23[1]).longValue();

		PIROut romPirOut = blockPIR(addrPre_23, ROM);
		PIROut stashPirOut = blockPIR(stashAddrPre_23, stash);
		byte[] indicator_23 = new byte[] { stashPtr_23[0][0], stashPtr_23[1][0] };
		byte[][] block_23 = oblivSelect(indicator_23, romPirOut.rec_23, stashPirOut.rec_23);

		if (isLast) {
			byte[][] deltaBlock_23 = isRead ? new byte[][] { new byte[DBytes], new byte[DBytes] }
					: new byte[][] { Util.xor(block_23[0], newRec_23[0]), Util.xor(block_23[1], newRec_23[1]) };

			updateStashAndWOM(block_23, deltaBlock_23, romPirOut.t);

			return block_23;
		}

		byte[][] ptr_23 = ptrPIR(addrSuf_23, block_23);
		byte[][] ptrDelta_23 = isRead ? new byte[][] { new byte[nextLogNBytes], new byte[nextLogNBytes] }
				: new byte[][] { Util.xor(ptr_23[0], newRec_23[0]), Util.xor(ptr_23[1], newRec_23[1]) };
		byte[][] deltaBlock_23 = genBlockOrArrayDelta(addrSuf_23, ttp, nextLogNBytes, ptrDelta_23);

		updateStashAndWOM(block_23, deltaBlock_23, romPirOut.t);

		return ptr_23;
	}

	private byte[][] oblivSelect(byte[] indicator_23, byte[][] romBlock_23, byte[][] stashBlock_23) {
		SSOT ssot = null;
		byte[][] block_23 = new byte[2][];

		if (party == Party.Eddie) {
			int b1 = (indicator_23[0] ^ indicator_23[1]) & 1;
			byte[][] v01 = new byte[2][];
			v01[0] = Util.xor(romBlock_23[0], romBlock_23[1]);
			v01[1] = Util.xor(stashBlock_23[0], stashBlock_23[1]);

			ssot = new SSOT(cons[0], cons[1]);
			byte[] block_12 = ssot.runE(b1, v01);

			block_23[0] = Util.nextBytes(DBytes, Crypto.sr_DE);
			block_23[1] = Util.xor(block_12, block_23[0]);
			cons[1].write(bandwidth, block_23[1]);
			Util.setXor(block_23[1], cons[1].read());

		} else if (party == Party.Debbie) {
			ssot = new SSOT(cons[1], cons[0]);
			ssot.runD(DBytes);

			block_23[0] = Util.nextBytes(DBytes, Crypto.sr_CD);
			block_23[1] = Util.nextBytes(DBytes, Crypto.sr_DE);

		} else if (party == Party.Charlie) {
			int b0 = indicator_23[1] & 1;
			byte[][] u01 = new byte[2][];
			u01[0] = romBlock_23[1];
			u01[1] = stashBlock_23[1];

			ssot = new SSOT(cons[0], cons[1]);
			byte[] block_12 = ssot.runC(b0, u01);

			block_23[1] = Util.nextBytes(DBytes, Crypto.sr_CD);
			block_23[0] = Util.xor(block_12, block_23[1]);
			cons[0].write(bandwidth, block_23[0]);
			Util.setXor(block_23[0], cons[0].read());

		} else {
		}

		return block_23;
	}

	private void updateStashAndWOM(byte[][] block_23, byte[][] deltaBlock_23, Array64<Byte>[] fssout) {
		byte[][] newBlock_23 = new byte[2][];
		newBlock_23[0] = Util.xor(block_23[0], deltaBlock_23[0]);
		newBlock_23[1] = Util.xor(block_23[1], deltaBlock_23[1]);

		for (int i = 0; i < 2; i++) {
			for (long j = 0; j < N; j++) {
				if (fssout[i].get(j).byteValue() == 1) {
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

	private byte[][] accessFirst(long[] addrPre_23, int[] addrSuf_23, byte[][] newPtr_23) {
		PIROut blockPirOut = blockPIR(addrPre_23, ROM);
		byte[][] block_23 = blockPirOut.rec_23;

		byte[][] ptr_23 = ptrPIR(addrSuf_23, block_23);
		byte[][] deltaPtr_23 = new byte[][] { Util.xor(ptr_23[0], newPtr_23[0]), Util.xor(ptr_23[1], newPtr_23[1]) };
		byte[][] deltaBlock_23 = genBlockOrArrayDelta(addrSuf_23, ttp, nextLogNBytes, deltaPtr_23);
		byte[][] rom = genBlockOrArrayDelta(new int[] { (int) addrPre_23[0], (int) addrPre_23[1] }, (int) N, DBytes,
				deltaBlock_23);

		for (int i = 0; i < 2; i++) {
			for (long j = 0; j < N; j++) {
				Util.setXor(ROM[i].get(j), Arrays.copyOfRange(rom[i], (int) j * DBytes, (int) (j + 1) * DBytes));
			}
		}

		return ptr_23;
	}

	private byte[][] accessFirstAndLast(long[] addr_23, byte[][] newRec_23, boolean isRead) {
		PIROut pirout = blockPIR(addr_23, ROM);
		byte[][] rec_23 = pirout.rec_23;

		byte[][] delta_23 = isRead ? new byte[][] { new byte[DBytes], new byte[DBytes] }
				: new byte[][] { Util.xor(rec_23[0], newRec_23[0]), Util.xor(rec_23[1], newRec_23[1]) };

		byte[][] rom = genBlockOrArrayDelta(new int[] { (int) addr_23[0], (int) addr_23[1] }, (int) N, DBytes,
				delta_23);
		for (int i = 0; i < 2; i++) {
			for (long j = 0; j < N; j++) {
				Util.setXor(ROM[i].get(j), Arrays.copyOfRange(rom[i], (int) j * DBytes, (int) (j + 1) * DBytes));
			}
		}

		return rec_23;
	}

	class PIROut {
		Array64<Byte>[] t;
		public byte[][] rec_23;

		public PIROut(Array64<Byte>[] t, byte[][] rec_23) {
			this.t = t;
			this.rec_23 = rec_23;
		}
	}

	private PIROut blockPIR(long[] addr_23, Array64<byte[]>[] mem_23) {
		long mask = (1 << logN) - 1;
		addr_23[0] &= mask;
		addr_23[1] &= mask;

		FSSKey[] keys = fss.Gen(addr_23[0] ^ addr_23[1], logN);
		cons[0].write(bandwidth, keys[0]);
		cons[1].write(bandwidth, keys[1]);
		keys[1] = (FSSKey) cons[0].readObject();
		keys[0] = (FSSKey) cons[1].readObject();

		byte[] rec_13 = new byte[DBytes];
		@SuppressWarnings("unchecked")
		Array64<Byte>[] t = (Array64<Byte>[]) new Array64[2];
		for (int i = 0; i < 2; i++) {
			t[i] = fss.EvalAllWithShift(keys[i], logN, addr_23[i]);
			for (long j = 0; j < N; j++) {
				if (t[i].get(j).byteValue() == 1) {
					Util.setXor(rec_13, mem_23[i].get(j));
				}
			}
		}

		byte[][] rec_23 = new byte[2][];
		rec_23[0] = rec_13;
		cons[0].write(bandwidth, rec_23[0]);
		rec_23[1] = cons[1].read();

		return new PIROut(t, rec_23);
	}

	private byte[][] ptrPIR(int[] idx_23, byte[][] block_23) {
		FSSKey[] keys = fss.Gen(idx_23[0] ^ idx_23[1], tau);
		cons[0].write(bandwidth, keys[0]);
		cons[1].write(bandwidth, keys[1]);
		keys[1] = (FSSKey) cons[0].readObject();
		keys[0] = (FSSKey) cons[1].readObject();

		byte[] rec_13 = new byte[nextLogNBytes];
		for (int i = 0; i < 2; i++) {
			Array64<Byte> fssout = fss.EvalAll(keys[i], tau);
			for (int j = 0; j < ttp; j++) {
				if (fssout.get(j ^ idx_23[i]).byteValue() == 1) {
					Util.setXor(rec_13, Arrays.copyOfRange(block_23[i], j * nextLogNBytes, (j + 1) * nextLogNBytes));
				}
			}
		}

		byte[][] rec_23 = new byte[2][];
		rec_23[0] = rec_13;
		cons[0].write(bandwidth, rec_23[0]);
		rec_23[1] = cons[1].read();

		return rec_23;
	}

	private byte[][] genBlockOrArrayDelta(int[] idx_23, int numChunk, int chunkBytes, byte[][] delta_23) {
		InsLbl inslbl = null;
		byte[][] mem_23 = new byte[2][];
		int memBytes = numChunk * chunkBytes;

		if (party == Party.Eddie) {
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_DE, Crypto.sr_CE);
			inslbl.runP1(idx_23[0] ^ idx_23[1], Util.xor(delta_23[0], delta_23[1]), numChunk);

			mem_23[0] = Util.nextBytes(memBytes, Crypto.sr_DE);
			mem_23[1] = Util.nextBytes(memBytes, Crypto.sr_CE);

		} else if (party == Party.Debbie) {
			inslbl = new InsLbl(cons[1], cons[0], Crypto.sr_DE, Crypto.sr_CD);
			byte[] mem_12 = inslbl.runP2(idx_23[0], delta_23[0], numChunk);

			mem_23[1] = Util.nextBytes(memBytes, Crypto.sr_DE);
			mem_23[0] = Util.xor(mem_12, mem_23[1]);
			cons[0].write(bandwidth, mem_23[0]);
			Util.setXor(mem_23[0], cons[0].read());

		} else if (party == Party.Charlie) {
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_CE, Crypto.sr_CD);
			byte[] mem_12 = inslbl.runP3(numChunk, chunkBytes);

			mem_23[0] = Util.nextBytes(memBytes, Crypto.sr_CE);
			mem_23[1] = Util.xor(mem_12, mem_23[0]);
			cons[1].write(bandwidth, mem_23[1]);
			Util.setXor(mem_23[1], cons[1].read());

		} else {
		}

		return mem_23;
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

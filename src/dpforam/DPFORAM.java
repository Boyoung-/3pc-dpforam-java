package dpforam;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import struct.Party;
import subprotocols.InsLbl;
import util.Array64;
import util.Util;

// TODO: measure bandwidth, check clone()

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

	// TODO: customize serialization of Array64<byte[]>
	@SuppressWarnings("unchecked")
	private void WOMtoROM() {
		if (isFirst)
			return;

		for (long i = 0; i < N; i++) {
			ROM[0].set(i, WOM.get(i).clone());
		}
		cons[0].write(WOM);
		ROM[1] = (Array64<byte[]>) cons[1].readObject();
	}

	public byte[] access(long addr, byte[] newRec_13, boolean isRead) {
		assert (newRec_13.length == (isLast ? DBytes : nextLogNBytes));

		if (isFirst && isLast)
			return accessFirstAndLast(addr, newRec_13, isRead);

		int mask = (1 << tau) - 1;
		long addrPre = isLast ? addr : (addr >>> tau);
		int addrSuf = isLast ? 0 : ((int) addr & mask);
		if (isFirst) {
			return accessFirst(addrPre, addrSuf, newRec_13);
		}

		byte[] newStashPtr = Util.padArray(BigInteger.valueOf(stashCtr).toByteArray(), logNBytes);
		byte[] stashPtr_13 = posMap.access(addrPre, newStashPtr, false);
		
		// TODO: access on addr sharing
		cons[0].write(stashPtr_13);
		cons[1].write(stashPtr_13);
		byte[] stashPtr = stashPtr_13.clone();
		Util.setXor(stashPtr, cons[0].read());
		Util.setXor(stashPtr, cons[1].read());
		
		long stashAddrPre = new BigInteger(1, stashPtr).longValue();
		//byte[] block = (stashAddrPre == 0) ? ROM.get(addrPre).clone() : stash.get(stashAddrPre).clone();
		PIROut romPirOut = blockPIR(addrPre, ROM);
		PIROut stashPirOut = blockPIR(stashAddrPre, stash);
		// TODO: 3pc selection
		byte[] block_13 = (stashAddrPre == 0) ? romPirOut.rec_13 : stashPirOut.rec_13;
		
//		if (!isFirst && !isLast)
//			System.out.println("STASH PTR = " + stashAddrPre);
		
		if (isLast) {
			// TODO: re-think!
			byte[] deltaNewBlock_13 = isRead ? new byte[DBytes] : Util.xor(block_13, newRec_13);
			newRec_13 = Util.xor(block_13, deltaNewBlock_13);
			byte[][] newBlock_23 = new byte[2][];
			newBlock_23[0] = newRec_13;
			cons[0].write(newBlock_23[0]);
			newBlock_23[1] = cons[1].read();
			
			// TODO: PIW
			Util.setXor(WOM.get(addrPre), deltaNewBlock_13);
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
			
			return block_13;
		}
		
//		System.out.println("addrSuf = " + addrSuf);
		
		byte[][] block_23 = new byte[2][];
		block_23[0] = block_13;
		cons[0].write(block_23[0]);
		block_23[1] = cons[1].read();
		// TODO: pir on shared idx
		PIROut ptrPirOut = ptrPIR(addrSuf, block_23);
		byte[] ptr_13 = ptrPirOut.rec_13;
		
//		if (party == Party.Eddie) {
//			byte[] test = ptrPirOut.rec_13.clone();
//			Util.setXor(test, cons[0].read());
//			Util.setXor(test, cons[1].read());
//			System.out.println("BBBBBBBBB - PTR end of pir = " + new BigInteger(1, test).longValue());
//		} else if (party == Party.Debbie) {
//			cons[1].write(ptrPirOut.rec_13);
//		} else if (party == Party.Charlie) {
//			cons[0].write(ptrPirOut.rec_13);
//		} else {
//		}
		
//		if (party == Party.Eddie) {
//			byte[] test = ptr_13.clone();
//			Util.setXor(test, cons[0].read());
//			Util.setXor(test, cons[1].read());
//			System.out.println("NEXT LEVEL PTR = " + new BigInteger(1, test).longValue());
//		} else if (party == Party.Debbie) {
//			cons[1].write(ptr_13);
//		} else if (party == Party.Charlie) {
//			cons[0].write(ptr_13);
//		} else {
//		}
		
//		if (party == Party.Eddie) {
//			byte[] test = block_23[1].clone();
//			Util.setXor(test, cons[0].read());
//			Util.setXor(test, cons[1].read());
//			System.out.println("NEXT LEVEL PTR in block = " + new BigInteger(1, Arrays.copyOfRange(test, addrSuf*nextLogNBytes, (addrSuf+1)*nextLogNBytes)).longValue());
//		} else if (party == Party.Debbie) {
//			cons[1].write(block_23[1]);
//		} else if (party == Party.Charlie) {
//			cons[0].write(block_23[1]);
//		} else {
//		}
//		
//		if (party == Party.Eddie) {
//			byte[] test = stash[0].get(stashAddrPre).clone();
//			Util.setXor(test, cons[0].read());
//			Util.setXor(test, cons[1].read());
//			System.out.println("NEXT LEVEL PTR in block = " + new BigInteger(1, Arrays.copyOfRange(test, addrSuf*nextLogNBytes, (addrSuf+1)*nextLogNBytes)).longValue());
//		} else if (party == Party.Debbie) {
//			cons[1].write(stash[0].get(stashAddrPre));
//		} else if (party == Party.Charlie) {
//			cons[0].write(stash[0].get(stashAddrPre));
//		} else {
//		}
//		
//		System.out.println("stashCtr-1 = " + (stashCtr-1));
//		System.out.println("stashAddrPre = " + stashAddrPre);
		
		// TODO: secret-shared isRead
		byte[] ptrDelta_13 = isRead? (new byte[nextLogNBytes]) : Util.xor(ptr_13, newRec_13);

//		System.out.println("isRead = " + isRead);
//		System.out.println("ptr_13 = " + new BigInteger(1, ptr_13).longValue());
//		System.out.println("NEXT LEVEL NEW PTR = " + new BigInteger(1, newRec_13).longValue());
//		System.out.println("ptrDelta_13 = " + new BigInteger(1, ptrDelta_13).longValue());
		
		byte[] deltaNewBlock_13 = updateBlockOrPtr_13(addrSuf, ttp, nextLogNBytes, ptrDelta_13);
		byte[] newBlock_13 = Util.xor(block_13, deltaNewBlock_13);
		byte[][] newBlock_23 = new byte[2][];
		newBlock_23[0] = newBlock_13;
		cons[0].write(newBlock_23[0]);
		newBlock_23[1] = cons[1].read();
		
//		if (party == Party.Eddie) {
//			byte[] test = ptrDelta_13.clone();
//			Util.setXor(test, cons[0].read());
//			Util.setXor(test, cons[1].read());
//			System.out.println("NEXT LEVEL PTR DELTA = " + new BigInteger(1, test).longValue());
//		} else if (party == Party.Debbie) {
//			cons[1].write(ptrDelta_13);
//		} else if (party == Party.Charlie) {
//			cons[0].write(ptrDelta_13);
//		} else {
//		}
		
		//byte[] rec = Arrays.copyOfRange(block, addrSuf * newRec.length, (addrSuf + 1) * newRec.length);
		//newRec = isRead ? rec : newRec;
		//System.arraycopy(newRec, 0, block, addrSuf * newRec.length, newRec.length);
		
		// TODO: PIW
		Util.setXor(WOM.get(addrPre), deltaNewBlock_13);
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
		
		return ptr_13;

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
	}

	
	// TODO: clean InsLbl, change below to private
	public byte[] accessFirst(long addrPre, int addrSuf, byte[] newPtr_13) {
		PIROut blockPirOut = blockPIR(addrPre, ROM);
		byte[] block_13 = blockPirOut.rec_13;
		byte[][] block_23 = new byte[2][];
		block_23[0] = block_13;
		cons[0].write(block_23[0]);
		block_23[1] = cons[1].read();
		PIROut ptrPirOut = ptrPIR(addrSuf, block_23);
		byte[] ptr_13 = ptrPirOut.rec_13;
		byte[] deltaPtr_13 = Util.xor(ptr_13, newPtr_13);
		
		byte[] deltaBlock_13 = updateBlockOrPtr_13(addrSuf, ttp, nextLogNBytes, deltaPtr_13);
		byte[][] rom = updateBlockOrPtr_23((int) addrPre, (int) N, DBytes, deltaBlock_13);
		
		for (int i=0; i<2; i++) {
			for (long j=0; j<N; j++) {
				Util.setXor(ROM[i].get(j), Arrays.copyOfRange(rom[i], (int) j * DBytes, (int) (j+1) * DBytes));
			}
		}
		
		return ptr_13;
	}

	
	// TODO: change below to private
	public byte[] accessFirstAndLast(long addr, byte[] newRec_13, boolean isRead) {
		PIROut pirout = blockPIR(addr, ROM);
		byte[] rec_13 = pirout.rec_13;		
		byte[] delta_13 = isRead ? new byte[DBytes] : Util.xor(rec_13, newRec_13);
		
		byte[][] rom = updateBlockOrPtr_23((int) addr, (int) N, DBytes, delta_13);		
		for (int i=0; i<2; i++) {
			for (long j=0; j<N; j++) {
				Util.setXor(ROM[i].get(j), Arrays.copyOfRange(rom[i], (int) j * DBytes, (int) (j+1) * DBytes));
			}
		}		
		return rec_13;
	}
	
	class PIROut {
		Array64<byte[][]>[] fssout;
		public byte[] rec_13;
		
		public PIROut(Array64<byte[][]>[] fssout, byte[] rec_13) {
			this.fssout = fssout;
			this.rec_13 = rec_13;
		}
	}
	
	private PIROut blockPIR(long addr, Array64<byte[]>[] mem) {
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
					Util.setXor(rec_13, mem[i].get(j));
				}
			}
		}
		return new PIROut(fssOut, rec_13);
	}
	
	private PIROut ptrPIR(int idx, byte[][] block_23) {
//		if (logN == 6) {
//			if (party == Party.Eddie) {
//				byte[] test = block_23[0].clone();
//				Util.setXor(test, cons[0].read());
//				Util.setXor(test, cons[1].read());
//				System.out.println("AAAAAAAAAAAAA - NEXT LEVEL PTR in block = " + new BigInteger(1, Arrays.copyOfRange(test, idx*nextLogNBytes, (idx+1)*nextLogNBytes)).longValue());
//				test = block_23[1].clone();
//				Util.setXor(test, cons[0].read());
//				Util.setXor(test, cons[1].read());
//				System.out.println("AAAAAAAAAAAAA - NEXT LEVEL PTR in block = " + new BigInteger(1, Arrays.copyOfRange(test, idx*nextLogNBytes, (idx+1)*nextLogNBytes)).longValue());
//			} else if (party == Party.Debbie) {
//				cons[1].write(block_23[0]);
//				cons[1].write(block_23[1]);
//			} else if (party == Party.Charlie) {
//				cons[0].write(block_23[0]);
//				cons[0].write(block_23[1]);
//			} else {
//			}
//		}		
		
		FSSKey[] keys = fss.Gen(idx, tau, new byte[nextLogNBytes]);
		cons[0].write(keys[0]);
		cons[1].write(keys[1]);
		keys[1] = (FSSKey) cons[0].readObject();
		keys[0] = (FSSKey) cons[1].readObject();
		byte[] rec_13 = new byte[nextLogNBytes];
		@SuppressWarnings("unchecked")
		Array64<byte[][]>[] fssOut = (Array64<byte[][]>[]) new Array64[] {new Array64<byte[][]>(ttp), new Array64<byte[][]>(ttp)};
		for (int i=0; i<2; i++) {
			for (int j=0; j<ttp; j++) {
				fssOut[i].set(j, fss.Eval(keys[i], j, tau));
				if (fssOut[i].get(j)[1][0] == 1) {
					Util.setXor(rec_13, Arrays.copyOfRange(block_23[i], j*nextLogNBytes, (j+1)*nextLogNBytes));
				}
			}
		}
		
//		if (logN == 6) {
//			if (party == Party.Eddie) {
//				byte[] test = rec_13.clone();
//				Util.setXor(test, cons[0].read());
//				Util.setXor(test, cons[1].read());
//				System.out.println("AAAAAAAAAAAAA - PTR end of pir = " + new BigInteger(1, test).longValue());
//			} else if (party == Party.Debbie) {
//				cons[1].write(rec_13);
//			} else if (party == Party.Charlie) {
//				cons[0].write(rec_13);
//			} else {
//			}
//		}		
		
		return new PIROut(fssOut, rec_13);
	}
	
	private byte[][] updateBlockOrPtr_23(int idx, int numChunk, int chunkBytes, byte[] delta_13) {
		InsLbl inslbl = null;
		byte[][] mem = new byte[2][];
		int memBytes = numChunk * chunkBytes;
		
		if (party == Party.Eddie) {
			delta_13 = Util.xor(delta_13, cons[1].read());
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_DE, Crypto.sr_CE);
			inslbl.runP1(idx, delta_13, numChunk);
			
			mem[0] = Util.nextBytes(memBytes, Crypto.sr_DE);
			mem[1] = Util.nextBytes(memBytes, Crypto.sr_CE);
			
		} else if (party == Party.Debbie) {
			inslbl = new InsLbl(cons[1], cons[0], Crypto.sr_DE, Crypto.sr_CD);
			byte[] mem_12 = inslbl.runP2(0, delta_13, numChunk);
			
			mem[1] = Util.nextBytes(memBytes, Crypto.sr_DE);
			mem[0] = Util.xor(mem_12, mem[1]);
			cons[0].write(mem[0]);
			Util.setXor(mem[0], cons[0].read());
			
		} else if (party == Party.Charlie) {
			cons[0].write(delta_13);
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
	
	private byte[] updateBlockOrPtr_13(int idx, int numChunk, int chunkBytes, byte[] delta_13) {
		InsLbl inslbl = null;
		byte[] mem_13 = null;
		int memBytes = numChunk * chunkBytes;
		
		if (party == Party.Eddie) {
			delta_13 = Util.xor(delta_13, cons[1].read());
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_DE, Crypto.sr_CE);
			inslbl.runP1(idx, delta_13, numChunk);			
			mem_13 = new byte[memBytes];
			
		} else if (party == Party.Debbie) {
			inslbl = new InsLbl(cons[1], cons[0], Crypto.sr_DE, Crypto.sr_CD);
			mem_13 = inslbl.runP2(0, delta_13, numChunk);
			
		} else if (party == Party.Charlie) {
			cons[0].write(delta_13);
			inslbl = new InsLbl(cons[0], cons[1], Crypto.sr_CE, Crypto.sr_CD);
			mem_13 = inslbl.runP3(numChunk, chunkBytes);
			
		} else {
		}
		
		return mem_13;
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

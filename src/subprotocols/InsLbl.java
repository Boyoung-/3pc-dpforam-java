package subprotocols;

import java.security.SecureRandom;
import java.util.Arrays;

import communication.Communication;
import crypto.Crypto;
import exceptions.NoSuchPartyException;
import oram.Forest;
import oram.Metadata;
import protocols.Protocol;
import struct.Party;
import util.M;
import util.Util;

public class InsLbl extends Protocol {

	SecureRandom sr1;
	SecureRandom sr2;

	public InsLbl(Communication con1, Communication con2) {
		super(con1, con2);

		online_band = all.InsLbl_on;
		offline_band = all.InsLbl_off;
		timer = all.InsLbl;
	}

	public InsLbl(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		super(con1, con2);
		this.sr1 = sr1;
		this.sr2 = sr2;

		online_band = all.InsLbl_on;
		offline_band = all.InsLbl_off;
		timer = all.InsLbl;
	}

	public void reinit(Communication con1, Communication con2, SecureRandom sr1, SecureRandom sr2) {
		this.con1 = con1;
		this.con2 = con2;
		this.sr1 = sr1;
		this.sr2 = sr2;
	}

	public void runP1(int dN1, byte[] L1, int ttp) {
		timer.start(M.offline_comp);

		int l = L1.length;

		byte[] p = Util.nextBytes(ttp * l, sr1);
		byte[] a = Util.nextBytes(ttp * l, sr1);
		byte[] b = Util.nextBytes(ttp * l, sr1);
		int v = sr1.nextInt(ttp);
		int w = sr1.nextInt(ttp);

		int alpha1 = Crypto.sr.nextInt(ttp);
		int u1 = alpha1 ^ v;
		byte[] pstar = Util.xor(p, Util.xorRotate(a, u1, ttp, l));

		timer.start(M.offline_write);
		con2.write(offline_band, u1);
		con2.write(offline_band, pstar);
		timer.stop(M.offline_write);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		int m = dN1 ^ alpha1;

		timer.start(M.online_write);
		con1.write(online_band, m);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		m = con1.readIntAndDec();
		timer.stop(M.online_read);

		int beta1 = m ^ dN1;

		int index = beta1 ^ w;
		for (int i = 0; i < l; i++) {
			b[index * l + i] = (byte) (b[index * l + i] ^ L1[i]);
		}

		timer.start(M.online_write);
		con2.write(online_band, b);
		timer.stop(M.online_write);

		timer.stop(M.online_comp);
		return;
	}

	public byte[] runP2(int dN2, byte[] L2, int ttp) {
		timer.start(M.offline_comp);

		int l = L2.length;

		byte[] p = Util.nextBytes(ttp * l, sr1);
		byte[] a = Util.nextBytes(ttp * l, sr1);
		byte[] b = Util.nextBytes(ttp * l, sr1);
		int v = sr1.nextInt(ttp);
		int w = sr1.nextInt(ttp);

		int beta2 = Crypto.sr.nextInt(ttp);
		int u2 = beta2 ^ w;
		byte[] z2 = Util.xor(p, Util.xorRotate(b, u2, ttp, l));

		timer.start(M.offline_write);
		con2.write(offline_band, u2);
		timer.stop(M.offline_write);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		int m = beta2 ^ dN2;

		timer.start(M.online_write);
		con1.write(online_band, m);
		timer.stop(M.online_write);

		timer.start(M.online_read);
		m = con1.readIntAndDec();
		timer.stop(M.online_read);

		int alpha2 = m ^ dN2;

		int index = alpha2 ^ v;
		for (int i = 0; i < l; i++) {
			a[index * l + i] = (byte) (a[index * l + i] ^ L2[i]);
		}

		timer.start(M.online_write);
		con2.write(online_band, a);
		timer.stop(M.online_write);

		timer.stop(M.online_comp);
		return z2;
	}

	public byte[] runP3(int ttp, int l) {
		timer.start(M.offline_comp);

		timer.start(M.offline_read);
		int u1 = con1.readIntAndDec();
		byte[] pstar = con1.readAndDec();
		int u2 = con2.readIntAndDec();
		timer.stop(M.offline_read);

		timer.stop(M.offline_comp);

		// ----------------------------------------- //

		timer.start(M.online_comp);

		timer.start(M.online_read);
		byte[] s1 = con1.readAndDec();
		byte[] s2 = con2.readAndDec();
		timer.stop(M.online_read);

		s2 = Util.xorRotate(s2, u1, ttp, l);
		s1 = Util.xorRotate(s1, u2, ttp, l);
		Util.setXor(pstar, s1);
		Util.setXor(pstar, s2);

		timer.stop(M.online_comp);
		return pstar;
	}

	@Override
	public void run(Party party, Metadata md, Forest[] forest) {

		for (int j = 0; j < 100; j++) {
			int ttp = (int) Math.pow(2, 8);
			int l = 10;
			int dN1 = Crypto.sr.nextInt(ttp);
			int dN2 = Crypto.sr.nextInt(ttp);
			byte[] L1 = Util.nextBytes(l, Crypto.sr);
			byte[] L2 = Util.nextBytes(l, Crypto.sr);

			if (party == Party.Eddie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CE);

				this.runP1(dN1, L1, ttp);
				con1.write(dN1);
				con1.write(L1);

			} else if (party == Party.Debbie) {
				this.reinit(con1, con2, Crypto.sr_DE, Crypto.sr_CD);

				byte[] m1 = this.runP2(dN2, L2, ttp);
				byte[] m2 = con2.read();
				dN1 = con1.readInt();
				L1 = con1.read();
				int dN = dN1 ^ dN2;
				byte[] L = Util.xor(L1, L2);
				byte[] M = Util.xor(m1, m2);
				byte[] expectL = Arrays.copyOfRange(M, dN * l, dN * l + l);

				boolean fail = false;
				if (!Util.equal(L, expectL)) {
					System.err.println(j + ": InsLbl test failed on L");
					fail = true;
				}
				for (int i = 0; i < dN * l; i++) {
					if (M[i] != 0) {
						System.err.println(j + ": InsLbl test failed 1");
						fail = true;
						break;
					}
				}
				for (int i = dN * l + l; i < M.length; i++) {
					if (M[i] != 0) {
						System.err.println(j + ": InsLbl test failed 2");
						fail = true;
						break;
					}
				}
				if (!fail)
					System.out.println(j + ": InsLbl test passed");

			} else if (party == Party.Charlie) {
				this.reinit(con1, con2, Crypto.sr_CE, Crypto.sr_CD);

				byte[] m2 = this.runP3(ttp, l);
				con2.write(m2);

			} else {
				throw new NoSuchPartyException(party + "");
			}
		}
	}

	@Override
	public void run(Party party, Metadata md, Forest forest) {
	}
}

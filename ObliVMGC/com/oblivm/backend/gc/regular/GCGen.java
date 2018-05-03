package com.oblivm.backend.gc.regular;

import java.util.ArrayList;

import com.oblivm.backend.flexsc.Flag;
import com.oblivm.backend.flexsc.Mode;
import com.oblivm.backend.gc.GCGenComp;
import com.oblivm.backend.gc.GCSignal;
import com.oblivm.backend.network.Network;

import util.Bandwidth;
import util.Timer;

public class GCGen extends GCGenComp {
	Garbler gb;

	Timer timer = null;
	Bandwidth band;
	int m;
	ArrayList<byte[]> msg = new ArrayList<byte[]>(threshold);

	public GCGen(Network channel) {
		super(channel, Mode.REAL);
		gb = new Garbler();
		for (int i = 0; i < 2; ++i) {
			labelL[i] = new GCSignal(new byte[10]);
			labelR[i] = new GCSignal(new byte[10]);
			lb[i] = new GCSignal(new byte[10]);
			toSend[0][i] = new GCSignal(new byte[10]);
			toSend[1][i] = new GCSignal(new byte[10]);
		}
	}

	public GCGen(Network channel, Timer timer, Bandwidth band, int m) {
		super(channel, Mode.REAL);
		gb = new Garbler();
		for (int i = 0; i < 2; ++i) {
			labelL[i] = new GCSignal(new byte[10]);
			labelR[i] = new GCSignal(new byte[10]);
			lb[i] = new GCSignal(new byte[10]);
			toSend[0][i] = new GCSignal(new byte[10]);
			toSend[1][i] = new GCSignal(new byte[10]);
		}

		this.timer = timer;
		this.band = band;
		this.m = m;
	}

	private GCSignal[][] gtt = new GCSignal[2][2];
	private GCSignal[][] toSend = new GCSignal[2][2];
	private GCSignal labelL[] = new GCSignal[2];
	private GCSignal labelR[] = new GCSignal[2];
	private GCSignal[] lb = new GCSignal[2];

	private GCSignal garble(GCSignal a, GCSignal b) {
		labelL[0] = a;
		GCSignal.xor(R, labelL[0], labelL[1]);
		labelR[0] = b;
		GCSignal.xor(R, labelR[0], labelR[1]);

		int cL = a.getLSB();
		int cR = b.getLSB();

		gb.enc(labelL[cL], labelR[cR], gid, GCSignal.ZERO, lb[cL & cR]);
		GCSignal.xor(R, lb[cL & cR], lb[1 - (cL & cR)]);

		gtt[0 ^ cL][0 ^ cR] = lb[0];
		gtt[0 ^ cL][1 ^ cR] = lb[0];
		gtt[1 ^ cL][0 ^ cR] = lb[0];
		gtt[1 ^ cL][1 ^ cR] = lb[1];

		if (cL != 0 || cR != 0)
			gb.enc(labelL[0], labelR[0], gid, gtt[0 ^ cL][0 ^ cR], toSend[0 ^ cL][0 ^ cR]);
		if (cL != 0 || cR != 1)
			gb.enc(labelL[0], labelR[1], gid, gtt[0 ^ cL][1 ^ cR], toSend[0 ^ cL][1 ^ cR]);
		if (cL != 1 || cR != 0)
			gb.enc(labelL[1], labelR[0], gid, gtt[1 ^ cL][0 ^ cR], toSend[1 ^ cL][0 ^ cR]);
		if (cL != 1 || cR != 1)
			gb.enc(labelL[1], labelR[1], gid, gtt[1 ^ cL][1 ^ cR], toSend[1 ^ cL][1 ^ cR]);

		return GCSignal.newInstance(lb[0].bytes);
	}

	public void sendLastSetGTT() {
		if (msg.size() > 0) {
			timer.start(m);
			channel.receiver.write(band, msg);
			timer.stop(m);
			msg.clear();
		}
	}

	private void sendGTT() {
		if (timer == null) {
			try {
				Flag.sw.startGCIO();
				toSend[0][1].send(channel);
				toSend[1][0].send(channel);
				toSend[1][1].send(channel);
				Flag.sw.stopGCIO();
			} catch (Exception e) {
				e.printStackTrace();
				System.exit(1);
			}
		} else {
			byte[] rows = new byte[GCSignal.len * 3];
			System.arraycopy(toSend[0][1].bytes, 0, rows, 0, GCSignal.len);
			System.arraycopy(toSend[1][0].bytes, 0, rows, GCSignal.len, GCSignal.len);
			System.arraycopy(toSend[1][1].bytes, 0, rows, GCSignal.len * 2, GCSignal.len);

			msg.add(rows);
			if (msg.size() == threshold) {
				timer.start(m);
				channel.receiver.write(band, msg);
				timer.stop(m);
				msg.clear();
			}
		}
	}

	public GCSignal and(GCSignal a, GCSignal b) {
		Flag.sw.startGC();
		GCSignal res;
		if (a.isPublic() && b.isPublic())
			res = ((a.v && b.v) ? new GCSignal(true) : new GCSignal(false));
		else if (a.isPublic())
			res = a.v ? b : new GCSignal(false);
		else if (b.isPublic())
			res = b.v ? a : new GCSignal(false);
		else {
			++numOfAnds;
			GCSignal ret;
			ret = garble(a, b);

			sendGTT();
			gid++;
			gatesRemain = true;
			res = ret;
		}
		Flag.sw.stopGC();
		return res;
	}

	@Override
	public void setEvaluate() {
	}

}

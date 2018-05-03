package struct;

import util.Bandwidth;
import util.Timer;

public class TimeAndBandwidth {
	public Bandwidth KSearch_on;
	public Bandwidth KSearch_off;

	public Bandwidth SSPIR_on;
	public Bandwidth SSPIR_off;
	public Bandwidth ShiftPIR_on;
	public Bandwidth ShiftPIR_off;
	public Bandwidth ThreeShiftPIR_on;
	public Bandwidth ThreeShiftPIR_off;
	public Bandwidth ShiftXorPIR_on;
	public Bandwidth ShiftXorPIR_off;
	public Bandwidth ThreeShiftXorPIR_on;
	public Bandwidth ThreeShiftXorPIR_off;

	public Bandwidth InsLbl_on;
	public Bandwidth InsLbl_off;
	public Bandwidth ULiT_on;
	public Bandwidth ULiT_off;

	public Bandwidth Shift_on;
	public Bandwidth Shift_off;
	public Bandwidth FlipFlag_on;
	public Bandwidth FlipFlag_off;

	public Bandwidth SSXOT_on;
	public Bandwidth SSXOT_off;
	public Bandwidth UpdateRoot_on;
	public Bandwidth UpdateRoot_off;
	public Bandwidth PermBucket_on;
	public Bandwidth PermBucket_off;
	public Bandwidth PermTuple_on;
	public Bandwidth PermTuple_off;

	public Bandwidth Access_on;
	public Bandwidth Access_off;

	public Bandwidth PostProcess_on;
	public Bandwidth PostProcess_off;

	public Bandwidth Eviction_on;
	public Bandwidth Eviction_off;

	public Timer KSearch;
	public Timer SSPIR;
	public Timer ShiftPIR;
	public Timer ThreeShiftPIR;
	public Timer ShiftXorPIR;
	public Timer ThreeShiftXorPIR;
	public Timer InsLbl;
	public Timer ULiT;
	public Timer Shift;
	public Timer FlipFlag;
	public Timer SSXOT;
	public Timer UpdateRoot;
	public Timer PermBucket;
	public Timer PermTuple;
	public Timer Access;
	public Timer PostProcess;
	public Timer Eviction;

	public TimeAndBandwidth() {
		KSearch_on = new Bandwidth();
		KSearch_off = new Bandwidth();
		SSPIR_on = new Bandwidth();
		SSPIR_off = new Bandwidth();
		ShiftPIR_on = new Bandwidth();
		ShiftPIR_off = new Bandwidth();
		ThreeShiftPIR_on = new Bandwidth();
		ThreeShiftPIR_off = new Bandwidth();
		ShiftXorPIR_on = new Bandwidth();
		ShiftXorPIR_off = new Bandwidth();
		ThreeShiftXorPIR_on = new Bandwidth();
		ThreeShiftXorPIR_off = new Bandwidth();
		InsLbl_on = new Bandwidth();
		InsLbl_off = new Bandwidth();
		ULiT_on = new Bandwidth();
		ULiT_off = new Bandwidth();
		Shift_on = new Bandwidth();
		Shift_off = new Bandwidth();
		FlipFlag_on = new Bandwidth();
		FlipFlag_off = new Bandwidth();
		SSXOT_on = new Bandwidth();
		SSXOT_off = new Bandwidth();
		UpdateRoot_on = new Bandwidth();
		UpdateRoot_off = new Bandwidth();
		PermBucket_on = new Bandwidth();
		PermBucket_off = new Bandwidth();
		PermTuple_on = new Bandwidth();
		PermTuple_off = new Bandwidth();
		Access_on = new Bandwidth();
		Access_off = new Bandwidth();
		PostProcess_on = new Bandwidth();
		PostProcess_off = new Bandwidth();
		Eviction_on = new Bandwidth();
		Eviction_off = new Bandwidth();

		KSearch = new Timer();
		SSPIR = new Timer();
		ShiftPIR = new Timer();
		ThreeShiftPIR = new Timer();
		ShiftXorPIR = new Timer();
		ThreeShiftXorPIR = new Timer();
		InsLbl = new Timer();
		ULiT = new Timer();
		Shift = new Timer();
		FlipFlag = new Timer();
		SSXOT = new Timer();
		UpdateRoot = new Timer();
		PermBucket = new Timer();
		PermTuple = new Timer();
		Access = new Timer();
		PostProcess = new Timer();
		Eviction = new Timer();
	}
}

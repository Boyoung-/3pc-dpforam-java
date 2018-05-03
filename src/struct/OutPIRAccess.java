package struct;

import oram.Tuple;

public class OutPIRAccess {
	public Tuple[] pathTuples_CD;
	public Tuple[] pathTuples_CE;
	public Tuple[] pathTuples_DE;
	public OutPIRCOT j;
	public TwoThreeXorByte X;
	public TwoThreeXorByte nextL;
	public byte[] Lip1;

	public OutPIRAccess(Tuple[] pathTuples_CD, Tuple[] pathTuples_CE, Tuple[] pathTuples_DE, OutPIRCOT j,
			TwoThreeXorByte X, TwoThreeXorByte nextL, byte[] Lip1) {
		this.pathTuples_CD = pathTuples_CD;
		this.pathTuples_CE = pathTuples_CE;
		this.pathTuples_DE = pathTuples_DE;
		this.j = j;
		this.X = X;
		this.nextL = nextL;
		this.Lip1 = Lip1;
	}
}

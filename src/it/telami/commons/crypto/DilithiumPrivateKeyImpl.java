package it.telami.commons.crypto;

final class DilithiumPrivateKeyImpl implements DilithiumPrivateKey {
	private final DilithiumParameterSpec spec;
	//Probably here just for serialization purpose...
	final byte[] rho;
	private final byte[] K;
	private final byte[] tr;
	final PolyVec s1;
	final PolyVec s2;
	final PolyVec t0;
	private final byte[] prvBytes;
	final PolyVec[] a;
	private final PolyVec s1Hat;
	private final PolyVec s2Hat;
	private final PolyVec t0Hat;

	DilithiumPrivateKeyImpl (
			final DilithiumParameterSpec spec,
			final byte[] rho,
			final byte[] K,
			final byte[] tr,
			final PolyVec s1,
			final PolyVec s2,
			final PolyVec t0,
			final byte[] prvBytes,
			final PolyVec[] A,
			final PolyVec s1Hat,
			final PolyVec s2Hat,
			final PolyVec t0Hat) {
		this.spec = spec;
		this.rho = rho;
		this.K = K;
		this.tr = tr;
		this.s1 = s1;
		this.s2 = s2;
		this.t0 = t0;
		this.prvBytes = prvBytes;
		this.a = A;
		this.s1Hat = s1Hat;
		this.s2Hat = s2Hat;
		this.t0Hat = t0Hat;
	}

	@Override
	public String getAlgorithm () {
		return "it.telami.commons.crypto.Dilithium";
	}

	@Override
	public String getFormat () {
		return "RAW";
	}
	
	@Override
	public DilithiumParameterSpec getSpec () {
		return spec;
	}

	@Override
	public byte[] getK () {
		return K;
	}

	@Override
	public byte[] getTr () {
		return tr;
	}

	@Override
	public byte[] getEncoded () {
		return prvBytes;
	}

	@Override
	public PolyVec getS1Hat () {
		return s1Hat;
	}

	@Override
	public PolyVec getS2Hat () {
		return s2Hat;
	}

	@Override
	public PolyVec getT0Hat () {
		return t0Hat;
	}
}

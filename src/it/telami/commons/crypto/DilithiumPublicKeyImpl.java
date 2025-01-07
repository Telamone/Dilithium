package it.telami.commons.crypto;

final class DilithiumPublicKeyImpl implements DilithiumPublicKey {
	private final DilithiumParameterSpec spec;
	final byte[] rho;
	private final PolyVec t1;
	private final byte[] pubBytes;
	final PolyVec[] a;

	public DilithiumPublicKeyImpl (
			final DilithiumParameterSpec spec,
			final byte[] rho,
			final PolyVec t1,
			final byte[] pubBytes,
			final PolyVec[] a) {
		this.spec = spec;
		this.rho = rho;
		this.t1 = t1;
		this.pubBytes = pubBytes;
		this.a = a;
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
	public PolyVec getT1 () {
		return t1;
	}

	@Override
	public byte[] getEncoded () {
		return pubBytes;
	}
}

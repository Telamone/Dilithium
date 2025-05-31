package it.telami.commons.crypto.dilithium;

final class Utils {
	private Utils () {}

	static byte[] getSHAKE256Digest (final int sz,
									 final byte[] a0,
									 final byte[] a1,
									 final int l) {
		final Digest s;
		final byte[] c;
		(s = new Digest(256)).update(a0, a0.length);
		s.update(a1, l);
		s.doOutput(c = new byte[sz], 0, sz);
		return c;
	}
	static byte[] getSHAKE256Digest (final int sz,
									 final byte[] a) {
		final Digest s;
		final byte[] c;
		(s = new Digest(256)).update(a, a.length);
		s.doOutput(c = new byte[sz], 0, sz);
		return c;
	}

	static byte[] crh (final byte[] p) {
		return getSHAKE256Digest(32, p);
	}

	static int getSigLength (final DilithiumParameterSpec spec) {
		return spec.tilde + spec.omega + PackingUtils.getPolyZPackedBytes(spec.gamma1) * spec.l + spec.k;
	}
}

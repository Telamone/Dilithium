package it.telami.commons.crypto.dilithium;

final class Utils {
	private Utils () {}

	static byte[] concatOrCopy (final byte[]... arr) {
		final byte[] r;
		if (arr.length == 2) {
			final int s0 = arr[0].length, s1 = arr[1].length;
			r = new byte[s0 + s1];
			System.arraycopy(arr[0], 0, r, 0, s0);
			System.arraycopy(arr[1], 0, r, s0, s1);
		} else {
			final int s0 = arr[0].length;
			r = new byte[s0];
			System.arraycopy(arr[0], 0, r, 0, s0);
		}
		return r;
	}

	static byte[] getSHAKE256Digest (final int sz,
									 final byte[]... arr) {
		final Digest s = new Digest(256);
		byte[] c = concatOrCopy(arr);
		s.update(c, c.length);
		c = new byte[sz];
		s.doOutput(c, 0, sz);
		return c;
	}

	static byte[] crh (final byte[] p) {
		return getSHAKE256Digest(32, p);
	}

	static byte[] mu_crh (final byte[] p) {
		return getSHAKE256Digest(64, p);
	}

	static int getSigLength (final DilithiumParameterSpec spec) {
		return spec.tilde + spec.omega + PackingUtils.getPolyZPackedBytes(spec.gamma1) * spec.l + spec.k;
	}
}

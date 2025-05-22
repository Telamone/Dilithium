package it.telami.commons.crypto.dilithium;

import java.security.KeyPair;

final class Dilithium {
	static KeyPair generateKeyPair (final DilithiumParameterSpec spec, final byte[] seed) {
		byte[] pu;
		final int tilde;
		final byte[] rho, k;
		byte[] pr;
		System.arraycopy(pu = Utils.getSHAKE256Digest(((tilde = spec.tilde) << 1) + 64, seed), 0, rho = new byte[tilde], 0, tilde);
		System.arraycopy(pu, tilde + 64, k = new byte[tilde], 0, tilde);
		System.arraycopy(pu, tilde, pr = new byte[64], 0, 64);
		final PolyVec[] a = expandA(rho, spec.k, spec.l);
		final PolyVec s1, s1hat, s2, t1, res = (t1 = (s1hat = (s1 = PolyVec
				.randomVec(pr, spec.eta, spec.l, 0))
				.copyAndNTT())
				.mulMatrixPointWiseMontgomery(a)
				.reduce()
				.invNTTtoMont()
				.add(s2 = PolyVec.randomVec(pr, spec.eta, spec.k, spec.l))
				.c_ADD_q())
				.powerRound();
		return new KeyPair(
				new DilithiumPublicKeyImpl(spec, rho, t1, pu = PackingUtils.packPubKey(tilde, rho, t1), a),
				new DilithiumPrivateKeyImpl(spec, rho, k, pr = Utils.crh(pu), s1, s2, res, PackingUtils.packPrvKey(spec.eta, tilde, rho, k, pr, s1, s2, res), a, s1hat, s2.ntt(), res.ntt()));
	}
	
	static byte[] sign (final DilithiumPrivateKeyImpl prv, final byte[] m) {
		final DilithiumParameterSpec spec;
		final byte[] sig
				= new byte[Utils.getSigLength(spec = prv.getSpec())], mu, rhoPrime
				= Utils.mu_crh(Utils.concatOrCopy(prv.k, mu
				= Utils.mu_crh(Utils.concatOrCopy(prv.tr, m))));
		final PolyVec[] a = prv.a;
		final int
				mul = mu.length,
				l = spec.l,
				g1 = spec.gamma1,
				g2 = spec.gamma2,
				tilde = spec.tilde,
				tau = spec.tau,
				beta = spec.beta,
				omega = spec.omega;
		int kappa = -1;
		final PolyVec
				s1 = prv.s1Hat,
				s2 = prv.s2Hat,
				t0 = prv.t0Hat;
		PolyVec z, y, w, res;
		Digest s;
		Poly cp;
		Hints h;
		for (;;) {
			PackingUtils.packW1(
					g2,
					res = (w = (y = PolyVec
							.randomVecGamma1(rhoPrime, l, g1, ++kappa))
							.copyAndNTT()
							.mulMatrixPointWiseMontgomery(a)
							.reduce()
							.invNTTtoMont()
							.c_ADD_q())
							.decompose(g2),
					sig);
			s = new Digest(256);
			s.update(mu, mul);
			s.update(sig, res
					.poly
					.length
					* PackingUtils
					.getPolyW1PackedBytes(g2));
			s.doOutput(sig, 0, tilde);
			if ((z = s1.copyAndPointWiseMontgomery(cp
					= generateChallenge
					(tilde, tau, sig)
					.ntt()))
					.invNTTtoMont()
					.add(y)
					.reduce()
					.chkNorm(g1 - beta)
					|| w.sub(s2
							.copyAndPointWiseMontgomery(cp)
							.invNTTtoMont())
					.reduce()
					.chkNorm(g2 - beta)
					|| (y = t0
					.copyAndPointWiseMontgomery(cp))
					.invNTTtoMont()
					.reduce()
					.chkNorm(g2)
					|| omega < (h = makeHints
					(g2, w.add(y).c_ADD_q(), res))
					.cnt)
				continue;
			PackingUtils.packSig(g1, omega, tilde, sig, sig, z, h.v);
			return sig;
		}
	}
	
	static boolean verify (final DilithiumPublicKeyImpl pk,
						   final byte[] sig,
						   final byte[] m) {
		final DilithiumParameterSpec spec;
		if (Utils.getSigLength(spec = pk.getSpec()) != sig.length)
			throw new DilithiumSignatureVerificationException("Invalid signature length");
		final byte[] mu, buf, c2, cappedSign;
		final int tilde;
		int off;
		System.arraycopy(
				sig,
				0,
				cappedSign = new byte[tilde = off = spec.tilde],
				0,
				tilde);
		final int l = spec.l, g1 = spec.gamma1, g2 = spec.gamma2;
		PolyVec z = new PolyVec(l);
		for (int
			 b = PackingUtils.getPolyZPackedBytes(g1),
			 i = 0;
			 i < l;
			 off += b, i++)
			z.poly[i] = PackingUtils.zUnpack(g1, sig, off);
		if (z.chkNorm(g1 - spec.beta))
			throw new DilithiumSignatureVerificationException("Norm check failed");
		final int k = spec.k, omega = spec.omega;
		final PolyVec h = new PolyVec(k);
		int c, n = 0;
		for (int i = 0; i < k; n = c, i++) {
			final Poly cp = h.poly[i] = new Poly();
			c = sig[off + omega + i] & 0xff;
			if (c < n || c > omega)
				throw new DilithiumSignatureVerificationException("Byte out of range");
			if (n < c) {
				cp.cof[sig[off + n++] & 0xff] = 1;
				for (int j = n; j < c; j++) {
					/* Coefficients are ordered for strong un_forge_ability */
					if ((sig[off + j] & 0xff) <= (sig[off + j - 1] & 0xff))
						throw new DilithiumSignatureVerificationException("Non crescent byte order");
					cp.cof[sig[off + j] & 0xff] = 1;
				}
			}
		}
		for (int j = n; j < omega; j++)
			if (sig[off + j] != 0)
				throw new DilithiumSignatureVerificationException("Non ending signature");
		z = useHint(g2, z
				.ntt()
				.mulMatrixPointWiseMontgomery(pk.a)
				.sub(pk.t1
						.copyAndShift()
						.ntt()
						.copyAndPointWiseMontgomery(
								generateChallenge(
										tilde,
										spec.tau,
										cappedSign)
										.ntt()))
				.reduce()
				.invNTTtoMont()
				.c_ADD_q(), h);
		mu = Utils.getSHAKE256Digest(64, Utils.crh(pk.getEncoded()), m);
		buf = new byte[PackingUtils.getPolyW1PackedBytes(g2) * z.poly.length];
		PackingUtils.packW1(g2, z, buf);
		c2 = Utils.getSHAKE256Digest(tilde, mu, buf);
		for (int i = 0; i < tilde; i++)
			if (cappedSign[i] != c2[i])
				return false;
		return true;
	}

	static PolyVec[] expandA (final byte[] rho,
							  final int k,
							  final int l) {
		final PolyVec[] a = new PolyVec[k];
		int i = -1, j;
		while (++i < k) {
			a[i] = new PolyVec(l);
			j = -1;
			while (++j < l)
				a[i].poly[j] = Poly.genUniformRandom(rho, (i << 8) + j);
		}
		return a;
	}

	private static PolyVec useHint (final int gamma2,
									final PolyVec u,
									final PolyVec h) {
		final int l = u.poly.length;
		int i = -1;
		while (++i < l)
			useHint(gamma2, u.poly[i], h.poly[i]);
		return u;
	}
	private static void useHint (final int gamma2,
								 final Poly u,
								 final Poly h) {
		int i = -1;
		while (i < 255)
			u.cof[++i] = useHint(gamma2, u.cof[i], h.cof[i]);
	}
	private static int useHint (final int gamma2,
								int a,
								final int hint) {
		int a1;
		if (gamma2 == 261888)
			a1 = (a + 127 >> 7) * 1025 + 2097152 >> 22 & 15;
		else {
			a1 = (a + 127 >> 7) * 11275 + 8388608 >> 24;
			a1 ^= 43 - a1 >> 31 & a1;
		}
		if (hint == 0)
			return a1;
		a -= a1 * gamma2 << 1;
		a -= 0x3ff000 - a >> 31 & 0x7fe001;
		return gamma2 == 261888
				? a > 0
				? a1 + 1 & 15
				: a1 - 1 & 15
				: a > 0
				? a1 == 43
				? 0
				: a1 + 1
				: a1 == 0
				? 43
				: a1 - 1;
	}

	private static class Hints {
		private PolyVec v;
		private int cnt;
	}
	private static class Hint {
		private Poly v;
		private int cnt;
	}
	private static Hints makeHints (final int gamma2,
									final PolyVec v0,
									final PolyVec v1) {
		final Hints hints = new Hints();
		final int l = v0.poly.length;
		hints.v = new PolyVec(l);
		int i = -1;
		while (++i < l) {
			final Hint hint = polyMakeHint(gamma2, v0.poly[i], v1.poly[i]);
			hints.cnt += hint.cnt;
			hints.v.poly[i] = hint.v;
		}
		return hints;

	}
	private static Hint polyMakeHint (final int gamma2,
									  final Poly a,
									  final Poly b) {
		final Hint hint;
		(hint = new Hint()).v = new Poly();
		int i = -1;
		while (i < 255)
			hint.cnt += hint.v.cof[++i] = makeHint(gamma2, a.cof[i], b.cof[i]);
		return hint;
	}

	private static int makeHint (final int gamma2,
								 final int a0,
								 final int a1) {
		return a0 <= gamma2
				|| a0 > 0x7fe001 - gamma2
				|| (a0 == 0x7fe001 - gamma2
				&& a1 == 0) ? 0 : 1;
	}

	private static Poly generateChallenge (final int tilde,
										   final int tau,
										   final byte[] seed) {
		final Poly pre = new Poly();
		int b, pos;
		long signs;
		final byte[] buf = new byte[136];
		final Digest s = new Digest(256);
		s.update(seed, tilde);
		s.doOutput(buf, 0, 136);
		signs = 0L;
		for (int i = 0; i < 8; i++)
			signs |= (long) (buf[i] & 0xff) << 8 * i;
		pos = 8;
		for (int i = 256 - tau; i < 256; i++) {
			do {
				if (pos >= 136) {
					s.doOutput(buf, 0, 136);
					pos = 0;
				}
				b = (buf[pos++] & 0xff);
			} while (b > i);
			pre.cof[i] = pre.cof[b];
			pre.cof[b] = (int) (1 - 2 * (signs & 1));
			signs >>= 1;
		}
		return pre;
	}
}

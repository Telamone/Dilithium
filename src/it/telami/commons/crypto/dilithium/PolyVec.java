package it.telami.commons.crypto.dilithium;

import java.util.Arrays;
import java.util.stream.IntStream;

final class PolyVec {
	final Poly[] poly;
	
	PolyVec (final int sz) {
		this.poly = new Poly[sz];
	}
	
	private PolyVec (final Poly[] poly) {
		this.poly = poly;
	}
	
	static PolyVec randomVec (final byte[] rho,
							  final int eta,
							  final int length,
							  final int nonce) {
		return new PolyVec(IntStream
				.range(0, length)
				.parallel()
				.mapToObj(i -> Poly.genRandom(
						rho,
						nonce + i,
						eta))
				.toArray(Poly[]::new));
	}
	
	static PolyVec randomVecGamma1 (final byte[] seed,
									final int length,
									final int gamma1,
									final int nonce) {
		return new PolyVec(IntStream
				.range(0, length)
				.parallel()
				.mapToObj(i -> Poly.genRandomGamma1(
						seed,
						length * nonce + i,
						gamma1))
				.toArray(Poly[]::new));
	}

	PolyVec ntt () {
		Arrays.stream(poly)
				.parallel()
				.forEach(Poly::ntt);
		return this;
	}

	PolyVec copyAndNTT () {
		return new PolyVec(Arrays
				.stream(poly)
				.parallel()
				.map(Poly::copyAndNTT)
				.toArray(Poly[]::new));
	}
	
	PolyVec reduce () {
		Arrays.stream(poly)
				.parallel()
				.forEach(Poly::reduce);
		return this;
	}
	
	PolyVec decompose (final int gamma2) {
		return new PolyVec(Arrays
				.stream(poly)
				.parallel()
				.map(p -> p.decompose(gamma2))
				.toArray(Poly[]::new));
	}

	PolyVec invNTTtoMont () {
		Arrays.stream(poly)
				.parallel()
				.forEach(Poly::invNTTtoMont);
		return this;
	}
	
	PolyVec add (final PolyVec o) {
		IntStream.range(0, poly.length)
				.parallel()
				.forEach(i -> poly[i]
						.add(o.poly[i]));
		return this;
	}

	PolyVec sub (final PolyVec o) {
		IntStream.range(0, poly.length)
				.parallel()
				.forEach(i -> poly[i]
						.sub(o.poly[i]));
		return this;
	}
	
	PolyVec c_ADD_q () {
		Arrays.stream(poly)
				.parallel()
				.forEach(Poly::c_ADD_q);
		return this;
	}
	
	PolyVec copyAndShift () {
		return new PolyVec(Arrays
				.stream(poly)
				.parallel()
				.map(Poly::shiftL)
				.toArray(Poly[]::new));
	}
	
	PolyVec powerRound () {
		return new PolyVec(Arrays
				.stream(poly)
				.parallel()
				.map(Poly::powerRound)
				.toArray(Poly[]::new));
	}
	
	PolyVec copyAndPointWiseMontgomery (final Poly u) {
		return new PolyVec(Arrays
				.stream(poly)
				.parallel()
				.map(u::multiplyAndReduce)
				.toArray(Poly[]::new));
	}

	PolyVec mulMatrixPointWiseMontgomery (final PolyVec[] m) {
		return new PolyVec(Arrays
				.stream(m)
				.parallel()
				.map(this::pointWiseAccMontgomery)
				.toArray(Poly[]::new));
	}
	private Poly pointWiseAccMontgomery (final PolyVec u) {
		final Poly w = u.poly[0].multiplyAndReduce(poly[0]);
		for (int i = 1; i < poly.length; i++)
			w.add(u.poly[i].multiplyAndReduce(poly[i]));
		return w;
	}
	
	boolean chkNorm (final int bound) {
		return Arrays.stream(poly)
				.parallel()
				.anyMatch(p -> p.chkNorm(bound));
	}
}

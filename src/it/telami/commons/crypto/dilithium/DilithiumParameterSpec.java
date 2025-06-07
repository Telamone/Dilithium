package it.telami.commons.crypto.dilithium;

import java.security.spec.AlgorithmParameterSpec;

@SuppressWarnings("all")
public final class DilithiumParameterSpec implements AlgorithmParameterSpec {
	public final String name;
	public final int k;
	public final int l;
	public final int gamma1;
	public final int gamma2;
	public final int tilde;
	public final int tau;
	public final int d;
	public final int challengeEntropy;
	public final int eta;
	public final int beta;
	public final int omega;

	private DilithiumParameterSpec (
			final String name,
			final int k,
			final int l,
			final int gamma1,
			final int gamma2,
			final int tilde,
			final int tau,
			final int d,
			final int challengeEntropy,
			final int eta,
			final int beta,
			final int omega) {
		this.name = name;
		this.k = k;
		this.l = l;
		this.gamma1 = gamma1;
		this.gamma2 = gamma2;
		this.tilde = tilde;
		this.tau = tau;
		this.d = d;
		this.challengeEntropy = challengeEntropy;
		this.eta = eta;
		this.beta = beta;
		this.omega = omega;
	}
	
	public final static DilithiumParameterSpec LEVEL_2 = new DilithiumParameterSpec("Dilithium level 2 parameters", 4, 4, 131072, 95232, 32, 39, 13, 192, 2, 78, 80);
	public final static DilithiumParameterSpec LEVEL_3 = new DilithiumParameterSpec("Dilithium level 3 parameters", 6, 5, 524288, 261888, 48, 49, 13, 225, 4, 196, 55);
	public final static DilithiumParameterSpec LEVEL_5 = new DilithiumParameterSpec("Dilithium level 5 parameters", 8, 7, 524288, 261888, 64, 60, 13, 257, 2, 120, 75);

	public String toString () {
		return name;
	}
}

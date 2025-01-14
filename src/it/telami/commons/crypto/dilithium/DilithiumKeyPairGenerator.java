package it.telami.commons.crypto.dilithium;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

@SuppressWarnings("unused")
public final class DilithiumKeyPairGenerator extends KeyPairGeneratorSpi {
	private DilithiumParameterSpec params;
	private SecureRandom random;

	@Override
	public void initialize (final int keySize, final SecureRandom random) {
		throw new UnsupportedOperationException("Dynamic key size not supported");
	}

	@Override
	public KeyPair generateKeyPair () {
		if (random == null || params == null)
			throw new IllegalStateException("The generator is not configured");
		final byte[] seed = new byte[32];
		try {
			random.nextBytes(seed);
			return Dilithium.generateKeyPair(params, seed);
		} finally {
			Arrays.fill(seed, (byte) 0);
		}
	}

	@Override
	public void initialize (final AlgorithmParameterSpec params, final SecureRandom random) throws InvalidAlgorithmParameterException {
		if (params instanceof final DilithiumParameterSpec dParams) {
			this.params = dParams;
			this.random = random;
		} else throw new InvalidAlgorithmParameterException("Inappropriate parameter type");
	}
}

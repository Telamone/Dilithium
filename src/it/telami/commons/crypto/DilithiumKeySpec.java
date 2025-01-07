package it.telami.commons.crypto;

import java.security.spec.KeySpec;

sealed class DilithiumKeySpec implements KeySpec permits DilithiumPrivateKeySpec, DilithiumPublicKeySpec {
	private final DilithiumParameterSpec paramSpec;
	private final byte[] bytes;
	DilithiumKeySpec (
			final DilithiumParameterSpec paramSpec,
			final byte[] bytes) {
		this.paramSpec = paramSpec;
		this.bytes = bytes;
	}

	public DilithiumParameterSpec getParameterSpec () {
		return paramSpec;
	}

	public byte[] getBytes () {
		return this.bytes;
	}
}

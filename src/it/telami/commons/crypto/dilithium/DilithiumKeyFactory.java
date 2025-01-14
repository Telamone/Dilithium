package it.telami.commons.crypto.dilithium;

import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.spec.KeySpec;

@SuppressWarnings("unused")
public final class DilithiumKeyFactory extends KeyFactorySpi {
	@Override
	public DilithiumPublicKey engineGeneratePublic (final KeySpec keySpec) {
		if (keySpec instanceof final DilithiumPublicKeySpec publicKeySpec)
			return PackingUtils.unpackPublicKey(publicKeySpec.getParameterSpec(), publicKeySpec.getBytes());
		throw new IllegalArgumentException("Invalid KeySpec");
	}

	@Override
	public DilithiumPrivateKey engineGeneratePrivate (final KeySpec keySpec) {
		if (keySpec instanceof final DilithiumPrivateKeySpec privateKeySpec)
			return PackingUtils.unpackPrivateKey(privateKeySpec.getParameterSpec(), privateKeySpec.getBytes());
		throw new IllegalArgumentException("Invalid KeySpec");
	}

	@Override
	public <T extends KeySpec> T engineGetKeySpec (final Key key, final Class<T> keySpec) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Key engineTranslateKey (final Key key) {
		throw new UnsupportedOperationException();
	}
}

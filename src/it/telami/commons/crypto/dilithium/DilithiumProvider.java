package it.telami.commons.crypto.dilithium;

import java.security.Provider;

@SuppressWarnings("unused")
public final class DilithiumProvider extends Provider {
	public DilithiumProvider () {
		super("Dilithium", "1.0.2", "Modified by Telami (this: https://github.com/Telamone/Dilithium) (original: https://github.com/mthiim/dilithium-java)");
		put("KeyPairGenerator.Dilithium", "it.telami.commons.crypto.dilithium.DilithiumKeyPairGenerator");
		put("Alg.Alias.KeyPairGenerator.Dilithium", "Dilithium");
		put("KeyFactory.Dilithium", "it.telami.commons.crypto.dilithium.DilithiumKeyFactory");
		put("Alg.Alias.KeyFactory.Dilithium", "Dilithium");
		put("Signature.Dilithium", "it.telami.commons.crypto.dilithium.DilithiumSignature");
		put("Alg.Alias.Signature.Dilithium", "Dilithium");
		put("Signature.ThreadSafeDilithium", "it.telami.commons.crypto.dilithium.ThreadSafeDilithiumSignature");
		put("Alg.Alias.Signature.ThreadSafeDilithium", "ThreadSafeDilithium");
	}
}

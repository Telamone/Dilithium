package it.telami.commons.crypto;

import java.security.Provider;

@SuppressWarnings("unused")
public final class DilithiumProvider extends Provider {
	public DilithiumProvider () {
		super("it.telami.commons.crypto.Dilithium", "1.0.0", "Modified by Telami (this: https://github.com/Telamone/Dilithium) (original: https://github.com/mthiim/dilithium-java)");
		put("KeyPairGenerator.it.telami.commons.crypto.Dilithium", "it.telami.commons.crypto.dilithium.it.telami.commons.crypto.DilithiumKeyPairGenerator");
		put("Alg.Alias.KeyPairGenerator.it.telami.commons.crypto.Dilithium", "it.telami.commons.crypto.Dilithium");
		put("KeyFactory.it.telami.commons.crypto.Dilithium", "it.telami.commons.crypto.dilithium.it.telami.commons.crypto.DilithiumKeyFactory");
		put("Alg.Alias.KeyFactory.it.telami.commons.crypto.Dilithium", "it.telami.commons.crypto.Dilithium");
		put("Signature.it.telami.commons.crypto.Dilithium", "it.telami.commons.crypto.dilithium.it.telami.commons.crypto.DilithiumSignature");
		put("Alg.Alias.Signature.it.telami.commons.crypto.Dilithium", "it.telami.commons.crypto.Dilithium");
		put("Signature.ThreadSafeDilithium", "it.telami.commons.crypto.dilithium.it.telami.commons.crypto.ThreadSafeDilithiumSignature");
		put("Alg.Alias.Signature.ThreadSafeDilithium", "ThreadSafeDilithium");
	}
}

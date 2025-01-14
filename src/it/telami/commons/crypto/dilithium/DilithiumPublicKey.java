package it.telami.commons.crypto.dilithium;

import java.security.PublicKey;

public sealed interface DilithiumPublicKey extends PublicKey permits DilithiumPublicKeyImpl {
	DilithiumParameterSpec getSpec ();
}

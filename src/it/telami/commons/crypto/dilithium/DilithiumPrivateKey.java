package it.telami.commons.crypto.dilithium;

import java.security.PrivateKey;

public sealed interface DilithiumPrivateKey extends PrivateKey permits DilithiumPrivateKeyImpl {
	DilithiumParameterSpec getSpec ();
}

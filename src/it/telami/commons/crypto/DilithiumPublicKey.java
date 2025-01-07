package it.telami.commons.crypto;

import java.security.PublicKey;

public sealed interface DilithiumPublicKey extends PublicKey permits DilithiumPublicKeyImpl {
	PolyVec getT1 ();
	DilithiumParameterSpec getSpec ();
}

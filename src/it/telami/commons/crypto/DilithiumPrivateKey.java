package it.telami.commons.crypto;

import java.security.PrivateKey;

public sealed interface DilithiumPrivateKey extends PrivateKey permits DilithiumPrivateKeyImpl {
	DilithiumParameterSpec getSpec ();
	byte[] getTr ();
	byte[] getK ();
	PolyVec getS1Hat ();
	PolyVec getS2Hat ();
	PolyVec getT0Hat ();
}

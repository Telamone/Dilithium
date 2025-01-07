package it.telami.commons.crypto;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;

@SuppressWarnings("unused")
public final class DilithiumSignature extends SignatureSpi {
	private static final int initialSize = Integer.getInteger("SignatureUpdateBufferSize", 1735);

	private DilithiumPublicKeyImpl pubKey;
	private DilithiumPrivateKeyImpl prvKey;
	private ByteArrayOutputStream byteAOS = new ByteArrayOutputStream(initialSize);
	
	@Override
	public void engineInitVerify (final PublicKey publicKey) {
		if (publicKey instanceof DilithiumPublicKeyImpl pk)
			pubKey = pk;
		else throw new IllegalArgumentException("Not a valid public key");
	}

	@Override
	public void engineInitSign (final PrivateKey privateKey) {
		if (privateKey instanceof DilithiumPrivateKeyImpl pk)
			prvKey = pk;
		else throw new IllegalArgumentException("Not a valid private key");
	}

	@Override
	public void engineUpdate (final byte b) {
		byteAOS.write(b & 0xff);
	}

	@Override
	public void engineUpdate (final byte[] b,
							  final int off,
							  final int len) {
		byteAOS.write(b, off, len);
	}

	@Override
	public byte[] engineSign () {
		if (prvKey == null)
			throw new IllegalStateException("Not in signing mode");
		try {
			return Dilithium.sign(prvKey, byteAOS.toByteArray());
		} finally {
			byteAOS = new ByteArrayOutputStream(initialSize);
		}
	}

	@Override
	public boolean engineVerify (final byte[] sigBytes) {
		if (pubKey == null)
			throw new IllegalStateException("Not in verify mode");
		try {
			return Dilithium.verify(pubKey, sigBytes, byteAOS.toByteArray());
		} finally {
			byteAOS = new ByteArrayOutputStream(initialSize);
		}
	}

	public void engineSetParameter (final String param, final Object value) {
		throw new UnsupportedOperationException();
	}
	public Object engineGetParameter (final String param)  {
		throw new UnsupportedOperationException();
	}
}

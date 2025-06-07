package it.telami.commons.crypto.dilithium;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;

@SuppressWarnings("unused")
public final class DilithiumSignature extends SignatureSpi {
	static final int initialSize = Integer.getInteger("DilithiumSignatureUpdateBufferSize", 4373);
	static final boolean shouldZero = Boolean.getBoolean("DilithiumSignatureShouldZero");

	private DilithiumPublicKeyImpl pubKey;
	private DilithiumPrivateKeyImpl prvKey;
	private int i;
	private byte[] data = new byte[initialSize];

	public void engineInitVerify (final PublicKey publicKey) {
		if (publicKey instanceof DilithiumPublicKeyImpl pk)
			pubKey = pk;
		else throw new IllegalArgumentException("Not a valid public key");
	}

	public void engineInitSign (final PrivateKey privateKey) {
		if (privateKey instanceof DilithiumPrivateKeyImpl pk)
			prvKey = pk;
		else throw new IllegalArgumentException("Not a valid private key");
	}

	public void engineUpdate (final byte b) {
		if (i < data.length)
			data[i++] = b;
		else {
			final byte[] data;
			System.arraycopy(
					this.data,
					0,
					data = new byte[i << 1],
					0,
					i);
			(this.data = data)[i++] = b;
		}
	}
	public void engineUpdate (final byte[] b,
							  final int off,
							  final int len) {
		if (data.length < i + len) {
			final byte[] data;
			System.arraycopy(
					this.data,
					0,
					data = new byte[i + len],
					0,
					i);
			System.arraycopy(
					b,
					0,
					data,
					i,
					len);
			i += len;
			this.data = data;
		} else {
			System.arraycopy(
					b,
					off,
					data,
					i,
					len);
			i += len;
		}
	}

	public byte[] engineSign () {
		if (prvKey != null) try {
			return Dilithium.sign(prvKey, data, i);
		} finally {
			if (shouldZero)
				while (i != 0)
					data[--i] = (byte) 0;
			else i = 0;
		}
		else throw new IllegalStateException("Not in signing mode");
	}

	public boolean engineVerify (final byte[] sigBytes) {
		if (pubKey != null) try {
			return Dilithium.verify(pubKey, sigBytes, data, i);
		} finally {
			if (shouldZero)
				while (i != 0)
					data[--i] = (byte) 0;
			else i = 0;
		}
		else throw new IllegalStateException("Not in verify mode");
	}

	public void engineSetParameter (final String param, final Object value) {
		throw new UnsupportedOperationException();
	}
	public Object engineGetParameter (final String param)  {
		throw new UnsupportedOperationException();
	}
}

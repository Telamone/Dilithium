package it.telami.commons.crypto.dilithium;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;

@SuppressWarnings("unused")
public final class ThreadSafeDilithiumSignature extends SignatureSpi {
	private static final class Data {
		private int i;
		private byte[] data = new byte[DilithiumSignature.initialSize];
		private Data () {}
	}

	private DilithiumPublicKeyImpl pubKey;
	private DilithiumPrivateKeyImpl prvKey;
	private final ThreadLocal<Data> data = ThreadLocal.withInitial(Data::new);

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
		final Data d;
		if ((d = data.get()).i < d.data.length)
			d.data[d.i++] = b;
		else {
			final byte[] data;
			System.arraycopy(
					d.data,
					0,
					data = new byte[d.i << 1],
					0,
					d.i);
			(d.data = data)[d.i++] = b;
		}
	}
	public void engineUpdate (final byte[] b,
							  final int off,
							  final int len) {
		final Data d;
		if ((d = data.get()).data.length < d.i + len) {
			final byte[] data;
			System.arraycopy(
					d.data,
					0,
					data = new byte[d.i + len],
					0,
					d.i);
			System.arraycopy(
					b,
					0,
					data,
					d.i,
					len);
			d.i += len;
			d.data = data;
		} else {
			System.arraycopy(
					b,
					off,
					d.data,
					d.i,
					len);
			d.i += len;
		}
	}

	public byte[] engineSign () {
		if (prvKey != null) {
			final Data d = data.get();
			try {
				return Dilithium.sign(prvKey, d.data, d.i);
			} finally {
				if (DilithiumSignature.shouldZero)
					while (d.i != 0)
						d.data[--d.i] = (byte) 0;
				else d.i = 0;
			}
		} else throw new IllegalStateException("Not in signing mode");
	}

	public boolean engineVerify (final byte[] sigBytes) {
		if (pubKey != null) {
			final Data d = data.get();
			try {
				return Dilithium.verify(pubKey, sigBytes, d.data, d.i);
			} finally {
				if (DilithiumSignature.shouldZero)
					while (d.i != 0)
						d.data[--d.i] = (byte) 0;
				else d.i = 0;
			}
		} else throw new IllegalStateException("Not in verify mode");
	}

	public void engineSetParameter (final String param, final Object value) {
		throw new UnsupportedOperationException();
	}
	public Object engineGetParameter (final String param)  {
		throw new UnsupportedOperationException();
	}
}

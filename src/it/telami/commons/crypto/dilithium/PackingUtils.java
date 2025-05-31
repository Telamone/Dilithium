package it.telami.commons.crypto.dilithium;

final class PackingUtils {
	static Poly etaUnpack (final int eta,
						   final byte[] bytes,
						   final int off) {
		final Poly p = new Poly();
		if (eta == 2) for (int i = 0; i < 32; i++) {
			p.cof[8 * i    ] = bytes[off + 3 * i    ]      & 7;
			p.cof[8 * i + 1] = bytes[off + 3 * i    ] >> 3 & 7;
			p.cof[8 * i + 2] = bytes[off + 3 * i    ] >> 6 & 3
					         | bytes[off + 3 * i + 1] << 2 & 4;
			p.cof[8 * i + 3] = bytes[off + 3 * i + 1] >> 1 & 7;
			p.cof[8 * i + 4] = bytes[off + 3 * i + 1] >> 4 & 7;
			p.cof[8 * i + 5] = bytes[off + 3 * i + 1] >> 7 & 1
				           	 | bytes[off + 3 * i + 2] << 1 & 6;
			p.cof[8 * i + 6] = bytes[off + 3 * i + 2] >> 2 & 7;
			p.cof[8 * i + 7] = bytes[off + 3 * i + 2] >> 5 & 7;
			p.cof[8 * i    ] = eta - p.cof[8 * i    ];
			p.cof[8 * i + 1] = eta - p.cof[8 * i + 1];
			p.cof[8 * i + 2] = eta - p.cof[8 * i + 2];
			p.cof[8 * i + 3] = eta - p.cof[8 * i + 3];
			p.cof[8 * i + 4] = eta - p.cof[8 * i + 4];
			p.cof[8 * i + 5] = eta - p.cof[8 * i + 5];
			p.cof[8 * i + 6] = eta - p.cof[8 * i + 6];
			p.cof[8 * i + 7] = eta - p.cof[8 * i + 7];
		} else for (int i = 0; i < 128; i++) {
			p.cof[2 * i    ] = bytes[off + i]      & 0xf;
			p.cof[2 * i + 1] = bytes[off + i] >> 4 & 0xf;
			p.cof[2 * i    ] = eta - p.cof[2 * i    ];
			p.cof[2 * i + 1] = eta - p.cof[2 * i + 1];
		}
		return p;
	}

	static int getPolyEtaPackedBytes (final int eta) {
		return eta != 2 ? 128 : 96;
	}

	static int getPolyW1PackedBytes (final int gamma2) {
		return gamma2 != 261888 ? 192 : 128;
	}

	static int getPolyZPackedBytes (final int gamma1) {
		return gamma1 != 131072 ? 640 : 576;
	}

	static byte[] packPrvKey (final int eta,
							  final int tilde,
							  final byte[] rho,
							  final byte[] k,
							  final byte[] tr,
							  final PolyVec s1,
							  final PolyVec s2,
							  final PolyVec t0) {
		final int
				s1l = s1.poly.length,
				s2l = s2.poly.length,
				t0l = t0.poly.length;
		final int p = getPolyEtaPackedBytes(eta);
		final byte[] buf = new byte[(tilde << 1) + 32 + s1l * p + s2l * (p + 416)];
        System.arraycopy(rho, 0, buf, 0, tilde);
        System.arraycopy(k, 0, buf, tilde, tilde);
        System.arraycopy(tr, 0, buf, tilde << 1, 32);
		int off = (tilde << 1) + 32 - p;
		for (int i = 0; i < s1l; i++)
			s1.poly[i].etaPack(buf, off += p, eta);
		for (int i = 0; i < s2l; i++)
			s2.poly[i].etaPack(buf, off += p, eta);
		off = off - 416 + p;
		for (int i = 0; i < t0l; i++)
			t0.poly[i].t0Pack(buf, off += 416);
		return buf;
	}

	static byte[] packPubKey (final int tilde,
							  final byte[] rho,
							  final PolyVec t) {
		final int tl = t.poly.length;
		final byte[] pk = new byte[tilde + tl * 320];
        System.arraycopy(rho, 0, pk, 0, tilde);
		for (int i = 0; i < tl; i++)
			t.poly[i].t1Pack(pk, tilde + i * 320);
		return pk;
	}

	static void packSig (final int gamma1,
						 final int omega,
						 final int tilde,
						 final byte[] sig,
						 final byte[] c,
						 final PolyVec z,
						 final PolyVec h) {
		final int polyZPackedBytes;
        System.arraycopy(c, 0, sig, 0, tilde);
		int off = tilde - (polyZPackedBytes = getPolyZPackedBytes(gamma1)),
				l = z.poly.length,
				i = -1,
				j,
				k = 0;
		while (++i < l)
			z.poly[i].zPack(gamma1, sig, off += polyZPackedBytes);
		off += polyZPackedBytes;
		l = omega + h.poly.length;
		i = -1;
		while (++i < l)
			sig[off + i] = 0;
		l -= omega;
		i = -1;
		while (++i < l) {
			j = -1;
			while (j < 255)
				if (h.poly[i].cof[++j] != 0)
					sig[off + k++] = (byte) j;
			sig[off + omega + i] = (byte) k;
		}
	}

	static void packW1 (final int gamma2,
					    final PolyVec w,
					    final byte[] sig) {
		final int polyW1PackedBytes = getPolyW1PackedBytes(gamma2), wl = w.poly.length;
		for (int i = 0, off = -polyW1PackedBytes; i < wl; i++)
			w.poly[i].w1pack(gamma2, sig, off += polyW1PackedBytes);
	}

	static Poly t0unpack (final byte[] bytes, final int off) {
		final Poly p = new Poly();
		for (int i = 0; i < 32; i++) {
			p.cof[8 * i    ]  =  bytes[off + 13 * i     ] & 0xff;
			p.cof[8 * i    ] |= (bytes[off + 13 * i + 1 ] & 0x1f) << 8;
			p.cof[8 * i + 1]  = (bytes[off + 13 * i + 1 ] & 0xff) >> 5;
			p.cof[8 * i + 1] |= (bytes[off + 13 * i + 2 ] & 0xff) << 3;
			p.cof[8 * i + 1] |= (bytes[off + 13 * i + 3 ] & 0x3 ) << 11;
			p.cof[8 * i + 2]  = (bytes[off + 13 * i + 3 ] & 0xff) >> 2;
			p.cof[8 * i + 2] |= (bytes[off + 13 * i + 4 ] & 0x7f) << 6;
			p.cof[8 * i + 3]  = (bytes[off + 13 * i + 4 ] & 0xff) >> 7;
			p.cof[8 * i + 3] |= (bytes[off + 13 * i + 5 ] & 0xff) << 1;
			p.cof[8 * i + 3] |= (bytes[off + 13 * i + 6 ] & 0xf ) << 9;
			p.cof[8 * i + 4]  = (bytes[off + 13 * i + 6 ] & 0xff) >> 4;
			p.cof[8 * i + 4] |= (bytes[off + 13 * i + 7 ] & 0xff) << 4;
			p.cof[8 * i + 4] |= (bytes[off + 13 * i + 8 ] & 0x1 ) << 12;
			p.cof[8 * i + 5]  = (bytes[off + 13 * i + 8 ] & 0xff) >> 1;
			p.cof[8 * i + 5] |= (bytes[off + 13 * i + 9 ] & 0x3f) << 7;
			p.cof[8 * i + 6]  = (bytes[off + 13 * i + 9 ] & 0xff) >> 6;
			p.cof[8 * i + 6] |= (bytes[off + 13 * i + 10] & 0xff) << 2;
			p.cof[8 * i + 6] |= (bytes[off + 13 * i + 11] & 0x7 ) << 10;
			p.cof[8 * i + 7]  = (bytes[off + 13 * i + 11] & 0xff) >> 3;
			p.cof[8 * i + 7] |= (bytes[off + 13 * i + 12] & 0xff) << 5;
			p.cof[8 * i    ]  =  4096 - p.cof[8 * i    ];
			p.cof[8 * i + 1]  =  4096 - p.cof[8 * i + 1];
			p.cof[8 * i + 2]  =  4096 - p.cof[8 * i + 2];
			p.cof[8 * i + 3]  =  4096 - p.cof[8 * i + 3];
			p.cof[8 * i + 4]  =  4096 - p.cof[8 * i + 4];
			p.cof[8 * i + 5]  =  4096 - p.cof[8 * i + 5];
			p.cof[8 * i + 6]  =  4096 - p.cof[8 * i + 6];
			p.cof[8 * i + 7]  =  4096 - p.cof[8 * i + 7];
		}
		return p;
	}

	static Poly t1unpack (final byte[] bytes, final int off) {
		final Poly p = new Poly();
		for (int i = 0; i < 64; i++) {
			p.cof[4 * i    ] = bytes[off + 5 * i    ]      & 0xff
					         | bytes[off + 5 * i + 1] << 8 & 0x300;
			p.cof[4 * i + 1] = bytes[off + 5 * i + 1] >> 2 & 0x3f
					         | bytes[off + 5 * i + 2] << 6 & 0x3c0;
			p.cof[4 * i + 2] = bytes[off + 5 * i + 2] >> 4 & 0xf
					         | bytes[off + 5 * i + 3] << 4 & 0x3f0;
			p.cof[4 * i + 3] = bytes[off + 5 * i + 3] >> 6 & 0x3
					         | bytes[off + 5 * i + 4] << 2 & 0x3fc;
		}
		return p;
	}

	static DilithiumPrivateKey unpackPrivateKey (final DilithiumParameterSpec parameterSpec, final byte[] bytes) {
		final int eta = parameterSpec.eta, polyEtaPackedBytes = getPolyEtaPackedBytes(eta), tilde;
		final byte[] rho;
        System.arraycopy(bytes, 0, rho = new byte[tilde = parameterSpec.tilde], 0, tilde);
		final byte[] key;
        System.arraycopy(bytes, tilde, key = new byte[tilde], 0, tilde);
		final byte[] tr;
        System.arraycopy(bytes, tilde << 1, tr = new byte[32], 0, 32);
		int off = (tilde << 1) + 32 - polyEtaPackedBytes;
		final int l, k;
		final PolyVec s1 = new PolyVec(l = parameterSpec.l);
		for (int i = 0; i < l; i++)
			s1.poly[i] = etaUnpack(eta, bytes, off += polyEtaPackedBytes);
		final PolyVec s2 = new PolyVec(k = parameterSpec.k);
		for (int i = 0; i < k; i++)
			s2.poly[i] = etaUnpack(eta, bytes, off += polyEtaPackedBytes);
		off = off - 416 + polyEtaPackedBytes;
		final PolyVec t0 = new PolyVec(k);
		for (int i = 0; i < k; i++)
		    t0.poly[i] = t0unpack(bytes, off += 416);
		return new DilithiumPrivateKeyImpl(
				parameterSpec,
				rho,
				key,
				tr,
				s1,
				s2,
				t0,
				bytes,
				Dilithium.expandA(rho, k, l),
				s1.copyAndNTT(),
				s2.copyAndNTT(),
				t0.copyAndNTT());
	}

	static DilithiumPublicKey unpackPublicKey (final DilithiumParameterSpec parameterSpec, final byte[] bytes) {
		final int tilde;
		final byte[] rho;
        System.arraycopy(bytes, 0, rho = new byte[tilde = parameterSpec.tilde], 0, tilde);
		int off = tilde - 320;
		final int k;
		final PolyVec p = new PolyVec(k = parameterSpec.k);
		for (int i = 0; i < k; i++)
			p.poly[i] = t1unpack(bytes, off += 320);
		return new DilithiumPublicKeyImpl(
				parameterSpec,
				rho,
				p,
				bytes,
				Dilithium.expandA(rho, k, parameterSpec.l));
	}

	static Poly zUnpack (final int gamma1,
						 final byte[] sig,
						 final int off) {
		final Poly pre = new Poly();
		if (gamma1 != 131072) for (int i = 0; i < 128; ++i) {
			pre.cof[2 * i    ]  = sig[off + 5 * i    ]       & 0xff;
			pre.cof[2 * i    ] |= sig[off + 5 * i + 1] << 8  & 0xff00;
			pre.cof[2 * i    ] |= sig[off + 5 * i + 2] << 16 & 0xf0000;
			pre.cof[2 * i + 1]  = sig[off + 5 * i + 2] >> 4  & 0xf;
			pre.cof[2 * i + 1] |= sig[off + 5 * i + 3] << 4  & 0xff0;
			pre.cof[2 * i + 1] |= sig[off + 5 * i + 4] << 12 & 0xff000;
			pre.cof[2 * i    ] = gamma1 - pre.cof[2 * i    ];
			pre.cof[2 * i + 1] = gamma1 - pre.cof[2 * i + 1];
		} else for (int i = 0; i < 64; i++) {
			pre.cof[4 * i    ]  = sig[off + 9 * i    ]       & 0xff;
			pre.cof[4 * i    ] |= sig[off + 9 * i + 1] << 8  & 0xff00;
			pre.cof[4 * i    ] |= sig[off + 9 * i + 2] << 16 & 0x30000;
			pre.cof[4 * i + 1]  = sig[off + 9 * i + 2] >> 2  & 0x3f;
			pre.cof[4 * i + 1] |= sig[off + 9 * i + 3] << 6  & 0x3fc0;
			pre.cof[4 * i + 1] |= sig[off + 9 * i + 4] << 14 & 0x3c000;
			pre.cof[4 * i + 2]  = sig[off + 9 * i + 4] >> 4  & 0xf;
			pre.cof[4 * i + 2] |= sig[off + 9 * i + 5] << 4  & 0xff0;
			pre.cof[4 * i + 2] |= sig[off + 9 * i + 6] << 12 & 0x3f000;
			pre.cof[4 * i + 3]  = sig[off + 9 * i + 6] >> 6  & 0x3;
			pre.cof[4 * i + 3] |= sig[off + 9 * i + 7] << 2  & 0x3fc;
			pre.cof[4 * i + 3] |= sig[off + 9 * i + 8] << 10 & 0x3fc00;
			pre.cof[4 * i    ] = gamma1 - pre.cof[4 * i    ];
			pre.cof[4 * i + 1] = gamma1 - pre.cof[4 * i + 1];
			pre.cof[4 * i + 2] = gamma1 - pre.cof[4 * i + 2];
			pre.cof[4 * i + 3] = gamma1 - pre.cof[4 * i + 3];
		}
		return pre;
	}

}

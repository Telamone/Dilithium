package it.telami.commons.crypto.dilithium;

final class Poly {
	private static final long[] zetas = new long[] {
			0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
			1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
			2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
			-2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
			2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
			-3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
			-1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
			811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
			-3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
			-1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
			3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
			-671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
			-3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
			-3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
			189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
			1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
			2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
			266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
			900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
			-655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
			342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
			2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
			-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
			-1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
			-1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
			-542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
			-2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
			-3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
			-3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
			-426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
			-2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
			-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782
	};

	final int[] cof;

	private Poly (final int[] cof) {
		this.cof = cof;
	}

	Poly () {
		cof = new int[256];
	}

	void add (final Poly p) {
		int i = -1;
        while (i < 255)
			cof[++i] = cof[i] + p.cof[i] % 0x7fe001;
	}

	void sub (final Poly p) {
		int i = -1;
		while (i < 255)
			cof[++i] = cof[i] - p.cof[i] % 0x7fe001;
	}

	static Poly genRandom (final byte[] rho,
						   final int nonce,
						   final int eta) {
		final Digest s;
		(s = new Digest(256)).update(rho, rho.length);
		s.update(new byte[] {
				(byte) (nonce & 0xff),
				(byte) ((nonce >> 8) & 0xff)
		}, 2);
		int ctr;
		final byte[] bb;
		s.doOutput(bb = new byte[ctr = eta * 68], 0, ctr);
		final Poly pre = new Poly();
		ctr = rej_eta(eta, pre.cof, 0, 256, bb, ctr);
		while (ctr < 256) {
			s.doOutput(bb, 0, 136);
			ctr += rej_eta(eta, pre.cof, ctr, 256 - ctr, bb, 136);
		}
		return pre;
	}

	private static int rej_eta (final int eta,
								final int[] cof,
								final int off,
								final int len,
								final byte[] buf,
								final int bufLen) {
		int ctr = 0, pos = 0, t0, t1;
		if (eta != 2) while (ctr < len && pos < bufLen) {
			t0 = buf[pos] & 15;
			t1 = (buf[pos++] >> 4) & 15;
			if (t0 < 9)
				cof[off + ctr++] = 4 - t0;
			if (t1 < 9 && ctr < len)
				cof[off + ctr++] = 4 - t1;
		} else while (ctr < len && pos < bufLen) {
			t0 = buf[pos] & 15;
			t1 = (buf[pos++] >> 4) & 15;
			if (t0 < 15)
				cof[off + ctr++] = 2 - t0 + (205 * t0 >>> 10) * 5;
			if (t1 < 15 && ctr < len)
				cof[off + ctr++] = 2 - t1 + (205 * t1 >>> 10) * 5;
		}
		return ctr;
	}

	Poly ntt () {
		int len, start, j, k = 0;
		long zeta;
		int t;
		for (len = 128; len > 0; len >>= 1)
			for (start = 0; start < 256; start = j + len) {
				zeta = zetas[++k];
				for (j = (start += len) - len; j < start; ++j)
					cof[j + len]
							= (cof[j]
							+= t
							= reduce(zeta * cof[j + len]))
							- t
							- t;
			}
		return this;
	}
	Poly copyAndNTT () {
		final Poly c = new Poly(cof.clone());
		int len, start, j, k = 0;
		long zeta;
		int t;
		for (len = 128; len > 0; len >>= 1)
			for (start = 0; start < 256; start = j + len) {
				zeta = zetas[++k];
				for (j = (start += len) - len; j < start; ++j)
					c.cof[j + len]
							= (c.cof[j]
							+= t
							= reduce(zeta * c.cof[j + len]))
							- t
							- t;
			}
		return c;
	}

	private static int reduce (final long a) {
		return (int) ((a + (int) (a * 0x3802001L) * 0xffffffffff801fffL) >> 32);
	}
	static Poly genUniformRandom (final byte[] rho, final int nonce) {
		int ctr, off, bufLen = 840;
		final Digest s;
		(s = new Digest(128)).update(rho, rho.length);
		s.update(new byte[] {
				(byte) (nonce & 0xff),
				(byte) ((nonce >> 8) & 0xff)
		}, 2);
		final byte[] buf;
		s.doOutput(buf = new byte[840], 0, 840);
		final Poly pre;
		ctr = rej_uniform((pre = new Poly()).cof, 0, 256, buf, 840);
		while (ctr < 256) {
			off = bufLen % 3;
			for (int i = 0; i < off; i++)
				buf[i] = buf[bufLen - off + i];
			s.doOutput(buf, off, 168);
			ctr += rej_uniform(pre.cof, ctr, 256 - ctr, buf, bufLen = 168 + off);
		}
		return pre;
	}

	private static int rej_uniform (final int[] cof,
									final int off,
									final int len,
									final byte[] buf,
									final int bufLen) {
		int ctr = 0, pos = 0, t;
		while (ctr < len && pos + 2 < bufLen)
			if ((t = buf[pos     ] & 0xff       |
					(buf[pos +  1] & 0xff) << 8 |
					(buf[pos += 2] & 0x7f) << 16)
					< 0x7fe001)
				cof[off + ctr++] = t;
		return ctr;
	}

	Poly multiplyAndReduce (final Poly other) {
		final Poly c = new Poly();
		int i = -1;
		while (i < 255)
			c.cof[++i] = reduce((long) cof[i] * other.cof[i]);
		return c;
	}

	void reduce () {
		int i = -1;
		while (i < 255)
			cof[++i] += (cof[i] + 0x400000 >> 23) * 0xff801fff;
	}

	void invNTTtoMont () {
		int start, len, j, k = 256, t;
		long zeta;
		for (len = 1; len < 256; len <<= 1)
			for (start = 0; start < 256; start = j + len) {
				zeta = -zetas[--k];
				for (j = (start += len) - len; j < start; ++j) {
					cof[j] = (t = cof[j]) + cof[j + len];
					cof[j + len] = reduce(zeta * (t - cof[j + len]));
				}
			}
		j = -1;
		while (j < 255)
			cof[++j] = reduce(41978L * cof[j]);
	}

	void c_ADD_q () {
		int i = -1;
		while (i < 255)
			cof[++i] += cof[i] >> 31 & 0x7fe001;
	}

	Poly powerRound () {
		final Poly o = new Poly();
		int i = -1;
		while (i < 255)
			o.cof[++i]
					= cof[i]
					- ((cof[i]
					= cof[i]
					+ 4095
					>> 13)
					<< 13);
		return o;
	}

	void t1Pack (final byte[] r, final int off) {
		int i = -1;
		while (i < 63) {
			r[off + 5 * ++i    ] = (byte) ((cof[(i << 2)    ]      )                           );
			r[off + 5 *   i + 1] = (byte) ((cof[(i << 2)    ] >>> 8) | (cof[(i << 2) + 1] << 2));
			r[off + 5 *   i + 2] = (byte) ((cof[(i << 2) + 1] >>> 6) | (cof[(i << 2) + 2] << 4));
			r[off + 5 *   i + 3] = (byte) ((cof[(i << 2) + 2] >>> 4) | (cof[(i << 2) + 3] << 6));
			r[off + 5 *   i + 4] = (byte) ((cof[(i << 2) + 3] >>> 2)                           );
		}
	}

	void etaPack (final byte[] buf,
				  final int off,
				  final int eta) {
		int i = -1;
		if (eta != 2) {
			while (i < 127)
				buf[off + ++i] = (byte) (eta - cof[i << 1] | eta - cof[(i << 1) + 1] << 4);
		} else {
			final byte[] t = new byte[8];
			while (i < 31) {
				t[0] = (byte) (eta - cof[(++i << 3)    ]);
				t[1] = (byte) (eta - cof[(  i << 3) + 1]);
				t[2] = (byte) (eta - cof[(  i << 3) + 2]);
				t[3] = (byte) (eta - cof[(  i << 3) + 3]);
				t[4] = (byte) (eta - cof[(  i << 3) + 4]);
				t[5] = (byte) (eta - cof[(  i << 3) + 5]);
				t[6] = (byte) (eta - cof[(  i << 3) + 6]);
				t[7] = (byte) (eta - cof[(  i << 3) + 7]);
				buf[off + 3 * i    ] = (byte) ((t[0]     ) | (t[1] << 3) | (t[2] << 6)              );
				buf[off + 3 * i + 1] = (byte) ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
				buf[off + 3 * i + 2] = (byte) ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)              );
			}
		}
	}

	void t0Pack (final byte[] buf, final int off) {
		int i = -1;
		final int[] t = new int[8];
		while (i < 31) {
			t[0] = 4096 - this.cof[(++i << 3)    ];
			t[1] = 4096 - this.cof[(  i << 3) + 1];
			t[2] = 4096 - this.cof[(  i << 3) + 2];
			t[3] = 4096 - this.cof[(  i << 3) + 3];
			t[4] = 4096 - this.cof[(  i << 3) + 4];
			t[5] = 4096 - this.cof[(  i << 3) + 5];
			t[6] = 4096 - this.cof[(  i << 3) + 6];
			t[7] = 4096 - this.cof[(  i << 3) + 7];
			buf[off + 13 * i    ] = (byte) t[0];
			buf[off + 13 * i + 1] = (byte) (t[0] >> 8);
			buf[off + 13 * i + 1] |= (byte) (t[1] << 5);
			buf[off + 13 * i + 2] = (byte) (t[1] >> 3);
			buf[off + 13 * i + 3] = (byte) (t[1] >> 11);
			buf[off + 13 * i + 3] |= (byte) (t[2] << 2);
			buf[off + 13 * i + 4] = (byte) (t[2] >> 6);
			buf[off + 13 * i + 4] |= (byte) (t[3] << 7);
			buf[off + 13 * i + 5] = (byte) (t[3] >> 1);
			buf[off + 13 * i + 6] = (byte) (t[3] >> 9);
			buf[off + 13 * i + 6] |= (byte) (t[4] << 4);
			buf[off + 13 * i + 7] = (byte) (t[4] >> 4);
			buf[off + 13 * i + 8] = (byte) (t[4] >> 12);
			buf[off + 13 * i + 8] |= (byte) (t[5] << 1);
			buf[off + 13 * i + 9] = (byte) (t[5] >> 7);
			buf[off + 13 * i + 9] |= (byte) (t[6] << 6);
			buf[off + 13 * i + 10] = (byte) (t[6] >> 2);
			buf[off + 13 * i + 11] = (byte) (t[6] >> 10);
			buf[off + 13 * i + 11] |= (byte) (t[7] << 3);
			buf[off + 13 * i + 12] = (byte) (t[7] >> 5);
		}
	}

	static Poly genRandomGamma1 (final byte[] seed,
								 final int nonce,
								 final int gamma1) {
		final Digest s;
		(s = new Digest(256)).update(seed, seed.length);
		s.update(new byte[] {
				(byte) (nonce & 0xff),
				(byte) ((nonce >> 8) & 0xff)
		}, 2);
		final byte[] buf;
		s.doOutput(buf = new byte[680], 0, 680);
		final Poly pre = new Poly();
		int i = -1;
		if (gamma1 != 131072) while (i < 127) {
			pre.cof[(++i << 1)    ] =   buf[5 * i    ] & 0xff;
			pre.cof[(  i << 1)    ] |= (buf[5 * i + 1] & 0xff) << 8;
			pre.cof[(  i << 1)    ] |= (buf[5 * i + 2] & 0xf) << 16;
			pre.cof[(  i << 1) + 1] =  (buf[5 * i + 2] & 0xff) >> 4;
			pre.cof[(  i << 1) + 1] |= (buf[5 * i + 3] & 0xff) << 4;
			pre.cof[(  i << 1) + 1] |= (buf[5 * i + 4] & 0xff) << 12;
			pre.cof[(  i << 1)    ] = gamma1 - pre.cof[(i << 1)    ];
			pre.cof[(  i << 1) + 1] = gamma1 - pre.cof[(i << 1) + 1];
		} else while (i < 63) {
			pre.cof[(++i << 2)    ] =   buf[9 * i    ] & 0xff;
			pre.cof[(  i << 2)    ] |= (buf[9 * i + 1] & 0xff) << 8;
			pre.cof[(  i << 2)    ] |= (buf[9 * i + 2] & 0xff) << 16;
			pre.cof[(  i << 2)    ] &= 0x3ffff;
			pre.cof[(  i << 2) + 1] =  (buf[9 * i + 2] & 0xff) >> 2;
			pre.cof[(  i << 2) + 1] |= (buf[9 * i + 3] & 0xff) << 6;
			pre.cof[(  i << 2) + 1] |= (buf[9 * i + 4] & 0xff) << 14;
			pre.cof[(  i << 2) + 1] &= 0x3ffff;
			pre.cof[(  i << 2) + 2] =  (buf[9 * i + 4] & 0xff) >> 4;
			pre.cof[(  i << 2) + 2] |= (buf[9 * i + 5] & 0xff) << 4;
			pre.cof[(  i << 2) + 2] |= (buf[9 * i + 6] & 0xff) << 12;
			pre.cof[(  i << 2) + 2] &= 0x3ffff;
			pre.cof[(  i << 2) + 3] =  (buf[9 * i + 6] & 0xff) >> 6;
			pre.cof[(  i << 2) + 3] |= (buf[9 * i + 7] & 0xff) << 2;
			pre.cof[(  i << 2) + 3] |= (buf[9 * i + 8] & 0xff) << 10;
			pre.cof[(  i << 2)    ] = gamma1 - pre.cof[(i << 2)    ];
			pre.cof[(  i << 2) + 1] = gamma1 - pre.cof[(i << 2) + 1];
			pre.cof[(  i << 2) + 2] = gamma1 - pre.cof[(i << 2) + 2];
			pre.cof[(  i << 2) + 3] = gamma1 - pre.cof[(i << 2) + 3];
		}
		return pre;
	}

	Poly decompose (final int gamma2) {
		final Poly o = new Poly();
		int i = -1;
		while (i < 255) {
			final int a = cof[++i];
			int a1 = a + 127 >> 7;
			if (gamma2 != 261888) {
				a1 = a1 * 11275 + 8388608 >> 24;
				a1 ^= 43 - a1 >> 31 & a1;
			} else {
				a1 = a1 * 1025 + 2097152 >> 22 & 15;
			}
			cof[i] = a - ((o.cof[i] = a1) * gamma2 << 1);
			cof[i] -= 4190208 - cof[i] >> 31 & 0x7fe001;
		}
		return o;
	}

	void w1pack (final int gamma2,
				 final byte[] buf,
				 final int off) {
		int i = -1;
		if (gamma2 != 95232) {
			while (i < 127)
				buf[off + ++i] = (byte) (this.cof[i << 1] | (this.cof[(i << 1) + 1] << 4));
		} else {
			while (i < 63) {
				buf[off + 3 * ++i    ]  = (byte)  this.cof[(i << 2)    ]      ;
				buf[off + 3 *   i    ] |= (byte) (this.cof[(i << 2) + 1] << 6);
				buf[off + 3 *   i + 1]  = (byte) (this.cof[(i << 2) + 1] >> 2);
				buf[off + 3 *   i + 1] |= (byte) (this.cof[(i << 2) + 2] << 4);
				buf[off + 3 *   i + 2]  = (byte) (this.cof[(i << 2) + 2] >> 4);
				buf[off + 3 *   i + 2] |= (byte) (this.cof[(i << 2) + 3] << 2);
			}
		}
	}

	boolean chkNorm (final int b) {
		if (b > 1047552)
			return true;
		/*
		 * It's okay to leak which coefficient violates the bound since the probability
		 * for each coefficient is independent of secret data, but we must not leak the
		 * sign of the centralized representative.
		 */
		int i = -1;
		while (i < 255)
			if (cof[++i] - (cof[i] >> 31 & cof[i] << 1) >= b)
				return true;
		return false;
	}

	void zPack (final int gamma1,
				final byte[] sign,
				final int off) {
		if (gamma1 != 131072) {
			int a, b;
			for (int i = 0; i < 128; i++) {
				a = gamma1 - cof[(i << 1)    ];
				b = gamma1 - cof[(i << 1) + 1];
				sign[off + 5 * i    ]  = (byte)  a       ;
				sign[off + 5 * i + 1]  = (byte) (a >> 8 );
				sign[off + 5 * i + 2]  = (byte) (a >> 16);
				sign[off + 5 * i + 2] |= (byte) (b << 4 );
				sign[off + 5 * i + 3]  = (byte) (b >> 4 );
				sign[off + 5 * i + 4]  = (byte) (b >> 12);
			}
		} else {
			int a, b, c, d;
			for (int i = 0; i < 64; i++) {
				a = gamma1 - cof[(i << 2)    ];
				b = gamma1 - cof[(i << 2) + 1];
				c = gamma1 - cof[(i << 2) + 2];
				d = gamma1 - cof[(i << 2) + 3];
				sign[off + 9 * i    ]  = (byte)  a       ;
				sign[off + 9 * i + 1]  = (byte) (a >> 8 );
				sign[off + 9 * i + 2]  = (byte) (a >> 16);
				sign[off + 9 * i + 2] |= (byte) (b << 2 );
				sign[off + 9 * i + 3]  = (byte) (b >> 6 );
				sign[off + 9 * i + 4]  = (byte) (b >> 14);
				sign[off + 9 * i + 4] |= (byte) (c << 4 );
				sign[off + 9 * i + 5]  = (byte) (c >> 4 );
				sign[off + 9 * i + 6]  = (byte) (c >> 12);
				sign[off + 9 * i + 6] |= (byte) (d << 6 );
				sign[off + 9 * i + 7]  = (byte) (d >> 2 );
				sign[off + 9 * i + 8]  = (byte) (d >> 10);
			}
		}
	}

	Poly shiftL () {
		final Poly c = new Poly();
		int i = -1;
		while (i < 255)
			c.cof[++i] = cof[i] << 13;
		return c;
	}
}

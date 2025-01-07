package it.telami.commons.crypto;

final class Digest {
    private final long[] state;
    private final byte[] dataQueue;
    private final int rate;
    private int bitsInQueue;
    private boolean notSqueezing;

    Digest (final int bits) {
        state = new long[25];
        dataQueue = new byte[192];
        rate = 1600 - (bits << 1);
        notSqueezing = true;
    }

    void doOutput (final byte[] out,
                   final int outOff,
                   final int outLen) {
        if (notSqueezing) {
            dataQueue[bitsInQueue >>> 3] = (byte) 0xf;
            bitsInQueue += 4;
        }
        squeeze(out, outOff, (long) outLen << 3);
    }
    void update (final byte[] data, final int len) {
        final long[] state = this.state;
        final byte[] dataQueue = this.dataQueue;
        final int bytesInQueue, rateBytes, available;
        available = (rateBytes = rate >>> 3) -
                (bytesInQueue = bitsInQueue >>> 3);
        if (len < available) {
            System.arraycopy(
                    data,
                    0,
                    dataQueue,
                    bytesInQueue,
                    len);
            bitsInQueue += len << 3;
            return;
        }
        int count = 0;
        if (bytesInQueue > 0) {
            System.arraycopy(
                    data,
                    0,
                    dataQueue,
                    bytesInQueue,
                    available);
            count += available;
            xorAndPermute(
                    state,
                    dataQueue,
                    0,
                    rateBytes >>> 3);
        }
        final int ci = len - rateBytes;
        while (ci >= count) {
            xorAndPermute(
                    state,
                    data,
                    count,
                    rateBytes >>> 3);
            count += rateBytes;
        }
        System.arraycopy(
                data,
                count,
                dataQueue,
                0,
                (bitsInQueue
                        = len
                        - count
                        << 3)
                        >>> 3);
    }

    private void squeeze (final byte[] output,
                          final int offset,
                          final long outputLength) {
        if (notSqueezing)
            padAndSwitchToSqueezingPhase();
        long i = 0;
        final long[] state = this.state;
        final byte[] dataQueue = this.dataQueue;
        final int rate = this.rate;
        int bitsInQueue = this.bitsInQueue;
        while (i < outputLength) {
            final int partialBlock;
            if (bitsInQueue == 0) {
                permute(state);
                longToLittleEndian(
                        state,
                        rate >>> 6,
                        dataQueue);
                partialBlock = (int) Math.min(
                        rate,
                        outputLength - i);
                System.arraycopy(
                        dataQueue,
                        0,
                        output,
                        offset + (int) (i / 8),
                        partialBlock / 8);
                bitsInQueue = rate - partialBlock;
            } else {
                partialBlock = (int) Math.min(
                        bitsInQueue,
                        outputLength - i);
                System.arraycopy(
                        dataQueue,
                        (rate - bitsInQueue) / 8,
                        output,
                        offset + (int) (i / 8),
                        partialBlock / 8);
                bitsInQueue -= partialBlock;
            }
            i += partialBlock;
        }
        this.bitsInQueue = bitsInQueue;
    }
    private void padAndSwitchToSqueezingPhase () {
        final long[] state = this.state;
        final byte[] dataQueue = this.dataQueue;
        final int rate = this.rate;
        int biq = bitsInQueue;
        dataQueue[biq >>> 3] |= (byte) (1 << (biq & 7));
        if (++biq == rate)
            xorAndPermute(state, dataQueue, 0, biq >>> 6);
        else {
            final int full = biq >>> 6;
            int off = 0;
            for (int i = 0; i < full; ++i, off += 8)
                state[i] ^= littleEndianToLong(dataQueue, off);
            final int partial = biq & 63;
            if (partial != 0)
                state[full] ^= (1L
                        << partial)
                        - 1L
                        & littleEndianToLong
                        (dataQueue, off);
        }
        state[rate - 1 >>> 6] ^= 0x8000000000000000L;
        bitsInQueue = 0;
        notSqueezing = false;
    }

    private static void xorAndPermute (
            final long[] state,
            final byte[] data,
            int off,
            final int count) {
        for (int i = 0; i < count; off += 8, i++)
            state[i] ^= littleEndianToLong(data, off);
        permute(state);
    }

    private static final long[] permuteConstants = new long[] {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL,
            0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000aL, 0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    private static void permute (final long[] a) {
        long    a00 = a[ 0], a01 = a[ 1], a02 = a[ 2], a03 = a[ 3], a04 = a[ 4],
                a05 = a[ 5], a06 = a[ 6], a07 = a[ 7], a08 = a[ 8], a09 = a[ 9],
                a10 = a[10], a11 = a[11], a12 = a[12], a13 = a[13], a14 = a[14],
                a15 = a[15], a16 = a[16], a17 = a[17], a18 = a[18], a19 = a[19],
                a20 = a[20], a21 = a[21], a22 = a[22], a23 = a[23], a24 = a[24],
                c0, c1, c2, c3, c4, d0, d1, d2, d3, d4;
        for (int i = 0; i < 24; i++) {
            c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
            c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
            c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
            c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
            c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;
            d0 = (c1 << 1 | c1 >>> 63) ^ c4;
            d1 = (c2 << 1 | c2 >>> 63) ^ c0;
            d2 = (c3 << 1 | c3 >>> 63) ^ c1;
            d3 = (c4 << 1 | c4 >>> 63) ^ c2;
            d4 = (c0 << 1 | c0 >>> 63) ^ c3;
            a00 ^= d0; a05 ^= d0; a10 ^= d0; a15 ^= d0; a20 ^= d0;
            a01 ^= d1; a06 ^= d1; a11 ^= d1; a16 ^= d1; a21 ^= d1;
            a02 ^= d2; a07 ^= d2; a12 ^= d2; a17 ^= d2; a22 ^= d2;
            a03 ^= d3; a08 ^= d3; a13 ^= d3; a18 ^= d3; a23 ^= d3;
            a04 ^= d4; a09 ^= d4; a14 ^= d4; a19 ^= d4; a24 ^= d4;
            c1  = a01 <<  1 | a01 >>> 63;
            a01 = a06 << 44 | a06 >>> 20;
            a06 = a09 << 20 | a09 >>> 44;
            a09 = a22 << 61 | a22 >>>  3;
            a22 = a14 << 39 | a14 >>> 25;
            a14 = a20 << 18 | a20 >>> 46;
            a20 = a02 << 62 | a02 >>>  2;
            a02 = a12 << 43 | a12 >>> 21;
            a12 = a13 << 25 | a13 >>> 39;
            a13 = a19 <<  8 | a19 >>> 56;
            a19 = a23 << 56 | a23 >>>  8;
            a23 = a15 << 41 | a15 >>> 23;
            a15 = a04 << 27 | a04 >>> 37;
            a04 = a24 << 14 | a24 >>> 50;
            a24 = a21 <<  2 | a21 >>> 62;
            a21 = a08 << 55 | a08 >>>  9;
            a08 = a16 << 45 | a16 >>> 19;
            a16 = a05 << 36 | a05 >>> 28;
            a05 = a03 << 28 | a03 >>> 36;
            a03 = a18 << 21 | a18 >>> 43;
            a18 = a17 << 15 | a17 >>> 49;
            a17 = a11 << 10 | a11 >>> 54;
            a11 = a07 <<  6 | a07 >>> 58;
            a07 = a10 <<  3 | a10 >>> 61;
            a10 = c1;
            c0 = a00 ^ (~a01 & a02);
            c1 = a01 ^ (~a02 & a03);
            a02 ^= ~a03 & a04;
            a03 ^= ~a04 & a00;
            a04 ^= ~a00 & a01;
            a00 = c0;
            a01 = c1;
            c0 = a05 ^ (~a06 & a07);
            c1 = a06 ^ (~a07 & a08);
            a07 ^= ~a08 & a09;
            a08 ^= ~a09 & a05;
            a09 ^= ~a05 & a06;
            a05 = c0;
            a06 = c1;
            c0 = a10 ^ (~a11 & a12);
            c1 = a11 ^ (~a12 & a13);
            a12 ^= ~a13 & a14;
            a13 ^= ~a14 & a10;
            a14 ^= ~a10 & a11;
            a10 = c0;
            a11 = c1;
            c0 = a15 ^ (~a16 & a17);
            c1 = a16 ^ (~a17 & a18);
            a17 ^= ~a18 & a19;
            a18 ^= ~a19 & a15;
            a19 ^= ~a15 & a16;
            a15 = c0;
            a16 = c1;
            c0 = a20 ^ (~a21 & a22);
            c1 = a21 ^ (~a22 & a23);
            a22 ^= ~a23 & a24;
            a23 ^= ~a24 & a20;
            a24 ^= ~a20 & a21;
            a20 = c0;
            a21 = c1;
            a00 ^= permuteConstants[i];
        }
        a[ 0] = a00; a[ 1] = a01; a[ 2] = a02; a[ 3] = a03; a[ 4] = a04;
        a[ 5] = a05; a[ 6] = a06; a[ 7] = a07; a[ 8] = a08; a[ 9] = a09;
        a[10] = a10; a[11] = a11; a[12] = a12; a[13] = a13; a[14] = a14;
        a[15] = a15; a[16] = a16; a[17] = a17; a[18] = a18; a[19] = a19;
        a[20] = a20; a[21] = a21; a[22] = a22; a[23] = a23; a[24] = a24;
    }

    private static int littleEndianToInt (final byte[] bs, final int off) {
        return  bs[off    ]       |
                bs[off + 1] << 8  |
                bs[off + 2] << 16 |
                bs[off + 3] << 24 ;
    }
    private static long littleEndianToLong (final byte[] bs, final int off) {
        return (long) littleEndianToInt(bs, off + 4) << 32 | littleEndianToInt(bs, off);
    }

    private static void intToLittleEndian (final int n, final byte[] bs, final int off) {
        bs[off    ] = (byte)  n        ;
        bs[off + 1] = (byte) (n >>> 8 );
        bs[off + 2] = (byte) (n >>> 16);
        bs[off + 3] = (byte) (n >>> 24);
    }
    private static void longToLittleEndian (final long n, final byte[] bs, final int off) {
        intToLittleEndian((int)  n        , bs,     off    );
        intToLittleEndian((int) (n >>> 32), bs, off + 4);
    }
    private static void longToLittleEndian (final long[] ns, final int nsLen, final byte[] bs) {
        for (int i = 0, off = 0; i < nsLen; off += 8, i++)
            longToLittleEndian(ns[i], bs, off);
    }
}
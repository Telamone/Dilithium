package it.telami.commons.crypto.dilithium;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;

final class DilithiumBenchmark {

    /* Last Benchmark Output:
     * Telami's Dilithium sign:   411214 ns/ops
     * Telami's Dilithium verify: 83625 ns/ops
     * Java's Dilithium sign:     764147 ns/ops
     * Java's Dilithium verify:   252157 ns/ops
     */

    public static void main (final String[] ignored) throws Throwable {
        Security.addProvider(new DilithiumProvider());

        //Utils
        final int WARMUP_ITERATIONS = 30_000;
        final int TEST_CASES = 1_000 + WARMUP_ITERATIONS;
        //Don't specify '4627' or it will initialize all the internal arrays!
        byte[][] signs = new byte[TEST_CASES][];

        //Test cases setup
        final byte[][] testCases;
        {
            final VarHandle arrayView = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.nativeOrder());
            testCases = IntStream
                    .generate(ThreadLocalRandom.current()::nextInt)
                    .parallel()
                    .mapToObj(i -> {
                        final ThreadLocalRandom random = ThreadLocalRandom.current();
                        final byte[] a = new byte[i &= 0x7f8];
                        while ((i -= 8) >= 0)
                            arrayView.set(a, i, random.nextLong());
                        return a;
                    })
                    .limit(TEST_CASES)
                    .toArray(byte[][]::new);
        }   //Free 'arrayView'!

        //Library algorithm setup
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
        kpg.initialize(DilithiumParameterSpec.LEVEL_5);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey prvK = kp.getPrivate();
        PublicKey pubK = kp.getPublic();
        Signature signature = Signature.getInstance("Dilithium");
        signature.initSign(prvK);

        //Result
        System.out.println("Telami's Dilithium sign:   " + (benchmarkSign(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");

        //Switch to verification
        signature.initVerify(pubK);

        //Result
        System.out.println("Telami's Dilithium verify: " + (benchmarkVerification(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");

        //Java algorithm setup
        kpg = KeyPairGenerator.getInstance("ML-DSA");
        kpg.initialize(NamedParameterSpec.ML_DSA_87);
        kp = kpg.generateKeyPair();
        prvK = kp.getPrivate();
        pubK = kp.getPublic();
        signature = Signature.getInstance("ML-DSA");
        signature.initSign(prvK);

        //Result
        System.out.println("Java's Dilithium sign:     " + (benchmarkSign(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");

        //Switch to verification
        signature.initVerify(pubK);

        //Result
        System.out.println("Java's Dilithium verify:   " + (benchmarkVerification(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
    }

    @SuppressWarnings("SameParameterValue")
    private static long benchmarkSign (final int WARMUP_ITERATIONS,
                                       final int TEST_CASES,
                                       final Signature signature,
                                       final byte[][] testCases,
                                       final byte[][] signs) throws Throwable {
        int i = 0;
        //Warmup
        while (i < WARMUP_ITERATIONS) {
            signature.update(testCases[i]);
            signs[i++] = signature.sign();
        }
        final long start = System.nanoTime();
        //Benchmark
        while (i < TEST_CASES) {
            signature.update(testCases[i]);
            signs[i++] = signature.sign();
        }
        return System.nanoTime() - start;
    }
    @SuppressWarnings("SameParameterValue")
    private static long benchmarkVerification (final int WARMUP_ITERATIONS,
                                               final int TEST_CASES,
                                               final Signature signature,
                                               final byte[][] testCases,
                                               final byte[][] signs) throws Throwable {
        int i = 0;
        boolean verified = true;
        //Warmup
        while (i < WARMUP_ITERATIONS) {
            signature.update(testCases[i]);
            verified &= signature.verify(signs[i++]);
        }
        long start = System.nanoTime();
        //Benchmark
        while (i < TEST_CASES) {
            signature.update(testCases[i]);
            verified &= signature.verify(signs[i++]);
        }
        start = System.nanoTime() - start;
        if (!verified)
            System.out.println("Error (non-verified)!");
        return start;
    }
}

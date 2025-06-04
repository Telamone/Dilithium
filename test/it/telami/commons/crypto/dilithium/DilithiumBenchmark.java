package it.telami.commons.crypto.dilithium;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.IntStream;

final class DilithiumBenchmark {

    /* Best Benchmark Results (i7 10700k | 4.7 Ghz | All cores):
     * Telami's ThreadSafeDilithium sign:   70696 ns/ops
     * Telami's ThreadSafeDilithium verify: 14219 ns/ops
     * Telami's Dilithium sign:             383210 ns/ops
     * Telami's Dilithium verify:           79012 ns/ops
     * Java's Dilithium sign:               767563 ns/ops
     * Java's Dilithium verify:             255607 ns/ops
     */

    public static void main (final String[] ignored) throws Throwable {
        Security.addProvider(new DilithiumProvider());

        //Utils
        final int WARMUP_ITERATIONS = 31_000;
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

        //Thread-safe library algorithm setup
        final ForkJoinPool threadPool = new ForkJoinPool(Runtime.getRuntime().availableProcessors() - 1);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
        kpg.initialize(DilithiumParameterSpec.LEVEL_5);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey prvK = kp.getPrivate();
        PublicKey pubK = kp.getPublic();
        Signature signature = Signature.getInstance("ThreadSafeDilithium");
        signature.initSign(prvK);

        //Result
        System.out.println("Telami's ThreadSafeDilithium sign:   " + (benchmarkParallelSign(
                threadPool,
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
        System.out.println("Telami's ThreadSafeDilithium verify: " + (benchmarkParallelVerification(
                threadPool,
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");

        //Cleaning
        threadPool.close();

        //Library algorithm setup
        kpg = KeyPairGenerator.getInstance("Dilithium");
        kpg.initialize(DilithiumParameterSpec.LEVEL_5);
        kp = kpg.generateKeyPair();
        prvK = kp.getPrivate();
        pubK = kp.getPublic();
        signature = Signature.getInstance("Dilithium");
        signature.initSign(prvK);

        //Result
        System.out.println("Telami's Dilithium sign:             " + (benchmarkSign(
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
        System.out.println("Telami's Dilithium verify:           " + (benchmarkVerification(
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
        System.out.println("Java's Dilithium sign:               " + (benchmarkSign(
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
        System.out.println("Java's Dilithium verify:             " + (benchmarkVerification(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
    }

    @SuppressWarnings("SameParameterValue")
    private static long benchmarkParallelSign (final ForkJoinPool threadPool,
                                               final int WARMUP_ITERATIONS,
                                               final int TEST_CASES,
                                               final Signature signature,
                                               final byte[][] testCases,
                                               final byte[][] signs) {
        int i = 0;
        //Warmup
        while (i < WARMUP_ITERATIONS) {
            final int j = i++;
            threadPool.execute(() -> {
                try {
                    signature.update(testCases[j]);
                    signs[j] = signature.sign();
                } catch (final Throwable t) {
                    throw new RuntimeException(t);
                }
            });
        }
        //noinspection ResultOfMethodCallIgnored
        threadPool.awaitQuiescence(0xffffffffffffffffL, TimeUnit.NANOSECONDS);
        final long start = System.nanoTime();
        //Benchmark
        while (i < TEST_CASES) {
            final int j = i++;
            threadPool.execute(() -> {
                try {
                    signature.update(testCases[j]);
                    signs[j] = signature.sign();
                } catch (final Throwable t) {
                    throw new RuntimeException(t);
                }
            });
        }
        //noinspection ResultOfMethodCallIgnored
        threadPool.awaitQuiescence(0xffffffffffffffffL, TimeUnit.NANOSECONDS);
        return System.nanoTime() - start;
    }
    @SuppressWarnings("SameParameterValue")
    private static long benchmarkParallelVerification (final ForkJoinPool threadPool,
                                                       final int WARMUP_ITERATIONS,
                                                       final int TEST_CASES,
                                                       final Signature signature,
                                                       final byte[][] testCases,
                                                       final byte[][] signs) {
        int i = 0;
        final AtomicBoolean verified = new AtomicBoolean(true);
        //Warmup
        while (i < WARMUP_ITERATIONS) {
            final int j = i++;
            threadPool.execute(() -> {
                try {
                    signature.update(testCases[j]);
                    verified.compareAndSet(true, signature.verify(signs[j]));
                } catch (final Throwable t) {
                    throw new RuntimeException(t);
                }
            });
        }
        //noinspection ResultOfMethodCallIgnored
        threadPool.awaitQuiescence(0xffffffffffffffffL, TimeUnit.NANOSECONDS);
        long start = System.nanoTime();
        //Benchmark
        while (i < TEST_CASES) {
            final int j = i++;
            threadPool.execute(() -> {
                try {
                    signature.update(testCases[j]);
                    verified.compareAndSet(true, signature.verify(signs[j]));
                } catch (final Throwable t) {
                    throw new RuntimeException(t);
                }
            });
        }
        //noinspection ResultOfMethodCallIgnored
        threadPool.awaitQuiescence(0xffffffffffffffffL, TimeUnit.NANOSECONDS);
        start = System.nanoTime() - start;
        if (!verified.getOpaque())
            System.out.println("Error (non-verified)!");
        return start;
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

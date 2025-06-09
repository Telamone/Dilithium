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
import java.util.concurrent.locks.LockSupport;
import java.util.stream.IntStream;

final class DilithiumBenchmark {

    /* Last Benchmark Result (i7 10700k | 4.7 Ghz | All cores) [Output aligned manually]:
     * Telami's ThreadSafeDilithium sign:   73633 ns/ops  [AVERAGE] | 147900 ns (Length: 2488) [MIN] | 38823700 ns (Length: 3512) [MAX]
     * Telami's ThreadSafeDilithium verify: 14452 ns/ops  [AVERAGE] | 93800 ns  (Length: 2144) [MIN] | 11538000 ns (Length: 2592) [MAX]
     * Telami's Dilithium sign:             425841 ns/ops [AVERAGE] | 120500 ns (Length: 2304) [MIN] | 14040400 ns (Length: 2912) [MAX]
     * Telami's Dilithium verify:           86517 ns/ops  [AVERAGE] | 68200 ns  (Length: 2176) [MIN] | 8511200 ns  (Length: 3504) [MAX]
     * Java's Dilithium sign:               783274 ns/ops [AVERAGE] | 375300 ns (Length: 2064) [MIN] | 16404500 ns (Length: 2936) [MAX]
     * Java's Dilithium verify:             255352 ns/ops [AVERAGE] | 243600 ns (Length: 2080) [MIN] | 9440400 ns  (Length: 2088) [MAX]
     */

    public static void main (final String[] ignored) throws Throwable {
        Security.addProvider(new DilithiumProvider());

        //Utils
        final int WARMUP_ITERATIONS = 50_000;
        final int TEST_CASES = 50_000 + WARMUP_ITERATIONS;
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
                        final byte[] a = new byte[i = (i & 0x7f8) + 0x800];
                        while ((i -= 8) >= 0)
                            arrayView.set(a, i, ThreadLocalRandom.current().nextLong());
                        return a;
                    })
                    .limit(TEST_CASES)
                    .toArray(byte[][]::new);
        }   //Free 'arrayView'!

        //Search for minimum and maximum times (with their respective lengths)
        //Harms the benchmark a little, but the operation is cheap
        final long[] timesAndLengths = new long[TEST_CASES - WARMUP_ITERATIONS];

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
        System.out.print("Telami's ThreadSafeDilithium sign:   " + (benchmarkParallelSign(
                threadPool,
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs,
                timesAndLengths)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
        System.out.println(extractResult(timesAndLengths));

        //Switch to verification
        signature.initVerify(pubK);

        //Result
        System.out.print("Telami's ThreadSafeDilithium verify: " + (benchmarkParallelVerification(
                threadPool,
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs,
                timesAndLengths)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
        System.out.println(extractResult(timesAndLengths));

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
        System.out.print("Telami's Dilithium sign:             " + (benchmarkSign(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs,
                timesAndLengths)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
        System.out.println(extractResult(timesAndLengths));

        //Switch to verification
        signature.initVerify(pubK);

        //Result
        System.out.print("Telami's Dilithium verify:           " + (benchmarkVerification(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs,
                timesAndLengths)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
        System.out.println(extractResult(timesAndLengths));

        //Java algorithm setup
        kpg = KeyPairGenerator.getInstance("ML-DSA");
        kpg.initialize(NamedParameterSpec.ML_DSA_87);
        kp = kpg.generateKeyPair();
        prvK = kp.getPrivate();
        pubK = kp.getPublic();
        signature = Signature.getInstance("ML-DSA");
        signature.initSign(prvK);

        //Result
        System.out.print("Java's Dilithium sign:               " + (benchmarkSign(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs,
                timesAndLengths)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
        System.out.println(extractResult(timesAndLengths));

        //Switch to verification
        signature.initVerify(pubK);

        //Result
        System.out.print("Java's Dilithium verify:             " + (benchmarkVerification(
                WARMUP_ITERATIONS,
                TEST_CASES,
                signature,
                testCases,
                signs,
                timesAndLengths)
                / (TEST_CASES - WARMUP_ITERATIONS))
                + " ns/ops");
        System.out.println(extractResult(timesAndLengths));
    }

    @SuppressWarnings("SameParameterValue")
    private static long benchmarkParallelSign (final ForkJoinPool threadPool,
                                               final int WARMUP_ITERATIONS,
                                               final int TEST_CASES,
                                               final Signature signature,
                                               final byte[][] testCases,
                                               final byte[][] signs,
                                               final long[] timesAndLengths) {
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
                    final long t = System.nanoTime();
                    signature.update(testCases[j]);
                    signs[j] = signature.sign();
                    timesAndLengths[j - WARMUP_ITERATIONS] = System.nanoTime() - t | (long) testCases[j].length << 52;
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
                                                       final byte[][] signs,
                                                       final long[] timesAndLengths) {
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
                    final long t = System.nanoTime();
                    signature.update(testCases[j]);
                    verified.compareAndSet(true, signature.verify(signs[j]));
                    timesAndLengths[j - WARMUP_ITERATIONS] = System.nanoTime() - t | (long) testCases[j].length << 52;
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
                                       final byte[][] signs,
                                       final long[] timesAndLengths) throws Throwable {
        int i = 0;
        //Warmup
        while (i < WARMUP_ITERATIONS) {
            signature.update(testCases[i]);
            signs[i++] = signature.sign();
        }
        final long start = System.nanoTime();
        //Benchmark
        while (i < TEST_CASES) {
            final long t = System.nanoTime();
            signature.update(testCases[i]);
            signs[i] = signature.sign();
            timesAndLengths[i - WARMUP_ITERATIONS] = System.nanoTime() - t | (long) testCases[i++].length << 52;
        }
        return System.nanoTime() - start;
    }
    @SuppressWarnings("SameParameterValue")
    private static long benchmarkVerification (final int WARMUP_ITERATIONS,
                                               final int TEST_CASES,
                                               final Signature signature,
                                               final byte[][] testCases,
                                               final byte[][] signs,
                                               final long[] timesAndLengths) throws Throwable {
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
            final long t = System.nanoTime();
            signature.update(testCases[i]);
            verified &= signature.verify(signs[i]);
            timesAndLengths[i - WARMUP_ITERATIONS] = System.nanoTime() - t | (long) testCases[i++].length << 52;
        }
        start = System.nanoTime() - start;
        if (!verified)
            System.out.println("Error (non-verified)!");
        return start;
    }

    @SuppressWarnings("SameParameterValue")
    private static String extractResult (final long[] timesAndLengths) {
        //The queue is empty, but the other threads might not have finished their work!
        LockSupport.parkNanos(100_000_000L);
        if (timesAndLengths.length == 0)
            return "";
        //Too lazy for using parallel streams :p
        int min = 0, max = 0;
        for (int i = 1; i < timesAndLengths.length; i++) {
            if ((timesAndLengths[i] & 0xfffffffffffffL) < (timesAndLengths[min] & 0xfffffffffffffL))
                min = i;
            if ((timesAndLengths[i] & 0xfffffffffffffL) > (timesAndLengths[max] & 0xfffffffffffffL))
                max = i;
        }
        return " [AVERAGE] | "
                + (timesAndLengths[min] & 0xfffffffffffffL)
                + " ns (Length: "
                + (timesAndLengths[min] >>> 52)
                + ") [MIN] | "
                + (timesAndLengths[max] & 0xfffffffffffffL)
                + " ns (Length: "
                + (timesAndLengths[max] >>> 52)
                + ") [MAX]";
    }
}

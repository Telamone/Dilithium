# Dilithium ✍️

The development is done using always the <b>latest</b> java version, this might imply that
the new features could be used <i>anytime</i>. (Current Java version: <b>24</b>) <br>
This is a <b>reworked</b> version of
<a href="https://github.com/mthiim/dilithium-java">this repository</a>
adapted to my needs. <br>
It's also included in my
<a href="https://github.com/Telamone/TelLibrary">library</a>
as it's used internally for <b>secure data authentication</b>. <br>
For more information about the algorithm, I would recommend to visit the original repository. <br>

<br>

# Basic Demo 🎯

Code:

```java
Security.addProvider(new DilithiumProvider());

final KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
kpg.initialize(DilithiumParameterSpec.LEVEL_5);

final KeyPair kp = kpg.generateKeyPair();

final PrivateKey prvK = kp.getPrivate();
final PublicKey pubK = kp.getPublic();

final Signature signature = Signature.getInstance("Dilithium"); //or "ThreadSafeDilithium"

final byte[] message = "Message!".getBytes();

signature.initSign(prvK);
signature.update(message);
final byte[] sign = signature.sign();

signature.initVerify(pubK);
signature.update(message);
System.out.println("This works, right? " + signature.verify(sign));

System.out.println("Let's try changing the message...");

signature.update("MODIFIED!!!".getBytes());
System.out.println("This doesn't work, right? " + !signature.verify(sign));
```

Output:

    This works, right? true
    Let's try changing the message...
    This doesn't work, right? true

<br>

# Benchmark 🚀

In the <i>test</i> directory there are both the demo shown above and the benchmark class. <br>
A proper comment report the <b>latest best results</b> of the benchmark. <br>
The benchmark is done comparing this repository's <b>Dilithium</b>, <b>ThreadSafeDilithium</b> and java's <b>ML-DSA</b>. <br>
These are the latest (in the moment this README is updated) best results on my platform:

    Telami's ThreadSafeDilithium sign:   73633 ns/ops  [AVERAGE] | 147900 ns (Length: 2488) [MIN] | 38823700 ns (Length: 3512) [MAX]
    Telami's ThreadSafeDilithium verify: 14452 ns/ops  [AVERAGE] | 93800 ns  (Length: 2144) [MIN] | 11538000 ns (Length: 2592) [MAX]
    Telami's Dilithium sign:             425841 ns/ops [AVERAGE] | 120500 ns (Length: 2304) [MIN] | 14040400 ns (Length: 2912) [MAX]
    Telami's Dilithium verify:           86517 ns/ops  [AVERAGE] | 68200 ns  (Length: 2176) [MIN] | 8511200 ns  (Length: 3504) [MAX]
    Java's Dilithium sign:               783274 ns/ops [AVERAGE] | 375300 ns (Length: 2064) [MIN] | 16404500 ns (Length: 2936) [MAX]
    Java's Dilithium verify:             255352 ns/ops [AVERAGE] | 243600 ns (Length: 2080) [MIN] | 9440400 ns  (Length: 2088) [MAX]

## Time tables

Sign implementation | Min      | Avg     | Max
--- |----------|---------| ---
Telami's ThreadSafeDilithium | ~147 µs  | ~73 µs  | ~38 ms
Telami's Dilithium | ~120 µs  | ~425 µs | ~14 ms
Java's Dilithium | ~375 µs  | ~783 µs | ~16 ms

Verify implementation | Min     | Avg     | Max
--- |---------|---------| ---
Telami's ThreadSafeDilithium | ~93 µs  | ~14 µs  | ~11 ms
Telami's Dilithium | ~68 µs  | ~86 µs  | ~8 ms
Java's Dilithium | ~243 µs | ~255 µs | ~9 ms

> [!NOTE]
> In my <b>ThreadSafeDilithium</b> implementation, the <b>Avarage</b> is <i>less</i> than the <b>Minimum</b>
> because the first is considering the <b>parallelization</b> while the other not.

<br>

# Future work 📌

The use of SIMD is one of the things I can't wait to implement, but I will
wait until the Vector APIs become available by default.

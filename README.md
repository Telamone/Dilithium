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

    Telami's ThreadSafeDilithium sign:   73860 ns/ops  [AVERAGE] | 191400 ns (Length: 2232) [MIN] | 45536600 ns (Length: 3424) [MAX]
    Telami's ThreadSafeDilithium verify: 17803 ns/ops  [AVERAGE] | 113100 ns (Length: 2048) [MIN] | 2955600 ns  (Length: 3288) [MAX]
    Telami's Dilithium sign:             403489 ns/ops [AVERAGE] | 123400 ns (Length: 3064) [MIN] | 1907800 ns  (Length: 3640) [MAX]
    Telami's Dilithium verify:           86129 ns/ops  [AVERAGE] | 72600 ns  (Length: 2976) [MIN] | 107200 ns   (Length: 3648) [MAX]
    Java's Dilithium sign:               771415 ns/ops [AVERAGE] | 384900 ns (Length: 2200) [MIN] | 3727500 ns  (Length: 2904) [MAX]
    Java's Dilithium verify:             259724 ns/ops [AVERAGE] | 251700 ns (Length: 2048) [MIN] | 407700 ns   (Length: 2816) [MAX]

<br>

# Future work 📌

The use of SIMD is one of the things I can't wait to implement, but I will
wait until the Vector APIs become available by default.
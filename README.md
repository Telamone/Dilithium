# Dilithium

This is a modified version of
<a href="https://github.com/mthiim/dilithium-java">this repository</a>
adapted to my needs.<br>

It's also included in my personal
<a href="https://github.com/Telamone/TelLibrary">java libraries</a>
as it's used for secure data authentication.

In future updates I'll probably try improving code quality and speed
attaching some benchmarks.<br>
As for now, this is only a simple rework of the already existing library.<br>

For more information, I would recommend to visit the original repository.

# Demo

Code:

        Security.addProvider(new DilithiumProvider());

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
        kpg.initialize(DilithiumParameterSpec.LEVEL_5);

        final KeyPair kp = kpg.generateKeyPair();

        final PrivateKey prvK = kp.getPrivate();
        final PublicKey pubK = kp.getPublic();

        final Signature signature = Signature.getInstance("Dilithium");

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

Output:

        This works, right? true
        Let's try changing the message...
        This doesn't work, right? true
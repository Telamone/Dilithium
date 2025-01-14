package it.telami.commons.crypto.dilithium;

import java.security.*;

final class DilithiumTest {
    public static void main (final String[] args) throws Throwable {
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
    }
}

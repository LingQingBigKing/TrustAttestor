package com.lingqing.trustattestor;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Desktop JCA evidence tests; does not stand in for Android device coverage. */
public final class ExtendedProbeEvidenceTest {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        hmacKnownAnswer();
        rsaSignatures();
        rsaEncryption();
        ecdhAgreement();
        aesReference();
        gcmChunkingAndIntegrity();
        System.out.println("ExtendedProbeEvidenceTest: " + assertions + " assertions passed");
    }

    private static void hmacKnownAnswer() throws Exception {
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        byte[] message = "Hi There".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        check(Arrays.equals(expected, ExtendedProbeEvidence.hmac(key, message)), "RFC 4231 HMAC-SHA256 case 1");
        check(ExtendedProbeEvidence.validHmac(key, message, expected), "complete MAC verifies");
        check(!ExtendedProbeEvidence.validHmac(key, message, ExtendedProbeEvidence.changed(expected)), "same-length wrong MAC rejected");
        check(!ExtendedProbeEvidence.validHmac(key, ExtendedProbeEvidence.changed(message), expected), "message binding");
        check(!ExtendedProbeEvidence.validHmac(ExtendedProbeEvidence.changed(key), message, expected), "key binding");
        check(!ExtendedProbeEvidence.validHmac(key, message, null), "missing output unavailable");
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static void rsaSignatures() throws Exception {
        KeyPair pair = rsa();
        byte[] message = "RSA full message binding".getBytes(StandardCharsets.UTF_8);
        for (String digest : new String[] { "SHA-256", "SHA-512" }) {
            Signature signer = Signature.getInstance("RSASSA-PSS");
            signer.setParameter(ExtendedProbeEvidence.pss(digest));
            signer.initSign(pair.getPrivate());
            signer.update(message, 0, 5);
            signer.update(message, 5, message.length - 5);
            byte[] signed = signer.sign();
            check(ExtendedProbeEvidence.verifyRsa(pair.getPublic(), digest, true, message, signed), "PSS complete split message " + digest);
            check(!ExtendedProbeEvidence.verifyRsa(pair.getPublic(), digest, true, ExtendedProbeEvidence.changed(message), signed), "PSS rejects changed message " + digest);
            check(!ExtendedProbeEvidence.verifyRsa(pair.getPublic(), digest, true, message, new byte[0]), "PSS rejects missing output");
        }
        Signature pkcs1 = Signature.getInstance("SHA256withRSA");
        pkcs1.initSign(pair.getPrivate());
        pkcs1.update(message);
        byte[] signed = pkcs1.sign();
        check(ExtendedProbeEvidence.verifyRsa(pair.getPublic(), "SHA-256", false, message, signed), "PKCS1 reference verifies actual padding");
        check(!ExtendedProbeEvidence.verifyRsa(pair.getPublic(), "SHA-256", true, message, signed), "PKCS1 output is not PSS");
    }

    private static void rsaEncryption() throws Exception {
        KeyPair pair = rsa();
        byte[] message = "RSA OAEP independent encryption".getBytes(StandardCharsets.UTF_8);
        for (String digest : new String[] { "SHA-256", "SHA-1" }) {
            byte[] encrypted = ExtendedProbeEvidence.rsaEncrypt(pair.getPublic(), message, digest, true);
            Cipher decrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
            decrypt.init(Cipher.DECRYPT_MODE, pair.getPrivate(), ExtendedProbeEvidence.oaep(digest));
            check(Arrays.equals(message, decrypt.doFinal(encrypted)), "OAEP digest explicit " + digest);
            check("SHA-1".equals(((java.security.spec.MGF1ParameterSpec) ExtendedProbeEvidence.oaep(digest).getMGFParameters()).getDigestAlgorithm()), "MGF1 explicitly SHA-1 independently of OAEP digest");
        }
        byte[] encrypted = ExtendedProbeEvidence.rsaEncrypt(pair.getPublic(), message, "SHA-256", false);
        Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decrypt.init(Cipher.DECRYPT_MODE, pair.getPrivate());
        check(Arrays.equals(message, decrypt.doFinal(encrypted)), "PKCS1 independent encryption");
    }

    private static void ecdhAgreement() throws Exception {
        KeyPair alice = ExtendedProbeEvidence.softwareEc();
        KeyPair bob = ExtendedProbeEvidence.softwareEc();
        KeyPair other = ExtendedProbeEvidence.softwareEc();
        byte[] a = ExtendedProbeEvidence.ecdh(alice.getPrivate(), bob.getPublic());
        byte[] b = ExtendedProbeEvidence.ecdh(bob.getPrivate(), alice.getPublic());
        check(ExtendedProbeEvidence.sameSecret(a, b), "ECDH both sides agree");
        check(!ExtendedProbeEvidence.sameSecret(a, ExtendedProbeEvidence.ecdh(other.getPrivate(), alice.getPublic())), "ECDH wrong peer rejected");
        check(!ExtendedProbeEvidence.sameSecret(a, ExtendedProbeEvidence.changed(a)), "nonempty wrong secret rejected");
        check(!ExtendedProbeEvidence.sameSecret(new byte[0], new byte[0]), "empty agreement not evidence");
        check(!ExtendedProbeEvidence.sameSecret(Arrays.copyOf(a, 16), Arrays.copyOf(a, 16)), "truncated agreement not evidence");
        check(!ExtendedProbeEvidence.sameSecret(a, null), "null agreement not evidence");
    }

    private static void aesReference() throws Exception {
        byte[] key = hex("000102030405060708090a0b0c0d0e0f");
        byte[] message = new byte[32];
        for (int i = 0; i < message.length; i++) message[i] = (byte) (i + 7);
        for (String transformation : new String[] { "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding", "AES/CTR/NoPadding" }) {
            Cipher encrypt = Cipher.getInstance(transformation);
            encrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            byte[] encrypted = encrypt.doFinal(message);
            check(ExtendedProbeEvidence.aesMatches(key, transformation, encrypt.getIV(), encrypted, message), "AES independent full output " + transformation);
            check(!ExtendedProbeEvidence.aesMatches(key, transformation, encrypt.getIV(), encrypted, ExtendedProbeEvidence.changed(message)), "AES same-length wrong output rejected " + transformation);
            if (transformation.contains("PKCS5")) check(ExtendedProbeEvidence.aesMatches(key, "AES/CBC/PKCS7Padding", encrypt.getIV(), encrypted, message), "Android PKCS7 reference maps to AES PKCS5");
        }
    }

    private static void gcmChunkingAndIntegrity() throws Exception {
        byte[] key = hex("000102030405060708090a0b0c0d0e0f");
        byte[] message = "Buffering and AAD must preserve this entire plaintext".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "associated-data".getBytes(StandardCharsets.UTF_8);
        for (boolean chunks : new boolean[] { false, true }) {
            Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
            encrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            encrypt.updateAAD(aad);
            byte[] encrypted = ExtendedProbeEvidence.collectCipher(encrypt, message, chunks);
            byte[] iv = encrypt.getIV();
            check(ExtendedProbeEvidence.gcmMatches(key, iv, aad, encrypted, message), "GCM reference validates collected output");
            Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
            decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            decrypt.updateAAD(aad);
            check(MessageDigest.isEqual(message, ExtendedProbeEvidence.collectCipher(decrypt, encrypted, !chunks)), "GCM buffered decrypt output collection");
            expectBadTag(() -> ExtendedProbeEvidence.gcmMatches(key, iv, ExtendedProbeEvidence.changed(aad), encrypted, message), "AAD mismatch rejected");
            expectBadTag(() -> ExtendedProbeEvidence.gcmMatches(key, iv, aad, ExtendedProbeEvidence.changed(encrypted), message), "changed tag rejected");
        }
        byte[] original = { 1, 2, 3 };
        byte[] changed = ExtendedProbeEvidence.changed(original);
        check(Arrays.equals(original, new byte[] { 1, 2, 3 }) && changed[2] == 2, "negative fixture never mutates control");
    }

    private interface Checked { void run() throws Exception; }
    private static void expectBadTag(Checked operation, String message) throws Exception {
        try { operation.run(); throw new AssertionError(message); }
        catch (AEADBadTagException expected) { assertions++; }
    }

    private static byte[] hex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }

    private static void check(boolean success, String message) {
        if (!success) throw new AssertionError(message);
        assertions++;
    }
}

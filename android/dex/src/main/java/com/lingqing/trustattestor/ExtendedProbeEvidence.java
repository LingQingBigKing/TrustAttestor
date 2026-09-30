package com.lingqing.trustattestor;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/** Independent software references for app-owned test material; no Android APIs. */
final class ExtendedProbeEvidence {
    private ExtendedProbeEvidence() { }

    private interface Factory<T> { T create(Provider provider) throws GeneralSecurityException; }

    private static <T> T software(Factory<T> factory) throws GeneralSecurityException {
        GeneralSecurityException last = null;
        for (Provider provider : Security.getProviders()) {
            if (provider.getName().toLowerCase(java.util.Locale.ROOT).contains("keystore")) continue;
            try { return factory.create(provider); }
            catch (GeneralSecurityException failure) { last = failure; }
        }
        throw new GeneralSecurityException("independent software provider unavailable", last);
    }

    static PublicKey detached(PublicKey key) throws GeneralSecurityException {
        if (key == null || key.getEncoded() == null) throw new GeneralSecurityException("missing public key");
        return software(provider -> KeyFactory.getInstance(key.getAlgorithm(), provider))
                .generatePublic(new X509EncodedKeySpec(key.getEncoded()));
    }

    static PSSParameterSpec pss(String digest) {
        return new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest),
                "SHA-512".equals(digest) ? 64 : 32, 1);
    }

    static boolean verifyRsa(PublicKey key, String digest, boolean pss, byte[] message, byte[] signature)
            throws GeneralSecurityException {
        if (signature == null || signature.length == 0) return false;
        Signature verifier;
        if (pss) {
            verifier = software(provider -> {
                Signature candidate;
                try { candidate = Signature.getInstance("RSASSA-PSS", provider); }
                catch (GeneralSecurityException unsupported) {
                    candidate = Signature.getInstance(digest.replace("-", "") + "withRSA/PSS", provider);
                }
                candidate.setParameter(pss(digest));
                return candidate;
            });
        } else {
            verifier = software(provider -> Signature.getInstance(digest.replace("-", "") + "withRSA", provider));
        }
        verifier.initVerify(detached(key));
        verifier.update(message);
        return verifier.verify(signature);
    }

    static OAEPParameterSpec oaep(String digest) {
        // Android's longstanding OAEP default is SHA-1 for MGF1, independently of the main digest.
        return new OAEPParameterSpec(digest, "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }

    static byte[] rsaEncrypt(PublicKey key, byte[] message, String digest, boolean oaep)
            throws GeneralSecurityException {
        Cipher cipher = software(provider -> Cipher.getInstance(
                oaep ? "RSA/ECB/OAEPPadding" : "RSA/ECB/PKCS1Padding", provider));
        if (oaep) cipher.init(Cipher.ENCRYPT_MODE, detached(key), oaep(digest));
        else cipher.init(Cipher.ENCRYPT_MODE, detached(key));
        return cipher.doFinal(message);
    }

    static byte[] hmac(byte[] material, byte[] message) throws GeneralSecurityException {
        Mac reference = software(provider -> Mac.getInstance("HmacSHA256", provider));
        reference.init(new SecretKeySpec(material, "HmacSHA256"));
        return reference.doFinal(message);
    }

    static boolean validHmac(byte[] material, byte[] message, byte[] output) throws GeneralSecurityException {
        return output != null && MessageDigest.isEqual(hmac(material, message), output);
    }

    static KeyPair softwareEc() throws GeneralSecurityException {
        KeyPairGenerator generator = software(provider -> KeyPairGenerator.getInstance("EC", provider));
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    static byte[] ecdh(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement agreement = software(provider -> KeyAgreement.getInstance("ECDH", provider));
        agreement.init(privateKey);
        agreement.doPhase(detached(publicKey), true);
        return agreement.generateSecret();
    }

    static boolean sameSecret(byte[] expected, byte[] actual) {
        // P-256 ECDH uses the fixed-width x coordinate. Empty or truncated results are not equality.
        return expected != null && actual != null && expected.length == 32
                && MessageDigest.isEqual(expected, actual);
    }

    static boolean aesMatches(byte[] material, String transformation, byte[] iv,
                              byte[] ciphertext, byte[] plaintext) throws GeneralSecurityException {
        if (iv == null || ciphertext == null) return false;
        // PKCS7 is named PKCS5 by the desktop JCA provider; AES padding bytes are identical.
        String portable = transformation.replace("PKCS7Padding", "PKCS5Padding");
        Cipher reference = software(provider -> Cipher.getInstance(portable, provider));
        reference.init(Cipher.DECRYPT_MODE, new SecretKeySpec(material, "AES"), new IvParameterSpec(iv));
        return MessageDigest.isEqual(plaintext, reference.doFinal(ciphertext));
    }

    static boolean gcmMatches(byte[] material, byte[] iv, byte[] aad, byte[] ciphertext, byte[] plaintext)
            throws GeneralSecurityException {
        Cipher reference = software(provider -> Cipher.getInstance("AES/GCM/NoPadding", provider));
        reference.init(Cipher.DECRYPT_MODE, new SecretKeySpec(material, "AES"), new GCMParameterSpec(128, iv));
        reference.updateAAD(aad);
        return MessageDigest.isEqual(plaintext, reference.doFinal(ciphertext));
    }

    static byte[] collectCipher(Cipher cipher, byte[] message, boolean chunked) throws GeneralSecurityException {
        if (!chunked) return cipher.doFinal(message);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int first = message.length / 3;
        int second = (message.length * 2) / 3;
        append(output, cipher.update(message, 0, first));
        append(output, cipher.update(message, first, second - first));
        append(output, cipher.doFinal(message, second, message.length - second));
        return output.toByteArray();
    }

    private static void append(ByteArrayOutputStream output, byte[] bytes) {
        if (bytes != null) output.write(bytes, 0, bytes.length);
    }

    static byte[] changed(byte[] source) {
        if (source == null || source.length == 0) throw new IllegalArgumentException("empty test input");
        byte[] changed = Arrays.copyOf(source, source.length);
        changed[changed.length - 1] ^= 1;
        return changed;
    }
}

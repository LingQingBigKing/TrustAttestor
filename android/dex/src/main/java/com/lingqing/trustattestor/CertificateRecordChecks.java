package com.lingqing.trustattestor;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import io.github.vvb2060.keyattestation.attestation.Attestation;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;

/** Bounded public-API checks of one temporary, unauthenticated EC key owned by this invocation. */
final class CertificateRecordChecks {
    private CertificateRecordChecks() { }

    static void run(SilentKeystoreChecks.Reporter readReporter, SilentKeystoreChecks.Reporter roundTripReporter) {
        String alias = "TrustAttestor_certificate_" + UUID.randomUUID();
        KeyStore store = null;
        boolean owned = false;
        boolean readsReported = false;
        boolean roundTripReported = false;
        try {
            guard();
            store = store();
            if (store.containsAlias(alias)) throw new GeneralSecurityException("temporary alias collision");
            owned = true; // Also clean up a partially successful generation, never another alias.
            byte[] challenge = random();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .setAttestationChallenge(challenge).build());
            KeyPair generated = generator.generateKeyPair();
            guard();
            Certificate[] initial = store.getCertificateChain(alias);
            requireX509Chain(initial);
            CertificateRecordEvidence.Chain expected = new CertificateRecordEvidence.Chain(
                    CertificateRecordEvidence.encode(initial));
            validateEncoding(expected.encoded());
            PrivateKey originalKey = privateKey(store, alias);
            bindBaseline(store.getCertificate(alias), initial, generated.getPublic(), challenge, originalKey);

            try {
                for (int i = 0; i < 3; i++) checkRead(store, alias, expected);
                checkRead(store(), alias, expected);
                readReporter.report("certificate.read", VERIFIED,
                        "本轮公钥、challenge 及签名绑定已验证；三次完整读取及新 KeyStore 读取的全部 "
                                + expected.size() + " 张证书 DER 一致");
                readsReported = true;
            } catch (Exception failure) {
                report(readReporter, "certificate.read", failure);
                readsReported = true;
                roundTripReporter.report("certificate.round_trip", UNAVAILABLE, "完整链稳定读取未通过，未执行回装");
                roundTripReported = true;
                return;
            }

            try {
                CertificateRecordEvidence.Metadata before = metadata(originalKey);
                Certificate[] preserved = restore(expected);
                guard();
                // AOSP's AndroidKeyStore SPI retains this same AndroidKeyStore private key and
                // replaces its certificate subcomponents. No private material is exported/imported.
                store.setKeyEntry(alias, originalKey, null, preserved);
                guard();
                checkRead(store, alias, expected);
                KeyStore fresh = store();
                checkRead(fresh, alias, expected);
                PrivateKey currentKey = privateKey(fresh, alias);
                require(CertificateRecordEvidence.compare(before, metadata(currentKey)));
                requireSignature(originalKey, generated.getPublic());
                requireSignature(currentKey, generated.getPublic());
                guard();
                roundTripReporter.report("certificate.round_trip", VERIFIED,
                        "原链回装成功；全部证书 DER、已知 KeyInfo 稳定字段保持一致，回装前后私钥句柄均绑定本轮生成公钥");
                roundTripReported = true;
            } catch (Exception failure) {
                report(roundTripReporter, "certificate.round_trip", failure);
                roundTripReported = true;
            }
        } catch (Exception failure) {
            // No record conclusion is possible until the initial public key/challenge/signature bind.
            if (!readsReported) readReporter.report("certificate.read", UNAVAILABLE, detail(failure));
            if (!roundTripReported) roundTripReporter.report("certificate.round_trip", UNAVAILABLE, detail(failure));
        } finally {
            if (owned && store != null) {
                try {
                    store.deleteEntry(alias);
                    // Cleanup remains allowed after cancellation; successful deletion alone is not enough.
                    if (!SilentProbeEvidence.readAlias(store, alias).absent())
                        throw new GeneralSecurityException("temporary certificate key remains after cleanup");
                } catch (Exception failure) {
                    // Separate evidence IDs preserve any already confirmed record contradiction.
                    readReporter.report("certificate.read.cleanup", UNAVAILABLE, "临时密钥清理未验证：" + detail(failure));
                    roundTripReporter.report("certificate.round_trip.cleanup", UNAVAILABLE, "临时密钥清理未验证：" + detail(failure));
                }
            }
        }
    }

    private static void bindBaseline(Certificate leaf, Certificate[] chain, PublicKey generated,
                                     byte[] challenge, PrivateKey key) throws Exception {
        if (!(leaf instanceof X509Certificate) || chain == null || chain.length < 2)
            throw new GeneralSecurityException("initial attestation leaf unavailable");
        if (!Arrays.equals(leaf.getEncoded(), chain[0].getEncoded())
                || !SilentProbeEvidence.samePublicKey(generated, leaf.getPublicKey()))
            throw new GeneralSecurityException("initial certificate public key binding failed");
        Attestation attestation = Attestation.loadFromCertificate((X509Certificate) leaf);
        if (attestation == null || !Arrays.equals(challenge, attestation.getAttestationChallenge()))
            throw new GeneralSecurityException("initial attestation challenge binding failed");
        byte[] message = random();
        if (!SilentProbeEvidence.verifyEc(generated, "SHA256withECDSA", message, sign(key, message)))
            throw new GeneralSecurityException("initial private key signature binding failed");
        guard();
    }

    private static void checkRead(KeyStore store, String alias, CertificateRecordEvidence.Chain expected)
            throws Exception {
        guard();
        Certificate leaf = store.getCertificate(alias);
        Certificate[] chain = store.getCertificateChain(alias);
        requireX509Chain(chain);
        byte[][] observed = CertificateRecordEvidence.encode(chain);
        if (!(leaf instanceof X509Certificate))
            throw new GeneralSecurityException("single certificate read unavailable");
        byte[] leafDer = leaf.getEncoded();
        if (leafDer == null || leafDer.length == 0
                || leafDer.length > CertificateRecordEvidence.MAX_CERTIFICATE_BYTES)
            throw new GeneralSecurityException("single certificate encoding unavailable");
        validateEncoding(observed);
        validateEncoding(new byte[][] { leafDer });
        guard(); // Interrupted or incomplete calls never produce a positive record finding.
        require(CertificateRecordEvidence.compare(expected, observed, true));
        if (!Arrays.equals(encodedAt(expected.encoded(), 0), leafDer))
            throw new RecordMismatch("同一 alias 的单证书查询与原始链叶证书不一致");
    }

    private static void requireX509Chain(Certificate[] chain) throws GeneralSecurityException {
        if (chain == null || chain.length == 0 || chain.length > CertificateRecordEvidence.MAX_CERTIFICATES)
            throw new GeneralSecurityException("complete certificate chain unavailable");
        for (Certificate certificate : chain) {
            if (!(certificate instanceof X509Certificate))
                throw new GeneralSecurityException("X.509 certificate chain member unavailable");
        }
    }

    private static void validateEncoding(byte[][] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length == 0 || encoded.length > CertificateRecordEvidence.MAX_CERTIFICATES)
            throw new GeneralSecurityException("complete certificate encoding unavailable");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        int total = 0;
        for (int i = 0; i < encoded.length; i++) {
            // Reflective Array.get preserves the element's reference type through
            // ordinary Android bytecode shrinking and avoids byte[][] ambiguity.
            byte[] der = encodedAt(encoded, i);
            if (der.length == 0 || der.length > CertificateRecordEvidence.MAX_CERTIFICATE_BYTES)
                throw new GeneralSecurityException("certificate encoding unavailable");
            total += der.length;
            if (total > CertificateRecordEvidence.MAX_CHAIN_BYTES)
                throw new GeneralSecurityException("certificate chain exceeds evidence limit");
            ByteArrayInputStream input = new ByteArrayInputStream(der);
            Certificate parsed = factory.generateCertificate(input);
            if (!(parsed instanceof X509Certificate) || input.available() != 0)
                throw new GeneralSecurityException("complete X.509 encoding unavailable");
        }
    }

    private static byte[] encodedAt(byte[][] encoded, int index) throws GeneralSecurityException {
        Object element = java.lang.reflect.Array.get(encoded, index);
        if (!(element instanceof byte[]))
            throw new GeneralSecurityException("certificate encoding unavailable");
        return (byte[]) element;
    }

    private static Certificate[] restore(CertificateRecordEvidence.Chain expected) throws Exception {
        byte[][] encoded = expected.encoded();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate[] result = new Certificate[encoded.length];
        for (int i = 0; i < encoded.length; i++)
            result[i] = factory.generateCertificate(new ByteArrayInputStream(encodedAt(encoded, i)));
        return result;
    }

    private static CertificateRecordEvidence.Metadata metadata(PrivateKey key) throws Exception {
        guard();
        KeyInfo info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("alias", info.getKeystoreAlias());
        fields.put("algorithm", key.getAlgorithm());
        fields.put("keySize", String.valueOf(info.getKeySize()));
        if (info.getOrigin() != KeyProperties.ORIGIN_UNKNOWN)
            fields.put("origin", String.valueOf(info.getOrigin()));
        fields.put("purposes", String.valueOf(info.getPurposes()));
        fields.put("digests", CertificateRecordEvidence.unordered(info.getDigests()));
        fields.put("signaturePaddings", CertificateRecordEvidence.unordered(info.getSignaturePaddings()));
        fields.put("encryptionPaddings", CertificateRecordEvidence.unordered(info.getEncryptionPaddings()));
        fields.put("blockModes", CertificateRecordEvidence.unordered(info.getBlockModes()));
        fields.put("userAuthenticationRequired", String.valueOf(info.isUserAuthenticationRequired()));
        fields.put("userAuthenticationValidityDurationSeconds", String.valueOf(info.getUserAuthenticationValidityDurationSeconds()));
        fields.put("validityStart", date(info.getKeyValidityStart()));
        fields.put("originationEnd", date(info.getKeyValidityForOriginationEnd()));
        fields.put("consumptionEnd", date(info.getKeyValidityForConsumptionEnd()));
        if (Build.VERSION.SDK_INT >= 31) {
            int level = info.getSecurityLevel();
            if (level == KeyProperties.SECURITY_LEVEL_SOFTWARE
                    || level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                    || level == KeyProperties.SECURITY_LEVEL_STRONGBOX)
                fields.put("securityLevel", String.valueOf(level));
        } else fields.put("insideSecureHardware", String.valueOf(info.isInsideSecureHardware()));
        // Remaining use count and platform/version fields can change without changing key identity.
        guard();
        return new CertificateRecordEvidence.Metadata(fields);
    }

    private static String date(Date value) { return value == null ? "none" : String.valueOf(value.getTime()); }

    private static void requireSignature(PrivateKey key, PublicKey generated) throws Exception {
        byte[] message = random();
        byte[] output = sign(key, message);
        boolean valid = SilentProbeEvidence.verifyEc(generated, "SHA256withECDSA", message, output);
        guard();
        if (!valid) throw new RecordMismatch("回装成功后返回的签名不能由本轮生成公钥验证");
    }

    private static byte[] sign(PrivateKey key, byte[] message) throws Exception {
        guard();
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(message);
        byte[] output = signer.sign();
        guard();
        return output;
    }

    private static PrivateKey privateKey(KeyStore store, String alias) throws Exception {
        guard();
        Key key = store.getKey(alias, null);
        if (!(key instanceof PrivateKey)) throw new GeneralSecurityException("private key read unavailable");
        return (PrivateKey) key;
    }

    private static KeyStore store() throws Exception {
        guard();
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }

    private static byte[] random() {
        byte[] value = new byte[32];
        new SecureRandom().nextBytes(value);
        return value;
    }

    private static void guard() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException("certificate record check interrupted");
    }

    private static final class RecordMismatch extends GeneralSecurityException {
        RecordMismatch(String message) { super(message); }
    }

    private static void require(SilentProbeEvidence.Decision decision) throws GeneralSecurityException {
        if (decision.status == DETECTED) throw new RecordMismatch(decision.detail);
        if (decision.status != VERIFIED) throw new GeneralSecurityException(decision.detail);
    }

    private static void report(SilentKeystoreChecks.Reporter reporter, String check, Exception failure) {
        reporter.report(check, failure instanceof RecordMismatch ? DETECTED : UNAVAILABLE, detail(failure));
    }

    private static String detail(Exception failure) {
        if (failure instanceof InterruptedException || Thread.currentThread().isInterrupted()) return "检测已中断";
        return failure.getClass().getSimpleName() + ": " + String.valueOf(failure.getMessage());
    }
}

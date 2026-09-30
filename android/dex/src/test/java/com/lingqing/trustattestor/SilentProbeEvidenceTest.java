package com.lingqing.trustattestor;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;

/** Run main with JDK 17. Uses real JCA crypto plus a faulting KeyStoreSpi, not an Android device. */
public final class SilentProbeEvidenceTest {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        authenticationFields();
        unlockedFields();
        realSignatureEvidence();
        actualAesParameters();
        queryFailuresAreNotAbsence();
        certificateEntryObservations();
        System.out.println("SilentProbeEvidenceTest: " + assertions + " assertions passed");
    }

    private static SilentProbeEvidence.AuthFields fields(Boolean noAuth, Integer type, Integer timeout) {
        return new SilentProbeEvidence.AuthFields(noAuth, type, timeout);
    }

    private static void authenticationFields() {
        var empty = fields(null, null, null);
        var perUse = fields(null, 3, null);
        check(SilentProbeEvidence.authentication(empty, perUse, 3).status == VERIFIED,
                "absent timeout in a decoded list represents per-use authentication");
        check(SilentProbeEvidence.authentication(perUse, empty, 3).status == VERIFIED,
                "software enforcement remains observable without being labelled hardware enforcement");
        check(SilentProbeEvidence.authentication(empty, fields(null, 3, 0), 3).status == VERIFIED,
                "zero timeout is equivalent to a per-use request");
        check(SilentProbeEvidence.authentication(null, perUse, 3).status == UNAVAILABLE,
                "an unreadable list is not an empty decoded list");
        check(SilentProbeEvidence.authentication(empty, empty, 3).status == DETECTED,
                "a decoded proof must represent the requested auth type");
        check(SilentProbeEvidence.authentication(fields(true, null, null), perUse, 3).status == DETECTED,
                "NO_AUTH_REQUIRED contradicts the request even in the other enforcement list");
        check(SilentProbeEvidence.authentication(fields(null, 1, null), fields(null, 2, null), 3).status == DETECTED,
                "OR-merging two conflicting singleton auth types must not conceal a discrepancy");
        check(SilentProbeEvidence.authentication(empty, fields(null, -1, null), 3).status == DETECTED,
                "ANY is not the exact requested type");
        check(SilentProbeEvidence.authentication(empty, fields(null, 3, 30), 3).status == DETECTED,
                "positive timeout contradicts per-use authentication");
        check(SilentProbeEvidence.authentication(fields(null, null, 10), fields(null, 3, 0), 3).status == DETECTED,
                "a timeout in either origin cannot be discarded");
        String detail = SilentProbeEvidence.authentication(empty, perUse, 3).detail;
        check(detail.contains("software=") && detail.contains("hardware="), "evidence retains field origin");
    }

    private static void unlockedFields() {
        check(SilentProbeEvidence.unlockedDeviceField(true, 3, null, true).status == VERIFIED,
                "hardware marker is present");
        check(SilentProbeEvidence.unlockedDeviceField(true, 3, true, null).status == VERIFIED,
                "software marker is also a valid echo");
        check(SilentProbeEvidence.unlockedDeviceField(true, 3, null, null).status == DETECTED,
                "absent boolean tags are false in the supported decoded ASN.1 schema");
        check(SilentProbeEvidence.unlockedDeviceField(false, 3, null, null).status == UNAVAILABLE,
                "failed parsing is not absent tags");
        check(SilentProbeEvidence.unlockedDeviceField(true, 2, null, null).status == VERIFIED,
                "older schema makes the field check not applicable, not unavailable");
        check(SilentProbeEvidence.unlockedDeviceField(true, 400, false, false).status == DETECTED,
                "explicit false markers do not satisfy true request");
    }

    private static KeyPair pair(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static byte[] sign(KeyPair key, String algorithm, byte[] payload) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(key.getPrivate());
        signer.update(payload);
        return signer.sign();
    }

    private static void realSignatureEvidence() throws Exception {
        KeyPair first = pair("secp256r1");
        KeyPair second = pair("secp256r1");
        byte[] payload = "this operation's payload".getBytes(StandardCharsets.UTF_8);
        byte[] signed = sign(first, "SHA256withECDSA", payload);
        check(SilentProbeEvidence.isP256(first.getPublic()), "P-256 curve parameters match");
        check(!SilentProbeEvidence.isP256(pair("secp384r1").getPublic()), "a different named curve is not P-256");
        check(SilentProbeEvidence.samePublicKey(first.getPublic(), first.getPublic()), "public key identity matches");
        check(!SilentProbeEvidence.samePublicKey(first.getPublic(), second.getPublic()), "different aliases have different keys");
        check(SilentProbeEvidence.verifyEc(first.getPublic(), "SHA256withECDSA", payload, signed), "real signature verifies");
        check(!SilentProbeEvidence.verifyEc(second.getPublic(), "SHA256withECDSA", payload, signed), "old or other public key rejected");
        check(!SilentProbeEvidence.verifyEc(first.getPublic(), "SHA512withECDSA", payload, signed), "nonempty bytes cannot stand in for correct digest");
        check(!SilentProbeEvidence.verifyEc(first.getPublic(), "SHA256withECDSA", new byte[]{1}, signed), "payload binding enforced");
        check(!SilentProbeEvidence.verifyEc(first.getPublic(), "SHA256withECDSA", payload, new byte[0]), "empty signature is not success");
        check(!SilentProbeEvidence.verifyEc(first.getPublic(), "SHA256withECDSA", payload, null), "missing signature is not success");
        byte[] sha512 = sign(first, "SHA512withECDSA", payload);
        check(SilentProbeEvidence.verifyEc(first.getPublic(), "SHA512withECDSA", payload, sha512), "valid restricted-algorithm evidence verifies independently");
    }

    private static void actualAesParameters() throws Exception {
        byte[] material = new byte[32];
        new java.security.SecureRandom().nextBytes(material);
        byte[] plaintext = "independent AES output check".getBytes(StandardCharsets.UTF_8);
        Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(material, "AES"));
        byte[] output = encrypt.doFinal(plaintext);
        GCMParameterSpec actual = encrypt.getParameters().getParameterSpec(GCMParameterSpec.class);
        check(SilentProbeEvidence.verifyGcm(material, plaintext, output, actual), "independent GCM decrypt validates output and actual parameters");
        check(!SilentProbeEvidence.verifyGcm(material, new byte[]{9}, output, actual), "wrong plaintext is not accepted");
        byte[] wrongIv = actual.getIV();
        wrongIv[0] ^= 1;
        expect(AEADBadTagException.class,
                () -> SilentProbeEvidence.verifyGcm(material, plaintext, output, new GCMParameterSpec(actual.getTLen(), wrongIv)),
                "claimed IV must match the IV actually used");
        byte[] altered = output.clone();
        altered[altered.length - 1] ^= 1;
        expect(AEADBadTagException.class, () -> SilentProbeEvidence.verifyGcm(material, plaintext, altered, actual),
                "a nonempty invalid ciphertext cannot establish policy bypass");
        check(!SilentProbeEvidence.verifyGcm(material, plaintext, null, actual), "missing output is not evidence");
    }

    private static void queryFailuresAreNotAbsence() throws Exception {
        FakeSpi spi = new FakeSpi();
        KeyStore store = new TestStore(spi);
        store.load(null);
        check(SilentProbeEvidence.readAlias(store, "test").absent(), "all successful empty observations establish absence");
        for (String stage : new String[]{"contains", "aliases", "key", "certificate", "chain"}) {
            spi.fail = stage;
            expect(Exception.class, () -> SilentProbeEvidence.readAlias(store, "test"),
                    stage + " failure must propagate instead of returning a false/empty observation");
        }
        spi.fail = "";
        spi.present = true;
        check(!SilentProbeEvidence.readAlias(store, "test").absent(), "visible alias is not absent");
        spi.fail = "delete";
        expect(KeyStoreException.class, () -> store.deleteEntry("test"), "delete failure remains explicit");
        spi.fail = "";
        check(!SilentProbeEvidence.readAlias(store, "test").absent(), "failed deletion leaves the entry visible");
        store.deleteEntry("test");
        check(SilentProbeEvidence.readAlias(store, "test").absent(), "successful deletion can be followed by absence observation");
    }

    private static final class TestStore extends KeyStore {
        TestStore(KeyStoreSpi spi) { super(spi, null, "TestStore"); }
    }

    private static void certificateEntryObservations() throws Exception {
        // Real signed certificates keep the content comparison independent of the classifier.
        var fixture = java.nio.file.Path.of("dex/src/test/resources/attestation/google-attestation-roots-20260912.pem");
        Certificate[] certificates;
        try (var input = java.nio.file.Files.newInputStream(fixture)) {
            certificates = java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificates(input).toArray(new Certificate[0]);
        }
        Certificate first = certificates[0], replacement = certificates[1];
        var correct = new SilentProbeEvidence.AliasSnapshot(true, true, null, first, null);
        check(SilentProbeEvidence.certificateEntry(correct, true, false, first).status == VERIFIED,
                "a certificate-only observation can be verified");
        check(SilentProbeEvidence.certificateEntry(correct, true, false, replacement).status == DETECTED,
                "an old certificate after replacement contradicts the write");
        var replaced = new SilentProbeEvidence.AliasSnapshot(true, true, null, replacement, null);
        check(SilentProbeEvidence.certificateEntry(replaced, true, false, replacement).status == VERIFIED,
                "the exact replacement is accepted");
        check(SilentProbeEvidence.certificateEntry(correct, true, true, first).status == DETECTED,
                "conflicting entry types cannot pass");
        check(SilentProbeEvidence.certificateEntry(correct, false, false, first).status == DETECTED,
                "an existing certificate cannot lose its certificate-entry type");
        var privateIdentity = new SilentProbeEvidence.AliasSnapshot(true, true, pair("secp256r1").getPrivate(), first, null);
        check(SilentProbeEvidence.certificateEntry(privateIdentity, true, false, first).status == DETECTED,
                "a certificate-only entry cannot acquire a private-key identity");
        var inconsistentAliases = new SilentProbeEvidence.AliasSnapshot(true, false, null, first, null);
        check(SilentProbeEvidence.certificateEntry(inconsistentAliases, true, false, first).status == DETECTED,
                "successful enumeration must agree with containsAlias");
        check(SilentProbeEvidence.certificateEntry(null, true, false, first).status == UNAVAILABLE,
                "a failed observation is not a certificate contradiction");
        check(SilentProbeEvidence.certificateEntry(correct, true, false, null).status == UNAVAILABLE,
                "missing expected data does not pass or detect");
    }

    private static final class FakeSpi extends KeyStoreSpi {
        String fail = "";
        boolean present;
        private void fault(String stage) {
            if (stage.equals(fail)) throw new IllegalStateException(stage + " service failure");
        }
        @Override public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
            if ("key".equals(fail)) throw new UnrecoverableKeyException("query failure");
            return present ? new SecretKeySpec(new byte[16], "AES") : null;
        }
        @Override public Certificate[] engineGetCertificateChain(String alias) { fault("chain"); return null; }
        @Override public Certificate engineGetCertificate(String alias) { fault("certificate"); return null; }
        @Override public Date engineGetCreationDate(String alias) { return null; }
        @Override public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) { throw new UnsupportedOperationException(); }
        @Override public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) { throw new UnsupportedOperationException(); }
        @Override public void engineSetCertificateEntry(String alias, Certificate cert) { throw new UnsupportedOperationException(); }
        @Override public void engineDeleteEntry(String alias) throws KeyStoreException {
            if ("delete".equals(fail)) throw new KeyStoreException("delete failed");
            present = false;
        }
        @Override public Enumeration<String> engineAliases() { fault("aliases"); return Collections.enumeration(present ? Collections.singleton("test") : Collections.emptyList()); }
        @Override public boolean engineContainsAlias(String alias) { fault("contains"); return present; }
        @Override public int engineSize() { return present ? 1 : 0; }
        @Override public boolean engineIsKeyEntry(String alias) { return present; }
        @Override public boolean engineIsCertificateEntry(String alias) { return false; }
        @Override public String engineGetCertificateAlias(Certificate cert) { return null; }
        @Override public void engineStore(OutputStream stream, char[] password) { }
        @Override public void engineLoad(InputStream stream, char[] password) { }
    }

    interface Checked { void run() throws Exception; }
    private static void expect(Class<? extends Exception> type, Checked action, String message) throws Exception {
        try {
            action.run();
            check(false, message);
        } catch (Exception failure) {
            check(type.isInstance(failure), message + ": " + failure.getClass().getName());
        }
    }
    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

package io.github.vvb2060.keyattestation.attestation;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** JDK 17 standalone tests using official signed certificates and real JCA verification. */
public final class AttestationTrustPolicyTest {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        Path fixture = Path.of(args.length == 0
                ? "dex/src/test/resources/attestation/google-attestation-roots-20260912.pem" : args[0]);
        List<X509Certificate> roots = readCertificates(fixture);
        anchors(roots);
        validity(roots, readCertificates(fixture.resolveSibling("google-factory-blueline-sdk28.pem")));
        revocationSnapshots();
        System.out.println("AttestationTrustPolicyTest: " + assertions + " assertions passed");
    }

    private static List<X509Certificate> readCertificates(Path fixture) throws Exception {
        List<X509Certificate> roots = new ArrayList<>();
        try (var stream = Files.newInputStream(fixture)) {
            for (var cert : CertificateFactory.getInstance("X.509").generateCertificates(stream)) {
                roots.add((X509Certificate) cert);
            }
        }
        return roots;
    }

    private static void anchors(List<X509Certificate> roots) throws Exception {
        check(roots.size() == 2, "official fixture contains both current roots");
        check(AttestationTrustPolicy.googleRoot(roots.get(0).getPublicKey())
                == AttestationTrustPolicy.GoogleRoot.LEGACY_RSA, "legacy exact SPKI matches");
        check(AttestationTrustPolicy.googleRoot(roots.get(1).getPublicKey())
                == AttestationTrustPolicy.GoogleRoot.ROTATED_EC, "2026 rotated exact SPKI matches");
        for (var root : roots) {
            check(AttestationTrustPolicy.signaturesValid(List.of(root)), "official self-signature verifies");
            byte[] changed = root.getPublicKey().getEncoded().clone();
            changed[changed.length - 1] ^= 1;
            check(AttestationTrustPolicy.googleRoot(changed) == AttestationTrustPolicy.GoogleRoot.NONE,
                    "a changed public key is not an official anchor");
        }
        check(AttestationTrustPolicy.googleRoot(KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic())
                == AttestationTrustPolicy.GoogleRoot.NONE, "unrelated key is not anchored");
        check(!AttestationTrustPolicy.signaturesValid(roots), "unrelated valid roots do not make a valid chain");
        check(!AttestationTrustPolicy.signaturesValid(List.of()), "missing chain is not verified");
    }

    private static void validity(List<X509Certificate> roots, List<X509Certificate> factory) throws Exception {
        var legacy = List.of(roots.get(0));
        check(!AttestationTrustPolicy.allowsLegacyFactoryValidity(legacy), "root alone does not identify factory provisioning");
        check(AttestationTrustPolicy.signaturesValid(factory), "official device fixture has a real valid signature chain");
        check(AttestationTrustPolicy.allowsLegacyFactoryValidity(factory), "authenticated factory intermediate qualifies");
        check(!AttestationTrustPolicy.allowsLegacyFactoryValidity(List.of(roots.get(1))),
                "rotated root does not inherit the factory expiry exception");
        check(!AttestationTrustPolicy.allowsLegacyFactoryValidity(roots), "broken chain cannot get expiry exception");
        check(!AttestationTrustPolicy.allowsLegacyFactoryValidity(AttestationTrustPolicy.GoogleRoot.LEGACY_RSA,
                true, true, true), "any RKP extension disables factory exception, regardless of optional decoding");
        check(!AttestationTrustPolicy.allowsLegacyFactoryValidity(AttestationTrustPolicy.GoogleRoot.NONE,
                false, true, true), "self-consistency without Google anchor cannot get expiry exception");
        check(!AttestationTrustPolicy.allowsLegacyFactoryValidity(AttestationTrustPolicy.GoogleRoot.LEGACY_RSA,
                false, true, false), "old root without a factory intermediate cannot get expiry exception");
        check(!AttestationTrustPolicy.requiresValidityCheck(0, factory.size()), "app target dates are not CA authenticity evidence");
        check(!AttestationTrustPolicy.requiresValidityCheck(factory.size() - 1, factory.size()), "trust anchor dates are outside the path date policy");
        check(AttestationTrustPolicy.requiresValidityCheck(1, factory.size()), "intermediate dates are checked");
        check(!AttestationTrustPolicy.checkValidity(roots.get(0), true,
                Date.from(Instant.parse("2026-09-12T00:00:00Z"))), "valid certificate needs no exception");
        Date expired = Date.from(Instant.parse("2050-01-01T00:00:00Z"));
        check(AttestationTrustPolicy.checkValidity(roots.get(0), true, expired), "eligible actual expiry is retained as exempted");
        expect(CertificateExpiredException.class,
                () -> AttestationTrustPolicy.checkValidity(roots.get(1), false, expired), "RKP dates remain enforced");
        expect(CertificateNotYetValidException.class, () -> AttestationTrustPolicy.checkValidity(roots.get(0), true,
                Date.from(Instant.parse("2020-01-01T00:00:00Z"))), "factory exception does not accept not-before violations");
    }

    private static void revocationSnapshots() {
        var entries = new LinkedHashMap<String, RevocationSnapshot.Entry>();
        entries.put("ab", new RevocationSnapshot.Entry("REVOKED", null));
        entries.put("ac", new RevocationSnapshot.Entry("SUSPENDED", "SOFTWARE_FLAW"));
        entries.put("ad", new RevocationSnapshot.Entry(null, null));
        entries.put("ae", new RevocationSnapshot.Entry("FUTURE_STATUS", "context"));
        var cached = new RevocationSnapshot(entries, RevocationSnapshot.Source.CACHED,
                "2026-09-12 12:34:56", "cached fixture");
        check(cached.get(new BigInteger("ab", 16)).isRevokedOrSuspended(), "missing optional reason retains revoked status");
        check(cached.get(new BigInteger("ac", 16)).isRevokedOrSuspended(), "suspended is a known rejection");
        check(!cached.canCheck(new BigInteger("ad", 16)), "missing status is unavailable, not revoked or clean");
        check(!cached.canCheck(new BigInteger("ae", 16)), "new unknown status remains unavailable");
        check(cached.canCheck(BigInteger.ONE), "absence can be reported against this available snapshot");
        check(cached.metadata().freshness() == RevocationSnapshot.Freshness.CACHED_NOT_REVALIDATED,
                "cached timestamp never claims fresh online validation");
        check(cached.metadata().retrievedAt().equals("2026-09-12 12:34:56"), "retrieval timestamp retained verbatim");
        entries.clear();
        check(cached.metadata().entryCount() == 4 && cached.get(new BigInteger("ab", 16)) != null,
                "one scan keeps an immutable snapshot");
        var hexOnly = new RevocationSnapshot(Map.of("10", new RevocationSnapshot.Entry("REVOKED", null)),
                RevocationSnapshot.Source.EMBEDDED, null, "fixture");
        check(hexOnly.get(BigInteger.TEN) == null, "decimal text must not alias a different hexadecimal serial");
        check(hexOnly.get(BigInteger.valueOf(16)) != null, "canonical hexadecimal serial matches");
        check(hexOnly.metadata().freshness() == RevocationSnapshot.Freshness.EMBEDDED_DATE_UNKNOWN,
                "bundled snapshot does not invent a publication date");
        check(!RevocationSnapshot.unavailable("missing fixture").canCheck(BigInteger.ONE),
                "missing data cannot become a clean negative");
    }

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
        assertions++;
    }

    private static void expect(Class<? extends Exception> expected, Throwing task, String label) throws Exception {
        try { task.run(); }
        catch (Exception error) {
            if (expected.isInstance(error)) { assertions++; return; }
            throw error;
        }
        throw new AssertionError(label);
    }

    private interface Throwing { void run() throws Exception; }
}

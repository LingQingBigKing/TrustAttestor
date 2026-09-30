package io.github.vvb2060.keyattestation.attestation;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Date;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;

/** Local trust anchors, independently checked against https://android.googleapis.com/attestation/root.
 * Snapshot: 2026-09-12. Compare exact SubjectPublicKeyInfo bytes, never certificate names.
 */
public final class AttestationTrustPolicy {
    public enum GoogleRoot { NONE, LEGACY_RSA, ROTATED_EC }

    private static final byte[] LEGACY_SPKI = Base64.getDecoder().decode(
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==");
    private static final byte[] ROTATED_SPKI = Base64.getDecoder().decode(
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr");
    static final String PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30";

    private AttestationTrustPolicy() {}

    public static GoogleRoot googleRoot(PublicKey key) {
        return key == null ? GoogleRoot.NONE : googleRoot(key.getEncoded());
    }

    public static GoogleRoot googleRoot(byte[] subjectPublicKeyInfo) {
        if (Arrays.equals(LEGACY_SPKI, subjectPublicKeyInfo)) return GoogleRoot.LEGACY_RSA;
        if (Arrays.equals(ROTATED_SPKI, subjectPublicKeyInfo)) return GoogleRoot.ROTATED_EC;
        return GoogleRoot.NONE;
    }

    /** Input is leaf-to-root. A self-consistent chain alone never establishes a Google anchor. */
    public static boolean signaturesValid(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty()) return false;
        try {
            for (int i = 0; i < chain.size(); i++) {
                X509Certificate cert = chain.get(i);
                X509Certificate parent = chain.get(Math.min(i + 1, chain.size() - 1));
                cert.verify(parent.getPublicKey());
            }
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    public static boolean hasProvisioningExtension(List<X509Certificate> chain) {
        return chain.stream().anyMatch(cert -> cert.getExtensionValue(PROVISIONING_INFO_OID) != null);
    }

    /** Google's documented expiry exception applies only to the authenticated legacy factory
     * root system. RKP (including an unreadable provisioning extension) keeps date enforcement.
     * No device-year, issuer-name or leaf-name heuristic grants this exception.
     */
    public static boolean allowsLegacyFactoryValidity(List<X509Certificate> chain) {
        if (chain == null || chain.size() < 3) return false;
        return allowsLegacyFactoryValidity(googleRoot(chain.get(chain.size() - 1).getPublicKey()),
                hasProvisioningExtension(chain), signaturesValid(chain),
                hasFactoryIntermediateSubject(chain.get(chain.size() - 2)));
    }

    static boolean allowsLegacyFactoryValidity(GoogleRoot root, boolean provisioningPresent,
                                               boolean signaturesValid, boolean factoryIntermediate) {
        return root == GoogleRoot.LEGACY_RSA && !provisioningPresent && signaturesValid && factoryIntermediate;
    }

    private static boolean hasFactoryIntermediateSubject(X509Certificate certificate) {
        // Match the structured attribute, not text inside a CN. This classifies an already
        // authenticated chain; it does not establish the Google trust anchor.
        try {
            return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded())
                    .getRDNs(new ASN1ObjectIdentifier("2.5.4.5")).length != 0;
        } catch (RuntimeException malformedName) {
            return false;
        }
    }

    /** Google verifier checks CA dates, excluding the app-controlled target and trust anchor.
     * Extra ATTEST_KEY intermediates remain subject to the CA policy.
     */
    public static boolean requiresValidityCheck(int leafToRootIndex, int chainLength) {
        if (chainLength <= 0 || leafToRootIndex < 0 || leafToRootIndex >= chainLength) {
            throw new IllegalArgumentException("Invalid certificate position");
        }
        return leafToRootIndex != 0 && leafToRootIndex != chainLength - 1;
    }

    /** Returns whether an actual expiry was exempted. Not-before is always enforced. */
    public static boolean checkValidity(X509Certificate certificate, boolean allowLegacyFactoryExpiry,
                                        Date now) throws CertificateExpiredException, CertificateNotYetValidException {
        if (now.before(certificate.getNotBefore())) {
            throw new CertificateNotYetValidException("Certificate is not yet valid");
        }
        try {
            certificate.checkValidity(now);
            return false;
        } catch (CertificateExpiredException expired) {
            if (!allowLegacyFactoryExpiry) throw expired;
            return true;
        }
    }
}

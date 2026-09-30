package io.github.vvb2060.keyattestation.attestation;

import android.app.ActivityThread;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.UnicodeString;
import com.lingqing.trustattestor.KeyAttestation;
import org.bouncycastle.asn1.ASN1Encodable;

public class CertificateInfo {
    public static final int KEY_FAILED = -1;
    public static final int KEY_UNKNOWN = 0;
    public static final int KEY_AOSP = 1;
    public static final int KEY_GOOGLE = 2;
    public static final int KEY_KNOX = 3;
    public static final int KEY_OEM = 4;
    /** Google Remote Key Provisioning chain identified by its signed provisioning extension. */
    public static final int KEY_GOOGLE_RKP = 5;

    public static final int CERT_UNKNOWN = 0;
    public static final int CERT_SIGN = 1;
    public static final int CERT_REVOKED = 2;
    public static final int CERT_EXPIRED = 3;
    public static final int CERT_NORMAL = 4;
    public static final int CERT_UNAVAILABLE = 5;

    private static final String PROVISIONING_INFO_OID = AttestationTrustPolicy.PROVISIONING_INFO_OID;

    private static final String AOSP_ROOT_EC_PUBLIC_KEY = "" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
            "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==";

    private static final String AOSP_ROOT_RSA_PUBLIC_KEY = "" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
            "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
            "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
            "+Vfkl5YLCazOkjWFmwIDAQAB";

    private static final String KNOX_SAKV2_ROOT_PUBLIC_KEY = "" +
            "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA" +
            "46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12" +
            "4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo" +
            "ZsapxB0gAOs0jSPRX5M=";

    private static final byte[] aospEcKey = Base64.decode(AOSP_ROOT_EC_PUBLIC_KEY, 0);
    private static final byte[] aospRsaKey = Base64.decode(AOSP_ROOT_RSA_PUBLIC_KEY, 0);
    private static final byte[] knoxSakv2Key = Base64.decode(KNOX_SAKV2_ROOT_PUBLIC_KEY, 0);
    private static final Set<PublicKey> oemKeys = getOemPublicKey();

    private final X509Certificate cert;
    private int issuer = KEY_UNKNOWN;
    private int status = CERT_UNKNOWN;
    private GeneralSecurityException securityException;
    private Attestation attestation;
    private CertificateParsingException certException;

    private Integer certsIssued;
    private boolean provisioningInfoPresent;
    private boolean provisioningExtensionPresent;
    private String validatedAttestedEntity;
    private Boolean lostDevice;
    private int provisioningInfoCertificateIndex = -1;
    private boolean validityExempted;
    private boolean validityCheckSkipped;
    private boolean revocationStatusAvailable;
    private RevocationSnapshot.Metadata revocationSnapshotMetadata;

    private CertificateInfo(X509Certificate cert) {
        this.cert = cert;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public int getIssuer() {
        return issuer;
    }

    public int getStatus() {
        return status;
    }

    public GeneralSecurityException getSecurityException() {
        return securityException;
    }

    public Attestation getAttestation() {
        return attestation;
    }

    public CertificateParsingException getCertException() {
        return certException;
    }

    public Integer getCertsIssued() {
        return certsIssued;
    }

    /**
     * Returns true only when the RKP provisioning extension was present and decoded as a CBOR map.
     * An extension that merely exists but cannot be decoded is intentionally not treated as RKP.
     */
    public boolean hasProvisioningInfo() {
        return provisioningInfoPresent;
    }

    public String getValidatedAttestedEntity() { return validatedAttestedEntity; }
    public Boolean getLostDevice() { return lostDevice; }
    /** Index in the original leaf-to-root chain; fields belong to this signed certificate. */
    public int getProvisioningInfoCertificateIndex() { return provisioningInfoCertificateIndex; }
    public boolean hasProvisioningExtension() { return provisioningExtensionPresent; }
    public boolean isValidityExempted() { return validityExempted; }
    public boolean isValidityCheckSkipped() { return validityCheckSkipped; }
    public boolean isRevocationStatusAvailable() { return revocationStatusAvailable; }
    public RevocationSnapshot.Metadata getRevocationSnapshotMetadata() { return revocationSnapshotMetadata; }

    private void checkIssuer() {
        var publicKey = cert.getPublicKey().getEncoded();
        if (AttestationTrustPolicy.googleRoot(publicKey) != AttestationTrustPolicy.GoogleRoot.NONE) {
            issuer = KEY_GOOGLE;
        } else if (Arrays.equals(publicKey, aospEcKey)) {
            issuer = KEY_AOSP;
        } else if (Arrays.equals(publicKey, aospRsaKey)) {
            issuer = KEY_AOSP;
        } else if (Arrays.equals(publicKey, knoxSakv2Key)) {
            issuer = KEY_KNOX;
        } else if (oemKeys != null) {
            for (var key : oemKeys) {
                if (Arrays.equals(publicKey, key.getEncoded())) {
                    issuer = KEY_OEM;
                    break;
                }
            }
        }
    }

    private void checkStatus(PublicKey parentKey, boolean allowLegacyFactoryValidity,
                             RevocationSnapshot revocations, boolean checkValidity) {
        revocationSnapshotMetadata = revocations.metadata();
        revocationStatusAvailable = revocations.canCheck(cert.getSerialNumber());
        try {
            status = CERT_SIGN;
            cert.verify(parentKey);
            status = CERT_REVOKED;
            var certStatus = RevocationList.get(revocations, cert.getSerialNumber());
            if (certStatus != null) {
                throw new CertificateException("Certificate revocation " + certStatus);
            }
            if (!revocationStatusAvailable) {
                status = CERT_UNAVAILABLE;
                return;
            }
            status = CERT_EXPIRED;
            validityCheckSkipped = !checkValidity;
            if (checkValidity) {
                validityExempted = AttestationTrustPolicy.checkValidity(cert,
                        allowLegacyFactoryValidity, new java.util.Date());
            }
            status = CERT_NORMAL;
        } catch (GeneralSecurityException e) {
            securityException = e;
        }
    }

    private boolean checkAttestation() {
        boolean terminate;
        try {
            attestation = Attestation.loadFromCertificate(cert);
            // If key purpose included KeyPurpose::SIGN,
            // then it could be used to sign arbitrary data, including any tbsCertificate,
            // and so an attestation produced by the key would have no security properties.
            // If the parent certificate can attest that the key purpose is only KeyPurpose::ATTEST_KEY,
            // then the child certificate can be trusted.
            var purposes = attestation.getTeeEnforced().getPurposes();
            terminate = purposes == null || !purposes.contains(AuthorizationList.KM_PURPOSE_ATTEST_KEY);
        } catch (CertificateParsingException e) {
            certException = e;
            terminate = false;
        }
        return terminate;
    }

    private void checkProvisioningInfo(int certificateIndex) {
        var bytes = cert.getExtensionValue(PROVISIONING_INFO_OID);
        if (bytes == null) return;
        provisioningExtensionPresent = true;
        provisioningInfoCertificateIndex = certificateIndex;
        try {
            // X509Certificate.getExtensionValue returns the DER encoded OCTET STRING
            // wrapper.  Decode that wrapper before handing the payload to CBOR; this
            // also handles the DER forms emitted by Android 14/15 RKP providers.
            ASN1Encodable asn1 = Asn1Utils.getAsn1EncodableFromBytes(bytes);
            var cborBytes = Asn1Utils.getByteArrayFromAsn1(asn1);
            var decoded = CborDecoder.decode(cborBytes);
            if (decoded.isEmpty() || !(decoded.get(0) instanceof Map map)) {
                throw new CertificateParsingException("RKP provisioning payload is not a CBOR map");
            }
            // Unknown optional fields and types must not erase other successfully decoded fields.
            for (var key : map.getKeys()) {
                if (!(key instanceof Number number)) continue;
                int keyInt;
                try { keyInt = intValueExactCompat(number.getValue()); }
                catch (ArithmeticException ignored) { continue; }
                var value = map.get(key);
                try {
                    if (keyInt == 1 && value instanceof Number count) {
                        certsIssued = intValueExactCompat(count.getValue());
                        if (certsIssued < 0) certsIssued = null;
                    } else if (keyInt == 4 && value instanceof UnicodeString text) {
                        validatedAttestedEntity = text.getString();
                    } else if (keyInt == 6) {
                        lostDevice = CborUtils.getBoolean(map, key);
                    }
                } catch (RuntimeException optionalFieldError) {
                    Log.w(KeyAttestation.TAG, "Unreadable optional provisioning field: " + keyInt);
                }
            }
            provisioningInfoPresent = true;
        } catch (Exception e) {
            Log.e(KeyAttestation.TAG, "checkProvisioningInfo", e);
        }
    }

    /** Android API 27 compatible equivalent of BigInteger.intValueExact(). */
    private static int intValueExactCompat(BigInteger value) {
        if (value == null || value.bitLength() > 31) {
            throw new ArithmeticException("BigInteger does not fit in int");
        }
        return value.intValue();
    }

    public static AttestationResult parseCertificateChain(List<X509Certificate> certs) {
        if (certs == null || certs.isEmpty()) throw new IllegalArgumentException("No certificate found");
        var revocations = RevocationList.refreshSnapshot();
        boolean allowLegacyFactoryValidity = AttestationTrustPolicy.allowsLegacyFactoryValidity(certs);
        var infoList = new ArrayList<CertificateInfo>();
        var allInfos = new ArrayList<CertificateInfo>(certs.size());

        // Provisioning information belongs to the RKP delegated chain and is
        // not necessarily on the leaf.  Build the full metadata set first so
        // an early Attestation-purpose termination cannot hide that extension.
        for (int index = 0; index < certs.size(); index++) {
            var info = new CertificateInfo(certs.get(index));
            info.checkProvisioningInfo(index);
            allInfos.add(info);
        }

        var parent = certs.get(certs.size() - 1);
        for (int i = certs.size() - 1; i >= 0; i--) {
            var parentKey = parent.getPublicKey();
            var info = allInfos.get(i);
            infoList.add(info);
            info.checkStatus(parentKey, allowLegacyFactoryValidity, revocations,
                    AttestationTrustPolicy.requiresValidityCheck(i, certs.size()));
            if (parent == info.cert) {
                info.checkIssuer();
            } else {
                parent = info.cert;
            }
            if (info.checkAttestation()) {
                break;
            }
        }

        return AttestationResult.form(infoList);
    }

    private static List<X509Certificate> sortCerts(List<X509Certificate> certs) {
        if (certs.size() < 2) {
            return certs;
        }

        var issuer = certs.get(0).getIssuerX500Principal();
        boolean okay = true;
        for (var cert : certs) {
            var subject = cert.getSubjectX500Principal();
            if (issuer.equals(subject)) {
                issuer = subject;
            } else {
                okay = false;
                break;
            }
        }
        if (okay) {
            return certs;
        }

        var newList = new ArrayList<X509Certificate>(certs.size());
        for (var cert : certs) {
            boolean found = false;
            var subject = cert.getSubjectX500Principal();
            for (var c : certs) {
                if (c == cert) continue;
                if (c.getIssuerX500Principal().equals(subject)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                newList.add(cert);
            }
        }
        if (newList.size() != 1) {
            return certs;
        }

        var oldList = new LinkedList<>(certs);
        oldList.remove(newList.get(0));
        for (int i = 0; i < newList.size(); i++) {
            issuer = newList.get(i).getIssuerX500Principal();
            for (var it = oldList.iterator(); it.hasNext(); ) {
                var cert = it.next();
                if (cert.getSubjectX500Principal().equals(issuer)) {
                    newList.add(cert);
                    it.remove();
                    break;
                }
            }
        }
        if (!oldList.isEmpty()) {
            return certs;
        }
        return newList;
    }

    public static AttestationResult parseCertificateChain(CertPath certPath)
            throws CertificateParsingException {
        // noinspection unchecked
        var certs = (List<X509Certificate>) certPath.getCertificates();
        if (certs.isEmpty()) {
            throw new CertificateParsingException("No certificate found");
        }
        return parseCertificateChain(sortCerts(certs));
    }

    private static Set<PublicKey> getOemPublicKey() {
        var resName = "android:array/vendor_required_attestation_certificates";
        // TrustAttestor modified: Use hidden api stub
        var res = ActivityThread.currentApplication().getResources();
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id == 0) {
            return null;
        }
        var set = new HashSet<PublicKey>();
        try {
            var cf = CertificateFactory.getInstance("X.509");
            for (var s : res.getStringArray(id)) {
                var cert = s.replaceAll("\\s+", "\n")
                        .replaceAll("-BEGIN\\nCERTIFICATE-", "-BEGIN CERTIFICATE-")
                        .replaceAll("-END\\nCERTIFICATE-", "-END CERTIFICATE-");
                var input = new ByteArrayInputStream(cert.getBytes());
                var publicKey = cf.generateCertificate(input).getPublicKey();
                set.add(publicKey);
            }
        } catch (CertificateException e) {
            Log.e(KeyAttestation.TAG, "getOemKeys: ", e);
            return null;
        }
        set.removeIf(key -> AttestationTrustPolicy.googleRoot(key) != AttestationTrustPolicy.GoogleRoot.NONE);
        if (set.isEmpty()) {
            return null;
        }
        set.forEach(key -> Log.i(KeyAttestation.TAG, "getOemKeys: " + key));
        return set;
    }
}

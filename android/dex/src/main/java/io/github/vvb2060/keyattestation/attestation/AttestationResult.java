package io.github.vvb2060.keyattestation.attestation;

import static io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_SOFTWARE;

import java.util.List;

public class AttestationResult {
    private final List<CertificateInfo> certs;
    private RootOfTrust rootOfTrust;
    private int issuer = CertificateInfo.KEY_UNKNOWN;
    private int status = CertificateInfo.KEY_FAILED;
    private boolean sw = true;
    public Attestation showAttestation;

    private AttestationResult(List<CertificateInfo> certs) {
        this.certs = certs;
    }

    public List<CertificateInfo> getCerts() {
        return certs;
    }

    public RootOfTrust getRootOfTrust() {
        return rootOfTrust;
    }

    public int getIssuer() {
        return issuer;
    }

    public int getStatus() {
        return status;
    }

    public boolean isSoftwareLevel() {
        return sw;
    }

    public Integer getOsPatchLevel() {
        return showAttestation != null ? showAttestation.getOsPatchLevel() : null;
    }

    public Integer getVendorPatchLevel() {
        return showAttestation != null ? showAttestation.getVendorPatchLevel() : null;
    }

    public Integer getBootPatchLevel() {
        return showAttestation != null ? showAttestation.getBootPatchLevel() : null;
    }

    /** Structural metadata does not make an otherwise unknown root trusted. */
    public boolean isProvisioningInfoPresent() {
        return certs.stream().anyMatch(CertificateInfo::hasProvisioningExtension);
    }

    public boolean isGoogleRootMatched() {
        return !certs.isEmpty() && certs.get(0).getIssuer() == CertificateInfo.KEY_GOOGLE;
    }

    public boolean isRevocationStatusAvailable() {
        return !certs.isEmpty() && certs.stream().allMatch(CertificateInfo::isRevocationStatusAvailable);
    }

    public RevocationSnapshot.Metadata getRevocationSnapshotMetadata() {
        return certs.isEmpty() ? RevocationList.getSnapshotMetadata()
                : certs.get(0).getRevocationSnapshotMetadata();
    }

    public static AttestationResult form(List<CertificateInfo> certs) {
        var result = new AttestationResult(certs);
        result.issuer = certs.get(0).getIssuer();
        result.status = result.issuer;
        for (var cert : certs) {
            if (cert.getStatus() < CertificateInfo.CERT_EXPIRED) {
                result.status = CertificateInfo.KEY_FAILED;
                break;
            }
        }
        // RKP is a classification beneath an authenticated Google root, never a DN-based trust upgrade.
        boolean chainValid = certs.stream().allMatch(cert -> cert.getStatus() == CertificateInfo.CERT_NORMAL);
        boolean provisioningInfo = certs.stream().anyMatch(CertificateInfo::hasProvisioningInfo);
        if (result.isGoogleRootMatched() && chainValid && provisioningInfo) {
            result.issuer = CertificateInfo.KEY_GOOGLE_RKP;
            result.status = CertificateInfo.KEY_GOOGLE_RKP;
        }
        var info = certs.get(certs.size() - 1);
        var attestation = info.getAttestation();
        if (attestation != null) {
            result.showAttestation = attestation;
            result.rootOfTrust = attestation.getRootOfTrust();
            result.sw = attestation.getAttestationSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE;
        } else {
            var parseException = info.getCertException();
            var detail = parseException == null ? "attestation extension missing" : parseException.getMessage();
            throw new RuntimeException("Cannot parse certificate: " + detail, parseException);
        }
        return result;
    }
}

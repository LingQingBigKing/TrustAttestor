package com.lingqing.trustattestor;

/** Run main on the host JDK; no Android runtime or JUnit dependency is required. */
public final class AttestationVerdictEvidenceTest {
    private static int assertions;

    public static void main(String[] args) {
        check(AttestationVerdictEvidence.detectedFlags(true, true, true, true) == 0L,
                "healthy verdict has no finding");
        check(AttestationVerdictEvidence.detectedFlags(false, true, true, true)
                        == AttestationVerdictEvidence.FLAG_TRUST_VALIDATION,
                "trust failure is specific");
        check(AttestationVerdictEvidence.detectedFlags(true, false, true, true)
                        == AttestationVerdictEvidence.FLAG_SECURITY_LEVEL,
                "security-level failure is specific");
        check(AttestationVerdictEvidence.detectedFlags(true, true, false, true)
                        == AttestationVerdictEvidence.FLAG_VERIFIED_BOOT_STATE,
                "unlocked device is specific");
        check(AttestationVerdictEvidence.detectedFlags(true, true, true, false)
                        == AttestationVerdictEvidence.FLAG_VERIFIED_BOOT_STATE,
                "non-Verified boot is specific");
        check(AttestationVerdictEvidence.detectedFlags(false, false, false, false)
                        == (AttestationVerdictEvidence.FLAG_TRUST_VALIDATION
                        | AttestationVerdictEvidence.FLAG_SECURITY_LEVEL
                        | AttestationVerdictEvidence.FLAG_VERIFIED_BOOT_STATE),
                "independent failures remain independently visible");
        System.out.println("AttestationVerdictEvidenceTest: " + assertions + " assertions passed");
    }

    private static void check(boolean value, String description) {
        assertions++;
        if (!value) throw new AssertionError(description);
    }
}

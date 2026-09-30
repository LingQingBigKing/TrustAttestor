package com.lingqing.trustattestor;

/** Converts base attestation-verdict failures into stable, user-visible finding flags. */
final class AttestationVerdictEvidence {
    static final long FLAG_VERIFIED_BOOT_STATE = 1L << 8;
    static final long FLAG_TRUST_VALIDATION = 1L << 14;
    static final long FLAG_SECURITY_LEVEL = 1L << 15;

    private AttestationVerdictEvidence() {}

    static long detectedFlags(
            boolean trustValidationPassed,
            boolean hardwareSecurityLevel,
            boolean deviceLocked,
            boolean verifiedBootVerified
    ) {
        long flags = 0L;
        if (!trustValidationPassed) flags |= FLAG_TRUST_VALIDATION;
        if (!hardwareSecurityLevel) flags |= FLAG_SECURITY_LEVEL;
        if (!deviceLocked || !verifiedBootVerified) flags |= FLAG_VERIFIED_BOOT_STATE;
        return flags;
    }
}

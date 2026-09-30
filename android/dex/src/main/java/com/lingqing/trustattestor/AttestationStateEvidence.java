package com.lingqing.trustattestor;

import java.util.Locale;

/** Pure decision helpers for attestation state and device-properties applicability. */
public final class AttestationStateEvidence {
    private static final int ANDROID_12_API = 31;

    public static final int VERIFIED_BOOT_VERIFIED = 0;
    public static final int VERIFIED_BOOT_SELF_SIGNED = 1;
    public static final int VERIFIED_BOOT_UNVERIFIED = 2;
    public static final int VERIFIED_BOOT_FAILED = 3;

    private AttestationStateEvidence() {}

    public static boolean shouldRunDeviceProperties(int sdkInt, boolean featureDeclared) {
        return sdkInt >= ANDROID_12_API && featureDeclared;
    }

    public static boolean isDeviceStateConsistent(
            int verifiedBootState,
            boolean attestedLocked,
            String property
    ) {
        if (verifiedBootState == VERIFIED_BOOT_FAILED || property == null || property.isEmpty()) {
            return true;
        }
        return attestedLocked
                ? "locked".equalsIgnoreCase(property)
                : "unlocked".equalsIgnoreCase(property);
    }

    public static boolean isBootStateConsistent(int verifiedBootState, String property) {
        if (property == null || property.isEmpty()) return true;
        return switch (property.toLowerCase(Locale.ROOT)) {
            case "green" -> verifiedBootState == VERIFIED_BOOT_VERIFIED;
            case "yellow" -> verifiedBootState == VERIFIED_BOOT_SELF_SIGNED;
            case "orange" -> verifiedBootState == VERIFIED_BOOT_UNVERIFIED;
            case "red" -> verifiedBootState == VERIFIED_BOOT_FAILED;
            default -> true;
        };
    }
}

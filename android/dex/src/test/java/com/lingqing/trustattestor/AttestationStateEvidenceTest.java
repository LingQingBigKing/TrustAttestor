package com.lingqing.trustattestor;

/** Standalone regression tests; run main with JDK 17. */
public final class AttestationStateEvidenceTest {
    private static int assertions;

    public static void main(String[] args) {
        userReportedContradictionsAreRejected();
        matchingStatesAreAccepted();
        emptyAndUnknownPropertiesKeepLegacySemantics();
        failedBootStateKeepsLegacyDeviceStateSemantics();
        devicePropertiesRequiresApiAndFeature();
        System.out.println("AttestationStateEvidenceTest: " + assertions + " assertions passed");
    }

    private static void userReportedContradictionsAreRejected() {
        check(!AttestationStateEvidence.isDeviceStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_UNVERIFIED,
                        false,
                        "locked"),
                "locked property contradicts attested unlocked state");
        check(!AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_UNVERIFIED,
                        "green"),
                "green property contradicts attested Unverified state");
    }

    private static void matchingStatesAreAccepted() {
        check(AttestationStateEvidence.isDeviceStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_VERIFIED,
                        true,
                        "locked"),
                "locked states match");
        check(AttestationStateEvidence.isDeviceStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_UNVERIFIED,
                        false,
                        "UNLOCKED"),
                "unlocked comparison is case-insensitive");
        check(AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_VERIFIED,
                        "green"),
                "Verified maps to green");
        check(AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_SELF_SIGNED,
                        "YELLOW"),
                "SelfSigned maps to yellow case-insensitively");
        check(AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_UNVERIFIED,
                        "orange"),
                "Unverified maps to orange");
        check(AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_FAILED,
                        "red"),
                "Failed maps to red");
    }

    private static void emptyAndUnknownPropertiesKeepLegacySemantics() {
        check(AttestationStateEvidence.isDeviceStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_VERIFIED,
                        false,
                        ""),
                "empty device-state property is ignored");
        check(AttestationStateEvidence.isDeviceStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_VERIFIED,
                        false,
                        null),
                "missing device-state property is ignored");
        check(!AttestationStateEvidence.isDeviceStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_VERIFIED,
                        true,
                        "unknown"),
                "unknown device-state value remains inconsistent");
        check(AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_UNVERIFIED,
                        ""),
                "empty verified-boot property is ignored");
        check(AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_UNVERIFIED,
                        null),
                "missing verified-boot property is ignored");
        check(AttestationStateEvidence.isBootStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_UNVERIFIED,
                        "unknown"),
                "unknown verified-boot value is ignored");
    }

    private static void failedBootStateKeepsLegacyDeviceStateSemantics() {
        check(AttestationStateEvidence.isDeviceStateConsistent(
                        AttestationStateEvidence.VERIFIED_BOOT_FAILED,
                        false,
                        "locked"),
                "Failed verified-boot state bypasses device-state comparison");
    }

    private static void devicePropertiesRequiresApiAndFeature() {
        check(!AttestationStateEvidence.shouldRunDeviceProperties(30, true),
                "API 30 is below the Device Properties API level");
        check(!AttestationStateEvidence.shouldRunDeviceProperties(31, false),
                "undeclared feature disables the probe");
        check(AttestationStateEvidence.shouldRunDeviceProperties(31, true),
                "API 31 with declared feature enables the probe");
        check(AttestationStateEvidence.shouldRunDeviceProperties(35, true),
                "newer API with declared feature enables the probe");
    }

    private static void check(boolean condition, String description) {
        assertions++;
        if (!condition) throw new AssertionError(description);
    }
}

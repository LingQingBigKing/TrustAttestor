package com.lingqing.trustattestor;

/** Standalone host regression test; no Android runtime or JUnit dependency is required. */
public final class DevicePropertiesProbeDecisionTest {
    private static int assertions;

    public static void main(String[] args) {
        requiresAllFiveProperties();
        selectsFrameworkPropertyPolicyByPlatformVersion();
        mapsOnlyRealAttestationOverrideProperties();
        requiresRepeatableReturnedAnomaly();
        requiresARepeatableNonTransientDifferential();
        System.out.println("DevicePropertiesProbeDecisionTest: " + assertions
                + " assertions passed");
    }

    private static void requiresAllFiveProperties() {
        for (int count = 0; count < DevicePropertiesProbeDecision.REQUIRED_PROPERTY_COUNT; count++) {
            check(!DevicePropertiesProbeDecision.hasCompletePropertySet(count),
                    count + " properties are incomplete");
        }
        check(DevicePropertiesProbeDecision.hasCompletePropertySet(5),
                "all five requested properties are complete");
        check(!DevicePropertiesProbeDecision.hasCompletePropertySet(6),
                "unexpected extra count is not the canonical profile");
    }

    private static void selectsFrameworkPropertyPolicyByPlatformVersion() {
        check(!DevicePropertiesProbeDecision.usesAttestationSpecificBuildProperties(31),
                "Android 12 submitted Build.* values");
        check(!DevicePropertiesProbeDecision.usesAttestationSpecificBuildProperties(33),
                "Android 13 submitted Build.* values");
        check(DevicePropertiesProbeDecision.usesAttestationSpecificBuildProperties(34),
                "Android 14 uses attestation-specific properties");
        check(DevicePropertiesProbeDecision.usesAttestationSpecificBuildProperties(35),
                "newer releases keep the attestation-specific path");
    }

    private static void mapsOnlyRealAttestationOverrideProperties() {
        check(DevicePropertiesProbeDecision.attestationOverrideProperty(33, "brand") == null,
                "Android 13 has no framework attestation override fields");
        check("ro.product.brand_for_attestation".equals(
                        DevicePropertiesProbeDecision.attestationOverrideProperty(34, "brand")),
                "brand uses the AOSP attestation override");
        check("ro.product.name_for_attestation".equals(
                        DevicePropertiesProbeDecision.attestationOverrideProperty(34, "product")),
                "product maps to name_for_attestation");
        check("ro.product.model_for_attestation".equals(
                        DevicePropertiesProbeDecision.attestationOverrideProperty(34, "model")),
                "model uses the AOSP attestation override");
        check(DevicePropertiesProbeDecision.attestationOverrideProperty(34, "device") == null,
                "device must not fall back to ro.product.vendor.device");
        check(DevicePropertiesProbeDecision.attestationOverrideProperty(34, "manufacturer") == null,
                "manufacturer must not fall back to ro.product.vendor.manufacturer");
    }

    private static void requiresRepeatableReturnedAnomaly() {
        check(DevicePropertiesProbeDecision.isRepeatableReturnedAnomaly(
                        "missing=model", "missing=model"),
                "the same anomaly in two successful responses is repeatable");
        check(!DevicePropertiesProbeDecision.isRepeatableReturnedAnomaly(
                        "missing=model", ""),
                "a clean retry rejects a one-off anomaly");
        check(!DevicePropertiesProbeDecision.isRepeatableReturnedAnomaly(
                        "missing=model", "missing=brand"),
                "different response anomalies are inconclusive");
        check(!DevicePropertiesProbeDecision.isRepeatableReturnedAnomaly(null, null),
                "missing observations are not anomalies");
    }

    private static void requiresARepeatableNonTransientDifferential() {
        check(DevicePropertiesProbeDecision.isRepeatableDifferential(
                        true, true, true, true, false, true),
                "two matching DP failures bracketed by healthy controls are detected");
        check(!DevicePropertiesProbeDecision.isRepeatableDifferential(
                        false, true, true, true, false, true),
                "missing pre-control is inconclusive");
        check(!DevicePropertiesProbeDecision.isRepeatableDifferential(
                        true, true, false, true, false, true),
                "missing post-control is inconclusive");
        check(!DevicePropertiesProbeDecision.isRepeatableDifferential(
                        true, true, true, false, false, true),
                "a successful retry is not detected");
        check(!DevicePropertiesProbeDecision.isRepeatableDifferential(
                        true, true, true, true, true, true),
                "transient Keystore failures remain unavailable");
        check(!DevicePropertiesProbeDecision.isRepeatableDifferential(
                        true, true, true, true, false, false),
                "different failures are not a repeatable differential");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

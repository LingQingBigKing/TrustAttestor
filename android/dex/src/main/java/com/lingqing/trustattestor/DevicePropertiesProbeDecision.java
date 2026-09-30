package com.lingqing.trustattestor;

/** Pure policy for the capability-gated Device Properties differential probe. */
final class DevicePropertiesProbeDecision {
    static final int REQUIRED_PROPERTY_COUNT = 5;
    private static final int ANDROID_14_API = 34;

    private DevicePropertiesProbeDecision() { }

    static boolean hasCompletePropertySet(int propertyCount) {
        return propertyCount == REQUIRED_PROPERTY_COUNT;
    }

    static boolean usesAttestationSpecificBuildProperties(int sdkInt) {
        // Android 12/13 submitted Build.* directly. Android 14 introduced the
        // three *_FOR_ATTESTATION overrides used by the framework request path.
        return sdkInt >= ANDROID_14_API;
    }

    static String attestationOverrideProperty(int sdkInt, String property) {
        if (!usesAttestationSpecificBuildProperties(sdkInt) || property == null) return null;
        return switch (property) {
            case "brand" -> "ro.product.brand_for_attestation";
            case "product" -> "ro.product.name_for_attestation";
            case "model" -> "ro.product.model_for_attestation";
            // AOSP submits Build.DEVICE and Build.MANUFACTURER directly. There are no
            // device/manufacturer *_for_attestation properties in this framework path.
            default -> null;
        };
    }

    static boolean isRepeatableReturnedAnomaly(String firstIssue, String retryIssue) {
        return firstIssue != null && !firstIssue.isBlank() && firstIssue.equals(retryIssue);
    }

    static boolean isRepeatableDifferential(
            boolean baselineBeforeSucceeded,
            boolean firstDevicePropertiesGenerationFailed,
            boolean baselineAfterSucceeded,
            boolean retryDevicePropertiesGenerationFailed,
            boolean transientFailure,
            boolean sameFailureSignature
    ) {
        return baselineBeforeSucceeded
                && firstDevicePropertiesGenerationFailed
                && baselineAfterSucceeded
                && retryDevicePropertiesGenerationFailed
                && !transientFailure
                && sameFailureSignature;
    }
}

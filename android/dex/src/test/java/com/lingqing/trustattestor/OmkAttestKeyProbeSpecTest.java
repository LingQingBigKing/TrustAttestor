package com.lingqing.trustattestor;

/** Standalone regression tests: run main; no Android runtime or JUnit required. */
public final class OmkAttestKeyProbeSpecTest {
    private static int assertions;

    public static void main(String[] args) {
        tagTypesMatchAospKeyMintAbi();
        encodedTagsUseTheRequiredUnionDiscriminators();
        tagDecompositionIsStable();
        appAttestKeyProbeRequiresBothPlatformAndFeature();
        System.out.println("OmkAttestKeyProbeSpecTest: " + assertions + " assertions passed");
    }

    private static void tagTypesMatchAospKeyMintAbi() {
        equal(0x00000000, OmkAttestKeyProbeSpec.TYPE_INVALID, "INVALID");
        equal(0x10000000, OmkAttestKeyProbeSpec.TYPE_ENUM, "ENUM");
        equal(0x20000000, OmkAttestKeyProbeSpec.TYPE_ENUM_REP, "ENUM_REP");
        equal(0x30000000, OmkAttestKeyProbeSpec.TYPE_UINT, "UINT");
        equal(0x40000000, OmkAttestKeyProbeSpec.TYPE_UINT_REP, "UINT_REP");
        equal(0x50000000, OmkAttestKeyProbeSpec.TYPE_ULONG, "ULONG");
        equal(0x60000000, OmkAttestKeyProbeSpec.TYPE_DATE, "DATE");
        equal(0x70000000, OmkAttestKeyProbeSpec.TYPE_BOOL, "BOOL");
        equal(0x80000000, OmkAttestKeyProbeSpec.TYPE_BIGNUM, "BIGNUM");
        equal(0x90000000, OmkAttestKeyProbeSpec.TYPE_BYTES, "BYTES");
        equal(0xA0000000, OmkAttestKeyProbeSpec.TYPE_ULONG_REP, "ULONG_REP");
    }

    private static void encodedTagsUseTheRequiredUnionDiscriminators() {
        equal(0x20000001, OmkAttestKeyProbeSpec.TAG_PURPOSE, "PURPOSE is ENUM_REP");
        equal(0x10000002, OmkAttestKeyProbeSpec.TAG_ALGORITHM, "ALGORITHM is ENUM");
        equal(0x30000003, OmkAttestKeyProbeSpec.TAG_KEY_SIZE, "KEY_SIZE is UINT");
        equal(0x20000004, OmkAttestKeyProbeSpec.TAG_BLOCK_MODE, "BLOCK_MODE is ENUM_REP");
        equal(0x20000005, OmkAttestKeyProbeSpec.TAG_DIGEST, "DIGEST is ENUM_REP");
        equal(0x20000006, OmkAttestKeyProbeSpec.TAG_PADDING, "PADDING is ENUM_REP");
        equal(0x1000000A, OmkAttestKeyProbeSpec.TAG_EC_CURVE, "EC_CURVE is ENUM");
        equal(0x700000CA, OmkAttestKeyProbeSpec.TAG_INCLUDE_UNIQUE_ID,
                "INCLUDE_UNIQUE_ID is BOOL at tag number 202");
        equal(0x700001F7, OmkAttestKeyProbeSpec.TAG_NO_AUTH_REQUIRED,
                "NO_AUTH_REQUIRED is BOOL");
        equal(0x600002BD, OmkAttestKeyProbeSpec.TAG_CREATION_DATETIME,
                "CREATION_DATETIME is DATE");
        equal(0x900002C3, OmkAttestKeyProbeSpec.TAG_UNIQUE_ID,
                "UNIQUE_ID is BYTES at tag number 707");
        equal(0x900002C4, OmkAttestKeyProbeSpec.TAG_ATTESTATION_CHALLENGE,
                "ATTESTATION_CHALLENGE is BYTES");
        equal(0x700002D0, OmkAttestKeyProbeSpec.TAG_DEVICE_UNIQUE_ATTESTATION,
                "DEVICE_UNIQUE_ATTESTATION is BOOL");
    }

    private static void tagDecompositionIsStable() {
        equal(OmkAttestKeyProbeSpec.TYPE_ENUM,
                OmkAttestKeyProbeSpec.typeOf(OmkAttestKeyProbeSpec.TAG_ALGORITHM),
                "algorithm discriminator");
        equal(OmkAttestKeyProbeSpec.TYPE_UINT,
                OmkAttestKeyProbeSpec.typeOf(OmkAttestKeyProbeSpec.TAG_KEY_SIZE),
                "key-size discriminator");
        equal(OmkAttestKeyProbeSpec.TYPE_ENUM_REP,
                OmkAttestKeyProbeSpec.typeOf(OmkAttestKeyProbeSpec.TAG_PURPOSE),
                "purpose discriminator");
        equal(OmkAttestKeyProbeSpec.TYPE_BYTES,
                OmkAttestKeyProbeSpec.typeOf(OmkAttestKeyProbeSpec.TAG_ATTESTATION_CHALLENGE),
                "challenge discriminator");
        equal(2, OmkAttestKeyProbeSpec.numberOf(OmkAttestKeyProbeSpec.TAG_ALGORITHM),
                "algorithm tag number");
        equal(708, OmkAttestKeyProbeSpec.numberOf(
                OmkAttestKeyProbeSpec.TAG_ATTESTATION_CHALLENGE), "challenge tag number");
        equal(202, OmkAttestKeyProbeSpec.numberOf(
                OmkAttestKeyProbeSpec.TAG_INCLUDE_UNIQUE_ID), "include-unique-ID tag number");
    }

    private static void appAttestKeyProbeRequiresBothPlatformAndFeature() {
        check("android.hardware.keystore.app_attest_key".equals(
                        OmkAttestKeyProbeSpec.FEATURE_KEYSTORE_APP_ATTEST_KEY),
                "feature string matches PackageManager contract");
        check(OmkAttestKeyProbeSpec.applicability(30, true)
                        == OmkAttestKeyProbeSpec.Applicability.REQUIRES_ANDROID_12,
                "feature alone cannot enable the Keystore2 probe before Android 12");
        check(OmkAttestKeyProbeSpec.applicability(31, false)
                        == OmkAttestKeyProbeSpec.Applicability.FEATURE_NOT_DECLARED,
                "missing feature is not an execution failure");
        check(OmkAttestKeyProbeSpec.applicability(31, true)
                        == OmkAttestKeyProbeSpec.Applicability.APPLICABLE,
                "Android 12 with the feature is applicable");
        check(OmkAttestKeyProbeSpec.applicability(35, true)
                        == OmkAttestKeyProbeSpec.Applicability.APPLICABLE,
                "newer Android versions remain applicable");
        check(!OmkAttestKeyProbeSpec.shouldRun(30, true),
                "pre-Android-12 probe is gated");
        check(!OmkAttestKeyProbeSpec.shouldRun(35, false),
                "feature-absent probe is gated");
        check(OmkAttestKeyProbeSpec.shouldRun(35, true),
                "supported probe runs");
    }

    private static void equal(int expected, int actual, String message) {
        assertions++;
        if (expected != actual) {
            throw new AssertionError(message + ": expected=0x"
                    + Integer.toHexString(expected) + ", actual=0x"
                    + Integer.toHexString(actual));
        }
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

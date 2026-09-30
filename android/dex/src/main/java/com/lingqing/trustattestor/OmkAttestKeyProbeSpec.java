package com.lingqing.trustattestor;

/**
 * Pure-Java constants and applicability rules used by the direct AttestKey descriptor probe.
 *
 * <p>The encoded tag values mirror {@code android.hardware.security.keymint.TagType} and
 * {@code Tag}. Keeping the complete encoded tags here prevents a tag number from accidentally
 * being combined with the wrong union discriminator.</p>
 */
final class OmkAttestKeyProbeSpec {
    static final String FEATURE_KEYSTORE_APP_ATTEST_KEY =
            "android.hardware.keystore.app_attest_key";

    static final int TYPE_MASK = 0xF0000000;
    static final int TAG_NUMBER_MASK = 0x0FFFFFFF;

    static final int TYPE_INVALID = 0x00000000;
    static final int TYPE_ENUM = 0x10000000;
    static final int TYPE_ENUM_REP = 0x20000000;
    static final int TYPE_UINT = 0x30000000;
    static final int TYPE_UINT_REP = 0x40000000;
    static final int TYPE_ULONG = 0x50000000;
    static final int TYPE_DATE = 0x60000000;
    static final int TYPE_BOOL = 0x70000000;
    static final int TYPE_BIGNUM = 0x80000000;
    static final int TYPE_BYTES = 0x90000000;
    static final int TYPE_ULONG_REP = 0xA0000000;

    static final int TAG_PURPOSE = 0x20000001;
    static final int TAG_ALGORITHM = 0x10000002;
    static final int TAG_KEY_SIZE = 0x30000003;
    static final int TAG_BLOCK_MODE = 0x20000004;
    static final int TAG_DIGEST = 0x20000005;
    static final int TAG_PADDING = 0x20000006;
    static final int TAG_EC_CURVE = 0x1000000A;
    static final int TAG_INCLUDE_UNIQUE_ID = 0x700000CA;
    static final int TAG_NO_AUTH_REQUIRED = 0x700001F7;
    static final int TAG_CREATION_DATETIME = 0x600002BD;
    static final int TAG_UNIQUE_ID = 0x900002C3;
    static final int TAG_ATTESTATION_CHALLENGE = 0x900002C4;
    static final int TAG_DEVICE_UNIQUE_ATTESTATION = 0x700002D0;

    enum Applicability {
        REQUIRES_ANDROID_12,
        FEATURE_NOT_DECLARED,
        APPLICABLE
    }

    private OmkAttestKeyProbeSpec() { }

    static Applicability applicability(int sdkInt, boolean appAttestKeyFeatureDeclared) {
        if (sdkInt < 31) return Applicability.REQUIRES_ANDROID_12;
        if (!appAttestKeyFeatureDeclared) return Applicability.FEATURE_NOT_DECLARED;
        return Applicability.APPLICABLE;
    }

    static boolean shouldRun(int sdkInt, boolean appAttestKeyFeatureDeclared) {
        return applicability(sdkInt, appAttestKeyFeatureDeclared) == Applicability.APPLICABLE;
    }

    static int typeOf(int tag) {
        return tag & TYPE_MASK;
    }

    static int numberOf(int tag) {
        return tag & TAG_NUMBER_MASK;
    }
}

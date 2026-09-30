package com.lingqing.trustattestor;

/** Pure status policy for optional API-36 cross-UID Keystore sharing. */
final class IsolatedAttestationCapabilityPolicy {
    static final int API_UNAVAILABLE = 2;
    static final int ACCESS_UNAVAILABLE = 3;

    private IsolatedAttestationCapabilityPolicy() { }

    /** Provider rejection of grant/read means the optional capability is not applicable. */
    static int optionalSharingFailureStatus() {
        return API_UNAVAILABLE;
    }

    /** Older responders used ACCESS_UNAVAILABLE for an unsupported grantee read. */
    static int normalizeRemoteStatus(int status) {
        return status == ACCESS_UNAVAILABLE ? API_UNAVAILABLE : status;
    }

    /** Never revoke a grant when grantKeyAccess itself did not return successfully. */
    static boolean shouldRevoke(boolean grantIssued) {
        return grantIssued;
    }
}

package com.lingqing.trustattestor;

/** Run main on the host JDK; no Android runtime or JUnit dependency is required. */
public final class IsolatedAttestationCapabilityPolicyTest {
    private static int assertions;

    public static void main(String[] args) {
        check(IsolatedAttestationCapabilityPolicy.optionalSharingFailureStatus() == 2,
                "provider rejection is optional API unavailability");
        check(IsolatedAttestationCapabilityPolicy.normalizeRemoteStatus(3) == 2,
                "legacy isolated-read access failure is normalized");
        check(IsolatedAttestationCapabilityPolicy.normalizeRemoteStatus(4) == 4,
                "transport failure stays distinct");
        check(!IsolatedAttestationCapabilityPolicy.shouldRevoke(false),
                "failed grant must not be revoked");
        check(IsolatedAttestationCapabilityPolicy.shouldRevoke(true),
                "issued grant must be revoked");
        System.out.println("IsolatedAttestationCapabilityPolicyTest: " + assertions
                + " assertions passed");
    }

    private static void check(boolean value, String description) {
        assertions++;
        if (!value) throw new AssertionError(description);
    }
}

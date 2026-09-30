package com.lingqing.trustattestor;

/** Desktop-only regression tests for the state-plane classification rules. */
public final class KeystoreStatePlaneEvidenceTest {
    private static int assertions;
    private static final int KEY_ID = 4;

    public static void main(String[] args) {
        consistentPairVerifies();
        certificateMismatchDetects();
        metadataMismatchDetects();
        missingPrerequisiteIsUnavailable();
        cleanupFailureOverridesFinding();
        ledgerTrajectoryVerifies();
        ledgerMismatchNeedsCompletePairs();
        duplicateKeyIdDetects();
        ledgerCleanupFailureIsUnavailable();
        System.out.println("KeystoreStatePlaneEvidenceTest: " + assertions
                + " assertions passed");
    }

    private static void consistentPairVerifies() {
        status(KeystoreStatePlaneEvidence.Status.VERIFIED,
                KeystoreStatePlaneEvidence.aliasKeyId(pair("one", 11, new byte[]{1, 2}), true),
                "matching APP and KEY_ID routes verify");
    }

    private static void certificateMismatchDetects() {
        var app = route("APP", 11, new byte[]{1, 2});
        var kid = route("KEY_ID", 11, new byte[]{1, 3});
        var observation = new KeystoreStatePlaneEvidence.AliasObservation(
                "one", KEY_ID, 11, app, kid, new byte[]{1, 2});
        status(KeystoreStatePlaneEvidence.Status.DETECTED,
                KeystoreStatePlaneEvidence.aliasKeyId(observation, true),
                "two successful routes with different certificate bytes detect");
    }

    private static void metadataMismatchDetects() {
        var app = route("APP", 11, new byte[]{1, 2});
        var wrong = new KeystoreStatePlaneEvidence.RouteSnapshot(
                "KEY_ID", KEY_ID, 12L, new byte[]{1, 2}, null);
        var observation = new KeystoreStatePlaneEvidence.AliasObservation(
                "one", KEY_ID, 11, app, wrong, new byte[]{1, 2});
        status(KeystoreStatePlaneEvidence.Status.DETECTED,
                KeystoreStatePlaneEvidence.aliasKeyId(observation, true),
                "successful route returning another key id detects");
    }

    private static void missingPrerequisiteIsUnavailable() {
        var observation = new KeystoreStatePlaneEvidence.AliasObservation(
                "one", KEY_ID, 11, route("APP", 11, new byte[]{1}), null,
                new byte[]{1});
        status(KeystoreStatePlaneEvidence.Status.UNAVAILABLE,
                KeystoreStatePlaneEvidence.aliasKeyId(observation, true),
                "failed KEY_ID read never becomes a finding");
        var missingField = new KeystoreStatePlaneEvidence.RouteSnapshot(
                "KEY_ID", null, 11L, new byte[]{1}, null);
        observation = new KeystoreStatePlaneEvidence.AliasObservation(
                "one", KEY_ID, 11, route("APP", 11, new byte[]{1}), missingField,
                new byte[]{1});
        status(KeystoreStatePlaneEvidence.Status.UNAVAILABLE,
                KeystoreStatePlaneEvidence.aliasKeyId(observation, true),
                "missing hidden metadata field is unavailable");
    }

    private static void cleanupFailureOverridesFinding() {
        var app = route("APP", 11, new byte[]{1});
        var kid = route("KEY_ID", 11, new byte[]{2});
        var observation = new KeystoreStatePlaneEvidence.AliasObservation(
                "one", KEY_ID, 11, app, kid, new byte[]{1});
        status(KeystoreStatePlaneEvidence.Status.UNAVAILABLE,
                KeystoreStatePlaneEvidence.aliasKeyId(observation, false),
                "cleanup failure overrides otherwise positive evidence");
    }

    private static void ledgerTrajectoryVerifies() {
        status(KeystoreStatePlaneEvidence.Status.VERIFIED,
                KeystoreStatePlaneEvidence.ledger(20, 21, 22, 20,
                        pair("first", 31, new byte[]{3}),
                        pair("second", 32, new byte[]{4}), true),
                "exact ledger increments and complete pairs verify");
    }

    private static void ledgerMismatchNeedsCompletePairs() {
        status(KeystoreStatePlaneEvidence.Status.DETECTED,
                KeystoreStatePlaneEvidence.ledger(20, 20, 20, 20,
                        pair("first", 31, new byte[]{3}),
                        pair("second", 32, new byte[]{4}), true),
                "stable ledger that omits two dual-readable keys detects");

        var incomplete = new KeystoreStatePlaneEvidence.AliasObservation(
                "second", KEY_ID, 32, route("APP", 32, new byte[]{4}), null,
                new byte[]{4});
        status(KeystoreStatePlaneEvidence.Status.UNAVAILABLE,
                KeystoreStatePlaneEvidence.ledger(20, 20, 20, 20,
                        pair("first", 31, new byte[]{3}), incomplete, true),
                "same count mismatch is unavailable without both successful routes");
    }

    private static void duplicateKeyIdDetects() {
        status(KeystoreStatePlaneEvidence.Status.DETECTED,
                KeystoreStatePlaneEvidence.ledger(20, 21, 22, 20,
                        pair("first", 31, new byte[]{3}),
                        pair("second", 31, new byte[]{4}), true),
                "two live aliases sharing one key id detect");
    }

    private static void ledgerCleanupFailureIsUnavailable() {
        status(KeystoreStatePlaneEvidence.Status.UNAVAILABLE,
                KeystoreStatePlaneEvidence.ledger(20, 20, 20, 20,
                        pair("first", 31, new byte[]{3}),
                        pair("second", 32, new byte[]{4}), false),
                "ledger cleanup failure overrides a count contradiction");
        status(KeystoreStatePlaneEvidence.Status.UNAVAILABLE,
                KeystoreStatePlaneEvidence.ledger(20, 21, 22, 21,
                        pair("first", 31, new byte[]{3}),
                        pair("second", 32, new byte[]{4}), true),
                "count not restored to baseline is unavailable rather than detected");
    }

    private static KeystoreStatePlaneEvidence.AliasObservation pair(
            String label, long keyId, byte[] certificate) {
        return new KeystoreStatePlaneEvidence.AliasObservation(label, KEY_ID, keyId,
                route("APP", keyId, certificate), route("KEY_ID", keyId, certificate),
                certificate);
    }

    private static KeystoreStatePlaneEvidence.RouteSnapshot route(
            String route, long keyId, byte[] certificate) {
        return new KeystoreStatePlaneEvidence.RouteSnapshot(
                route, KEY_ID, keyId, certificate, null);
    }

    private static void status(KeystoreStatePlaneEvidence.Status expected,
                               KeystoreStatePlaneEvidence.Decision actual,
                               String message) {
        check(actual != null && actual.status == expected,
                message + "; expected=" + expected + ", actual="
                        + (actual == null ? "null" : actual.status));
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

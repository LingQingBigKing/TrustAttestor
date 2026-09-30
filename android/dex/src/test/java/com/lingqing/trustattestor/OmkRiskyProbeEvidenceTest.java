package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.List;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;

/** Standalone regression tests: run main; no Android runtime or JUnit required. */
public final class OmkRiskyProbeEvidenceTest {
    private static int assertions;

    public static void main(String[] args) {
        tokenRequiresBothControls();
        fingerprintNeedsTagMapAndMissingTaTags();
        uniformVendorFallbackIsCleanShape();
        ambiguousCompleteFingerprintIsNeutral();
        incompletePrivateAbiFingerprintIsNotApplicable();
        riskyProbeTimeoutsAreBounded();
        teeSimDifferentialRemainsNeutralWithoutDangerousV5();
        teeSimBoundedPrefixIsACompletedNeutralObservation();
        teeSimCleanupFailureInvalidatesEvidence();
        acceptingPoisonedGenerateIsDirectFailure();
        attestKeyDescriptorDelegationRequiresValidPrerequisites();
        System.out.println("OmkRiskyProbeEvidenceTest: " + assertions + " assertions passed");
    }

    private static OmkRiskyProbeEvidence.Observation code(String name, int code) {
        return new OmkRiskyProbeEvidence.Observation(name, code, false, "code=" + code, 1000);
    }

    private static void tokenRequiresBothControls() {
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, false, true).status == DETECTED,
                "migrate reply with both controls is detected");
        check(OmkRiskyProbeEvidence.tokenDispatch(false, true, false, true).status == UNAVAILABLE,
                "missing before control is unavailable");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, true, true).status == UNAVAILABLE,
                "answered undefined code destroys discrimination");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, true, false, false).status == UNAVAILABLE,
                "failed after control invalidates the result");
        check(OmkRiskyProbeEvidence.tokenDispatch(true, false, false, true).status == VERIFIED,
                "both disguised transactions rejected is the clean shape");
    }

    private static void fingerprintNeedsTagMapAndMissingTaTags() {
        List<OmkRiskyProbeEvidence.Observation> rows = new ArrayList<>();
        rows.add(code("a1", -4)); rows.add(code("a2", -4));
        rows.add(code("b1", -7)); rows.add(code("b2", -7));
        rows.add(code("c1", -10)); rows.add(code("c2", -10));
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, false).status == DETECTED,
                "three AOSP tag mappings plus absent TA tags is detected");
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, true).status == VERIFIED,
                "TA tags make the complete observation neutral");
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, false, rows, false).status == UNAVAILABLE,
                "failed post-canary invalidates a would-be hit");
    }

    private static void uniformVendorFallbackIsCleanShape() {
        List<OmkRiskyProbeEvidence.Observation> rows = new ArrayList<>();
        for (int i = 0; i < 10; i++) rows.add(code("v" + i, -21));
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, null).status == VERIFIED,
                "uniform vendor fallback is a completed non-hit");
    }

    private static void ambiguousCompleteFingerprintIsNeutral() {
        List<OmkRiskyProbeEvidence.Observation> rows = new ArrayList<>();
        for (int i = 0; i < 10; i++) rows.add(code("v" + i, -38));
        check(OmkRiskyProbeEvidence.parameterFingerprint(true, true, rows, null).status == VERIFIED,
                "an ambiguous but complete fingerprint is not an execution failure");
    }

    private static void incompletePrivateAbiFingerprintIsNotApplicable() {
        check(OmkRiskyProbeEvidence.parameterFingerprint(
                        true, true, List.of(code("ALGORITHM+Integer", -4)), null).status == VERIFIED,
                "an OEM private ABI that cannot supply six vectors is neutral");
    }

    private static void riskyProbeTimeoutsAreBounded() {
        check(OmkRiskyProbes.PARAMETER_FINGERPRINT_TIMEOUT_SECONDS <= 12,
                "KeyMint parameter fingerprint is capped at twelve seconds");
        check(OmkRiskyProbes.TEESIM_TIMEOUT_SECONDS <= 10,
                "TeeSim fingerprint is capped at ten seconds");
    }

    private static void teeSimDifferentialRemainsNeutralWithoutDangerousV5() {
        List<OmkRiskyProbeEvidence.Observation> rows = List.of(
                code("V0", -21), code("V1", -38), code("V2", -21));
        check(OmkRiskyProbeEvidence.teeSimFingerprint(true, true, rows, false).status == VERIFIED,
                "unattributed V0-V4 differential remains neutral");
    }

    private static void acceptingPoisonedGenerateIsDirectFailure() {
        List<OmkRiskyProbeEvidence.Observation> rows = List.of(
                code("V0", -21),
                new OmkRiskyProbeEvidence.Observation("V1", null, true, "success", 1000));
        check(OmkRiskyProbeEvidence.teeSimFingerprint(true, true, rows, false).status == DETECTED,
                "accepted type-confused generate request is a direct failure");
    }

    private static void teeSimBoundedPrefixIsACompletedNeutralObservation() {
        check(OmkRiskyProbeEvidence.teeSimFingerprint(
                        true, true, List.of(code("V0", -21)), false).status == VERIFIED,
                "a valid bounded V0 prefix is neutral instead of unavailable");
    }

    private static void teeSimCleanupFailureInvalidatesEvidence() {
        check(OmkRiskyProbeEvidence.teeSimFingerprint(
                        true, true, List.of(code("V0", -21)), true).status == UNAVAILABLE,
                "cleanup failure still invalidates the TeeSim observation");
    }

    private static void attestKeyDescriptorDelegationRequiresValidPrerequisites() {
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, 42L, false, true).status == VERIFIED,
                "direct delegation with a positive key ID is verified");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, false, 0L, true, true).status == DETECTED,
                "exact invalid-attest-alias rejection after valid setup is detected");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        false, false, false, 0L, true, true).status == UNAVAILABLE,
                "an alias error without a generated source key is unavailable");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, false, false, 0L, true, true).status == UNAVAILABLE,
                "an alias error with an invalid source descriptor is unavailable");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, false, 0L, false, true).status == UNAVAILABLE,
                "unclassified delegation failures are unavailable");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, 42L, false, false).status == UNAVAILABLE,
                "cleanup failure invalidates an otherwise successful result");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, 0L, false, true).status == VERIFIED,
                "zero key ID is a valid randomized database ID");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, -42L, false, true).status == VERIFIED,
                "negative randomized key ID is valid");
        check(OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        true, true, true, -1L, false, true).status == UNAVAILABLE,
                "reserved unassigned key ID is not successful");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

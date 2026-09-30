package com.lingqing.trustattestor;

import java.util.List;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;

/** Run main with JDK 17. */
public final class StructuralProbeEvidenceTest {
    private static int assertions;

    public static void main(String[] args) {
        securityLevelContract();
        binderLocalityContract();
        System.out.println("StructuralProbeEvidenceTest: " + assertions + " assertions passed");
    }

    private static void securityLevelContract() {
        for (long allowed : new long[]{0, 1, 2, 100}) {
            check(StructuralProbeEvidence.isDefinedSecurityLevel(allowed),
                    "AIDL-defined security level " + allowed + " is accepted");
        }
        for (long invalid : new long[]{-1, 3, 99, 101, Long.MAX_VALUE}) {
            check(!StructuralProbeEvidence.isDefinedSecurityLevel(invalid),
                    "out-of-contract security level " + invalid + " is rejected");
        }

        var valid = StructuralProbeEvidence.securityLevels(List.of(
                StructuralProbeEvidence.SecurityLevelValue.observed("metadata.key", 1),
                StructuralProbeEvidence.SecurityLevelValue.observed("authorization[0]", 2)));
        check(valid.status == VERIFIED, "all readable in-range values verify");

        var invalid = StructuralProbeEvidence.securityLevels(List.of(
                StructuralProbeEvidence.SecurityLevelValue.unavailable("optional", "absent"),
                StructuralProbeEvidence.SecurityLevelValue.observed("metadata.key", 3)));
        check(invalid.status == DETECTED, "a decoded out-of-range value is detected");
        check(invalid.detail.contains("metadata.key=3"), "invalid value keeps its source in evidence");

        var absent = StructuralProbeEvidence.securityLevels(List.of(
                StructuralProbeEvidence.SecurityLevelValue.unavailable("metadata", "unreadable")));
        check(absent.status == UNAVAILABLE, "unreadable metadata does not become a finding");
        check(StructuralProbeEvidence.securityLevels(null).status == UNAVAILABLE,
                "missing observation list remains unavailable");
    }

    private static void binderLocalityContract() {
        var optionalRemote = new StructuralProbeEvidence.BinderLeg("getSecurityLevel",
                StructuralProbeEvidence.BinderLeg.Disposition.REMOTE, "unlink=true");
        var optionalLocal = new StructuralProbeEvidence.BinderLeg("getSecurityLevel",
                StructuralProbeEvidence.BinderLeg.Disposition.LOCAL, "unlink=false");
        var coreEntryRemote = new StructuralProbeEvidence.BinderLeg("getKeyEntry.iSecurityLevel",
                StructuralProbeEvidence.BinderLeg.Disposition.REMOTE, "unlink=true");
        var coreOperationRemote = new StructuralProbeEvidence.BinderLeg("IKeystoreOperation",
                StructuralProbeEvidence.BinderLeg.Disposition.REMOTE, "unlink=true");
        var coreEntryLocal = new StructuralProbeEvidence.BinderLeg("getKeyEntry.iSecurityLevel",
                StructuralProbeEvidence.BinderLeg.Disposition.LOCAL, "unlink=false");
        var optionalMissing = new StructuralProbeEvidence.BinderLeg("getSecurityLevel",
                StructuralProbeEvidence.BinderLeg.Disposition.UNAVAILABLE, "blocked");
        var coreEntryMissing = new StructuralProbeEvidence.BinderLeg("getKeyEntry.iSecurityLevel",
                StructuralProbeEvidence.BinderLeg.Disposition.UNAVAILABLE, "blocked");
        var coreOperationMissing = new StructuralProbeEvidence.BinderLeg("IKeystoreOperation",
                StructuralProbeEvidence.BinderLeg.Disposition.UNAVAILABLE, "blocked");

        check(StructuralProbeEvidence.binderLocality(List.of(optionalRemote, coreEntryLocal)).status == DETECTED,
                "a local core reply Binder is sufficient evidence");
        check(StructuralProbeEvidence.binderLocality(List.of(optionalLocal, coreEntryRemote)).status == DETECTED,
                "a local optional reply Binder still overrides a remote core leg");

        var entryVerified = StructuralProbeEvidence.binderLocality(List.of(
                optionalMissing, coreEntryRemote, coreOperationMissing));
        check(entryVerified.status == VERIFIED,
                "a remote getKeyEntry core leg verifies when other legs are unavailable");
        check(entryVerified.detail.contains("coreRemote=1"),
                "verified evidence records the remote core-leg count");

        check(StructuralProbeEvidence.binderLocality(List.of(
                        optionalRemote, coreEntryMissing, coreOperationRemote)).status == VERIFIED,
                "a remote operation core leg verifies when getKeyEntry is unavailable");
        check(StructuralProbeEvidence.binderLocality(List.of(
                        optionalRemote, coreEntryMissing, coreOperationMissing)).status == UNAVAILABLE,
                "an optional remote leg cannot verify when both core legs are unavailable");
        check(StructuralProbeEvidence.binderLocality(List.of(optionalRemote)).status == UNAVAILABLE,
                "an optional remote leg alone remains unavailable");
        check(StructuralProbeEvidence.binderLocality(List.of(
                        optionalMissing, coreEntryMissing, coreOperationMissing)).status == UNAVAILABLE,
                "all unavailable legs stay unavailable");
        check(StructuralProbeEvidence.binderLocality(null).status == UNAVAILABLE,
                "missing Binder observations stay unavailable");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

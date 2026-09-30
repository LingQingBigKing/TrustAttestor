package com.lingqing.trustattestor;

import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;

/** Desktop record-comparison regression tests; Android operations require device coverage. */
public final class CertificateRecordEvidenceTest {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        completeChain();
        isolatedSnapshots();
        metadataSemantics();
        invalidBaseline();
        evidenceBounds();
        System.out.println("CertificateRecordEvidenceTest: " + assertions + " assertions passed");
    }

    private static void completeChain() throws Exception {
        byte[][] original = {{1}, {2}, {3}, {4}};
        CertificateRecordEvidence.Chain baseline = new CertificateRecordEvidence.Chain(original);
        status(SilentProbeEvidence.Status.VERIFIED, CertificateRecordEvidence.compare(baseline, original, true), "all certificates identical");
        for (int i = 0; i < original.length; i++) {
            byte[][] altered = baseline.encoded();
            altered[i][0] ^= 16;
            status(SilentProbeEvidence.Status.DETECTED, CertificateRecordEvidence.compare(baseline, altered, true), "detect change at every chain index " + i);
        }
        status(SilentProbeEvidence.Status.DETECTED, CertificateRecordEvidence.compare(baseline, new byte[][]{{1},{2},{3}}, true), "missing tail");
        status(SilentProbeEvidence.Status.DETECTED, CertificateRecordEvidence.compare(baseline, new byte[][]{{1},{2},{4},{3}}, true), "changed order");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, new byte[][]{{1},{2},null,{4}}, true), "missing member can be an absorbed service failure");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, null, true), "null read can be an absorbed service failure");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, new byte[0][], true), "empty read unavailable");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, new byte[][]{{1},{2},{},{4}}, true), "empty encoding unavailable");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, null, false), "failed read not a detection");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, new byte[][]{{9}}, false), "partial failed read not a detection");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(null, original, true), "missing baseline not a detection");
    }

    private static void isolatedSnapshots() throws Exception {
        byte[][] original = {{1, 2}, {3, 4}};
        CertificateRecordEvidence.Chain baseline = new CertificateRecordEvidence.Chain(original);
        original[0][0] = 9;
        original[1] = null;
        byte[][] exported = baseline.encoded();
        exported[0][1] = 9;
        exported[1] = null;
        status(SilentProbeEvidence.Status.VERIFIED,
                CertificateRecordEvidence.compare(baseline, new byte[][]{{1,2},{3,4}}, true), "both constructor and accessor deep copy");
    }

    private static void metadataSemantics() throws Exception {
        Map<String, String> original = new LinkedHashMap<>();
        original.put("alias", "owned");
        original.put("purposes", "12");
        original.put("digests", CertificateRecordEvidence.unordered(new String[]{"SHA-512", "SHA-256"}));
        CertificateRecordEvidence.Metadata baseline = new CertificateRecordEvidence.Metadata(original);
        Map<String, String> reordered = new LinkedHashMap<>(original);
        reordered.put("digests", CertificateRecordEvidence.unordered(new String[]{"SHA-256", "SHA-512", "SHA-256"}));
        status(SilentProbeEvidence.Status.VERIFIED,
                CertificateRecordEvidence.compare(baseline, new CertificateRecordEvidence.Metadata(reordered)), "authorization order and duplicates have no meaning");
        original.put("alias", "other");
        status(SilentProbeEvidence.Status.DETECTED,
                CertificateRecordEvidence.compare(baseline, new CertificateRecordEvidence.Metadata(original)), "metadata constructor retains original identity");
        reordered.put("purposes", "4");
        status(SilentProbeEvidence.Status.DETECTED,
                CertificateRecordEvidence.compare(baseline, new CertificateRecordEvidence.Metadata(reordered)), "successful write may not alter key authorization");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, (CertificateRecordEvidence.Metadata) null), "failed metadata read not detection");
        Map<String, String> known = new LinkedHashMap<>();
        known.put("securityLevel", "1");
        status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(new CertificateRecordEvidence.Metadata(known),
                new CertificateRecordEvidence.Metadata(new LinkedHashMap<>())), "known security level becoming unknown is unavailable");
        check("[]".equals(CertificateRecordEvidence.unordered(new String[0])), "empty authorization is not unavailable");
    }

    private static void invalidBaseline() throws Exception {
        for (byte[][] invalid : new byte[][][]{null, {}, {null}, {{}}, {{1}}}) {
            try { new CertificateRecordEvidence.Chain(invalid); throw new AssertionError("invalid baseline accepted"); }
            catch (GeneralSecurityException expected) { assertions++; }
        }
        try { CertificateRecordEvidence.unordered(null); throw new AssertionError("missing metadata accepted"); }
        catch (GeneralSecurityException expected) { assertions++; }
    }

    private static void evidenceBounds() throws Exception {
        CertificateRecordEvidence.Chain baseline = new CertificateRecordEvidence.Chain(new byte[][]{{1},{2}});
        byte[][] tooMany = new byte[CertificateRecordEvidence.MAX_CERTIFICATES + 1][];
        for (int i = 0; i < tooMany.length; i++) tooMany[i] = new byte[]{1};
        byte[][] tooLarge = {{1}, new byte[CertificateRecordEvidence.MAX_CERTIFICATE_BYTES + 1]};
        byte[][] tooMuch = new byte[5][CertificateRecordEvidence.MAX_CERTIFICATE_BYTES];
        for (byte[][] excessive : new byte[][][]{tooMany, tooLarge, tooMuch}) {
            status(SilentProbeEvidence.Status.UNAVAILABLE, CertificateRecordEvidence.compare(baseline, excessive, true), "excessive evidence unavailable");
            try { new CertificateRecordEvidence.Chain(excessive); throw new AssertionError("excessive baseline accepted"); }
            catch (GeneralSecurityException expected) { assertions++; }
        }
        byte[][] maximum = new byte[4][CertificateRecordEvidence.MAX_CERTIFICATE_BYTES];
        CertificateRecordEvidence.Chain bounded = new CertificateRecordEvidence.Chain(maximum);
        status(SilentProbeEvidence.Status.VERIFIED, CertificateRecordEvidence.compare(bounded, maximum, true), "inclusive per-certificate and total byte limits");
        byte[][] maxCount = new byte[CertificateRecordEvidence.MAX_CERTIFICATES][1];
        CertificateRecordEvidence.Chain countBounded = new CertificateRecordEvidence.Chain(maxCount);
        status(SilentProbeEvidence.Status.VERIFIED, CertificateRecordEvidence.compare(countBounded, maxCount, true), "inclusive certificate count limit");
    }

    private static void status(SilentProbeEvidence.Status expected, SilentProbeEvidence.Decision actual, String message) {
        check(expected == actual.status, message + " got " + actual.status);
    }

    private static void check(boolean success, String message) {
        if (!success) throw new AssertionError(message);
        assertions++;
    }
}

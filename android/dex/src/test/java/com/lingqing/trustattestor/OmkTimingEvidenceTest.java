package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.List;

public final class OmkTimingEvidenceTest {
    private static int assertions;

    public static void main(String[] args) {
        stableReplyLagIsDetected();
        replyLagNeedsBothBatches();
        replyLagControlPreventsDetection();
        stableReplyLagControlIsUnavailable();
        stableRawReadDifferenceIsDetected();
        rawReadRatioBelowConservativeThresholdIsVerified();
        negativeReadControlPreventsDetection();
        noisyRawReadIsCompletedWithoutFinding();
        incompleteRawReadRemainsUnavailable();
        System.out.println("OmkTimingEvidenceTest: " + assertions + " assertions passed");
    }

    private static void stableReplyLagIsDetected() {
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.replyLag(
                replySamples(52.0, 3.0, 55.0, 2.0));
        check(decision.status == SilentProbeEvidence.Status.DETECTED,
                "stable reply lag should be detected");
    }

    private static void replyLagNeedsBothBatches() {
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.replyLag(
                replySamples(52.0, 3.0, 5.0, 2.0));
        check(decision.status == SilentProbeEvidence.Status.UNAVAILABLE,
                "one-batch reply lag should be inconclusive");
    }

    private static void replyLagControlPreventsDetection() {
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.replyLag(
                replySamples(52.0, 48.0, 10.0, 2.0));
        check(decision.status == SilentProbeEvidence.Status.VERIFIED,
                "a control window in only one batch must not be attributed to the target");
    }

    private static void stableReplyLagControlIsUnavailable() {
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.replyLag(
                replySamples(52.0, 25.0, 55.0, 25.0));
        check(decision.status == SilentProbeEvidence.Status.UNAVAILABLE,
                "a stable two-batch ordinary-key window must make reply lag unavailable");
    }

    private static void stableRawReadDifferenceIsDetected() {
        KeystoreTimingStatistics.Result target = KeystoreTimingStatistics.analyze(
                timingSamples(1.45, 1.0), 16, 0.01);
        KeystoreTimingStatistics.Result negative = KeystoreTimingStatistics.analyze(
                timingSamples(1.01, 1.0), 16, 0.01);
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.readPath(target, negative);
        check(decision.status == SilentProbeEvidence.Status.DETECTED,
                "stable target-only raw-read effect should be detected");
    }

    private static void rawReadRatioBelowConservativeThresholdIsVerified() {
        KeystoreTimingStatistics.Result target = KeystoreTimingStatistics.analyze(
                timingSamples(1.28, 1.0), 16, 0.01);
        KeystoreTimingStatistics.Result negative = KeystoreTimingStatistics.analyze(
                timingSamples(1.01, 1.0), 16, 0.01);
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.readPath(target, negative);
        check(decision.status == SilentProbeEvidence.Status.VERIFIED,
                "raw-read ratios below the conservative 1.30 threshold must stay verified");
    }

    private static void negativeReadControlPreventsDetection() {
        KeystoreTimingStatistics.Result target = KeystoreTimingStatistics.analyze(
                timingSamples(1.45, 1.0), 16, 0.01);
        KeystoreTimingStatistics.Result negative = KeystoreTimingStatistics.analyze(
                timingSamples(1.30, 1.0), 16, 0.01);
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.readPath(target, negative);
        check(decision.status == SilentProbeEvidence.Status.VERIFIED,
                "a completed positive control must suppress detection without becoming unavailable");
    }

    private static void noisyRawReadIsCompletedWithoutFinding() {
        KeystoreTimingStatistics.Result target = KeystoreTimingStatistics.analyze(
                oneBatchOnlyEffectSamples(), 16, 0.01);
        KeystoreTimingStatistics.Result negative = KeystoreTimingStatistics.analyze(
                timingSamples(1.01, 1.0), 16, 0.01);
        check(target.usable && target.noisy, "fixture must be a completed noisy sample");
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.readPath(target, negative);
        check(decision.status == SilentProbeEvidence.Status.VERIFIED,
                "completed noisy raw-read samples must not be reported as unfinished");
    }

    private static void incompleteRawReadRemainsUnavailable() {
        KeystoreTimingStatistics.Result incomplete = KeystoreTimingStatistics.analyze(
                timingSamples(1.45, 1.0).subList(0, 16), 16, 0.01);
        KeystoreTimingStatistics.Result negative = KeystoreTimingStatistics.analyze(
                timingSamples(1.01, 1.0), 16, 0.01);
        check(!incomplete.usable, "fixture must be incomplete");
        OmkTimingEvidence.Decision decision = OmkTimingEvidence.readPath(incomplete, negative);
        check(decision.status == SilentProbeEvidence.Status.UNAVAILABLE,
                "missing raw-read samples must remain unavailable");
    }

    private static List<OmkTimingEvidence.ReplyPair> replySamples(
            double batch0Target, double batch0Control,
            double batch1Target, double batch1Control) {
        List<OmkTimingEvidence.ReplyPair> samples = new ArrayList<>();
        for (int batch = 0; batch < 2; batch++) {
            double target = batch == 0 ? batch0Target : batch1Target;
            double control = batch == 0 ? batch0Control : batch1Control;
            for (int i = 0; i < 4; i++) {
                samples.add(new OmkTimingEvidence.ReplyPair(
                        batch, i < 2, target + (i & 1), control + (i & 1) * 0.1));
            }
        }
        return samples;
    }

    private static List<KeystoreTimingStatistics.Sample> timingSamples(
            double treatment, double control) {
        List<KeystoreTimingStatistics.Sample> samples = new ArrayList<>();
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < 16; i++) {
                double jitter = ((i % 5) - 2) * 0.002;
                samples.add(new KeystoreTimingStatistics.Sample(
                        treatment + jitter, control + jitter / 2.0, i < 8, batch));
            }
        }
        return samples;
    }

    private static List<KeystoreTimingStatistics.Sample> oneBatchOnlyEffectSamples() {
        List<KeystoreTimingStatistics.Sample> samples = new ArrayList<>();
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < 16; i++) {
                double treatment = batch == 0 ? 1.45 : 1.01;
                double jitter = ((i % 5) - 2) * 0.002;
                samples.add(new KeystoreTimingStatistics.Sample(
                        treatment + jitter, 1.0 + jitter / 2.0, i < 8, batch));
            }
        }
        return samples;
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

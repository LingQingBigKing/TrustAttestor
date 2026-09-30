package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.lingqing.trustattestor.KeystoreTimingStatistics.Result;
import com.lingqing.trustattestor.KeystoreTimingStatistics.Sample;

/** Standalone regression tests: run main; no Android runtime or JUnit required. */
public final class KeystoreTimingStatisticsTest {
    private static int assertions;

    public static void main(String[] args) {
        noDifference();
        stableDifferencesProduceTimingPositive();
        operationOrderReversesDirection();
        effectMustRepeatAcrossBatches();
        failedAndMissingPairsCannotBeSelectedAway();
        completeBalancedBatchesAreRequired();
        longTailsDoNotManufactureAnEffect();
        dispersionAndDirectionAgreementAreRequired();
        seventyPercentDirectionBoundaryIsPreserved();
        invalidInputIsUnusable();
        finiteExtremeDurationsDoNotOverflow();
        differenceMedianUsesPairs();
        calibratedAbsoluteFloor();
        System.out.println("KeystoreTimingStatisticsTest: " + assertions + " assertions passed");
    }

    private static void noDifference() {
        Result result = analyze(constant(10, 10));
        check(result.usable && !result.positive && !result.noisy, "equal durations are normal");
        check(result.validPairs == 32 && result.invalidPairs == 0, "complete pair counts");
        check("NONE".equals(result.direction), "zero direction");
        near(10, result.medianAttestedMillis, "attested median");
        near(10, result.medianPlainMillis, "plain median");
        near(0, result.medianDifferenceMillis, "paired difference median");
        near(0, result.medianLogRatio, "zero signed log ratio");
        near(0, result.madLogRatio, "zero MAD");
        result = analyze(constant(10.5, 10));
        check(result.usable && !result.positive && !result.noisy, "small stable effect below screen");
    }

    private static void stableDifferencesProduceTimingPositive() {
        Result result = analyze(constant(12, 10));
        check(result.usable && result.positive && !result.noisy, "stable latency difference");
        check("TREATMENT_SLOWER".equals(result.direction), "positive signed direction");
        check(result.reason.contains("all four batch/order groups"), "positive reason describes the observed separation");
        near(Math.log(1.2), result.medianLogRatio, "positive log ratio");
        near(2, result.medianDifferenceMillis, "positive paired difference");
        result = analyze(constant(10, 13));
        check(result.usable && result.positive, "reverse stable difference can be screened");
        check("CONTROL_SLOWER".equals(result.direction), "negative direction is preserved");
        near(Math.log(10.0 / 13.0), result.medianLogRatio, "negative signed ratio");
        near(-3, result.medianDifferenceMillis, "negative paired difference");
    }

    private static void operationOrderReversesDirection() {
        List<Sample> samples = new ArrayList<>();
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < 16; i++) {
                boolean first = i % 2 == 0;
                samples.add(new Sample(first ? 13 : 10, first ? 10 : 13, first, batch));
            }
        }
        Result result = analyze(samples);
        check(result.usable && !result.positive && result.noisy, "first-operation delay is rejected");
        check("MIXED".equals(result.direction), "AB/BA reversal must remain visible");
        near(0, result.medianLogRatio, "opposite signed effects must not become abs(log)");
    }

    private static void effectMustRepeatAcrossBatches() {
        List<Sample> samples = constant(12, 10);
        for (int i = 16; i < 32; i++) {
            samples.set(i, new Sample(10, 12, i % 2 == 0, 1));
        }
        Result result = analyze(samples);
        check(result.usable && !result.positive && result.noisy, "cross-batch reversal rejected");
        check("MIXED".equals(result.direction), "cross-batch direction preserved");
        for (int i = 16; i < 32; i++) {
            samples.set(i, new Sample(10, 10, i % 2 == 0, 1));
        }
        result = analyze(samples);
        check(result.usable && !result.positive && result.noisy, "effect disappearing is rejected");
        result = analyze(new ArrayList<>(constant(12, 10).subList(0, 16)));
        check(!result.usable && !result.positive, "first batch cannot produce an early positive");
    }

    private static void failedAndMissingPairsCannotBeSelectedAway() {
        List<Sample> samples = constant(12, 10);
        samples.set(0, new Sample(Double.NaN, 10, true, 0));
        Result result = analyze(samples);
        check(!result.usable && !result.positive, "selective attested failure rejects whole run");
        check(result.validPairs == 31 && result.invalidPairs == 1, "failed pair counted separately");
        samples = constant(12, 10);
        samples.set(17, new Sample(12, Double.NaN, false, 1));
        check(!analyze(samples).positive, "selective plain failure rejects positive");
        samples = constant(12, 10);
        samples.remove(0);
        result = analyze(samples);
        check(!result.usable && !result.positive && result.validPairs == 31, "missing pair rejected");
        samples = constant(12, 10);
        samples.add(new Sample(Double.NaN, Double.NaN, true, 0));
        result = analyze(samples);
        check(!result.usable && !result.positive && result.validPairs == 32,
                "replacement successes cannot erase a failed sample");
    }

    private static void completeBalancedBatchesAreRequired() {
        List<Sample> samples = new ArrayList<>();
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < 16; i++) {
                samples.add(new Sample(12, 10, i < 11, batch));
            }
        }
        check(!analyze(samples).usable, "five of sixteen is below one third in one order");
        samples.clear();
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < 16; i++) {
                samples.add(new Sample(12, 10, i < 10, batch));
            }
        }
        check(analyze(samples).positive, "six of sixteen satisfies the order minimum");
        samples.add(new Sample(12, 10, false, 0));
        check(!analyze(samples).usable, "extra pair cannot be silently trimmed");
        check(!KeystoreTimingStatistics.analyze(constant(12, 10), 15).usable,
                "expected batch size below sixteen is invalid");
        check(!KeystoreTimingStatistics.analyze(constant(12, 10), Integer.MAX_VALUE).usable,
                "large expected size cannot overflow the completeness check");
    }

    private static void longTailsDoNotManufactureAnEffect() {
        List<Sample> samples = constant(10, 10);
        samples.set(0, new Sample(1e250, 10, true, 0));
        samples.set(17, new Sample(10, 1e250, false, 1));
        Result result = analyze(samples);
        check(result.usable && !result.positive, "extreme isolated tails do not produce a positive");
        near(0, result.medianLogRatio, "signed median resists isolated extreme tails");
        near(0, result.medianDifferenceMillis, "paired median resists extreme tails");
        near(0, result.madLogRatio, "robust MAD unaffected by rare tails");
    }

    private static void dispersionAndDirectionAgreementAreRequired() {
        Result result = analyze(logPattern(new double[]{0.2, 0.6, 0.2, 0.6, 0.2, 0.6, 0.2, 0.6}));
        check(result.usable && result.positive && !result.noisy,
                "legacy strong separation permits MAD above the standard limit");
        result = analyze(logPattern(new double[]{0.13, 0.33, 0.13, 0.33, 0.13, 0.33, 0.13, 0.33}));
        check(result.usable && result.positive && !result.noisy,
                "legacy standard separation does not require effect above three times MAD");
        result = analyze(logPattern(new double[]{0.05, 0.75, 0.05, 0.75, 0.05, 0.75, 0.05, 0.75}));
        check(result.usable && !result.positive && result.noisy,
                "dispersion beyond both standard and strong limits is rejected");
        result = analyze(logPattern(new double[]{0.3, 0.3, 0.3, 0.5, 0.5, 0.5, -0.01, -0.01}));
        check(result.usable && !result.positive && result.noisy,
                "strong separation still requires its higher direction agreement");
        result = analyze(logPattern(new double[]{0.15, 0.15, 0.15, 0.15, 0.15, -0.01, -0.01, -0.01}));
        check(result.usable && !result.positive && result.noisy, "five of eight directions is insufficient");
        result = analyze(logPattern(new double[]{0.15, 0.15, 0.15, 0.15, 0.15, 0.15, -0.01, -0.01}));
        check(result.positive, "three quarters direction agreement satisfies the screen");
    }

    private static void seventyPercentDirectionBoundaryIsPreserved() {
        List<Sample> samples = logPattern(new double[]{
                0.15, 0.15, 0.15, 0.15, 0.15, 0.15, 0.15, -0.01, -0.01, -0.01});
        Result result = KeystoreTimingStatistics.analyze(samples, 20);
        check(result.usable && result.positive && !result.noisy,
                "seven of ten in each order preserves the legacy seventy percent threshold");
        samples = logPattern(new double[]{
                0.15, 0.15, 0.15, 0.15, 0.15, 0.15, -0.01, -0.01, -0.01, -0.01});
        result = KeystoreTimingStatistics.analyze(samples, 20);
        check(result.usable && !result.positive && result.noisy,
                "direction agreement below seventy percent remains rejected");
    }

    private static void invalidInputIsUnusable() {
        Result result = KeystoreTimingStatistics.analyze(null, 16);
        check(!result.usable && !result.positive && Double.isNaN(result.medianLogRatio), "null list");
        check(!analyze(Collections.<Sample>emptyList()).usable, "empty list");
        double[] invalid = {0, -0.0, -1, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY};
        for (double value : invalid) {
            List<Sample> samples = constant(12, 10);
            samples.set(0, new Sample(value, 10, true, 0));
            result = analyze(samples);
            check(!result.usable && !result.positive && result.invalidPairs == 1, "invalid attested value");
            samples.set(0, new Sample(12, value, true, 0));
            check(!analyze(samples).usable, "invalid plain value");
        }
        for (int batch : new int[]{-1, 2, Integer.MAX_VALUE}) {
            List<Sample> samples = constant(12, 10);
            samples.set(0, new Sample(12, 10, true, batch));
            check(!analyze(samples).usable, "batch identifier must be zero or one");
        }
        List<Sample> samples = constant(12, 10);
        samples.set(0, null);
        check(!analyze(samples).usable && analyze(samples).invalidPairs == 1, "null sample");
        check(!KeystoreTimingStatistics.analyze(samples, -1).usable, "negative expected count");
    }

    private static void finiteExtremeDurationsDoNotOverflow() {
        Result result = analyze(constant(Double.MAX_VALUE, Double.MAX_VALUE / 1.2));
        check(result.usable && result.positive, "large finite values remain valid");
        check(!Double.isInfinite(result.medianAttestedMillis), "even median avoids overflow");
        near(Math.log(1.2), result.medianLogRatio, "log subtraction avoids division overflow");
        result = analyze(constant(Double.MIN_VALUE * 2, Double.MIN_VALUE));
        check(result.usable && result.positive, "positive subnormal durations remain finite");
        check(result.medianPlainMillis == Double.MIN_VALUE, "median preserves positive subnormal value");
    }

    private static void differenceMedianUsesPairs() {
        List<Sample> samples = new ArrayList<>();
        double[] attested = {1, 2, 100, 1, 2, 100, 1, 2};
        double[] plain = {100, 1, 2, 100, 1, 2, 100, 1};
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < 16; i++) {
                samples.add(new Sample(attested[i / 2], plain[i / 2], i % 2 == 0, batch));
            }
        }
        Result result = analyze(samples);
        near(2, result.medianAttestedMillis, "paired example attested median");
        near(2, result.medianPlainMillis, "paired example plain median");
        near(1, result.medianDifferenceMillis, "median of paired differences, not difference of medians");
    }

    private static void calibratedAbsoluteFloor() {
        List<Sample> tiny = constant(0.12, 0.10);
        check(KeystoreTimingStatistics.analyze(tiny, 16).positive, "relative effect alone is strong");
        check(!KeystoreTimingStatistics.analyze(tiny, 16, 0.03).positive,
                "calibrated floor rejects effect below measurement quality");
        check(KeystoreTimingStatistics.analyze(constant(2.0, 1.0), 16, 0.1).positive,
                "real effect above calibrated floor remains independently positive");
        check(!KeystoreTimingStatistics.analyze(constant(2.0, 1.0), 16, 1.1).positive,
                "coarse clock floor also applies to every group");
    }

    private static List<Sample> constant(double attested, double plain) {
        List<Sample> samples = new ArrayList<>();
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < 16; i++) {
                samples.add(new Sample(attested, plain, i % 2 == 0, batch));
            }
        }
        return samples;
    }

    private static List<Sample> logPattern(double[] pattern) {
        List<Sample> samples = new ArrayList<>();
        for (int batch = 0; batch < 2; batch++) {
            for (int i = 0; i < pattern.length * 2; i++) {
                samples.add(new Sample(10 * Math.exp(pattern[i / 2]), 10, i % 2 == 0, batch));
            }
        }
        return samples;
    }

    private static Result analyze(List<Sample> samples) {
        return KeystoreTimingStatistics.analyze(samples, 16);
    }

    private static void near(double expected, double actual, String message) {
        check(!Double.isNaN(actual) && Math.abs(expected - actual) <= 1e-10, message);
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Robust paired timing decision for a standalone Keystore timing detector.
 *
 * <p>The detector intentionally knows nothing about the operation being measured. The caller
 * supplies a "treatment" timing and a matched "control" timing for each pair. Two disjoint
 * batches and both sampling orders are required so that drift/order effects cannot create a
 * positive result by themselves.</p>
 *
 * <p>A positive result only means that the treatment/control timing distributions are stably
 * separated. Attribution to KeyMint, a HAL, Binder scheduling, or any concrete implementation
 * must be established by the caller with an independent control.</p>
 */
public final class KeystoreTimingStatistics {
    private static final double MIN_LOG_EFFECT = Math.log(1.10);
    private static final double MAX_MAD_LOG_RATIO = 0.12;
    private static final double MIN_DIRECTION_FRACTION = 0.70;
    private static final double STRONG_LOG_EFFECT = Math.log(1.25);
    private static final double STRONG_MIN_DIRECTION_FRACTION = 0.78;
    private static final double STRONG_MAX_MAD_LOG_RATIO = 0.22;

    private KeystoreTimingStatistics() {
    }

    /** Failed operations must be retained as a sample containing NaN. */
    public static final class Sample {
        public final double treatmentMillis;
        public final double controlMillis;
        public final boolean treatmentFirst;
        public final int batch;

        /**
         * Legacy aliases retained so callers built against the previous attested/plain API keep
         * compiling. New code should use treatment/control names.
         */
        @Deprecated public final double attestedMillis;
        @Deprecated public final double plainMillis;
        @Deprecated public final boolean attestedFirst;

        public Sample(double treatmentMillis, double controlMillis,
                      boolean treatmentFirst, int batch) {
            this.treatmentMillis = treatmentMillis;
            this.controlMillis = controlMillis;
            this.treatmentFirst = treatmentFirst;
            this.batch = batch;
            this.attestedMillis = treatmentMillis;
            this.plainMillis = controlMillis;
            this.attestedFirst = treatmentFirst;
        }
    }

    public static final class Result {
        public final boolean usable;
        public final boolean positive;
        public final boolean noisy;
        public final int validPairs;
        public final int invalidPairs;
        public final double medianTreatmentMillis;
        public final double medianControlMillis;
        public final double medianDifferenceMillis;
        /** Signed log(treatment/control); positive means the treatment was slower. */
        public final double medianLogRatio;
        /** Signed percent effect derived from the median log ratio. */
        public final double medianRelativePercent;
        /** Unscaled median absolute deviation of the signed log ratios. */
        public final double madLogRatio;
        /** TREATMENT_SLOWER, CONTROL_SLOWER, NONE, or MIXED across batch/order groups. */
        public final String direction;
        public final String reason;

        /** Legacy aliases retained for source compatibility. */
        @Deprecated public final double medianAttestedMillis;
        @Deprecated public final double medianPlainMillis;

        private Result(boolean usable, boolean positive, boolean noisy,
                       int invalidPairs, Measurements measurements,
                       String direction, String reason) {
            this.usable = usable;
            this.positive = positive;
            this.noisy = noisy;
            this.validPairs = measurements.treatment.size();
            this.invalidPairs = invalidPairs;
            this.medianTreatmentMillis = median(measurements.treatment);
            this.medianControlMillis = median(measurements.control);
            this.medianDifferenceMillis = median(measurements.differences);
            this.medianLogRatio = median(measurements.logRatios);
            this.medianRelativePercent = Double.isFinite(this.medianLogRatio)
                    ? Math.expm1(this.medianLogRatio) * 100.0 : Double.NaN;
            this.madLogRatio = mad(measurements.logRatios, this.medianLogRatio);
            this.direction = direction;
            this.reason = reason;
            this.medianAttestedMillis = this.medianTreatmentMillis;
            this.medianPlainMillis = this.medianControlMillis;
        }
    }

    /**
     * Analyze paired samples without an absolute-effect floor.
     */
    public static Result analyze(List<Sample> samples, int expectedPairsPerBatch) {
        return analyze(samples, expectedPairsPerBatch, 0.0);
    }

    /**
     * Requires exactly {@code expectedPairsPerBatch} samples in each batch (0 and 1), with at
     * least ceil(expectedPairsPerBatch/3) samples in each order.
     *
     * <p>{@code minAbsoluteEffectMillis} is applied to the median paired difference in every
     * batch/order subgroup as well as the pooled data. It prevents a large relative ratio on a
     * tiny absolute interval from becoming a positive timing finding.</p>
     *
     * <p>The caller must collect disjoint batches; samples must not be reused or replaced after
     * an operation fails. Missing, extra, failed or invalid samples make the complete run
     * unusable.</p>
     */
    public static Result analyze(List<Sample> samples, int expectedPairsPerBatch,
                                 double minAbsoluteEffectMillis) {
        Measurements measurements = new Measurements();
        Group[] orders = {new Group(), new Group(), new Group(), new Group()};
        Group[] batches = {new Group(), new Group()};
        int invalidPairs = 0;

        if (!Double.isFinite(minAbsoluteEffectMillis) || minAbsoluteEffectMillis < 0.0) {
            minAbsoluteEffectMillis = 0.0;
        }

        if (samples != null) {
            for (Sample sample : samples) {
                if (sample == null || sample.batch < 0 || sample.batch > 1
                        || !positiveFinite(sample.treatmentMillis)
                        || !positiveFinite(sample.controlMillis)) {
                    invalidPairs++;
                    continue;
                }
                // Subtract logarithms to avoid overflow/underflow when forming treatment/control.
                double logRatio = Math.log(sample.treatmentMillis) - Math.log(sample.controlMillis);
                double difference = sample.treatmentMillis - sample.controlMillis;
                measurements.add(sample, logRatio, difference);
                orders[sample.batch * 2 + (sample.treatmentFirst ? 0 : 1)]
                        .add(logRatio, difference);
                batches[sample.batch].add(logRatio, difference);
            }
        }

        if (expectedPairsPerBatch < 16) {
            return result(false, false, false, invalidPairs, measurements, "NONE",
                    "Expected pairs per batch must be at least 16.");
        }
        if (samples == null) {
            return result(false, false, false, invalidPairs, measurements, "NONE",
                    "Samples are missing.");
        }
        if (invalidPairs != 0) {
            return result(false, false, false, invalidPairs, measurements, "NONE",
                    "Failed or invalid samples are present; do not discard or replace them.");
        }
        for (Group batch : batches) {
            if (batch.logRatios.size() != expectedPairsPerBatch) {
                return result(false, false, false, invalidPairs, measurements, "NONE",
                        "Both non-overlapping batches must contain exactly the expected pairs.");
            }
        }

        int minimumPerOrder = (int) (((long) expectedPairsPerBatch + 2) / 3);
        for (Group order : orders) {
            if (order.logRatios.size() < minimumPerOrder) {
                return result(false, false, false, invalidPairs, measurements, "NONE",
                        "Each batch must contain at least one third of its pairs in each order.");
            }
            order.summarize();
        }
        for (Group batch : batches) {
            batch.summarize();
        }
        Group pooled = new Group(measurements.logRatios, measurements.differences);
        pooled.summarize();
        String direction = direction(orders);

        boolean anyScreeningEffect = false;
        boolean allScreeningEffects = true;
        boolean dispersed = pooled.noisy();
        boolean stable = pooled.passesCriteria(minAbsoluteEffectMillis);
        for (Group order : orders) {
            boolean enoughEffect = order.hasEffect(minAbsoluteEffectMillis);
            anyScreeningEffect |= enoughEffect;
            allScreeningEffects &= enoughEffect;
            dispersed |= order.noisy();
            stable &= order.passesCriteria(minAbsoluteEffectMillis);
        }
        for (Group batch : batches) {
            dispersed |= batch.noisy();
            stable &= batch.passesCriteria(minAbsoluteEffectMillis);
        }

        if (!anyScreeningEffect) {
            return result(true, false, dispersed, invalidPairs, measurements, direction,
                    dispersed ? "Timing dispersion is too large for a reliable decision."
                            : "No repeatable effect reaches the timing threshold.");
        }
        if (!allScreeningEffects || "MIXED".equals(direction) || "NONE".equals(direction)) {
            return result(true, false, true, invalidPairs, measurements, direction,
                    "The signed effect does not repeat in both orders of both batches.");
        }
        if (!stable || dispersed) {
            return result(true, false, true, invalidPairs, measurements, direction,
                    "Direction agreement, absolute effect, or robust dispersion fails the stability criteria.");
        }
        return result(true, true, false, invalidPairs, measurements, direction,
                "Two non-overlapping batches have stable same-direction separation in all four batch/order groups.");
    }

    private static Result result(boolean usable, boolean positive, boolean noisy,
                                 int invalidPairs, Measurements measurements,
                                 String direction, String reason) {
        return new Result(usable, positive, noisy, invalidPairs, measurements, direction, reason);
    }

    private static boolean positiveFinite(double value) {
        return value > 0 && !Double.isNaN(value) && !Double.isInfinite(value);
    }

    private static String direction(Group[] groups) {
        int first = sign(groups[0].medianLogRatio);
        for (Group group : groups) {
            if (sign(group.medianLogRatio) != first) {
                return "MIXED";
            }
        }
        return first > 0 ? "TREATMENT_SLOWER" : first < 0 ? "CONTROL_SLOWER" : "NONE";
    }

    private static int sign(double value) {
        return value > 0 ? 1 : value < 0 ? -1 : 0;
    }

    private static double median(List<Double> values) {
        if (values.isEmpty()) {
            return Double.NaN;
        }
        double[] sorted = new double[values.size()];
        for (int i = 0; i < sorted.length; i++) {
            sorted[i] = values.get(i);
        }
        Arrays.sort(sorted);
        int middle = sorted.length / 2;
        if (sorted.length % 2 == 1) {
            return sorted[middle];
        }
        double lower = sorted[middle - 1];
        double upper = sorted[middle];
        // Preserve subnormal values for same-sign inputs, and avoid overflow across signs.
        return sign(lower) == sign(upper) ? lower + (upper - lower) / 2.0
                : lower / 2.0 + upper / 2.0;
    }

    private static double mad(List<Double> values, double center) {
        if (values.isEmpty() || !Double.isFinite(center)) {
            return Double.NaN;
        }
        List<Double> deviations = new ArrayList<>(values.size());
        for (double value : values) {
            deviations.add(Math.abs(value - center));
        }
        return median(deviations);
    }

    private static final class Measurements {
        final List<Double> treatment = new ArrayList<>();
        final List<Double> control = new ArrayList<>();
        final List<Double> differences = new ArrayList<>();
        final List<Double> logRatios = new ArrayList<>();

        void add(Sample sample, double logRatio, double difference) {
            treatment.add(sample.treatmentMillis);
            control.add(sample.controlMillis);
            differences.add(difference);
            logRatios.add(logRatio);
        }
    }

    private static final class Group {
        final List<Double> logRatios;
        final List<Double> differences;
        double medianLogRatio;
        double medianDifference;
        double madLogRatio;

        Group() {
            this(new ArrayList<Double>(), new ArrayList<Double>());
        }

        Group(List<Double> logRatios, List<Double> differences) {
            this.logRatios = logRatios;
            this.differences = differences;
        }

        void add(double logRatio, double difference) {
            logRatios.add(logRatio);
            differences.add(difference);
        }

        void summarize() {
            medianLogRatio = KeystoreTimingStatistics.median(logRatios);
            medianDifference = KeystoreTimingStatistics.median(differences);
            madLogRatio = KeystoreTimingStatistics.mad(logRatios, medianLogRatio);
        }

        double directionFraction() {
            if (logRatios.isEmpty()) return 0.0;
            int agreeing = 0;
            int expectedSign = sign(medianLogRatio);
            for (double value : logRatios) {
                if (expectedSign != 0 && sign(value) == expectedSign) {
                    agreeing++;
                }
            }
            return agreeing / (double) logRatios.size();
        }

        boolean hasEffect(double minAbsoluteEffectMillis) {
            return Math.abs(medianLogRatio) > MIN_LOG_EFFECT
                    && Math.abs(medianDifference) >= minAbsoluteEffectMillis;
        }

        boolean passesCriteria(double minAbsoluteEffectMillis) {
            boolean standard = hasEffect(minAbsoluteEffectMillis)
                    && directionFraction() >= MIN_DIRECTION_FRACTION
                    && madLogRatio <= MAX_MAD_LOG_RATIO;
            return standard || strongSeparation(minAbsoluteEffectMillis);
        }

        boolean strongSeparation(double minAbsoluteEffectMillis) {
            return Math.abs(medianLogRatio) >= STRONG_LOG_EFFECT
                    && Math.abs(medianDifference) >= minAbsoluteEffectMillis
                    && directionFraction() >= STRONG_MIN_DIRECTION_FRACTION
                    && madLogRatio <= STRONG_MAX_MAD_LOG_RATIO;
        }

        boolean noisy() {
            return madLogRatio > MAX_MAD_LOG_RATIO && !strongSeparation(0.0);
        }
    }
}

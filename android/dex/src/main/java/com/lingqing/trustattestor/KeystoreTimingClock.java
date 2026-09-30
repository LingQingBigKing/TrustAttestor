package com.lingqing.trustattestor;

import java.util.Arrays;
import java.util.Locale;

/**
 * A calibrated, fixed-source clock for one Keystore timing run.
 *
 * <p>The native bridge uses the operating system's raw monotonic clock. A missing bridge or an
 * unsupported native clock selects System.nanoTime before calibration. After selection, failures
 * invalidate the entire session: switching epochs or replacing failed samples is never safe.</p>
 *
 * <p>This class measures elapsed intervals only. It does not attribute time to KeyMint, Binder,
 * scheduling or the calling thread. The caller supplies those independent observations.</p>
 */
final class KeystoreTimingClock {
    private static final int WARMUP_READS = 16;
    private static final int CALIBRATION_PAIRS = 128;
    private static final double NANOS_PER_MILLI = 1_000_000.0;

    interface Source {
        String name();
        long readNanos();
        /** Declared resolution, or zero when the source does not expose it. */
        long resolutionNanos();
    }

    static final class ClockFailure extends IllegalStateException {
        ClockFailure(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final class NativeUnavailable extends IllegalStateException {
        NativeUnavailable(String message) {
            super(message);
        }
    }

    private static final Source JAVA_CLOCK = new Source() {
        @Override public String name() { return "System.nanoTime"; }
        @Override public long readNanos() { return System.nanoTime(); }
        @Override public long resolutionNanos() { return 0L; }
    };

    private static final Source RAW_CLOCK = new Source() {
        @Override public String name() { return "CLOCK_MONOTONIC_RAW"; }
        @Override public long readNanos() {
            long value = nativeClockNanos();
            if (value == -1L) throw new NativeUnavailable("native clock unavailable");
            return value;
        }
        @Override public long resolutionNanos() {
            long value = nativeClockResolutionNanos();
            if (value <= 0L) throw new NativeUnavailable("native clock resolution unavailable");
            return value;
        }
    };

    // Registered by the existing native bridge; no separate library load or privileged operation.
    private static native long nativeClockNanos();
    private static native long nativeClockResolutionNanos();

    private final Source source;
    private final String fallbackReason;
    private long resolutionNanos;
    private long minimumPositiveDeltaNanos;
    private double medianReadOverheadNanos;
    private long p95ReadOverheadNanos;
    private int calibrationPairs;
    private int zeroCalibrationPairs;
    private int invalidReads;
    private boolean hasPrevious;
    private long previous;
    private boolean calibrated;
    private ClockFailure failure;

    private KeystoreTimingClock(Source source, String fallbackReason) {
        if (source == null) throw new IllegalArgumentException("Clock source is required");
        this.source = source;
        this.fallbackReason = fallbackReason;
    }

    static KeystoreTimingClock create() {
        try {
            // Select the backend once. Initial unsupported/linkage failures alone allow fallback.
            long initial = RAW_CLOCK.readNanos();
            long resolution = RAW_CLOCK.resolutionNanos();
            KeystoreTimingClock clock = new KeystoreTimingClock(RAW_CLOCK, "none");
            clock.hasPrevious = true;
            clock.previous = initial;
            clock.calibrate(resolution);
            return clock;
        } catch (NativeUnavailable | LinkageError unavailable) {
            return create(JAVA_CLOCK, unavailable.getClass().getSimpleName());
        }
    }

    /** Host-test entry point. An injected source is never replaced, including during calibration. */
    static KeystoreTimingClock create(Source source) {
        return create(source, "none");
    }

    private static KeystoreTimingClock create(Source source, String fallbackReason) {
        KeystoreTimingClock clock = new KeystoreTimingClock(source, fallbackReason);
        try {
            clock.calibrate(source.resolutionNanos());
        } catch (RuntimeException | LinkageError unavailable) {
            clock.invalidate("clock resolution read failed", unavailable);
        }
        return clock;
    }

    private void calibrate(long declaredResolution) {
        if (declaredResolution < 0L) {
            invalidate("invalid declared clock resolution", null);
            return;
        }
        resolutionNanos = declaredResolution;
        long[] deltas = new long[CALIBRATION_PAIRS];
        long smallest = Long.MAX_VALUE;
        try {
            for (int i = 0; i < WARMUP_READS; i++) read();
            for (int i = 0; i < CALIBRATION_PAIRS; i++) {
                long start = read();
                long end = read();
                long delta = checkedDelta(start, end);
                deltas[i] = delta;
                calibrationPairs++;
                if (delta == 0L) zeroCalibrationPairs++;
                else if (delta < smallest) smallest = delta;
            }
            if (zeroCalibrationPairs == CALIBRATION_PAIRS) {
                invalidate("clock did not advance during calibration", null);
                return;
            }
            Arrays.sort(deltas);
            minimumPositiveDeltaNanos = smallest;
            medianReadOverheadNanos = deltas[CALIBRATION_PAIRS / 2 - 1]
                    + (deltas[CALIBRATION_PAIRS / 2]
                    - deltas[CALIBRATION_PAIRS / 2 - 1]) / 2.0;
            p95ReadOverheadNanos = deltas[(int) Math.ceil(CALIBRATION_PAIRS * 0.95) - 1];
            calibrated = true;
        } catch (ClockFailure unavailable) {
            // read()/checkedDelta() already recorded the first failure. Keep it permanently.
        }
    }

    long read() {
        requireNoFailure();
        final long value;
        try {
            value = source.readNanos();
        } catch (RuntimeException | LinkageError unavailable) {
            invalidReads++;
            throw invalidate("clock read failed", unavailable);
        }
        // nanoTime has an arbitrary origin and may be negative. Validate differences, not epochs.
        if (hasPrevious) checkedDelta(previous, value);
        previous = value;
        hasPrevious = true;
        return value;
    }

    double elapsedMillis(long start, long end) {
        requireNoFailure();
        if (!calibrated) throw invalidate("clock is not calibrated", null);
        long delta = checkedDelta(start, end);
        if (delta == 0L) {
            invalidReads++;
            throw invalidate("measured interval did not advance", null);
        }
        return delta / NANOS_PER_MILLI;
    }

    boolean usable() {
        return calibrated && failure == null;
    }

    /**
     * Never subtract timing overhead from samples. Instead require separation above a conservative
     * measurement floor. The smallest positive empty interval is observed granularity/overhead,
     * not a claim about the underlying hardware resolution.
     */
    double minimumEffectMillis(double configuredFloor) {
        if (!Double.isFinite(configuredFloor) || configuredFloor < 0.0) {
            throw new IllegalArgumentException("Minimum timing effect must be finite and nonnegative");
        }
        if (!usable()) throw failure != null ? failure
                : new ClockFailure("clock is not calibrated", null);
        double measuredFloorNanos = Math.max(
                Math.max(resolutionNanos, minimumPositiveDeltaNanos) * 8.0,
                Math.max(medianReadOverheadNanos * 8.0, p95ReadOverheadNanos * 4.0));
        return Math.max(configuredFloor, measuredFloorNanos / NANOS_PER_MILLI);
    }

    String summary() {
        return String.format(Locale.US,
                "clock{source=%s, usable=%s, resolutionNs=%d, minPositiveDeltaNs=%d, "
                        + "readOverheadMedianNs=%.1f, readOverheadP95Ns=%d, calibrationPairs=%d, "
                        + "zeroCalibrationPairs=%d, invalidReads=%d, fallback=%s, failure=%s}",
                source.name(), usable(), resolutionNanos, minimumPositiveDeltaNanos,
                medianReadOverheadNanos, p95ReadOverheadNanos, calibrationPairs,
                zeroCalibrationPairs, invalidReads, fallbackReason,
                failure == null ? "none" : failure.getMessage());
    }

    private long checkedDelta(long start, long end) {
        final long delta;
        try {
            delta = Math.subtractExact(end, start);
        } catch (ArithmeticException overflow) {
            invalidReads++;
            throw invalidate("clock interval overflow", overflow);
        }
        if (delta < 0L) {
            invalidReads++;
            throw invalidate("clock moved backwards", null);
        }
        return delta;
    }

    private ClockFailure invalidate(String reason, Throwable cause) {
        if (failure == null) failure = new ClockFailure(reason, cause);
        return failure;
    }

    private void requireNoFailure() {
        if (failure != null) throw failure;
    }
}

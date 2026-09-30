package com.lingqing.trustattestor;

/** Standalone clock regression tests; no Android runtime or JUnit required. */
public final class KeystoreTimingClockTest {
    private static int assertions;

    public static void main(String[] args) {
        calibrationPreservesConfiguredFloor();
        coarseClockRaisesMeasurementFloor();
        negativeEpochAndCrossingZeroAreValid();
        zeroIntervalsDuringCalibrationAreAllowed();
        frozenClockIsUnavailable();
        backwardClockFailsPermanently();
        sourceFailureNeverChangesBackend();
        calibrationFailureNeverChangesBackend();
        overflowingOrEmptyIntervalsFail();
        invalidDeclaredResolutionFails();
        extremeCalibrationValuesDoNotOverflow();
        hostWithoutNativeBridgeFallsBack();
        System.out.println("KeystoreTimingClockTest: " + assertions + " assertions passed");
    }

    private static void calibrationPreservesConfiguredFloor() {
        FakeSource source = new FakeSource(-10_000L, 100L, 1L);
        KeystoreTimingClock clock = KeystoreTimingClock.create(source);
        check(clock.usable(), "working clock is calibrated");
        check(source.reads == 16 + 128 * 2, "bounded warmup and calibration");
        near(0.1, clock.minimumEffectMillis(0.1), "existing effect floor is preserved");
        near(0.0008, clock.minimumEffectMillis(0.0), "observed read overhead sets floor");
        long start = clock.read();
        source.next += 25_000L;
        long end = clock.read();
        near(0.0251, clock.elapsedMillis(start, end), "actual elapsed time is not corrected");
        check(clock.summary().contains("calibrationPairs=128"), "summary identifies calibration");
        check(clock.summary().contains("readOverheadMedianNs=100.0"), "summary retains overhead");
        boolean rejected = false;
        try { clock.minimumEffectMillis(Double.NaN); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected && clock.usable(), "caller parameter errors do not invalidate the clock");
    }

    private static void coarseClockRaisesMeasurementFloor() {
        FakeSource source = new FakeSource(0L, 100L, 100_000L);
        KeystoreTimingClock clock = KeystoreTimingClock.create(source);
        near(0.8, clock.minimumEffectMillis(0.1), "declared resolution limits useful separation");
        near(2.0, clock.minimumEffectMillis(2.0), "configured larger floor remains intact");
    }

    private static void negativeEpochAndCrossingZeroAreValid() {
        FakeSource source = new FakeSource(-100_000L, 100L, 0L);
        KeystoreTimingClock clock = KeystoreTimingClock.create(source);
        long start = clock.read();
        check(start < 0L && clock.usable(), "negative source epoch is legitimate");
        source.next = 100L;
        long end = clock.read();
        near((end - start) / 1_000_000.0, clock.elapsedMillis(start, end),
                "negative-to-positive epoch transition is legitimate");
    }

    private static void zeroIntervalsDuringCalibrationAreAllowed() {
        KeystoreTimingClock clock = KeystoreTimingClock.create(new KeystoreTimingClock.Source() {
            int reads;
            @Override public String name() { return "quantized"; }
            @Override public long readNanos() { return (reads++ / 3) * 100L; }
            @Override public long resolutionNanos() { return 100L; }
        });
        check(clock.usable(), "equal consecutive timestamps can represent clock quantization");
        near(0.0008, clock.minimumEffectMillis(0.0), "positive observed tick remains useful");
    }

    private static void frozenClockIsUnavailable() {
        KeystoreTimingClock clock = KeystoreTimingClock.create(new FakeSource(-7L, 0L, 1L));
        check(!clock.usable(), "frozen clock cannot be calibrated");
        check(clock.summary().contains("zeroCalibrationPairs=128"), "zero readings remain visible");
        expectFailure(clock::read, "frozen clock stays unusable");
    }

    private static void backwardClockFailsPermanently() {
        FakeSource source = new FakeSource(100_000L, 100L, 1L);
        KeystoreTimingClock clock = KeystoreTimingClock.create(source);
        source.next = 1L;
        expectFailure(clock::read, "backward read is rejected");
        int reads = source.reads;
        source.next = Long.MAX_VALUE;
        expectFailure(clock::read, "source recovery cannot revive this session");
        check(!clock.usable() && source.reads == reads, "failed session stops reading backend");
        check(clock.summary().contains("invalidReads=1"), "failure counted once");
    }

    private static void sourceFailureNeverChangesBackend() {
        FakeSource source = new FakeSource(0L, 100L, 1L);
        KeystoreTimingClock clock = KeystoreTimingClock.create(source);
        source.failAt = source.reads;
        expectFailure(clock::read, "mid-run source error invalidates the clock");
        check(!clock.usable(), "failed source is unavailable");
        check(clock.summary().contains("source=fake"), "source identity never switches");
        expectFailure(() -> clock.elapsedMillis(1L, 2L), "stored times cannot bypass failure");
        expectFailure(() -> clock.minimumEffectMillis(0.1), "failed clock provides no usable floor");
    }

    private static void calibrationFailureNeverChangesBackend() {
        FakeSource source = new FakeSource(0L, 100L, 1L);
        source.failAt = 45;
        KeystoreTimingClock clock = KeystoreTimingClock.create(source);
        check(!clock.usable(), "incomplete calibration is unusable");
        check(clock.summary().contains("source=fake"), "calibration failure cannot change source");
        check(source.reads == 45, "calibration stops at first failure");
    }

    private static void overflowingOrEmptyIntervalsFail() {
        KeystoreTimingClock overflow = KeystoreTimingClock.create(new FakeSource(0L, 100L, 1L));
        expectFailure(() -> overflow.elapsedMillis(Long.MIN_VALUE, Long.MAX_VALUE),
                "subtraction overflow is not an elapsed interval");
        check(!overflow.usable(), "overflow permanently invalidates this run");
        KeystoreTimingClock empty = KeystoreTimingClock.create(new FakeSource(0L, 100L, 1L));
        expectFailure(() -> empty.elapsedMillis(7L, 7L), "unresolved measured operation rejected");
        KeystoreTimingClock backwards = KeystoreTimingClock.create(new FakeSource(0L, 100L, 1L));
        expectFailure(() -> backwards.elapsedMillis(9L, 8L), "reversed operation times rejected");
    }

    private static void invalidDeclaredResolutionFails() {
        KeystoreTimingClock clock = KeystoreTimingClock.create(new FakeSource(0L, 100L, -1L));
        check(!clock.usable(), "negative declared resolution is rejected");
        expectFailure(clock::read, "resolution failure cannot be bypassed");
    }

    private static void extremeCalibrationValuesDoNotOverflow() {
        KeystoreTimingClock clock = KeystoreTimingClock.create(
                new FakeSource(0L, 100L, Long.MAX_VALUE));
        check(clock.usable(), "large positive resolution remains representable");
        double floor = clock.minimumEffectMillis(0.0);
        check(Double.isFinite(floor) && floor > 1e12, "floor scaling uses non-overflowing arithmetic");
    }

    private static void hostWithoutNativeBridgeFallsBack() {
        KeystoreTimingClock clock = KeystoreTimingClock.create();
        check(clock.usable(), "host Java clock calibrates without the Android native bridge");
        check(clock.summary().contains("source=System.nanoTime"), "missing bridge selects Java once");
        check(clock.summary().contains("fallback=UnsatisfiedLinkError"), "fallback reason retained");
    }

    private static final class FakeSource implements KeystoreTimingClock.Source {
        long next;
        final long step;
        final long resolution;
        int reads;
        int failAt = Integer.MAX_VALUE;
        FakeSource(long next, long step, long resolution) {
            this.next = next;
            this.step = step;
            this.resolution = resolution;
        }
        @Override public String name() { return "fake"; }
        @Override public long readNanos() {
            if (reads == failAt) throw new IllegalStateException("simulated unavailable clock");
            reads++;
            long value = next;
            next += step;
            return value;
        }
        @Override public long resolutionNanos() { return resolution; }
    }

    private static void expectFailure(Runnable action, String message) {
        boolean failed = false;
        try { action.run(); }
        catch (KeystoreTimingClock.ClockFailure expected) { failed = true; }
        check(failed, message);
    }

    private static void near(double expected, double actual, String message) {
        check(Math.abs(expected - actual) <= Math.max(1e-12, Math.abs(expected) * 1e-12), message);
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

package com.lingqing.trustattestor;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.IBinder;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Safe timing variants of OMK Detector's reply-lag and raw getKeyEntry probes.
 *
 * <p>These probes never read an architectural counter or change CPU affinity. Every failure is
 * returned as UNAVAILABLE so one probe cannot prevent the rest of the attestation run.</p>
 */
@SuppressLint({"BlockedPrivateApi", "PrivateApi", "SoonBlockedPrivateApi"})
final class OmkTimingProbes {
    private static final String KEYSTORE2_SERVICE =
            "android.system.keystore2.IKeystoreService/default";
    private static final int REPLY_BATCHES = 2;
    private static final int REPLY_PAIRS_PER_BATCH = 4;
    // Match the source probe's conservative cadence; 4 ms still resolves a 25 ms window while
    // avoiding unnecessary Binder pressure on devices whose attestation generation is slow.
    private static final long POLL_INTERVAL_MILLIS = 4L;
    private static final long POLLER_READY_TIMEOUT_MILLIS = 2_000L;
    private static final long POLLER_JOIN_TIMEOUT_MILLIS = 2_000L;
    private static final long POLLER_INTERRUPT_JOIN_TIMEOUT_MILLIS = 500L;
    private static final int READ_PAIRS_PER_BATCH = 32;
    private static final int READ_WARMUP_CALLS = 8;
    private static final double READ_ABSOLUTE_FLOOR_MILLIS = 0.020;
    private static final SecureRandom RANDOM = new SecureRandom();

    private OmkTimingProbes() { }

    static final class Result {
        final String id;
        final SilentProbeEvidence.Status status;
        final String summary;
        final String detail;
        final Throwable failure;

        private Result(String id, SilentProbeEvidence.Status status, String summary,
                       String detail, Throwable failure) {
            this.id = id;
            this.status = status;
            this.summary = summary;
            this.detail = detail;
            this.failure = failure;
        }

        String debugDetail() {
            StringBuilder out = new StringBuilder(id).append(": ").append(status)
                    .append("; ").append(summary);
            if (detail != null && !detail.isEmpty()) out.append('\n').append(detail);
            if (failure != null) {
                out.append("\nrootFailure=").append(describe(failure));
                for (StackTraceElement frame : failure.getStackTrace()) {
                    out.append("\n  at ").append(frame);
                }
            }
            return out.toString();
        }
    }

    static Result runReplyLag() {
        final String id = "T.reply_lag";
        final List<String> aliases = new ArrayList<>();
        final List<OmkTimingEvidence.ReplyPair> samples = new ArrayList<>();
        final StringBuilder detail = new StringBuilder(
                "clock=System.nanoTime; batches=2; pairsPerBatch=4; pollIntervalMs="
                        + POLL_INTERVAL_MILLIS + '\n');
        Throwable firstFailure = null;
        Result result = null;
        try {
            KeyStore cleanupStore = KeyStore.getInstance("AndroidKeyStore");
            cleanupStore.load(null);
            measurement:
            for (int batch = 0; batch < REPLY_BATCHES; batch++) {
                List<Boolean> orders = balancedOrders(REPLY_PAIRS_PER_BATCH);
                for (int pair = 0; pair < REPLY_PAIRS_PER_BATCH; pair++) {
                    throwIfInterrupted();
                    boolean targetFirst = orders.get(pair);
                    String targetAlias = unusedAlias(cleanupStore, "reply_att");
                    String controlAlias = unusedAlias(cleanupStore, "reply_plain");
                    aliases.add(targetAlias);
                    aliases.add(controlAlias);
                    LagObservation target;
                    LagObservation control;
                    if (targetFirst) {
                        target = observeGeneration(targetAlias, true);
                        control = observeGeneration(controlAlias, false);
                    } else {
                        control = observeGeneration(controlAlias, false);
                        target = observeGeneration(targetAlias, true);
                    }
                    appendLag(detail, batch, pair, targetFirst, target, control);
                    if (!target.usable() || !control.usable()) {
                        firstFailure = target.failure != null ? target.failure : control.failure;
                        String reason = !target.usable() ? target.unavailableReason()
                                : control.unavailableReason();
                        result = unavailable(id,
                                "回复提前可见检测未能完成全部配对样本",
                                detail.append("unavailable=").append(reason).toString(),
                                firstFailure);
                        break measurement;
                    }
                    samples.add(new OmkTimingEvidence.ReplyPair(batch, targetFirst,
                            target.earlyGapMillis(), control.earlyGapMillis()));
                    safeDelete(cleanupStore, targetAlias);
                    safeDelete(cleanupStore, controlAlias);
                }
            }
            if (result == null) {
                OmkTimingEvidence.Decision decision = OmkTimingEvidence.replyLag(samples);
                detail.append(decision.detail);
                result = new Result(id, decision.status, decision.summary,
                        detail.toString(), null);
            }
        } catch (Throwable failure) {
            firstFailure = unwrap(failure);
            restoreInterrupt(firstFailure);
            result = unavailable(id, "回复提前可见检测执行失败",
                    detail.append("failure=").append(describe(firstFailure)).toString(),
                    firstFailure);
        }
        return applyCleanup(result, cleanupAliases(aliases));
    }

    static Result runReadPathTiming() {
        final String id = "H.raw_read_path_timing";
        if (Build.VERSION.SDK_INT < 31) {
            return new Result(id, SilentProbeEvidence.Status.UNAVAILABLE,
                    "Android 12 之前没有可比的 Keystore2 原始读取路径",
                    "sdk=" + Build.VERSION.SDK_INT, null);
        }
        final List<String> aliases = new ArrayList<>(4);
        final StringBuilder detail = new StringBuilder();
        Result result = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            String targetAlias = unusedAlias(keyStore, "read_att");
            String targetControlAlias = unusedAlias(keyStore, "read_target_plain");
            String negativeTreatmentAlias = unusedAlias(keyStore, "read_negative_a");
            String negativeControlAlias = unusedAlias(keyStore, "read_negative_b");
            Collections.addAll(aliases, targetAlias, targetControlAlias,
                    negativeTreatmentAlias, negativeControlAlias);

            generateKey(targetAlias, true);
            generateKey(targetControlAlias, false);
            generateKey(negativeTreatmentAlias, false);
            generateKey(negativeControlAlias, false);

            RawRead raw = RawRead.open(targetAlias, targetControlAlias,
                    negativeTreatmentAlias, negativeControlAlias);
            KeystoreTimingClock clock = KeystoreTimingClock.create();
            detail.append(clock.summary()).append('\n');
            if (!clock.usable()) {
                result = unavailable(id, "读取路径计时器不可用", detail.toString(), null);
            } else {
                for (int i = 0; i < READ_WARMUP_CALLS; i++) {
                    raw.read(targetAlias);
                    raw.read(targetControlAlias);
                    raw.read(negativeTreatmentAlias);
                    raw.read(negativeControlAlias);
                }

                List<KeystoreTimingStatistics.Sample> targetSamples = new ArrayList<>();
                List<KeystoreTimingStatistics.Sample> negativeSamples = new ArrayList<>();
                for (int batch = 0; batch < 2; batch++) {
                    List<Boolean> targetOrders = balancedOrders(READ_PAIRS_PER_BATCH);
                    List<Boolean> negativeOrders = balancedOrders(READ_PAIRS_PER_BATCH);
                    List<Boolean> pairOrders = balancedOrders(READ_PAIRS_PER_BATCH);
                    for (int pair = 0; pair < READ_PAIRS_PER_BATCH; pair++) {
                        throwIfInterrupted();
                        final boolean targetFirst = targetOrders.get(pair);
                        final boolean negativeTreatmentFirst = negativeOrders.get(pair);
                        final double[] targetTimes = new double[2];
                        final double[] negativeTimes = new double[2];
                        Runnable targetPair = () -> measurePairUnchecked(raw, clock,
                                targetAlias, targetControlAlias, targetFirst, targetTimes);
                        Runnable negativePair = () -> measurePairUnchecked(raw, clock,
                                negativeTreatmentAlias, negativeControlAlias,
                                negativeTreatmentFirst, negativeTimes);
                        if (pairOrders.get(pair)) {
                            targetPair.run();
                            negativePair.run();
                        } else {
                            negativePair.run();
                            targetPair.run();
                        }
                        targetSamples.add(new KeystoreTimingStatistics.Sample(
                                targetTimes[0], targetTimes[1], targetFirst, batch));
                        negativeSamples.add(new KeystoreTimingStatistics.Sample(
                                negativeTimes[0], negativeTimes[1],
                                negativeTreatmentFirst, batch));
                        if ((pair & 7) == 7) Thread.yield();
                    }
                    if (batch == 0) Thread.sleep(20L);
                }

                double minimumEffect = clock.minimumEffectMillis(READ_ABSOLUTE_FLOOR_MILLIS);
                KeystoreTimingStatistics.Result targetStats = KeystoreTimingStatistics.analyze(
                        targetSamples, READ_PAIRS_PER_BATCH, minimumEffect);
                KeystoreTimingStatistics.Result negativeStats = KeystoreTimingStatistics.analyze(
                        negativeSamples, READ_PAIRS_PER_BATCH, minimumEffect);
                OmkTimingEvidence.Decision decision =
                        OmkTimingEvidence.readPath(targetStats, negativeStats);
                detail.append("minimumEffectMs=")
                        .append(String.format(Locale.US, "%.6f", minimumEffect)).append('\n')
                        .append(decision.detail);
                result = new Result(id, decision.status, decision.summary,
                        detail.toString(), null);
            }
        } catch (Throwable failure) {
            Throwable cause = unwrap(failure);
            restoreInterrupt(cause);
            result = unavailable(id, "原始读取路径计时检测执行失败",
                    detail.append("failure=").append(describe(cause)).toString(), cause);
        }
        return applyCleanup(result, cleanupAliases(aliases));
    }

    private static LagObservation observeGeneration(String alias, boolean attested) {
        AtomicBoolean stop = new AtomicBoolean(false);
        AtomicLong visibleNanos = new AtomicLong(0L);
        AtomicLong polls = new AtomicLong(0L);
        AtomicReference<Throwable> pollFailure = new AtomicReference<>();
        CountDownLatch ready = new CountDownLatch(1);
        Thread poller = new Thread(() -> {
            try {
                KeyStore store = KeyStore.getInstance("AndroidKeyStore");
                store.load(null);
                ready.countDown();
                while (!stop.get()) {
                    polls.incrementAndGet();
                    if (store.containsAlias(alias)) {
                        visibleNanos.compareAndSet(0L, System.nanoTime());
                        break;
                    }
                    Thread.sleep(POLL_INTERVAL_MILLIS);
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                if (!stop.get()) pollFailure.compareAndSet(null, interrupted);
            } catch (Throwable failure) {
                pollFailure.compareAndSet(null, unwrap(failure));
            } finally {
                ready.countDown();
            }
        }, "TA-ReplyLagPoller");
        poller.setDaemon(true);
        poller.start();
        long start = 0L;
        long returned = 0L;
        Throwable generationFailure = null;
        try {
            if (!ready.await(POLLER_READY_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                generationFailure = new IllegalStateException("alias poller did not become ready");
            } else {
                start = System.nanoTime();
                generateKey(alias, attested);
                returned = System.nanoTime();
            }
        } catch (Throwable failure) {
            generationFailure = unwrap(failure);
            restoreInterrupt(generationFailure);
            returned = System.nanoTime();
        } finally {
            stop.set(true);
            boolean restoreCallerInterrupt = false;
            try {
                poller.join(POLLER_JOIN_TIMEOUT_MILLIS);
            } catch (InterruptedException interrupted) {
                restoreCallerInterrupt = true;
                if (generationFailure == null) generationFailure = interrupted;
            }
            if (poller.isAlive()) {
                poller.interrupt();
                try {
                    poller.join(POLLER_INTERRUPT_JOIN_TIMEOUT_MILLIS);
                } catch (InterruptedException interrupted) {
                    restoreCallerInterrupt = true;
                    if (generationFailure == null) generationFailure = interrupted;
                }
                if (poller.isAlive()) {
                    generationFailure = new IllegalStateException(
                            "alias poller did not stop after interrupt", generationFailure);
                }
            }
            if (restoreCallerInterrupt) Thread.currentThread().interrupt();
        }
        Throwable failure = generationFailure != null ? generationFailure : pollFailure.get();
        return new LagObservation(attested, start, returned, visibleNanos.get(), polls.get(), failure);
    }

    private static void appendLag(StringBuilder out, int batch, int pair,
                                  boolean targetFirst, LagObservation target,
                                  LagObservation control) {
        out.append(String.format(Locale.US,
                "batch=%d pair=%d order=%s target{gen=%.3fms,gap=%.3fms,polls=%d,error=%s} "
                        + "control{gen=%.3fms,gap=%.3fms,polls=%d,error=%s}%n",
                batch + 1, pair + 1, targetFirst ? "target-control" : "control-target",
                target.generationMillis(), target.earlyGapMillis(), target.polls,
                target.failure == null ? "none" : describe(target.failure),
                control.generationMillis(), control.earlyGapMillis(), control.polls,
                control.failure == null ? "none" : describe(control.failure)));
    }

    private static void measurePairUnchecked(RawRead raw, KeystoreTimingClock clock,
                                             String treatmentAlias, String controlAlias,
                                             boolean treatmentFirst, double[] result) {
        try {
            if (treatmentFirst) {
                result[0] = measureRead(raw, treatmentAlias, clock);
                result[1] = measureRead(raw, controlAlias, clock);
            } else {
                result[1] = measureRead(raw, controlAlias, clock);
                result[0] = measureRead(raw, treatmentAlias, clock);
            }
        } catch (Throwable failure) {
            throw new ProbeFailure(failure);
        }
    }

    private static double measureRead(RawRead raw, String alias, KeystoreTimingClock clock)
            throws Throwable {
        long start = clock.read();
        raw.read(alias);
        long end = clock.read();
        return clock.elapsedMillis(start, end);
    }

    private static List<Boolean> balancedOrders(int size) {
        if ((size & 1) != 0) throw new IllegalArgumentException("balanced size must be even");
        List<Boolean> result = new ArrayList<>(size);
        for (int i = 0; i < size / 2; i++) {
            result.add(Boolean.TRUE);
            result.add(Boolean.FALSE);
        }
        Collections.shuffle(result, RANDOM);
        return result;
    }

    private static void generateKey(String alias, boolean attested) throws Exception {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
        if (attested) {
            byte[] challenge = new byte[32];
            RANDOM.nextBytes(challenge);
            builder.setAttestationChallenge(challenge);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        generator.initialize(builder.build());
        generator.generateKeyPair();
    }

    private static String unusedAlias(KeyStore store, String label) throws Exception {
        for (int attempt = 0; attempt < 8; attempt++) {
            String alias = "__ta_omk_" + label + "_" + android.os.Process.myPid() + "_"
                    + Long.toUnsignedString(System.nanoTime()) + "_"
                    + Integer.toUnsignedString(RANDOM.nextInt());
            if (!store.containsAlias(alias)) return alias;
        }
        throw new IllegalStateException("could not allocate unused alias for " + label);
    }

    private static void safeDelete(KeyStore store, String alias) {
        try {
            if (store != null && alias != null) store.deleteEntry(alias);
        } catch (Throwable ignored) {
        }
    }

    private static CleanupOutcome cleanupAliases(List<String> aliases) {
        if (aliases == null || aliases.isEmpty()) {
            return new CleanupOutcome(true, "cleanup=not-required", null);
        }
        StringBuilder debug = new StringBuilder("cleanup{aliases=")
                .append(aliases.size()).append('}');
        Throwable firstFailure = null;
        KeyStore store;
        try {
            store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
        } catch (Throwable failure) {
            Throwable cause = unwrap(failure);
            restoreInterrupt(cause);
            appendCleanupFailure(debug, "open", null, cause);
            return new CleanupOutcome(false, debug.toString(), cause);
        }
        for (String alias : aliases) {
            try {
                if (store.containsAlias(alias)) store.deleteEntry(alias);
                if (store.containsAlias(alias)) {
                    throw new IllegalStateException("temporary alias still exists after delete");
                }
            } catch (Throwable failure) {
                Throwable cause = unwrap(failure);
                restoreInterrupt(cause);
                if (firstFailure == null) firstFailure = cause;
                appendCleanupFailure(debug, "delete-or-verify", alias, cause);
            }
        }
        if (firstFailure == null) debug.append("; verified=true");
        return new CleanupOutcome(firstFailure == null, debug.toString(), firstFailure);
    }

    private static Result applyCleanup(Result result, CleanupOutcome cleanup) {
        Result base = result;
        if (base == null) {
            base = unavailable("timing.unknown", "时序检测没有生成结果",
                    "result=null", null);
        }
        if (cleanup == null || cleanup.success) return base;
        String mergedDetail = (base.detail == null || base.detail.isEmpty())
                ? cleanup.detail : base.detail + '\n' + cleanup.detail;
        Throwable failure = base.failure != null ? base.failure : cleanup.failure;
        if (base.status == SilentProbeEvidence.Status.DETECTED) {
            return new Result(base.id, base.status, base.summary, mergedDetail, failure);
        }
        String summary = base.status == SilentProbeEvidence.Status.VERIFIED
                ? "检测已完成，但临时密钥清理验证失败"
                : base.summary + "；临时密钥清理验证也失败";
        return unavailable(base.id, summary, mergedDetail, failure);
    }

    private static void appendCleanupFailure(StringBuilder out, String stage, String alias,
                                             Throwable failure) {
        out.append("\ncleanupFailure{stage=").append(stage);
        if (alias != null) out.append(", alias=").append(alias);
        out.append(", error=").append(describe(failure)).append('}');
        if (failure != null) {
            for (StackTraceElement frame : failure.getStackTrace()) {
                out.append("\n  at ").append(frame);
            }
        }
    }

    private static void throwIfInterrupted() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException("probe interrupted");
    }

    private static void restoreInterrupt(Throwable failure) {
        Throwable cursor = failure;
        for (int depth = 0; cursor != null && depth < 32; depth++) {
            if (cursor instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                return;
            }
            Throwable next = cursor.getCause();
            if (next == cursor) return;
            cursor = next;
        }
    }

    private static Result unavailable(String id, String summary, String detail, Throwable failure) {
        return new Result(id, SilentProbeEvidence.Status.UNAVAILABLE, summary, detail, failure);
    }

    private static Throwable unwrap(Throwable failure) {
        Throwable cursor = failure;
        if (cursor instanceof ProbeFailure && cursor.getCause() != null) cursor = cursor.getCause();
        while ((cursor instanceof InvocationTargetException
                || cursor instanceof java.util.concurrent.ExecutionException)
                && cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        return cursor;
    }

    private static String describe(Throwable failure) {
        if (failure == null) return "none";
        String message = failure.getMessage();
        return failure.getClass().getName()
                + (message == null || message.isEmpty() ? "" : ": " + message);
    }

    private static final class ProbeFailure extends RuntimeException {
        ProbeFailure(Throwable cause) { super(cause); }
    }

    private static final class CleanupOutcome {
        final boolean success;
        final String detail;
        final Throwable failure;

        CleanupOutcome(boolean success, String detail, Throwable failure) {
            this.success = success;
            this.detail = detail;
            this.failure = failure;
        }
    }

    private static final class LagObservation {
        final boolean attested;
        final long startedNanos;
        final long returnedNanos;
        final long visibleNanos;
        final long polls;
        final Throwable failure;

        LagObservation(boolean attested, long startedNanos, long returnedNanos,
                       long visibleNanos, long polls, Throwable failure) {
            this.attested = attested;
            this.startedNanos = startedNanos;
            this.returnedNanos = returnedNanos;
            this.visibleNanos = visibleNanos;
            this.polls = polls;
            this.failure = failure;
        }

        boolean usable() {
            return failure == null && startedNanos != 0L && returnedNanos >= startedNanos;
        }

        String unavailableReason() {
            if (failure != null) return describe(failure);
            return "invalid timestamps start=" + startedNanos + ", returned=" + returnedNanos;
        }

        double generationMillis() {
            return returnedNanos >= startedNanos && startedNanos != 0L
                    ? (returnedNanos - startedNanos) / 1_000_000.0 : Double.NaN;
        }

        double earlyGapMillis() {
            if (visibleNanos == 0L || returnedNanos <= visibleNanos) return 0.0;
            return (returnedNanos - visibleNanos) / 1_000_000.0;
        }
    }

    private static final class RawRead {
        final Object service;
        final Method method;
        final Map<String, Object> descriptors;

        private RawRead(Object service, Method method,
                        Map<String, Object> descriptors) {
            this.service = service;
            this.method = method;
            this.descriptors = descriptors;
        }

        static RawRead open(String... aliases) throws Exception {
            IBinder binder = keystore2Binder();
            if (binder == null) throw new IllegalStateException("Keystore2 service binder is null");

            Class<?> stubClass = Class.forName(
                    "android.system.keystore2.IKeystoreService$Stub");
            Method asInterface = stubClass.getDeclaredMethod("asInterface", IBinder.class);
            try {
                asInterface.setAccessible(true);
            } catch (Throwable ignored) {
                // Public framework methods remain invocable when accessibility cannot be relaxed.
            }
            Object service = asInterface.invoke(null, binder);
            if (service == null) throw new IllegalStateException("IKeystoreService is null");

            Method getKeyEntry = findMethod(service.getClass(), "getKeyEntry", 1);
            Class<?> descriptorClass = getKeyEntry.getParameterTypes()[0];
            Map<String, Object> descriptors = new HashMap<>();
            for (String alias : aliases) {
                Object descriptor = descriptorClass.getDeclaredConstructor().newInstance();
                writeField(descriptor, "domain", 0);
                writeField(descriptor, "nspace", -1L);
                writeField(descriptor, "alias", alias);
                writeField(descriptor, "blob", null);
                descriptors.put(alias, descriptor);
            }
            return new RawRead(service, getKeyEntry, descriptors);
        }

        void read(String alias) throws Throwable {
            Object descriptor = descriptors.get(alias);
            if (descriptor == null) throw new IllegalArgumentException("unknown alias " + alias);
            try {
                Object response = method.invoke(service, descriptor);
                if (response == null) throw new IllegalStateException("getKeyEntry returned null");
            } catch (InvocationTargetException failure) {
                throw unwrap(failure);
            }
        }
    }

    private static Method findMethod(Class<?> type, String name, int parameterCount)
            throws NoSuchMethodException {
        for (Method method : type.getMethods()) {
            if (name.equals(method.getName()) && method.getParameterCount() == parameterCount) {
                try {
                    method.setAccessible(true);
                } catch (Throwable ignored) {
                    // Public interface methods remain invocable without this optimization.
                }
                return method;
            }
        }
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) {
                if (name.equals(method.getName())
                        && method.getParameterCount() == parameterCount) {
                    try {
                        method.setAccessible(true);
                    } catch (Throwable ignored) {
                        // Invocation below will report a real access failure if access is required.
                    }
                    return method;
                }
            }
        }
        throw new NoSuchMethodException(type.getName() + "." + name + "/" + parameterCount);
    }

    private static void writeField(Object target, String name, Object value) throws Exception {
        Field field = null;
        for (Class<?> current = target.getClass(); current != null;
             current = current.getSuperclass()) {
            try {
                field = current.getDeclaredField(name);
                break;
            } catch (NoSuchFieldException ignored) {
                // Keep looking through the generated Parcelable's hierarchy.
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(target.getClass().getName() + "." + name);
        }
        try {
            field.setAccessible(true);
        } catch (Throwable ignored) {
            // Public Parcelable fields remain writable without relaxed accessibility.
        }
        field.set(target, value);
    }

    private static IBinder keystore2Binder() throws Exception {
        return Keystore2ProbeAccess.binder();
    }

}

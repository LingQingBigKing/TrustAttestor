package com.lingqing.trustattestor;

import android.annotation.TargetApi;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Keeps the app-zygote carrier bound while the watch stimulus and final drain run. */
final class ThroneHuntCarrierManager {
    private static final int SETUP = 2;
    private static final int DRAIN = 3;
    private static final int RESET = 4;
    private static final long BIND_TIMEOUT_MS = 2500L;
    // PackageManagerService defers settings writes by 10 seconds. Keep the inherited watch alive
    // through that hard delay and leave a bounded allowance for KernelSU's search_manager walk.
    private static final long SEARCH_WINDOW_MS = ThroneHuntStimulus.SETTINGS_WRITE_WINDOW_MS;
    private static final long DRAIN_INTERVAL_MS = 250L;

    private ThroneHuntCarrierManager() { }

    @TargetApi(Build.VERSION_CODES.S)
    static String runRound(Context context) {
        if (!supportsRetainedPreloadDescriptors(Build.VERSION.SDK_INT)) {
            return unsupported("payload", 0,
                    "retained app-zygote preload descriptors require Android 12+");
        }
        if (context == null) return unavailable("payload", 0, "context is null");
        Context applicationContext = context.getApplicationContext();
        Session session = new Session(applicationContext == null ? context : applicationContext);
        String currentStage = "carrier_bind";
        try {
            if (!session.bind()) return unavailable(currentStage, 0, session.bindProblem());
            currentStage = "watch_setup";
            ThroneHuntWatchSnapshot setup = ThroneHuntWatchSnapshot.parse(session.transact(SETUP));
            if (!setup.supported) {
                return unsupported(currentStage, setup.errno, setup.problem());
            }
            if (!setup.usable()) return unavailable(currentStage, setup.errno, setup.problem());

            currentStage = "baseline";
            ThroneHuntWatchSnapshot baseline = ThroneHuntWatchSnapshot.parse(session.transact(DRAIN));
            if (!baseline.supported) {
                return unsupported(currentStage, baseline.errno, baseline.problem());
            }
            if (!baseline.usable()) {
                return unavailable(currentStage, baseline.errno, baseline.problem())
                        + baseline.encode("BASELINE_");
            }

            currentStage = "stimulus";
            ThroneHuntStimulus.Result stimulus = ThroneHuntStimulus.run(context);
            if (!stimulus.applied || !stimulus.readback) {
                return unavailable(currentStage, 0, stimulus.detail)
                        + baseline.encode("BASELINE_");
            }

            currentStage = "final_drain";
            ThroneHuntWatchSnapshot finalDrain = collectFinalDrain(session);
            if (!finalDrain.supported) {
                return unsupported(currentStage, finalDrain.errno, finalDrain.problem());
            }
            if (!finalDrain.usable()) {
                return unavailable(currentStage, finalDrain.errno, finalDrain.problem())
                        + baseline.encode("BASELINE_")
                        + finalDrain.encode("FINAL_");
            }
            return "ROUND_SUPPORTED=1\nROUND_APPLICABLE=1\nROUND_AVAILABLE=1\n"
                    + "STAGE=final_drain\nERRNO=0\nROUND_ERRNO=0\n"
                    + "STIMULUS=1\nREADBACK=1\n"
                    + baseline.encode("BASELINE_")
                    + finalDrain.encode("FINAL_")
                    + "DETAIL=" + escape(stimulus.detail) + "\n";
        } catch (Throwable failure) {
            return unavailable(currentStage, 0, describeFailure(failure));
        } finally {
            try { session.transact(RESET); } catch (Throwable ignored) { }
            session.close();
        }
    }

    static boolean supportsRetainedPreloadDescriptors(int sdkInt) {
        return sdkInt >= Build.VERSION_CODES.S;
    }

    static long maximumPassiveWaitMillis() {
        return BIND_TIMEOUT_MS + SEARCH_WINDOW_MS;
    }

    private static ThroneHuntWatchSnapshot collectFinalDrain(Session session) throws Exception {
        ThroneHuntWatchSnapshot accumulated = new ThroneHuntWatchSnapshot();
        accumulated.installed = true;
        accumulated.descriptor = 0;
        long deadline = SystemClock.elapsedRealtime() + SEARCH_WINDOW_MS;
        do {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining > 0) {
                try {
                    Thread.sleep(Math.min(DRAIN_INTERVAL_MS, remaining));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("search window interrupted", interrupted);
                }
            }
            ThroneHuntWatchSnapshot drain =
                    ThroneHuntWatchSnapshot.parse(session.transact(DRAIN));
            accumulated.addEventCountsFrom(drain);
            accumulated.stage = drain.stage;
            accumulated.detail = drain.detail;
            if (!drain.supported || !drain.usable()) {
                accumulated.supported = drain.supported;
                accumulated.installed = drain.installed;
                accumulated.addDenied = drain.addDenied;
                accumulated.invalid = drain.invalid;
                accumulated.overflow = drain.overflow;
                accumulated.gone = drain.gone;
                accumulated.descriptor = drain.descriptor;
                accumulated.errno = drain.errno;
                return accumulated;
            }
            if (accumulated.signalObserved()) break;
        } while (SystemClock.elapsedRealtime() < deadline);
        return accumulated;
    }

    private static String unsupported(String stage, int errno, String detail) {
        return roundStatus(false, false, stage, errno, detail);
    }

    private static String unavailable(String stage, int errno, String detail) {
        return roundStatus(true, false, stage, errno, detail);
    }

    private static String roundStatus(boolean supported, boolean available,
                                      String stage, int errno, String detail) {
        String safeStage = stage == null || stage.isEmpty() ? "payload" : stage;
        String message = safeStage
                + ": " + (detail == null ? "" : detail);
        return "ROUND_SUPPORTED=" + (supported ? "1" : "0") + "\n"
                + "ROUND_APPLICABLE=" + (supported ? "1" : "0") + "\n"
                + "ROUND_AVAILABLE=" + (available ? "1" : "0") + "\n"
                + "STAGE=" + escape(safeStage) + "\n"
                + "ERRNO=" + Math.max(0, errno) + "\n"
                + "ROUND_ERRNO=" + Math.max(0, errno) + "\n"
                + "STIMULUS=0\nREADBACK=0\nDETAIL=" + escape(message) + "\n";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String describeFailure(Throwable failure) {
        if (failure == null) return "unknown failure";
        StringBuilder description = new StringBuilder();
        Throwable cursor = failure;
        for (int depth = 0; cursor != null && depth < 3; depth++, cursor = cursor.getCause()) {
            if (description.length() > 0) description.append(" <- ");
            description.append(cursor.getClass().getSimpleName());
            String message = cursor.getMessage();
            if (message != null && !message.isEmpty()) description.append(": ").append(message);
        }
        return description.toString();
    }

    private static final class Session {
        private final Context context;
        private final CountDownLatch connected = new CountDownLatch(1);
        private volatile IBinder binder;
        private volatile boolean bound;
        private volatile String bindProblem = "binding was not attempted";
        private final ServiceConnection connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                binder = service;
                bindProblem = service == null
                        ? "onServiceConnected returned a null binder"
                        : "connected to " + component(name);
                connected.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name) {
                binder = null;
                bindProblem = "service disconnected: " + component(name);
                connected.countDown();
            }
            @Override public void onBindingDied(ComponentName name) {
                binder = null;
                bindProblem = "binding died: " + component(name);
                connected.countDown();
            }
            @Override public void onNullBinding(ComponentName name) {
                binder = null;
                bindProblem = "service returned a null binding: " + component(name);
                connected.countDown();
            }
        };

        Session(Context context) { this.context = context; }

        @TargetApi(Build.VERSION_CODES.S)
        boolean bind() {
            String instance = "throne" + Long.toHexString(System.nanoTime())
                    + UUID.randomUUID().toString().replace("-", "");
            try {
                bound = context.bindIsolatedService(
                        new Intent().setComponent(new ComponentName(
                                context.getPackageName(), TrustAttestorService.class.getName())),
                        Context.BIND_AUTO_CREATE, instance, context.getMainExecutor(), connection);
            } catch (Throwable failure) {
                bindProblem = "bindIsolatedService threw " + describeFailure(failure);
                return false;
            }
            if (!bound) {
                bindProblem = "bindIsolatedService returned false";
                return false;
            }
            final boolean signalled;
            try {
                signalled = connected.await(BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                bindProblem = "interrupted while waiting for service connection";
                return false;
            }
            if (!signalled) {
                bindProblem = "service connection timed out after " + BIND_TIMEOUT_MS + " ms";
                return false;
            }
            if (binder == null && (bindProblem == null || bindProblem.isEmpty())) {
                bindProblem = "service connection completed without a binder";
            }
            return binder != null;
        }

        String bindProblem() { return bindProblem; }

        String transact(int code) throws Exception {
            IBinder service = binder;
            if (service == null) {
                throw new IllegalStateException(transactionName(code)
                        + " cannot run because carrier binder is null (" + bindProblem + ")");
            }
            if (!service.isBinderAlive()) {
                throw new IllegalStateException(transactionName(code) + " carrier binder is dead");
            }
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                if (!service.transact(code, data, reply, 0)) {
                    throw new IllegalStateException(transactionName(code)
                            + " carrier transaction was not handled");
                }
                String payload = reply.readString();
                if (payload == null || payload.isEmpty()) {
                    throw new IllegalStateException(transactionName(code)
                            + " carrier transaction returned an empty payload");
                }
                return payload;
            } finally {
                data.recycle();
                reply.recycle();
            }
        }

        void close() {
            if (!bound) return;
            bound = false;
            try { context.unbindService(connection); } catch (Throwable ignored) { }
        }

        private static String component(ComponentName name) {
            return name == null ? "unknown component" : name.flattenToShortString();
        }

        private static String transactionName(int code) {
            return switch (code) {
                case SETUP -> "setup";
                case DRAIN -> "drain";
                case RESET -> "reset";
                default -> "transaction " + code;
            };
        }
    }
}


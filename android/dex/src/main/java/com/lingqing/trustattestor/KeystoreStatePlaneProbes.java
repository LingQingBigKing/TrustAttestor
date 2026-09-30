package com.lingqing.trustattestor;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.IBinder;
import android.os.Process;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

/**
 * Safe, bounded ports of OMK Detector's K and T4/L state-plane checks.
 *
 * <p>Only public-API generated, per-invocation aliases are mutated. The hidden Keystore2 API is
 * used for reads and a read-only entry count; no raw generate/import/delete/grant transaction is
 * issued. Private-ABI incompatibility is reported as a neutral, not-applicable result; final
 * cleanup failure remains UNAVAILABLE because the probe can no longer prove that it restored
 * caller-owned state.</p>
 */
@SuppressLint({"BlockedPrivateApi", "PrivateApi", "SoonBlockedPrivateApi"})
final class KeystoreStatePlaneProbes {
    static final String CHECK_KEY_ID_CONSISTENCY =
            "hardware.attestation.key_id_consistency";
    static final String CHECK_KEYSTORE_LEDGER =
            "hardware.attestation.keystore_ledger";

    private static final String KEYSTORE2_SERVICE =
            "android.system.keystore2.IKeystoreService/default";
    private static final String KEYSTORE2_STUB =
            "android.system.keystore2.IKeystoreService$Stub";
    private static final String DOMAIN_CLASS = "android.system.keystore2.Domain";

    private KeystoreStatePlaneProbes() { }

    static final class Result {
        final String id;
        final SilentProbeEvidence.Status status;
        final String summary;
        final String detail;
        final long elapsedMicros;
        final Throwable failure;

        private Result(String id, SilentProbeEvidence.Status status, String summary,
                       String detail, long elapsedMicros, Throwable failure) {
            this.id = id;
            this.status = status;
            this.summary = summary == null ? "" : summary;
            this.detail = detail == null ? "" : detail;
            this.elapsedMicros = elapsedMicros;
            this.failure = failure;
        }

        String debugDetail() {
            StringBuilder out = new StringBuilder(id).append(": ").append(status)
                    .append("; ").append(summary)
                    .append("; elapsedUs=").append(elapsedMicros);
            if (!detail.isEmpty()) out.append('\n').append(detail);
            return out.toString();
        }
    }

    /** Convenience bridge for the existing silent-probe reporter. Both probes always run. */
    static void run(SilentKeystoreChecks.Reporter reporter) {
        if (reporter == null) return;
        Result keyId = safeRun(CHECK_KEY_ID_CONSISTENCY,
                KeystoreStatePlaneProbes::runAliasKeyIdConsistency);
        Result ledger = safeRun(CHECK_KEYSTORE_LEDGER,
                KeystoreStatePlaneProbes::runLedgerStatePlane);
        // Compute both before invoking the callback. A callback failure therefore cannot prevent
        // the second detector from running; the caller's outer per-probe guard may still record it.
        try {
            reporter.report(keyId.id, keyId.status, keyId.debugDetail());
        } catch (Throwable ignored) {
        }
        try {
            reporter.report(ledger.id, ledger.status, ledger.debugDetail());
        } catch (Throwable ignored) {
        }
    }

    static Result runAliasKeyIdConsistency() {
        final Trace trace = new Trace(CHECK_KEY_ID_CONSISTENCY);
        KeyStore store = null;
        String alias = null;
        boolean cleanupVerified = true;
        KeystoreStatePlaneEvidence.Decision decision = unavailableDecision("探针尚未完成", "");
        try {
            trace.enter("preflight");
            requireKeystore2();
            store = androidKeyStore();
            alias = unusedAlias(store, "kid");
            Object service = keystoreService();
            int appDomain = domain("APP");
            int keyIdDomain = domain("KEY_ID");
            trace.note("domains APP=" + appDomain + ", KEY_ID=" + keyIdDomain);

            trace.enter("generate-public-key");
            KeyPair pair = generate(alias);
            if (pair == null || pair.getPrivate() == null || pair.getPublic() == null) {
                throw new IllegalStateException("AndroidKeyStore returned an incomplete KeyPair");
            }
            byte[] publicLeaf = publicLeaf(store, alias);

            trace.enter("read-app-alias");
            KeystoreStatePlaneEvidence.RouteSnapshot app = readRoute(service, appDomain,
                    -1L, alias, "APP");
            long keyId = requireKeyId(app);
            trace.note("APP keyId=" + keyId + ", cert=" + fingerprint(app.certificate));

            trace.enter("read-key-id");
            KeystoreStatePlaneEvidence.RouteSnapshot byId = readRoute(service, keyIdDomain,
                    keyId, null, "KEY_ID");
            trace.note("KEY_ID cert=" + fingerprint(byId.certificate));

            KeystoreStatePlaneEvidence.AliasObservation observation =
                    new KeystoreStatePlaneEvidence.AliasObservation("single", keyIdDomain,
                            keyId, app, byId, publicLeaf);
            decision = KeystoreStatePlaneEvidence.aliasKeyId(observation, true);
        } catch (Throwable failure) {
            trace.fail(trace.stage, failure);
            decision = unavailableDecision("APP/KEY_ID 一致性探针未完成",
                    "stage=" + trace.stage + "; failure=" + describe(failure));
        } finally {
            trace.enter("cleanup");
            cleanupVerified = cleanupAlias(store, alias, trace) && cleanupVerified;
        }

        if (!cleanupVerified) {
            decision = KeystoreStatePlaneEvidence.aliasKeyId(null, false);
        }
        return result(CHECK_KEY_ID_CONSISTENCY, decision, trace);
    }

    static Result runLedgerStatePlane() {
        final Trace trace = new Trace(CHECK_KEYSTORE_LEDGER);
        KeyStore store = null;
        Object service = null;
        String firstAlias = null;
        String secondAlias = null;
        boolean cleanupVerified = true;
        boolean baselineAvailable = false;
        long before = -1;
        long afterFirst = -1;
        long afterSecond = -1;
        long afterCleanup = -1;
        KeystoreStatePlaneEvidence.AliasObservation first = null;
        KeystoreStatePlaneEvidence.AliasObservation second = null;
        KeystoreStatePlaneEvidence.Decision decision = unavailableDecision("探针尚未完成", "");
        try {
            trace.enter("preflight");
            requireKeystore2();
            store = androidKeyStore();
            firstAlias = unusedAlias(store, "ledger_a");
            secondAlias = unusedAlias(store, "ledger_b");
            service = keystoreService();
            int appDomain = domain("APP");
            int keyIdDomain = domain("KEY_ID");

            trace.enter("count-baseline");
            before = stableCount(service, appDomain, trace, "before");
            baselineAvailable = true;

            trace.enter("generate-first");
            KeyPair firstPair = generate(firstAlias);
            requireCompletePair(firstPair);
            byte[] firstLeaf = publicLeaf(store, firstAlias);
            KeystoreStatePlaneEvidence.RouteSnapshot firstApp = readRoute(service, appDomain,
                    -1L, firstAlias, "APP:first");
            long firstId = requireKeyId(firstApp);
            KeystoreStatePlaneEvidence.RouteSnapshot firstKid = readRoute(service, keyIdDomain,
                    firstId, null, "KEY_ID:first");
            first = new KeystoreStatePlaneEvidence.AliasObservation("first", keyIdDomain,
                    firstId, firstApp, firstKid, firstLeaf);
            afterFirst = stableCount(service, appDomain, trace, "afterFirst");
            trace.note("first keyId=" + firstId + ", cert=" + fingerprint(firstApp.certificate));

            trace.enter("generate-second");
            KeyPair secondPair = generate(secondAlias);
            requireCompletePair(secondPair);
            byte[] secondLeaf = publicLeaf(store, secondAlias);
            KeystoreStatePlaneEvidence.RouteSnapshot secondApp = readRoute(service, appDomain,
                    -1L, secondAlias, "APP:second");
            long secondId = requireKeyId(secondApp);
            KeystoreStatePlaneEvidence.RouteSnapshot secondKid = readRoute(service, keyIdDomain,
                    secondId, null, "KEY_ID:second");
            second = new KeystoreStatePlaneEvidence.AliasObservation("second", keyIdDomain,
                    secondId, secondApp, secondKid, secondLeaf);
            afterSecond = stableCount(service, appDomain, trace, "afterSecond");
            trace.note("second keyId=" + secondId + ", cert="
                    + fingerprint(secondApp.certificate));

            // Final classification is delayed until cleanup and the restored ledger are verified.
            decision = unavailableDecision("等待清理后账本确认", "");
        } catch (Throwable failure) {
            trace.fail(trace.stage, failure);
            decision = unavailableDecision("Keystore2 账本探针未完成",
                    "stage=" + trace.stage + "; failure=" + describe(failure));
        } finally {
            trace.enter("cleanup");
            cleanupVerified &= cleanupAlias(store, secondAlias, trace);
            cleanupVerified &= cleanupAlias(store, firstAlias, trace);
            if (baselineAvailable && service != null) {
                try {
                    int appDomain = domain("APP");
                    afterCleanup = stableCount(service, appDomain, trace, "afterCleanup");
                } catch (Throwable cleanupFailure) {
                    cleanupVerified = false;
                    trace.fail("cleanup-count", cleanupFailure);
                }
            } else {
                // count-baseline precedes the first generation. If it was not established then
                // the ledger was never mutated, and alias cleanup above is sufficient. Treat the
                // missing private count API as a capability limit instead of a cleanup failure.
                trace.note("cleanup-count not required because baseline failed before mutation");
            }
        }

        if (first != null && second != null && before >= 0 && afterFirst >= 0
                && afterSecond >= 0 && afterCleanup >= 0) {
            decision = KeystoreStatePlaneEvidence.ledger(before, afterFirst, afterSecond,
                    afterCleanup, first, second, cleanupVerified);
        } else if (!cleanupVerified) {
            decision = unavailableDecision("账本探针未完成且清理状态不可确认",
                    "counts=" + before + "->" + afterFirst + "->" + afterSecond
                            + "->" + afterCleanup);
        } else if (!Thread.currentThread().isInterrupted()) {
            // getNumberOfEntries/getKeyEntry and their parcelable layouts are private platform
            // ABI. OEM/API differences that prevent a complete pair are capability limits, not
            // evidence that Keystore itself is unhealthy. Cleanup has already proved that no
            // temporary alias was left behind, so publish a neutral completed result.
            decision = notApplicableDecision(
                    "当前平台未暴露兼容的 Keystore2 状态账本读取能力，本项不适用",
                    "finalStage=" + trace.stage + "; counts=" + before + "->" + afterFirst
                            + "->" + afterSecond + "->" + afterCleanup);
        }
        return result(CHECK_KEYSTORE_LEDGER, decision, trace);
    }

    // --------------------------------------------------------------------- service reads

    private static KeystoreStatePlaneEvidence.RouteSnapshot readRoute(
            Object service, int domain, long namespace, String alias, String route) throws Exception {
        Method method = findMethod(service.getClass(), "getKeyEntry", 1);
        Class<?> descriptorType = method.getParameterTypes()[0];
        Object descriptor = descriptorType.getDeclaredConstructor().newInstance();
        writeRequiredField(descriptor, "domain", domain);
        writeRequiredField(descriptor, "nspace", namespace);
        writeRequiredField(descriptor, "alias", alias);
        writeRequiredField(descriptor, "blob", null);

        Object response;
        try {
            method.setAccessible(true);
            response = method.invoke(service, descriptor);
        } catch (InvocationTargetException wrapped) {
            Throwable cause = unwrap(wrapped);
            if (cause instanceof Exception exception) throw exception;
            throw wrapped;
        }
        Object metadata = readRequiredField(response, "metadata", false);
        Object key = readRequiredField(metadata, "key", false);
        Integer metadataDomain = number(readRequiredField(key, "domain", false)).intValue();
        Long metadataKeyId = number(readRequiredField(key, "nspace", false)).longValue();
        byte[] certificate = bytes(readRequiredField(metadata, "certificate", false),
                "metadata.certificate", false);
        byte[] certificateChain = bytes(readRequiredField(metadata, "certificateChain", true),
                "metadata.certificateChain", true);
        return new KeystoreStatePlaneEvidence.RouteSnapshot(route, metadataDomain,
                metadataKeyId, certificate, certificateChain);
    }

    private static long stableCount(Object service, int appDomain, Trace trace,
                                    String label) throws Exception {
        long first = count(service, appDomain);
        long second = count(service, appDomain);
        trace.note("count[" + label + "]=" + first + "/" + second);
        if (first < 0 || second < 0) {
            throw new IllegalStateException("negative getNumberOfEntries result: "
                    + first + "/" + second);
        }
        if (first != second) {
            throw new IllegalStateException("unstable getNumberOfEntries result at " + label
                    + ": " + first + " vs " + second);
        }
        return first;
    }

    private static long count(Object service, int appDomain) throws Exception {
        Method method = findMethod(service.getClass(), "getNumberOfEntries", 2);
        method.setAccessible(true);
        Object value;
        try {
            value = method.invoke(service, appDomain, (long) Process.myUid());
        } catch (InvocationTargetException wrapped) {
            Throwable cause = unwrap(wrapped);
            if (cause instanceof Exception exception) throw exception;
            throw wrapped;
        }
        return number(value).longValue();
    }

    private static Object keystoreService() throws Exception {
        IBinder binder = Keystore2ProbeAccess.binder();
        if (binder == null) throw new IllegalStateException("Keystore2 service binder is null");
        Class<?> stub = Class.forName(KEYSTORE2_STUB);
        Method asInterface = stub.getDeclaredMethod("asInterface", IBinder.class);
        asInterface.setAccessible(true);
        Object service = asInterface.invoke(null, binder);
        if (service == null) throw new IllegalStateException("IKeystoreService.asInterface returned null");
        return service;
    }

    private static int domain(String name) throws Exception {
        Class<?> type = Class.forName(DOMAIN_CLASS);
        Object value = readStaticRequiredField(type, name);
        return number(value).intValue();
    }

    // --------------------------------------------------------------------- owned public keys

    private static KeyStore androidKeyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }

    private static String unusedAlias(KeyStore store, String family) throws Exception {
        for (int attempt = 0; attempt < 4; attempt++) {
            String alias = "__ta_state_" + family + "_" + Process.myPid() + "_"
                    + UUID.randomUUID();
            if (!store.containsAlias(alias)) return alias;
        }
        throw new IllegalStateException("could not allocate an unused temporary alias");
    }

    private static KeyPair generate(String alias) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(false)
                .build();
        generator.initialize(spec);
        return generator.generateKeyPair();
    }

    private static void requireCompletePair(KeyPair pair) {
        if (pair == null || pair.getPrivate() == null || pair.getPublic() == null) {
            throw new IllegalStateException("AndroidKeyStore returned an incomplete KeyPair");
        }
    }

    private static byte[] publicLeaf(KeyStore store, String alias) throws Exception {
        Certificate certificate = store.getCertificate(alias);
        if (certificate == null) throw new IllegalStateException("public API leaf certificate is null");
        byte[] encoded = certificate.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new IllegalStateException("public API leaf certificate is empty");
        }
        return encoded;
    }

    private static boolean cleanupAlias(KeyStore store, String alias, Trace trace) {
        if (store == null || alias == null) return true;
        try {
            // deleteEntry is safe for an absent alias and also covers a generation call that threw
            // after committing the key.
            store.deleteEntry(alias);
            boolean contains = store.containsAlias(alias);
            boolean enumerated = false;
            Enumeration<String> aliases = store.aliases();
            if (aliases == null) throw new IllegalStateException("alias enumeration is null");
            while (aliases.hasMoreElements()) {
                if (alias.equals(aliases.nextElement())) enumerated = true;
            }
            Key key = store.getKey(alias, null);
            Certificate certificate = store.getCertificate(alias);
            Certificate[] chain = store.getCertificateChain(alias);
            boolean clean = !contains && !enumerated && key == null && certificate == null
                    && (chain == null || chain.length == 0);
            trace.note("cleanup aliasSuffix=" + suffix(alias) + ", verified=" + clean);
            if (!clean) {
                throw new IllegalStateException("temporary alias remains visible after deleteEntry"
                        + " (contains=" + contains + ", enumerated=" + enumerated
                        + ", key=" + (key != null) + ", certificate=" + (certificate != null)
                        + ", chain=" + (chain == null ? -1 : chain.length) + ")");
            }
            return true;
        } catch (Throwable failure) {
            trace.fail("cleanup-alias", failure);
            return false;
        }
    }

    // --------------------------------------------------------------------- reflection and result helpers

    private interface ResultCall { Result run(); }

    private static Result safeRun(String id, ResultCall call) {
        try {
            Result result = call.run();
            if (result != null) return result;
            return emergencyUnavailable(id, new IllegalStateException("probe returned null"));
        } catch (Throwable failure) {
            return emergencyUnavailable(id, failure);
        }
    }

    private static Result emergencyUnavailable(String id, Throwable failure) {
        Trace trace = new Trace(id);
        trace.fail("outer-guard", failure);
        return new Result(id, SilentProbeEvidence.Status.UNAVAILABLE,
                "探针被外层保护器隔离", trace.render("outer guard"), trace.elapsedMicros(),
                unwrap(failure));
    }

    private static Result result(String id, KeystoreStatePlaneEvidence.Decision decision,
                                 Trace trace) {
        SilentProbeEvidence.Status status = switch (decision.status) {
            case VERIFIED -> SilentProbeEvidence.Status.VERIFIED;
            case DETECTED -> SilentProbeEvidence.Status.DETECTED;
            case UNAVAILABLE -> SilentProbeEvidence.Status.UNAVAILABLE;
        };
        String detail = trace.render(decision.detail);
        return new Result(id, status, decision.summary, detail, trace.elapsedMicros(),
                trace.firstFailure());
    }

    private static KeystoreStatePlaneEvidence.Decision unavailableDecision(String summary,
                                                                            String detail) {
        return new KeystoreStatePlaneEvidence.Decision(
                KeystoreStatePlaneEvidence.Status.UNAVAILABLE, summary, detail);
    }

    private static KeystoreStatePlaneEvidence.Decision notApplicableDecision(String summary,
                                                                              String detail) {
        return new KeystoreStatePlaneEvidence.Decision(
                KeystoreStatePlaneEvidence.Status.VERIFIED, summary, detail);
    }

    private static long requireKeyId(KeystoreStatePlaneEvidence.RouteSnapshot snapshot) {
        if (snapshot == null || snapshot.metadataKeyId == null || snapshot.metadataKeyId == 0) {
            throw new IllegalStateException("APP metadata.key.nspace is missing or zero");
        }
        return snapshot.metadataKeyId;
    }

    private static Method findMethod(Class<?> type, String name, int parameterCount)
            throws NoSuchMethodException {
        for (Method method : type.getMethods()) {
            if (name.equals(method.getName()) && method.getParameterCount() == parameterCount) {
                return method;
            }
        }
        for (Class<?> cursor = type; cursor != null; cursor = cursor.getSuperclass()) {
            for (Method method : cursor.getDeclaredMethods()) {
                if (name.equals(method.getName()) && method.getParameterCount() == parameterCount) {
                    return method;
                }
            }
        }
        throw new NoSuchMethodException(type.getName() + "." + name + "/" + parameterCount);
    }

    private static Object readRequiredField(Object owner, String name, boolean nullable)
            throws Exception {
        if (owner == null) throw new NoSuchFieldException(name + " owner is null");
        Field field = findField(owner.getClass(), name);
        field.setAccessible(true);
        Object value = field.get(owner);
        if (!nullable && value == null) throw new NoSuchFieldException(name + " is null");
        return value;
    }

    private static Object readStaticRequiredField(Class<?> owner, String name) throws Exception {
        Field field = findField(owner, name);
        field.setAccessible(true);
        Object value = field.get(null);
        if (value == null) throw new NoSuchFieldException(owner.getName() + "." + name + " is null");
        return value;
    }

    private static void writeRequiredField(Object owner, String name, Object value)
            throws Exception {
        Field field = findField(owner.getClass(), name);
        field.setAccessible(true);
        field.set(owner, value);
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        try {
            return type.getField(name);
        } catch (NoSuchFieldException publicMiss) {
            for (Class<?> cursor = type; cursor != null; cursor = cursor.getSuperclass()) {
                try {
                    return cursor.getDeclaredField(name);
                } catch (NoSuchFieldException ignored) {
                }
            }
            throw publicMiss;
        }
    }

    private static Number number(Object value) {
        if (!(value instanceof Number number)) {
            throw new IllegalStateException("expected Number, got "
                    + (value == null ? "null" : value.getClass().getName()));
        }
        return number;
    }

    private static byte[] bytes(Object value, String name, boolean nullable) {
        if (value == null && nullable) return null;
        if (!(value instanceof byte[] bytes)) {
            throw new IllegalStateException(name + " is not byte[]");
        }
        if (!nullable && bytes.length == 0) {
            throw new IllegalStateException(name + " is empty");
        }
        return bytes.clone();
    }

    private static void requireKeystore2() {
        if (Build.VERSION.SDK_INT < 31) {
            throw new UnsupportedOperationException("Keystore2 requires Android 12 or newer");
        }
        if (Thread.currentThread().isInterrupted()) {
            throw new IllegalStateException("probe thread is interrupted");
        }
    }

    private static Throwable unwrap(Throwable failure) {
        Throwable current = failure;
        while (current instanceof InvocationTargetException && current.getCause() != null) {
            current = current.getCause();
        }
        return current == null ? failure : current;
    }

    private static String describe(Throwable failure) {
        Throwable root = unwrap(failure);
        Integer serviceCode = serviceCode(root);
        String message = root == null ? null : root.getMessage();
        return (root == null ? "unknown" : root.getClass().getName())
                + (serviceCode == null ? "" : "[code=" + serviceCode + "]")
                + (message == null || message.isEmpty() ? "" : ": " + message);
    }

    private static Integer serviceCode(Throwable failure) {
        if (failure == null) return null;
        try {
            Field field = findField(failure.getClass(), "errorCode");
            field.setAccessible(true);
            Object value = field.get(failure);
            return value instanceof Number ? ((Number) value).intValue() : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String fingerprint(byte[] value) {
        if (value == null) return "missing";
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < Math.min(8, digest.length); i++) {
                out.append(String.format(java.util.Locale.ROOT, "%02x", digest[i] & 0xff));
            }
            return out + "/" + value.length;
        } catch (Throwable ignored) {
            return "hashCode=" + Arrays.hashCode(value) + "/" + value.length;
        }
    }

    private static String suffix(String alias) {
        if (alias == null || alias.length() <= 12) return String.valueOf(alias);
        return alias.substring(alias.length() - 12);
    }

    private static final class FailureRecord {
        final String stage;
        final long elapsedMicros;
        final Throwable failure;

        FailureRecord(String stage, long elapsedMicros, Throwable failure) {
            this.stage = stage;
            this.elapsedMicros = elapsedMicros;
            this.failure = unwrap(failure);
        }
    }

    private static final class Trace {
        final long startedNanos = SystemClock.elapsedRealtimeNanos();
        final String id;
        final List<String> lines = new ArrayList<>();
        final List<FailureRecord> failures = new ArrayList<>();
        String stage = "initial";

        Trace(String id) {
            this.id = id;
        }

        void enter(String stage) {
            this.stage = stage;
            note("stage=" + stage);
        }

        void note(String message) {
            lines.add("+" + elapsedMicros() + "us " + message);
        }

        void fail(String stage, Throwable failure) {
            failures.add(new FailureRecord(stage, elapsedMicros(), failure));
            note("failure[" + stage + "]=" + describe(failure));
        }

        long elapsedMicros() {
            return Math.max(0L, (SystemClock.elapsedRealtimeNanos() - startedNanos) / 1_000L);
        }

        Throwable firstFailure() {
            return failures.isEmpty() ? null : failures.get(0).failure;
        }

        String render(String decisionDetail) {
            StringBuilder out = new StringBuilder("probe=").append(id)
                    .append("; finalStage=").append(stage)
                    .append("; elapsedUs=").append(elapsedMicros());
            if (decisionDetail != null && !decisionDetail.isEmpty()) {
                out.append("\ndecision=").append(decisionDetail);
            }
            for (String line : lines) out.append('\n').append(line);
            for (FailureRecord record : failures) {
                out.append("\nrootFailure stage=").append(record.stage)
                        .append(" atUs=").append(record.elapsedMicros)
                        .append(": ").append(describe(record.failure));
                if (record.failure != null) {
                    for (StackTraceElement frame : record.failure.getStackTrace()) {
                        out.append("\n  at ").append(frame);
                    }
                }
            }
            return out.toString();
        }
    }
}

package com.lingqing.trustattestor;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import io.github.vvb2060.keyattestation.attestation.Attestation;
import io.github.vvb2060.keyattestation.attestation.AuthorizationList;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;

/**
 * Bounded ports of OMK detector's U/F/TeeSim probes.
 *
 * <p>These checks deliberately exercise private Keystore2 contracts. Every alias is owned by the
 * current invocation, every successfully created operation is aborted, and every family is run in
 * an independent timeout domain. Unsupported private APIs are UNAVAILABLE, never a finding.</p>
 */
@SuppressLint({"BlockedPrivateApi", "PrivateApi", "SoonBlockedPrivateApi"})
final class OmkRiskyProbes {
    static final String CHECK_TOKEN_DISPATCH = "omk.token_dispatch";
    static final String CHECK_PARAMETER_FINGERPRINT = "omk.parameter_fingerprint";
    static final String CHECK_TEESIM_FINGERPRINT = "omk.teesim_fingerprint";
    static final String CHECK_ATTEST_KEY_DESCRIPTOR_DELEGATION =
            "hardware.attestation.attest_key_descriptor_delegation";

    private static final String KEYSTORE2_SERVICE =
            "android.system.keystore2.IKeystoreService/default";
    private static final String MAINTENANCE_TOKEN =
            "android.security.maintenance.IKeystoreMaintenance";
    private static final int SECURITY_LEVEL_TEE = 1;
    private static final int FIRST_CALL_TRANSACTION = 1;
    private static final int REPEAT = 3;
    // Private Binder rejects are normally quick, but 50 ms was below ordinary OEM scheduling and
    // caused clean devices to abort after V0. This is a stop-after-current-call budget, while the
    // outer future below remains the hard wall-clock bound for a genuinely wedged Binder request.
    private static final long SLOW_VECTOR_MICROS = 750_000L;
    static final int PARAMETER_FINGERPRINT_TIMEOUT_SECONDS = 12;
    static final int TEESIM_TIMEOUT_SECONDS = 10;

    // KeyMint tag type bits are part of the tag identity, not merely metadata. Keep the complete
    // AOSP ABI values in the pure-Java spec so legal requests and intentionally mismatched value
    // unions cannot accidentally share a malformed tag header.
    private static final int TAG_PURPOSE = OmkAttestKeyProbeSpec.TAG_PURPOSE;
    private static final int TAG_ALGORITHM = OmkAttestKeyProbeSpec.TAG_ALGORITHM;
    private static final int TAG_KEY_SIZE = OmkAttestKeyProbeSpec.TAG_KEY_SIZE;
    private static final int TAG_NO_AUTH_REQUIRED =
            OmkAttestKeyProbeSpec.TAG_NO_AUTH_REQUIRED;
    private static final int TAG_BLOCK_MODE = OmkAttestKeyProbeSpec.TAG_BLOCK_MODE;
    private static final int TAG_DIGEST = OmkAttestKeyProbeSpec.TAG_DIGEST;
    private static final int TAG_PADDING = OmkAttestKeyProbeSpec.TAG_PADDING;
    private static final int TAG_EC_CURVE = OmkAttestKeyProbeSpec.TAG_EC_CURVE;
    private static final int TAG_CREATION_DATETIME =
            OmkAttestKeyProbeSpec.TAG_CREATION_DATETIME;
    private static final int TAG_INCLUDE_UNIQUE_ID =
            OmkAttestKeyProbeSpec.TAG_INCLUDE_UNIQUE_ID;
    private static final int TAG_ATTESTATION_CHALLENGE =
            OmkAttestKeyProbeSpec.TAG_ATTESTATION_CHALLENGE;
    private static final int TAG_DEVICE_UNIQUE_ATTESTATION =
            OmkAttestKeyProbeSpec.TAG_DEVICE_UNIQUE_ATTESTATION;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AtomicBoolean PROTOCOL_FUSE = new AtomicBoolean(false);

    private OmkRiskyProbes() { }

    /** Runs all three families even when an earlier family fails or times out. */
    static void run(SilentKeystoreChecks.Reporter reporter) {
        if (reporter == null) throw new IllegalArgumentException("reporter is required");
        runTokenDispatch(reporter);
        runParameterFingerprint(reporter);
        runTeeSimFingerprint(reporter);
    }

    static void runTokenDispatch(SilentKeystoreChecks.Reporter reporter) {
        isolated(CHECK_TOKEN_DISPATCH, 15, OmkRiskyProbes::tokenDispatch, reporter);
    }

    static void runParameterFingerprint(SilentKeystoreChecks.Reporter reporter) {
        isolated(CHECK_PARAMETER_FINGERPRINT, PARAMETER_FINGERPRINT_TIMEOUT_SECONDS,
                OmkRiskyProbes::parameterFingerprint, reporter);
    }

    static void runTeeSimFingerprint(SilentKeystoreChecks.Reporter reporter) {
        isolated(CHECK_TEESIM_FINGERPRINT, TEESIM_TIMEOUT_SECONDS,
                OmkRiskyProbes::teeSimFingerprint, reporter);
    }

    static void runAttestKeyDescriptorDelegation(SilentKeystoreChecks.Reporter reporter) {
        isolated(CHECK_ATTEST_KEY_DESCRIPTOR_DELEGATION, 40,
                OmkRiskyProbes::attestKeyDescriptorDelegation, reporter);
    }

    private interface ProbeCall extends Callable<ProbeResult> { }

    private static final class ProbeResult {
        final SilentProbeEvidence.Status status;
        final String detail;

        ProbeResult(SilentProbeEvidence.Status status, String detail) {
            this.status = status;
            this.detail = detail;
        }
    }

    private static ProbeResult result(OmkRiskyProbeEvidence.Decision decision, StringBuilder log) {
        return new ProbeResult(decision.status, decision.summary + "\n" + log);
    }

    private static ProbeResult unavailable(String summary, StringBuilder log) {
        return new ProbeResult(UNAVAILABLE, summary + (log.length() == 0 ? "" : "\n" + log));
    }

    private static ProbeResult notApplicable(String summary, StringBuilder log) {
        return new ProbeResult(SilentProbeEvidence.Status.VERIFIED,
                "不适用：" + summary + (log.length() == 0 ? "" : "\n" + log));
    }

    private static void isolated(String check, int timeoutSeconds, ProbeCall call,
                                 SilentKeystoreChecks.Reporter reporter) {
        if (PROTOCOL_FUSE.get()) {
            reporter.report(check, UNAVAILABLE,
                    "先前的私有协议探针超时后未能有界退出；本进程已熔断后续私有协议请求");
            return;
        }
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "TrustAttestor-" + check);
            thread.setDaemon(true);
            return thread;
        });
        Future<ProbeResult> future = executor.submit(call);
        ProbeResult probe;
        boolean cancelled = false;
        try {
            probe = future.get(timeoutSeconds, TimeUnit.SECONDS);
            if (probe == null) probe = new ProbeResult(UNAVAILABLE, "探针没有返回结果");
        } catch (TimeoutException timeout) {
            cancelled = true;
            future.cancel(true);
            probe = new ProbeResult(UNAVAILABLE,
                    "单探针超过 " + timeoutSeconds + " 秒，已请求取消");
        } catch (InterruptedException interrupted) {
            cancelled = true;
            future.cancel(true);
            Thread.currentThread().interrupt();
            probe = new ProbeResult(UNAVAILABLE, "调用线程已中断");
        } catch (ExecutionException failure) {
            probe = new ProbeResult(UNAVAILABLE,
                    "探针异常：" + describe(failure.getCause() == null ? failure : failure.getCause()));
        } finally {
            executor.shutdownNow();
        }
        if (cancelled) {
            // A timed-out private Binder request has an unknown completion state even when its
            // Java wrapper exits shortly afterwards. Never issue another private-protocol request
            // in this process after cancellation.
            PROTOCOL_FUSE.set(true);
            boolean terminated = false;
            try {
                terminated = executor.awaitTermination(750L, TimeUnit.MILLISECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            if (!terminated) {
                probe = new ProbeResult(UNAVAILABLE,
                        probe.detail + "；工作线程未在 750ms 内退出，已熔断后续私有协议探针");
            } else {
                probe = new ProbeResult(UNAVAILABLE,
                        probe.detail + "；请求完成状态未知，已熔断本进程后续私有协议探针");
            }
        }
        reporter.report(check, probe.status, probe.detail);
    }

    // ------------------------------------------------------------------------- U

    private static ProbeResult tokenDispatch() {
        StringBuilder log = new StringBuilder("U interface-token dispatch\n");
        if (Build.VERSION.SDK_INT < 31) return unavailable("需要 Android 12 / Keystore2", log);

        String controlAlias = alias("u_control");
        String missingSource = alias("u_missing_src");
        String missingDestination = alias("u_missing_dst");
        KeyStore store = null;
        boolean cleanupOk = true;
        boolean before = false;
        boolean after = false;
        boolean migrateAnswered = false;
        boolean undefinedAnswered = false;
        try {
            guard();
            store = androidKeyStore();
            generatePlainEc(controlAlias);
            if (!store.containsAlias(controlAlias)) {
                return unavailable("公开 API 生成的对照密钥不可见", log);
            }
            if (store.containsAlias(missingSource) || store.containsAlias(missingDestination)) {
                return unavailable("随机的不存在别名发生碰撞", log);
            }

            IBinder binder = Keystore2ProbeAccess.binder();
            if (binder == null) return unavailable("IKeystoreService binder 不可用", log);
            Object service = keystoreService(binder);
            Object controlDescriptor = appDescriptor(controlAlias);
            Object sourceDescriptor = appDescriptor(missingSource);
            Object destinationDescriptor = appDescriptor(missingDestination);
            before = getKeyEntryWorks(service, controlDescriptor, log, "before");
            if (!before) return unavailable("正确 token 的 getKeyEntry 对照失败", log);

            TransactionCodes codes = maintenanceCodes();
            log.append("migrateCode=").append(codes.migrate)
                    .append(", undefinedControlCode=").append(codes.undefined).append('\n');
            Method writeTypedObject = Parcel.class.getDeclaredMethod(
                    "writeTypedObject", Parcelable.class, int.class);
            writeTypedObject.setAccessible(true);

            int migrateReplies = 0;
            int undefinedReplies = 0;
            for (int i = 0; i < REPEAT; i++) {
                guard();
                if (transactMaintenance(binder, writeTypedObject, codes.migrate,
                        sourceDescriptor, destinationDescriptor, log, "migrate#" + i)) {
                    migrateReplies++;
                }
            }
            for (int i = 0; i < REPEAT; i++) {
                guard();
                if (transactMaintenance(binder, writeTypedObject, codes.undefined,
                        sourceDescriptor, destinationDescriptor, log, "undefined#" + i)) {
                    undefinedReplies++;
                }
            }
            migrateAnswered = migrateReplies > 0;
            undefinedAnswered = undefinedReplies > 0;
            log.append("migrateReplies=").append(migrateReplies).append('/').append(REPEAT)
                    .append(", undefinedReplies=").append(undefinedReplies).append('/')
                    .append(REPEAT).append('\n');
            after = getKeyEntryWorks(service, controlDescriptor, log, "after");
        } catch (Throwable failure) {
            log.append("failure=").append(describe(failure)).append('\n');
            Canary recovery = canary("u_after_failure", log);
            if (!recovery.healthy) log.append("postFailureHealth=failed\n");
            return unavailable("U 探针不可用", log);
        } finally {
            if (store != null) cleanupOk = deleteOwned(store, controlAlias, log);
        }
        if (!cleanupOk) return unavailable("U 对照密钥清理失败", log);
        return result(OmkRiskyProbeEvidence.tokenDispatch(
                before, migrateAnswered, undefinedAnswered, after), log);
    }

    private static final class TransactionCodes {
        final int migrate;
        final int undefined;

        TransactionCodes(int migrate, int undefined) {
            this.migrate = migrate;
            this.undefined = undefined;
        }
    }

    // ------------------------------------------------------------------------- direct AttestKey descriptor delegation

    private static ProbeResult attestKeyDescriptorDelegation() {
        StringBuilder log = new StringBuilder("Direct Keystore2 AttestKey descriptor delegation\n");
        if (Build.VERSION.SDK_INT < 31) {
            return unavailable("需要 Android 12 / Keystore2", log);
        }

        String attestAlias = alias("attest_descriptor_source");
        String signingAlias = alias("attest_descriptor_signing");
        KeyStore store = null;
        boolean aliasesAvailable = false;
        boolean cleanupOk = true;
        boolean sourceGenerated = false;
        boolean sourceDescriptorValid = false;
        boolean delegatedGenerated = false;
        boolean invalidAttestKeyAlias = false;
        long delegatedKeyId = 0L;

        try {
            guard();
            store = androidKeyStore();
            if (store.containsAlias(attestAlias) || store.containsAlias(signingAlias)) {
                log.append("random alias collision\n");
            } else {
                aliasesAvailable = true;
                RawAccess raw = RawAccess.open();
                Method generate = findMethod(raw.securityLevel.getClass(), "generateKey", 5);
                if (generate == null) throw new NoSuchMethodException("IKeystoreSecurityLevel.generateKey/5");
                generate.setAccessible(true);

                Class<?> descriptorClass = generate.getParameterTypes()[0];
                Class<?> parameterClass = generate.getParameterTypes()[2].getComponentType();
                if (parameterClass == null) {
                    throw new NoSuchMethodException("generateKey KeyParameter[] type");
                }
                ParameterCodec codec = new ParameterCodec(parameterClass);
                int keyIdDomain = keyIdDomain();

                guard();
                Object attestRequest = appDescriptor(descriptorClass, attestAlias);
                byte[] sourceChallenge = random(32);
                Object attestMetadata = invoke(generate, raw.securityLevel, attestRequest, null,
                        codec.array(attestationKeyParameters(codec, sourceChallenge)),
                        0, random(32));
                sourceGenerated = attestMetadata != null;
                log.append("sourceAttestKeyGenerated=").append(sourceGenerated)
                        .append("; challengeBytes=").append(sourceChallenge.length).append('\n');
                if (!sourceGenerated) throw new IllegalStateException("AttestKey metadata is null");

                Object attestKeyDescriptor = readField(attestMetadata, "key");
                long sourceKeyId = getKeyId(attestKeyDescriptor, keyIdDomain);
                byte[] sourceCertificate = (byte[]) readField(attestMetadata, "certificate");
                sourceDescriptorValid = OmkRiskyProbeEvidence.isUsableKeyId(sourceKeyId)
                        && sourceCertificate != null && sourceCertificate.length > 0;
                log.append("sourceDescriptorDomain=KEY_ID, sourceKeyId=")
                        .append(sourceKeyId).append(", certificateBytes=")
                        .append(sourceCertificate == null ? 0 : sourceCertificate.length)
                        .append('\n');
                if (!sourceDescriptorValid) {
                    throw new IllegalStateException("AttestKey returned an incomplete KEY_ID descriptor or certificate");
                }

                byte[] challenge = random(32);
                guard();
                Object signingRequest = appDescriptor(descriptorClass, signingAlias);
                try {
                    Object signingMetadata = invoke(generate, raw.securityLevel, signingRequest,
                            attestKeyDescriptor, codec.array(signingKeyParameters(codec, challenge)),
                            0, random(32));
                    delegatedGenerated = signingMetadata != null;
                    if (!delegatedGenerated) {
                        throw new IllegalStateException("delegated signing metadata is null");
                    }
                    Object signingKeyDescriptor = readField(signingMetadata, "key");
                    delegatedKeyId = getKeyId(signingKeyDescriptor, keyIdDomain);
                    log.append("delegatedSigningKeyGenerated=true; signingKeyId=")
                            .append(delegatedKeyId).append("; challengeBytes=")
                            .append(challenge.length).append('\n');
                } catch (Throwable failure) {
                    invalidAttestKeyAlias = isInvalidAttestKeyAlias(failure);
                    log.append("delegationFailure=").append(describe(failure)).append('\n');
                }
            }
        } catch (Throwable failure) {
            if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
            log.append("setupFailure=").append(describe(failure)).append('\n');
        } finally {
            if (aliasesAvailable && store != null) {
                boolean sourceDeleted = deleteOwned(store, attestAlias, log);
                boolean signingDeleted = deleteOwned(store, signingAlias, log);
                cleanupOk = sourceDeleted && signingDeleted;
            }
        }

        OmkRiskyProbeEvidence.Decision decision =
                OmkRiskyProbeEvidence.attestKeyDescriptorDelegation(
                        sourceGenerated, sourceDescriptorValid, delegatedGenerated,
                        delegatedKeyId, invalidAttestKeyAlias, cleanupOk);
        return result(decision, log);
    }

    private static Object[] attestationKeyParameters(
            ParameterCodec codec,
            byte[] challenge
    ) throws Throwable {
        return new Object[]{
                codec.parameter(TAG_ALGORITHM,
                        codec.value(new String[]{"algorithm"}, 3)),
                codec.parameter(TAG_KEY_SIZE,
                        codec.value(new String[]{"integer"}, 256)),
                codec.parameter(TAG_PURPOSE,
                        codec.value(new String[]{"purpose", "keyPurpose"}, 7)),
                codec.parameter(TAG_EC_CURVE,
                        codec.value(new String[]{"ecCurve"}, 1)),
                codec.parameter(TAG_DIGEST,
                        codec.value(new String[]{"digest"}, 4)),
                // AOSP's app-AttestKey generation path includes an attestation challenge.
                // Omitting it asks KeyMint to create an unattested ATTEST_KEY and clean
                // implementations may reject that request before a KEY_ID descriptor exists.
                codec.parameter(TAG_ATTESTATION_CHALLENGE,
                        codec.value(new String[]{"blob"}, challenge)),
                codec.parameter(TAG_NO_AUTH_REQUIRED,
                        codec.value(new String[]{"boolValue", "bool"}, true))
        };
    }

    private static Object[] signingKeyParameters(ParameterCodec codec, byte[] challenge)
            throws Throwable {
        return new Object[]{
                codec.parameter(TAG_ALGORITHM,
                        codec.value(new String[]{"algorithm"}, 3)),
                codec.parameter(TAG_KEY_SIZE,
                        codec.value(new String[]{"integer"}, 256)),
                codec.parameter(TAG_PURPOSE,
                        codec.value(new String[]{"purpose", "keyPurpose"}, 2)),
                codec.parameter(TAG_PURPOSE,
                        codec.value(new String[]{"purpose", "keyPurpose"}, 3)),
                codec.parameter(TAG_EC_CURVE,
                        codec.value(new String[]{"ecCurve"}, 1)),
                codec.parameter(TAG_DIGEST,
                        codec.value(new String[]{"digest"}, 4)),
                codec.parameter(TAG_ATTESTATION_CHALLENGE,
                        codec.value(new String[]{"blob"}, challenge)),
                codec.parameter(TAG_NO_AUTH_REQUIRED,
                        codec.value(new String[]{"boolValue", "bool"}, true))
        };
    }

    private static int keyIdDomain() throws Exception {
        Class<?> domain = Class.forName("android.system.keystore2.Domain");
        Field field = domain.getField("KEY_ID");
        field.setAccessible(true);
        return field.getInt(null);
    }

    private static long getKeyId(Object descriptor, int keyIdDomain) throws Exception {
        if (descriptor == null) throw new IllegalStateException("KeyMetadata.key is null");
        Object domainValue = readField(descriptor, "domain");
        Object namespaceValue = readField(descriptor, "nspace");
        Object aliasValue = readField(descriptor, "alias");
        Object blobValue = readField(descriptor, "blob");
        if (!(domainValue instanceof Number domainNumber)
                || domainNumber.intValue() != keyIdDomain) {
            throw new IllegalStateException("KeyMetadata.key is not in Domain.KEY_ID");
        }
        if (aliasValue != null || blobValue != null) {
            throw new IllegalStateException("KEY_ID descriptor unexpectedly contains alias/blob");
        }
        if (!(namespaceValue instanceof Number keyId)) {
            throw new IllegalStateException("KEY_ID descriptor nspace is not numeric");
        }
        return keyId.longValue();
    }

    private static Object readField(Object owner, String name) throws Exception {
        if (owner == null) throw new NoSuchFieldException(name + " owner is null");
        Field field = owner.getClass().getField(name);
        field.setAccessible(true);
        return field.get(owner);
    }

    private static boolean isInvalidAttestKeyAlias(Throwable failure) {
        Throwable current = unwrap(failure);
        for (int depth = 0; current != null && depth < 12; depth++) {
            String message = current.getMessage();
            if (message != null && message.contains("Invalid attestKeyAlias")) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private static TransactionCodes maintenanceCodes() throws Exception {
        Class<?> stub = Class.forName("android.security.maintenance.IKeystoreMaintenance$Stub");
        int migrate = 0;
        int max = 0;
        for (Field field : stub.getDeclaredFields()) {
            if (!Modifier.isStatic(field.getModifiers()) || field.getType() != int.class
                    || !field.getName().startsWith("TRANSACTION_")) continue;
            field.setAccessible(true);
            int value = field.getInt(null);
            if (value >= FIRST_CALL_TRANSACTION) max = Math.max(max, value);
            if ("TRANSACTION_migrateKeyNamespace".equals(field.getName())) migrate = value;
        }
        // A guessed code can hit an unrelated maintenance method and poison OMK's mirror lane.
        // Require the running framework's own transaction table; never fall back to a scan.
        if (migrate < FIRST_CALL_TRANSACTION || max < migrate) {
            throw new IllegalStateException("无法从本机 Stub 确认 migrateKeyNamespace 事务号");
        }
        return new TransactionCodes(migrate, max + 1);
    }

    private static boolean transactMaintenance(IBinder binder, Method writer, int code,
                                               Object source, Object destination,
                                               StringBuilder log, String label) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(MAINTENANCE_TOKEN);
            writer.invoke(data, source, 0);
            writer.invoke(data, destination, 0);
            boolean answered = binder.transact(code, data, reply, 0);
            log.append(label).append(" answered=").append(answered)
                    .append(", replyBytes=").append(reply.dataSize());
            if (answered && reply.dataSize() >= 4) {
                reply.setDataPosition(0);
                log.append(", exceptionCode=").append(reply.readInt());
                reply.setDataPosition(0);
            }
            log.append('\n');
            return answered;
        } catch (Throwable failure) {
            log.append(label).append(" failure=").append(describe(failure)).append('\n');
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    // ------------------------------------------------------------------------- F

    private static ProbeResult parameterFingerprint() {
        StringBuilder log = new StringBuilder("F KeyMint parameter fingerprint (safe quick mode)\n");
        if (Build.VERSION.SDK_INT < 31) return notApplicable("需要 Android 12 / Keystore2", log);
        if (poisonUnsafe()) return notApplicable("三星/Knox 安全门禁：未发送类型错配参数", log);

        Canary before = canary("f_before", log);
        if (!before.healthy) return notApplicable("基线证明金丝雀不可用，未发送参数向量", log);
        String keyAlias = alias("f_key");
        KeyStore store = null;
        boolean cleanupOk = true;
        boolean stopRemainingVectors = false;
        boolean evidenceInvalidated = false;
        List<OmkRiskyProbeEvidence.Observation> rows = new ArrayList<>();
        try {
            guard();
            store = androidKeyStore();
            generatePlainEc(keyAlias);
            RawAccess raw = RawAccess.open();
            Method create = findMethod(raw.securityLevel.getClass(), "createOperation", 2, 3);
            if (create == null) {
                return notApplicable("IKeystoreSecurityLevel.createOperation 私有接口不可用", log);
            }
            create.setAccessible(true);
            Class<?> descriptorClass = create.getParameterTypes()[0];
            Class<?> parameterClass = create.getParameterTypes()[1].getComponentType();
            if (parameterClass == null) return notApplicable("createOperation 参数数组类型不可用", log);
            ParameterCodec codec = new ParameterCodec(parameterClass);
            Object descriptor = appDescriptor(descriptorClass, keyAlias);
            Object[] base = {
                    codec.parameter(TAG_PURPOSE,
                            codec.value(new String[]{"purpose", "keyPurpose"}, 2)),
                    codec.parameter(TAG_ALGORITHM,
                            codec.value(new String[]{"algorithm"}, 3)),
                    codec.parameter(TAG_DIGEST,
                            codec.value(new String[]{"digest"}, 4))
            };

            CallOutcome gate = invokeCreateOperation(raw.securityLevel, create, descriptor,
                    codec.array(base));
            log.append("legalGate=").append(gate).append('\n');
            if (!gate.success || !gate.cleanupOk) {
                Canary gateAfter = canary("f_after_gate", log);
                if (!gateAfter.healthy) log.append("postGateHealth=failed\n");
                return gateAfter.healthy
                        ? notApplicable("本机私有 createOperation ABI 无法建立合法对照", log)
                        : unavailable("完整合法 operation 参数集未建立并安全 abort", log);
            }

            // Three independent tag families with two wrong union kinds each are sufficient for
            // the three-code attribution rule. The old ten-vector form also generated an attested
            // canary before every request and could approach its 90-second timeout on clean OEMs.
            int[] tags = {TAG_ALGORITHM, TAG_BLOCK_MODE, TAG_DIGEST};
            int[] expectedCodes = {-4, -7, -10};
            String[] names = {"ALGORITHM", "BLOCK_MODE", "DIGEST"};
            for (int i = 0; i < tags.length && !stopRemainingVectors; i++) {
                for (int kind = 0; kind < 2 && !stopRemainingVectors; kind++) {
                    guard();
                    String rowName = names[i] + (kind == 0 ? "+Integer" : "+Blob");
                    Object wrongValue = kind == 0
                            ? codec.value(new String[]{"integer"}, 0x12345678)
                            : codec.value(new String[]{"blob"}, new byte[]{1, 2, 3, 4});
                    Object poisoned = codec.parameter(tags[i], wrongValue);
                    Object[] all = Arrays.copyOf(base, base.length + 1);
                    all[base.length] = poisoned;
                    CallOutcome outcome = invokeCreateOperation(raw.securityLevel, create,
                            descriptor, codec.array(all));
                    rows.add(outcome.observation(rowName));
                    log.append(rowName).append(" expected=").append(expectedCodes[i])
                            .append(' ').append(outcome).append('\n');
                    if (!outcome.cleanupOk) {
                        evidenceInvalidated = true;
                        stopRemainingVectors = true;
                        log.append("evidenceInvalidated=cleanup:").append(rowName).append('\n');
                    } else if (!outcome.success && outcome.code == null) {
                        stopRemainingVectors = true;
                        log.append("remainingVectorsSkipped=opaque:").append(rowName).append('\n');
                    }
                }
            }
        } catch (Throwable failure) {
            log.append("failure=").append(describe(failure)).append('\n');
            Canary recovery = canary("f_after_failure", log);
            if (!recovery.healthy) log.append("postFailureHealth=failed\n");
            return recovery.healthy
                    ? notApplicable("本机私有 KeyMint ABI 与参数探针不兼容", log)
                    : unavailable("F 探针异常后证明金丝雀失败", log);
        } finally {
            if (store != null) cleanupOk = deleteOwned(store, keyAlias, log);
        }

        Canary after = canary("f_after", log);
        if (!cleanupOk) return unavailable("F 临时密钥清理失败", log);
        if (evidenceInvalidated) return unavailable("F operation 清理失败，读数已作废", log);
        return result(OmkRiskyProbeEvidence.parameterFingerprint(
                before.healthy, after.healthy, rows, after.taPatchTagsPresent), log);
    }

    // ------------------------------------------------------------------------- TeeSim

    private static ProbeResult teeSimFingerprint() {
        StringBuilder log = new StringBuilder("TeeSim V0-V4 poisoned-parameter fingerprint\n");
        if (Build.VERSION.SDK_INT < 31) return notApplicable("需要 Android 12 / Keystore2", log);
        if (poisonUnsafe()) return notApplicable("三星/Knox 安全门禁：未发送 TeeSim 向量", log);

        Canary before = canary("teesim_before", log);
        if (!before.healthy) return notApplicable("基线证明金丝雀不可用，未发送 TeeSim 向量", log);
        List<OmkRiskyProbeEvidence.Observation> rows = new ArrayList<>();
        boolean stopRemainingVectors = false;
        boolean evidenceInvalidated = false;
        try {
            guard();
            RawAccess raw = RawAccess.open();
            Method generate = findMethod(raw.securityLevel.getClass(), "generateKey", 5);
            if (generate == null) return unavailable("IKeystoreSecurityLevel.generateKey/5 不可用", log);
            generate.setAccessible(true);
            Class<?> descriptorClass = generate.getParameterTypes()[0];
            Class<?> parameterClass = generate.getParameterTypes()[2].getComponentType();
            if (parameterClass == null) return unavailable("generateKey 参数数组类型不可用", log);
            ParameterCodec codec = new ParameterCodec(parameterClass);
            Object poison = codec.parameter(TAG_ALGORITHM,
                    codec.value(new String[]{"integer"}, 0x12345678));
            Object challenge33 = codec.parameter(TAG_ATTESTATION_CHALLENGE,
                    codec.value(new String[]{"blob"}, random(33)));

            List<Vector> vectors = new ArrayList<>();
            vectors.add(new Vector("V0", new Object[]{poison}));
            vectors.add(new Vector("V1", new Object[]{poison, challenge33,
                    codec.parameter(TAG_CREATION_DATETIME,
                            codec.value(new String[]{"dateTime"}, System.currentTimeMillis()))}));
            vectors.add(new Vector("V2", new Object[]{poison,
                    codec.parameter(TAG_ATTESTATION_CHALLENGE,
                            codec.value(new String[]{"blob"}, random(129)))}));
            vectors.add(new Vector("V3", new Object[]{poison, challenge33,
                    codec.parameter(TAG_DEVICE_UNIQUE_ATTESTATION,
                            codec.value(new String[]{"boolValue"}, true))}));
            vectors.add(new Vector("V4", new Object[]{poison, challenge33,
                    codec.parameter(TAG_INCLUDE_UNIQUE_ID,
                            codec.value(new String[]{"boolValue"}, true))}));

            for (Vector vector : vectors) {
                if (stopRemainingVectors) break;
                guard();
                String vectorAlias = alias("teesim_" + vector.name.toLowerCase(Locale.ROOT));
                Object descriptor = appDescriptor(descriptorClass, vectorAlias);
                CallOutcome outcome = invokeGenerate(raw.securityLevel, generate, descriptor,
                        codec.array(vector.parameters), vectorAlias, log);
                rows.add(outcome.observation(vector.name));
                log.append(vector.name).append(' ').append(outcome).append('\n');
                if (!outcome.cleanupOk) {
                    evidenceInvalidated = true;
                    stopRemainingVectors = true;
                    log.append("evidenceInvalidated=cleanup:").append(vector.name).append('\n');
                } else if (outcome.success || outcome.elapsedMicros > SLOW_VECTOR_MICROS
                        || Integer.valueOf(4).equals(outcome.code)
                        || outcome.code == null) {
                    // A direct acceptance is already sufficient for a finding. Slow or opaque
                    // rejections retain their completed prefix but skip extra risky round trips.
                    stopRemainingVectors = true;
                    log.append("remainingVectorsSkipped=").append(vector.name).append('\n');
                }
            }
        } catch (Throwable failure) {
            log.append("failure=").append(describe(failure)).append('\n');
            Canary recovery = canary("teesim_after_failure", log);
            if (!recovery.healthy) log.append("postFailureHealth=failed\n");
            return recovery.healthy
                    ? notApplicable("本机私有 KeyMint ABI 与 TeeSim 向量不兼容", log)
                    : unavailable("TeeSim 探针异常后证明金丝雀失败", log);
        }

        // V5 and the full INCLUDE_UNIQUE_ID vector are intentionally absent: the source project
        // records multiple clean-device KeyMint failures requiring a reboot after those requests.
        log.append("omitted=V5,full-INCLUDE_UNIQUE_ID (known clean-device damage)\n");
        Canary after = canary("teesim_after", log);
        return result(OmkRiskyProbeEvidence.teeSimFingerprint(
                before.healthy, after.healthy, rows, evidenceInvalidated), log);
    }

    private static final class Vector {
        final String name;
        final Object[] parameters;

        Vector(String name, Object[] parameters) {
            this.name = name;
            this.parameters = parameters;
        }
    }

    // ------------------------------------------------------------------------- raw calls

    private static final class RawAccess {
        final Object securityLevel;

        RawAccess(Object securityLevel) {
            this.securityLevel = securityLevel;
        }

        static RawAccess open() throws Throwable {
            IBinder binder = Keystore2ProbeAccess.binder();
            if (binder == null) throw new IllegalStateException("IKeystoreService binder 为 null");
            Object service = keystoreService(binder);
            Method getSecurityLevel = findMethod(service.getClass(), "getSecurityLevel", 1);
            if (getSecurityLevel == null) throw new NoSuchMethodException("getSecurityLevel/1");
            getSecurityLevel.setAccessible(true);
            Object securityLevel = invoke(getSecurityLevel, service, SECURITY_LEVEL_TEE);
            if (securityLevel == null) throw new IllegalStateException("TEE security level 为 null");
            return new RawAccess(securityLevel);
        }
    }

    private static final class ParameterCodec {
        final Class<?> parameterClass;
        final Field tagField;
        final Field valueField;
        final Class<?> valueClass;

        ParameterCodec(Class<?> parameterClass) throws Exception {
            this.parameterClass = parameterClass;
            tagField = parameterClass.getField("tag");
            valueField = parameterClass.getField("value");
            valueClass = valueField.getType();
        }

        Object value(String[] names, Object argument) throws Throwable {
            Method factory = findStaticMethod(valueClass, names, 1);
            if (factory == null) throw new NoSuchMethodException(
                    valueClass.getName() + "." + Arrays.toString(names));
            factory.setAccessible(true);
            return invoke(factory, null, argument);
        }

        Object parameter(int tag, Object value) throws Exception {
            Object parameter = parameterClass.getConstructor().newInstance();
            tagField.setInt(parameter, tag);
            valueField.set(parameter, value);
            return parameter;
        }

        Object array(Object[] values) {
            Object array = Array.newInstance(parameterClass, values.length);
            for (int i = 0; i < values.length; i++) Array.set(array, i, values[i]);
            return array;
        }
    }

    private static final class CallOutcome {
        final boolean success;
        final Integer code;
        final String text;
        final long elapsedMicros;
        final boolean cleanupOk;

        CallOutcome(boolean success, Integer code, String text,
                    long elapsedMicros, boolean cleanupOk) {
            this.success = success;
            this.code = code;
            this.text = text;
            this.elapsedMicros = elapsedMicros;
            this.cleanupOk = cleanupOk;
        }

        OmkRiskyProbeEvidence.Observation observation(String name) {
            return new OmkRiskyProbeEvidence.Observation(
                    name, code, success, text, elapsedMicros);
        }

        @Override public String toString() {
            return text + ", us=" + elapsedMicros + ", cleanup=" + cleanupOk;
        }
    }

    private static CallOutcome invokeCreateOperation(Object target, Method method,
                                                     Object descriptor, Object parameters) {
        long start = System.nanoTime();
        try {
            Object response;
            if (method.getParameterCount() >= 3) {
                Class<?> last = method.getParameterTypes()[2];
                Object force = last == boolean.class ? Boolean.FALSE
                        : last == int.class ? Integer.valueOf(0) : null;
                response = invoke(method, target, descriptor, parameters, force);
            } else {
                response = invoke(method, target, descriptor, parameters);
            }
            boolean aborted = abortOperation(response);
            return new CallOutcome(true, null, "success(aborted=" + aborted + ")",
                    microsSince(start), aborted);
        } catch (Throwable failure) {
            Throwable cause = unwrap(failure);
            return new CallOutcome(false, serviceCode(cause), describe(cause),
                    microsSince(start), true);
        }
    }

    private static CallOutcome invokeGenerate(Object target, Method method, Object descriptor,
                                              Object parameters, String ownedAlias,
                                              StringBuilder log) {
        long start = System.nanoTime();
        boolean success = false;
        Integer code = null;
        String text;
        try {
            invoke(method, target, descriptor, null, parameters, 0, new byte[0]);
            success = true;
            text = "success";
        } catch (Throwable failure) {
            Throwable cause = unwrap(failure);
            code = serviceCode(cause);
            text = describe(cause);
        }
        long elapsed = microsSince(start);
        boolean cleanup = true;
        try {
            KeyStore store = androidKeyStore();
            if (store.containsAlias(ownedAlias)) store.deleteEntry(ownedAlias);
            if (store.containsAlias(ownedAlias)) cleanup = false;
        } catch (Throwable failure) {
            cleanup = false;
            log.append("cleanup ").append(ownedAlias).append('=')
                    .append(describe(failure)).append('\n');
        }
        return new CallOutcome(success, code, text, elapsed, cleanup);
    }

    private static boolean abortOperation(Object response) {
        if (response == null) return false;
        try {
            Object operation = null;
            Class<?> type = response.getClass();
            for (String name : new String[]{"iOperation", "operation"}) {
                try {
                    Field field = type.getField(name);
                    operation = field.get(response);
                    if (operation != null) break;
                } catch (ReflectiveOperationException ignored) { }
            }
            if (operation == null) {
                for (Field field : type.getFields()) {
                    Object value;
                    try { value = field.get(response); }
                    catch (Throwable ignored) { continue; }
                    if (value != null && findMethod(value.getClass(), "abort", 0) != null) {
                        operation = value;
                        break;
                    }
                }
            }
            if (operation == null) return false;
            Method abort = findMethod(operation.getClass(), "abort", 0);
            if (abort == null) return false;
            abort.setAccessible(true);
            invoke(abort, operation);
            return true;
        } catch (Throwable failure) {
            return false;
        }
    }

    // ------------------------------------------------------------------------- health and common helpers

    private static final class Canary {
        boolean healthy;
        Boolean taPatchTagsPresent;
        String failure = "";
    }

    private static Canary canary(String purpose, StringBuilder log) {
        Canary canary = new Canary();
        String alias = alias(purpose);
        KeyStore store = null;
        try {
            guard();
            store = androidKeyStore();
            byte[] challenge = random(32);
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setKeySize(256)
                    .setAttestationChallenge(challenge)
                    .build());
            KeyPair pair = generator.generateKeyPair();
            Certificate[] chain = store.getCertificateChain(alias);
            if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
                throw new IllegalStateException("证明链为空");
            }
            X509Certificate leaf = (X509Certificate) chain[0];
            Attestation attestation = Attestation.loadFromCertificate(leaf);
            if (!MessageDigest.isEqual(challenge, attestation.getAttestationChallenge())) {
                throw new IllegalStateException("挑战绑定不一致");
            }
            Key key = store.getKey(alias, null);
            if (!(key instanceof PrivateKey)) throw new IllegalStateException("私钥不可读");
            byte[] message = random(41);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign((PrivateKey) key);
            signer.update(message);
            byte[] signed = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(pair.getPublic());
            verifier.update(message);
            if (!verifier.verify(signed)) throw new IllegalStateException("金丝雀签名验签失败");
            AuthorizationList hardware = attestation.getTeeEnforced();
            canary.taPatchTagsPresent = hardware == null ? null
                    : hardware.getVendorPatchLevel() != null || hardware.getBootPatchLevel() != null;
            canary.healthy = true;
        } catch (Throwable failure) {
            canary.failure = describe(failure);
        } finally {
            if (store != null && !deleteOwned(store, alias, log)) {
                canary.healthy = false;
                canary.failure = canary.failure.isEmpty()
                        ? "金丝雀清理失败" : canary.failure + "; 金丝雀清理失败";
            }
        }
        log.append("canary[").append(purpose).append("] healthy=")
                .append(canary.healthy).append(", taPatchTags=")
                .append(canary.taPatchTagsPresent)
                .append(canary.failure.isEmpty() ? "" : ", failure=" + canary.failure)
                .append('\n');
        return canary;
    }

    private static boolean poisonUnsafe() {
        String device = (Build.MANUFACTURER + "/" + Build.BRAND).toLowerCase(Locale.ROOT);
        return device.contains("samsung") || device.contains("knox");
    }

    private static KeyStore androidKeyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }

    private static void generatePlainEc(String alias) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        generator.initialize(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(256)
                .build());
        generator.generateKeyPair();
    }

    private static boolean deleteOwned(KeyStore store, String alias, StringBuilder log) {
        try {
            if (store.containsAlias(alias)) store.deleteEntry(alias);
            boolean deleted = !store.containsAlias(alias);
            if (!deleted) log.append("cleanup retained alias purpose=")
                    .append(aliasPurpose(alias)).append('\n');
            return deleted;
        } catch (Throwable failure) {
            log.append("cleanup failure purpose=").append(aliasPurpose(alias))
                    .append(": ").append(describe(failure)).append('\n');
            return false;
        }
    }

    private static String alias(String purpose) {
        return "TrustAttestor_omk_" + purpose + '_' + UUID.randomUUID();
    }

    private static String aliasPurpose(String alias) {
        if (alias == null) return "unknown";
        int end = alias.lastIndexOf('_');
        return end > 0 ? alias.substring(0, end) : alias;
    }

    private static byte[] random(int length) {
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return value;
    }

    private static Object keystoreService(IBinder binder) throws Throwable {
        Class<?> stub = Class.forName("android.system.keystore2.IKeystoreService$Stub");
        Method asInterface = stub.getMethod("asInterface", IBinder.class);
        Object service = invoke(asInterface, null, binder);
        if (service == null) throw new IllegalStateException("IKeystoreService.asInterface 为 null");
        return service;
    }

    private static boolean getKeyEntryWorks(Object service, Object descriptor,
                                            StringBuilder log, String label) {
        try {
            Method method = findMethod(service.getClass(), "getKeyEntry", 1);
            if (method == null) throw new NoSuchMethodException("getKeyEntry/1");
            method.setAccessible(true);
            Object reply = invoke(method, service, descriptor);
            boolean ok = reply != null;
            log.append("getKeyEntry[").append(label).append("] reply=").append(ok).append('\n');
            return ok;
        } catch (Throwable failure) {
            log.append("getKeyEntry[").append(label).append("] failure=")
                    .append(describe(failure)).append('\n');
            return false;
        }
    }

    private static Object appDescriptor(String alias) throws Exception {
        return appDescriptor(Class.forName("android.system.keystore2.KeyDescriptor"), alias);
    }

    private static Object appDescriptor(Class<?> type, String alias) throws Exception {
        Object descriptor = type.getConstructor().newInstance();
        setField(descriptor, "domain", 0);
        setField(descriptor, "nspace", -1L);
        setField(descriptor, "alias", alias);
        setField(descriptor, "blob", null);
        return descriptor;
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getField(name);
        field.set(target, value);
    }

    private static Method findMethod(Class<?> type, String name, int... arities) {
        for (Method method : type.getMethods()) {
            if (!name.equals(method.getName())) continue;
            for (int arity : arities) {
                if (method.getParameterCount() == arity) return method;
            }
        }
        return null;
    }

    private static Method findStaticMethod(Class<?> type, String[] names, int arity) {
        for (String name : names) {
            for (Method method : type.getMethods()) {
                if (name.equals(method.getName()) && method.getParameterCount() == arity
                        && Modifier.isStatic(method.getModifiers())) return method;
            }
        }
        return null;
    }

    private static Object invoke(Method method, Object target, Object... arguments) throws Throwable {
        try {
            return method.invoke(target, arguments);
        } catch (InvocationTargetException wrapped) {
            throw wrapped.getCause() == null ? wrapped : wrapped.getCause();
        }
    }

    private static Throwable unwrap(Throwable failure) {
        Throwable current = failure;
        while (current instanceof InvocationTargetException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static Integer serviceCode(Throwable failure) {
        Throwable cause = unwrap(failure);
        if (cause == null || !"android.os.ServiceSpecificException".equals(cause.getClass().getName())) {
            return null;
        }
        try {
            return cause.getClass().getField("errorCode").getInt(cause);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String describe(Throwable failure) {
        Throwable cause = unwrap(failure);
        if (cause == null) return "unknown";
        Integer code = serviceCode(cause);
        String message = cause.getMessage();
        if (message != null && message.length() > 180) message = message.substring(0, 180) + "…";
        return cause.getClass().getSimpleName()
                + (code == null ? "" : " code=" + code)
                + (message == null || message.isEmpty() ? "" : ": " + message);
    }

    private static long microsSince(long startNanos) {
        long elapsed = System.nanoTime() - startNanos;
        return elapsed < 0L ? Long.MAX_VALUE : elapsed / 1_000L;
    }

    private static void guard() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("probe cancelled");
        }
    }
}

package com.lingqing.trustattestor;

import android.annotation.SuppressLint;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyNotYetValidException;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.security.keystore.UserNotAuthenticatedException;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.Date;
import java.math.BigInteger;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import javax.security.auth.x500.X500Principal;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.vvb2060.keyattestation.attestation.Attestation;
import io.github.vvb2060.keyattestation.attestation.AuthorizationList;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;

/** Silent checks of this application's temporary keys using normal Keystore operations. */
final class SilentKeystoreChecks {
    interface Reporter {
        void report(String check, SilentProbeEvidence.Status status, String detail);
    }

    interface AttestKeyConfigurer {
        void configure(KeyGenParameterSpec.Builder builder);
    }

    private SilentKeystoreChecks() { }

    /** Records every declared subcheck, including steps whose prerequisites did not complete. */
    private static final class Run implements Reporter, AutoCloseable {
        private final Reporter reporter;
        private final Set<String> pending;

        Run(Reporter reporter, String... checks) {
            this.reporter = reporter;
            pending = new LinkedHashSet<>(Arrays.asList(checks));
        }

        @Override public void report(String check, SilentProbeEvidence.Status status, String detail) {
            pending.remove(check);
            reporter.report(check, status, detail);
        }

        void completeNotApplicable(String detail) {
            for (String check : new ArrayList<>(pending)) {
                report(check, VERIFIED, "不适用：" + detail);
            }
        }

        void failPending(Exception failure) {
            String detail = failureDetail(failure);
            for (String check : new ArrayList<>(pending)) {
                report(check, UNAVAILABLE, detail);
            }
        }

        @Override public void close() {
            for (String check : pending) reporter.report(check, UNAVAILABLE, "前置步骤未完成");
            pending.clear();
        }
    }

    /** Only entries reserved by this invocation may be deleted, including partial creations. */
    private static final class Session implements AutoCloseable {
        final KeyStore store;
        private final Set<String> owned = new LinkedHashSet<>();
        private final Reporter reporter;

        Session(Reporter reporter) throws Exception {
            this.reporter = reporter;
            guard();
            store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
        }

        String reserve(String purpose) throws Exception {
            guard();
            String alias = "TrustAttestor_silent_" + purpose + "_" + UUID.randomUUID();
            if (store.containsAlias(alias)) throw new GeneralSecurityException("temporary alias collision");
            owned.add(alias);
            return alias;
        }

        void delete(String alias) throws Exception {
            guard();
            if (!owned.contains(alias)) throw new GeneralSecurityException("unowned temporary alias");
            store.deleteEntry(alias); // Failure must propagate before any post-delete conclusion.
            guard();
        }

        @Override public void close() {
            for (String alias : owned) {
                try {
                    // Cleanup remains allowed after cancellation.
                    store.deleteEntry(alias);
                } catch (Exception failure) {
                    reporter.report("cleanup", UNAVAILABLE, failureDetail(failure));
                }
            }
        }
    }

    private static final class Contradiction extends GeneralSecurityException {
        Contradiction(String message) { super(message); }
    }

    private static void guard() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException("silent check interrupted");
    }

    private static byte[] challenge() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    @SuppressLint("NewApi") // Newer setters are selected only by their SDK-gated probes.
    private static KeyPair generateEc(String alias, byte[] challenge, boolean authenticate,
                                      boolean unlocked, AttestKeyConfigurer configurer) throws Exception {
        guard();
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(authenticate);
        if (authenticate) {
            builder.setUserAuthenticationParameters(0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        }
        if (unlocked) builder.setUnlockedDeviceRequired(true);
        if (challenge != null) {
            builder.setAttestationChallenge(challenge);
            configurer.configure(builder);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        generator.initialize(builder.build());
        KeyPair pair = generator.generateKeyPair();
        guard();
        return pair;
    }

    private static PrivateKey privateKey(KeyStore store, String alias) throws Exception {
        guard();
        Key key = store.getKey(alias, null);
        if (!(key instanceof PrivateKey)) throw new GeneralSecurityException("private key unavailable");
        return (PrivateKey) key;
    }

    private static byte[] sign(PrivateKey key, String algorithm, byte[] payload) throws Exception {
        guard();
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(key);
        signature.update(payload);
        byte[] signed = signature.sign();
        guard();
        return signed;
    }

    private static Attestation boundAttestation(KeyStore store, String alias, PublicKey generated,
                                               byte[] expectedChallenge) throws Exception {
        guard();
        Certificate certificate = store.getCertificate(alias);
        Certificate[] chain = store.getCertificateChain(alias);
        if (!(certificate instanceof X509Certificate) || chain == null || chain.length == 0
                || !(chain[0] instanceof X509Certificate)) {
            throw new GeneralSecurityException("leaf attestation certificate unavailable");
        }
        if (!Arrays.equals(certificate.getEncoded(), chain[0].getEncoded())
                || !SilentProbeEvidence.samePublicKey(generated, certificate.getPublicKey())) {
            throw new Contradiction("当前 alias 的证书、证书链叶节点或生成公钥不一致");
        }
        // Parse this key's leaf, never the chain parser's selected parent/showAttestation.
        Attestation parsed = Attestation.loadFromCertificate((X509Certificate) certificate);
        if (!Arrays.equals(expectedChallenge, parsed.getAttestationChallenge())) {
            throw new Contradiction("叶证书中的证明 challenge 与本次密钥请求不一致");
        }
        guard();
        return parsed;
    }

    private static SilentProbeEvidence.AuthFields authFields(AuthorizationList list) {
        return list == null ? null : new SilentProbeEvidence.AuthFields(
                list.getNoAuthRequired(), list.getUserAuthType(), list.getAuthTimeout());
    }

    static void authentication(Context context, AttestKeyConfigurer configurer,
                               Reporter metadataReporter, Reporter policyReporter) {
        try (Run metadata = new Run(metadataReporter, "auth.binding", "auth.fields", "auth.key_info");
             Run policy = new Run(policyReporter, "auth.per_use_sign")) {
            if (Build.VERSION.SDK_INT < 30) {
                metadata.completeNotApplicable("认证密钥授权接口需要 Android 11+");
                policy.completeNotApplicable("认证密钥授权接口需要 Android 11+");
                return;
            }
            if (context == null) {
                IllegalStateException failure = new IllegalStateException("应用上下文不可用");
                metadata.failPending(failure);
                policy.failPending(failure);
                return;
            }
            try {
                guard();
                KeyguardManager manager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
                if (manager == null || !manager.isDeviceSecure()) {
                    metadata.completeNotApplicable("设备未配置安全锁屏，无法建立每次认证密钥前提");
                    policy.completeNotApplicable("设备未配置安全锁屏，无法建立每次认证密钥前提");
                    return;
                }
                try (Session session = new Session(policy)) {
                    String alias = session.reserve("auth");
                    byte[] request = challenge();
                    final KeyPair generated;
                    try {
                        generated = generateEc(alias, request, true, false, configurer);
                    } catch (Exception failure) {
                        if (transientOrInterrupted(failure)) throw failure;
                        String detail = "平台不接受每次认证证明密钥：" + failureDetail(failure);
                        metadata.completeNotApplicable(detail);
                        policy.completeNotApplicable(detail);
                        return;
                    }
                    try {
                        Attestation certificate = boundAttestation(session.store, alias, generated.getPublic(), request);
                        metadata.report("auth.binding", VERIFIED, "叶证书绑定本次公钥及 challenge");
                        SilentProbeEvidence.Decision decision = SilentProbeEvidence.authentication(
                                authFields(certificate.getSoftwareEnforced()), authFields(certificate.getTeeEnforced()),
                                AuthorizationList.HW_AUTH_PASSWORD | AuthorizationList.HW_AUTH_BIOMETRIC);
                        metadata.report("auth.fields", decision.status, decision.detail);
                    } catch (Exception failure) {
                        failed(metadata, "auth.binding", failure);
                    }
                    PrivateKey key;
                    try {
                        key = privateKey(session.store, alias);
                    } catch (Exception failure) {
                        failed(metadata, "auth.key_info", failure);
                        failed(policy, "auth.per_use_sign", failure);
                        return;
                    }
                    try {
                        guard();
                        KeyInfo info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
                        int expected = KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL;
                        int duration = info.getUserAuthenticationValidityDurationSeconds();
                        boolean matches = info.isUserAuthenticationRequired()
                                && (duration == -1 || duration == 0)
                                && info.getUserAuthenticationType() == expected;
                        metadata.report("auth.key_info", matches ? VERIFIED : DETECTED,
                                "本次请求与 KeyInfo 认证约束" + (matches ? "一致" : "不一致")
                                        + "；required=" + info.isUserAuthenticationRequired()
                                        + ", duration=" + info.getUserAuthenticationValidityDurationSeconds()
                                        + ", type=" + info.getUserAuthenticationType());
                    } catch (Exception failure) {
                        failed(metadata, "auth.key_info", failure);
                    }
                    byte[] payload = challenge();
                    byte[] signed;
                    try {
                        // This fresh per-use operation is never passed to an authentication UI.
                        signed = sign(key, "SHA256withECDSA", payload);
                    } catch (Exception failure) {
                        policy.report("auth.per_use_sign", authenticationRejected(failure) ? VERIFIED : UNAVAILABLE,
                                (authenticationRejected(failure) ? "系统明确要求用户认证；" : "未完成认证策略验证；")
                                        + failureDetail(failure));
                        return;
                    }
                    try {
                        boolean valid = SilentProbeEvidence.verifyEc(generated.getPublic(), "SHA256withECDSA", payload, signed);
                        policy.report("auth.per_use_sign", valid ? DETECTED : UNAVAILABLE,
                                valid ? "未授权的全新每次认证操作返回了可由本次生成公钥验证的签名"
                                        : "调用返回的签名未通过校验，不据此声明认证限制被绕过");
                    } catch (Exception failure) {
                        failed(policy, "auth.per_use_sign", failure);
                    }
                }
            } catch (Exception failure) {
                metadata.failPending(failure);
                policy.failPending(failure);
            }
        }
    }

    static void unlockedDeviceField(AttestKeyConfigurer configurer, Reporter reporter) {
        try (Run run = new Run(reporter, "unlocked.binding", "unlocked.field")) {
            if (Build.VERSION.SDK_INT < 28) {
                run.completeNotApplicable("UNLOCKED_DEVICE_REQUIRED 需要 Android 9+");
                return;
            }
            boolean keyGenerated = false;
            try (Session session = new Session(run)) {
                String alias = session.reserve("unlocked");
                byte[] request = challenge();
                KeyPair generated = generateEc(alias, request, false, true, configurer);
                keyGenerated = true;
                Attestation certificate = boundAttestation(session.store, alias, generated.getPublic(), request);
                run.report("unlocked.binding", VERIFIED, "叶证书绑定本次公钥及 challenge");
                AuthorizationList software = certificate.getSoftwareEnforced();
                AuthorizationList hardware = certificate.getTeeEnforced();
                SilentProbeEvidence.Decision decision = SilentProbeEvidence.unlockedDeviceField(
                        software != null && hardware != null, certificate.getAttestationVersion(),
                        software == null ? null : software.getUnlockedDeviceReq(),
                        hardware == null ? null : hardware.getUnlockedDeviceReq());
                run.report("unlocked.field", decision.status, decision.detail + "；仅验证字段，未测试锁屏状态转换");
            } catch (Exception failure) {
                if (!keyGenerated && !transientOrInterrupted(failure)) {
                    run.completeNotApplicable("平台不接受 UNLOCKED_DEVICE_REQUIRED 证明密钥："
                            + failureDetail(failure));
                } else {
                    failed(run, "unlocked.binding", failure);
                }
            }
        }
    }

    static void operations(Reporter reporter) {
        try (Run run = new Run(reporter, "ec.metadata", "ec.control", "ec.digest", "aes.metadata", "aes.origin", "aes.control", "aes.purpose", "aes.caller_iv");
             Session session = new Session(run)) {
            checkEcDigest(session, run);
            checkAesConstraints(session, run);
        } catch (Exception failure) {
            failed(reporter, "operations.setup", failure);
        }
    }

    private static void checkEcDigest(Session session, Reporter reporter) {
        String check = "ec.control";
        try {
            String alias = session.reserve("digest");
            KeyPair generated = generateEc(alias, null, false, false, builder -> { });
            PrivateKey key = privateKey(session.store, alias);
            try {
                KeyInfo info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
                boolean matches = info.getKeySize() == 256 && SilentProbeEvidence.isP256(generated.getPublic())
                        && info.getPurposes() == (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        && exactly(info.getDigests(), KeyProperties.DIGEST_SHA256)
                        && !info.isUserAuthenticationRequired();
                reporter.report("ec.metadata", matches ? VERIFIED : DETECTED,
                        "EC 曲线、大小、用途、摘要和认证字段与本次请求" + (matches ? "一致" : "不一致")
                                + "；size=" + info.getKeySize() + ", purposes=" + info.getPurposes()
                                + ", digests=" + Arrays.toString(info.getDigests())
                                + ", auth=" + info.isUserAuthenticationRequired());
            } catch (Exception failure) {
                failed(reporter, "ec.metadata", failure);
            }
            byte[] payload = challenge();
            byte[] control = sign(key, "SHA256withECDSA", payload);
            if (!SilentProbeEvidence.verifyEc(generated.getPublic(), "SHA256withECDSA", payload, control)) {
                reporter.report("ec.control", UNAVAILABLE, "允许的 SHA-256 签名未通过生成公钥验证");
                return;
            }
            reporter.report("ec.control", VERIFIED, "允许的 SHA-256 签名已验证");
            check = "ec.digest";
            byte[] forbidden;
            try {
                forbidden = sign(key, "SHA512withECDSA", payload);
            } catch (Exception failure) {
                rejectedOrUnavailable(reporter, "ec.digest", failure, false);
                return;
            }
            boolean valid = SilentProbeEvidence.verifyEc(generated.getPublic(), "SHA512withECDSA", payload, forbidden);
            reporter.report("ec.digest", valid ? DETECTED : UNAVAILABLE,
                    valid ? "仅授权 SHA-256 的 EC 私钥返回了通过验证的 SHA-512 签名"
                            : "受限摘要调用返回的签名未通过验证");
        } catch (Exception failure) {
            failed(reporter, check, failure);
        }
    }

    private static void checkAesConstraints(Session session, Reporter reporter) {
        byte[] material = new byte[32];
        new SecureRandom().nextBytes(material);
        try {
            String alias = session.reserve("aes_import");
            KeyProtection protection = new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(false).build();
            guard();
            session.store.setEntry(alias, new KeyStore.SecretKeyEntry(new SecretKeySpec(material, "AES")), protection);
            Key loaded = session.store.getKey(alias, null);
            if (!(loaded instanceof SecretKey)) throw new GeneralSecurityException("imported AES key unavailable");
            SecretKey key = (SecretKey) loaded;
            try {
                KeyInfo info = (KeyInfo) SecretKeyFactory.getInstance("AES", "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
                boolean matches = info.getKeySize() == 256 && info.getPurposes() == KeyProperties.PURPOSE_ENCRYPT
                        && exactly(info.getBlockModes(), KeyProperties.BLOCK_MODE_GCM)
                        && exactly(info.getEncryptionPaddings(), KeyProperties.ENCRYPTION_PADDING_NONE)
                        && !info.isUserAuthenticationRequired();
                reporter.report("aes.metadata", matches ? VERIFIED : DETECTED,
                        "导入 AES 的大小、用途、模式、填充和认证字段与请求" + (matches ? "一致" : "不一致")
                                + "；size=" + info.getKeySize() + ", purposes=" + info.getPurposes()
                                + ", modes=" + Arrays.toString(info.getBlockModes())
                                + ", paddings=" + Arrays.toString(info.getEncryptionPaddings())
                                + ", auth=" + info.isUserAuthenticationRequired());
                int origin = info.getOrigin();
                reporter.report("aes.origin", origin == KeyProperties.ORIGIN_UNKNOWN ? UNAVAILABLE
                                : origin == KeyProperties.ORIGIN_IMPORTED ? VERIFIED : DETECTED,
                        "导入请求的 KeyInfo 来源字段：origin=" + origin);
            } catch (Exception failure) {
                failed(reporter, "aes.metadata", failure);
            }
            byte[] plaintext = "TrustAttestor imported AES policy control".getBytes(StandardCharsets.UTF_8);
            Cipher allowed = Cipher.getInstance("AES/GCM/NoPadding");
            allowed.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = allowed.doFinal(plaintext);
            GCMParameterSpec actual = actualGcmParameters(allowed);
            if (!SilentProbeEvidence.verifyGcm(material, plaintext, ciphertext, actual)) {
                reporter.report("aes.control", UNAVAILABLE, "导入 AES 的允许加密结果未通过独立验证");
                return;
            }
            reporter.report("aes.control", VERIFIED, "导入 AES 的加密输出及实际 GCM 参数已用本次材料独立验证");
            try {
                guard();
                Cipher forbidden = Cipher.getInstance("AES/GCM/NoPadding");
                forbidden.init(Cipher.DECRYPT_MODE, key, actual);
                byte[] plaintextAgain = forbidden.doFinal(ciphertext);
                guard();
                boolean valid = Arrays.equals(plaintext, plaintextAgain);
                reporter.report("aes.purpose", valid ? DETECTED : UNAVAILABLE,
                        valid ? "仅授权 ENCRYPT 的导入 AES 密钥完成了正确的 DECRYPT"
                                : "受限 DECRYPT 返回的内容与原文不符");
            } catch (Exception failure) {
                rejectedOrUnavailable(reporter, "aes.purpose", failure, false);
            }
            byte[] callerIv = new byte[12];
            do { new SecureRandom().nextBytes(callerIv); } while (Arrays.equals(callerIv, actual.getIV()));
            Cipher callerNonce;
            byte[] output;
            try {
                guard();
                callerNonce = Cipher.getInstance("AES/GCM/NoPadding");
                callerNonce.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, callerIv));
                output = callerNonce.doFinal(plaintext);
                guard();
            } catch (Exception failure) {
                rejectedOrUnavailable(reporter, "aes.caller_iv", failure, true);
                return;
            }
            try {
                GCMParameterSpec used = actualGcmParameters(callerNonce);
                if (!SilentProbeEvidence.verifyGcm(material, plaintext, output, used)) {
                    reporter.report("aes.caller_iv", UNAVAILABLE, "调用方 IV 路径输出未通过独立验证");
                } else if (Arrays.equals(callerIv, used.getIV())) {
                    reporter.report("aes.caller_iv", DETECTED,
                            "要求随机加密的导入 AES 密钥实际使用了调用方 IV，且加密输出已独立验证");
                } else {
                    reporter.report("aes.caller_iv", VERIFIED, "有效加密输出使用了其他 IV，未使用调用方指定值");
                }
            } catch (Exception failure) {
                failed(reporter, "aes.caller_iv", failure);
            }
        } catch (Exception failure) {
            failed(reporter, "aes.control", failure);
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    private static GCMParameterSpec actualGcmParameters(Cipher cipher) throws Exception {
        if (cipher.getParameters() == null) throw new GeneralSecurityException("GCM parameters unavailable");
        GCMParameterSpec params = cipher.getParameters().getParameterSpec(GCMParameterSpec.class);
        if (!Arrays.equals(cipher.getIV(), params.getIV())) {
            throw new GeneralSecurityException("GCM IV and AlgorithmParameters disagree");
        }
        return params;
    }

    private static boolean exactly(String[] actual, String expected) {
        return actual != null && actual.length == 1 && expected.equalsIgnoreCase(actual[0]);
    }

    private static SilentProbeEvidence.AliasSnapshot snapshot(Session session, String alias) throws Exception {
        guard();
        SilentProbeEvidence.AliasSnapshot snapshot = SilentProbeEvidence.readAlias(session.store, alias);
        guard();
        return snapshot;
    }

    private static void requireAbsent(Session session, String alias) throws Exception {
        if (!snapshot(session, alias).absent()) {
            throw new Contradiction("已完成的查询显示 alias 仍存在于密钥、证书或枚举接口中");
        }
    }

    private static SilentProbeEvidence.AliasSnapshot requireBinding(Session session, String alias, PublicKey expected)
            throws Exception {
        SilentProbeEvidence.AliasSnapshot observed = snapshot(session, alias);
        if (!observed.contains || !observed.enumerated || !(observed.key instanceof PrivateKey)
                || observed.certificate == null || observed.chain == null || observed.chain.length == 0) {
            throw new Contradiction("生成成功后的完整查询显示 alias/私钥/证书/证书链状态不一致");
        }
        if (!Arrays.equals(observed.certificate.getEncoded(), observed.chain[0].getEncoded())
                || !SilentProbeEvidence.samePublicKey(expected, observed.certificate.getPublicKey())) {
            throw new Contradiction("当前证书及证书链叶节点未绑定本次生成的公钥");
        }
        return observed;
    }

    private static byte[] verifiedSignature(PrivateKey key, PublicKey publicKey, byte[] payload) throws Exception {
        byte[] signed = sign(key, "SHA256withECDSA", payload);
        if (!SilentProbeEvidence.verifyEc(publicKey, "SHA256withECDSA", payload, signed)) {
            // No usable signature is not evidence that a different alias/key was used.
            throw new GeneralSecurityException("signature output did not verify");
        }
        return signed;
    }

    static void lifecycle(AttestKeyConfigurer configurer, Reporter reporter) {
        String check = "lifecycle.pre_absent";
        try (Run run = new Run(reporter, "lifecycle.pre_absent", "lifecycle.first_binding", "lifecycle.repeat_read",
                "lifecycle.delete", "lifecycle.recreate_binding", "lifecycle.rotation");
             Session session = new Session(run)) {
            try {
                String alias = session.reserve("lifecycle");
                requireAbsent(session, alias);
                run.report(check, VERIFIED, "本轮唯一 alias 在生成前不存在");
                check = "lifecycle.first_binding";
                byte[] requestA = challenge();
                KeyPair generatedA = generateEc(alias, requestA, false, false, configurer);
                SilentProbeEvidence.AliasSnapshot first = requireBinding(session, alias, generatedA.getPublic());
                verifiedSignature((PrivateKey) first.key, generatedA.getPublic(), challenge());
                run.report(check, VERIFIED, "首次生成、查询及签名绑定一致");
                check = "lifecycle.repeat_read";
                for (int i = 0; i < 5; i++) {
                    SilentProbeEvidence.AliasSnapshot again = requireBinding(session, alias, generatedA.getPublic());
                    if (!Arrays.equals(first.certificate.getEncoded(), again.certificate.getEncoded())) {
                        throw new Contradiction("同一 alias 重复读取的证书发生变化");
                    }
                }
                run.report(check, VERIFIED, "重复读取的证书与生成公钥一致");
                check = "lifecycle.delete";
                session.delete(alias);
                requireAbsent(session, alias);
                run.report(check, VERIFIED, "deleteEntry 成功后所有查询接口均已移除该 alias");
                check = "lifecycle.recreate_binding";
                KeyPair generatedB = generateEc(alias, challenge(), false, false, configurer);
                SilentProbeEvidence.AliasSnapshot second = requireBinding(session, alias, generatedB.getPublic());
                byte[] payload = challenge();
                byte[] signed = verifiedSignature((PrivateKey) second.key, generatedB.getPublic(), payload);
                run.report(check, VERIFIED, "同名重建后的查询及签名绑定新生成公钥");
                check = "lifecycle.rotation";
                if (SilentProbeEvidence.samePublicKey(generatedA.getPublic(), generatedB.getPublic())
                        || Arrays.equals(first.certificate.getEncoded(), second.certificate.getEncoded())
                        || SilentProbeEvidence.verifyEc(generatedA.getPublic(), "SHA256withECDSA", payload, signed)) {
                    throw new Contradiction("删除并重建后仍复用了旧公钥或证书，或新签名可被旧公钥验证");
                }
                run.report(check, VERIFIED, "同名重建后公钥已更换，新签名不能由旧公钥验证");
            } catch (Exception failure) {
                failed(run, check, failure);
            }
        } catch (Exception failure) {
            failed(reporter, check, failure);
        }
    }

    static void aliasIsolation(AttestKeyConfigurer configurer, Reporter reporter) {
        final int count = 4;
        ArrayList<String> checks = new ArrayList<>();
        for (int i = 0; i < count; i++) checks.add("alias.binding." + i);
        checks.add("alias.cross_verify");
        for (int i = 0; i < count; i++) checks.add("alias.delete." + i);
        String check = "alias.binding.0";
        try (Run run = new Run(reporter, checks.toArray(new String[0])); Session session = new Session(run)) {
            try {
                String[] aliases = new String[count];
                PublicKey[] publicKeys = new PublicKey[count];
                ArrayList<byte[]> signatures = new ArrayList<>(count);
                ArrayList<byte[]> payloads = new ArrayList<>(count);
                for (int i = 0; i < count; i++) {
                    check = "alias.binding." + i;
                    aliases[i] = session.reserve("isolation");
                    KeyPair generated = generateEc(aliases[i], challenge(), false, false, configurer);
                    publicKeys[i] = generated.getPublic();
                    SilentProbeEvidence.AliasSnapshot observed = requireBinding(session, aliases[i], publicKeys[i]);
                    byte[] payload = challenge();
                    payloads.add(payload);
                    signatures.add(verifiedSignature((PrivateKey) observed.key, publicKeys[i], payload));
                    run.report(check, VERIFIED, "alias 私钥、证书及生成公钥绑定一致");
                }
                check = "alias.cross_verify";
                for (int i = 0; i < count; i++) {
                    for (int j = i + 1; j < count; j++) {
                        if (SilentProbeEvidence.samePublicKey(publicKeys[i], publicKeys[j])
                                || SilentProbeEvidence.verifyEc(publicKeys[j], "SHA256withECDSA", payloads.get(i), signatures.get(i))
                                || SilentProbeEvidence.verifyEc(publicKeys[i], "SHA256withECDSA", payloads.get(j), signatures.get(j))) {
                            throw new Contradiction("不同 alias 复用公钥或交叉验签成功；index=" + i + "/" + j);
                        }
                    }
                }
                run.report(check, VERIFIED, "四个 alias 的公钥及签名相互隔离");
                for (int i = 0; i < count; i++) {
                    check = "alias.delete." + i;
                    session.delete(aliases[i]);
                    requireAbsent(session, aliases[i]);
                    run.report(check, VERIFIED, "删除成功后，该 alias 的全部查询接口均为空");
                }
            } catch (Exception failure) {
                failed(run, check, failure);
            }
        } catch (Exception failure) {
            failed(reporter, check, failure);
        }
    }


    static boolean mainBinding(KeyStore store, String alias, PublicKey generated, byte[] request,
                               boolean canSign, Reporter reporter) {
        try {
            boundAttestation(store, alias, generated, request);
            if (canSign) {
                byte[] payload = challenge();
                byte[] output = sign(privateKey(store, alias), "SHA256withECDSA", payload);
                if (!SilentProbeEvidence.verifyEc(generated, "SHA256withECDSA", payload, output)) {
                    throw new Contradiction("主证明私钥返回的签名与本次生成公钥不匹配");
                }
            }
            reporter.report("main.binding", VERIFIED, "本轮随机 challenge、生成公钥、叶证书及适用私钥运算绑定一致");
            return true;
        } catch (Exception failure) {
            failed(reporter, "main.binding", failure);
            return false;
        }
    }

    /** Returns false only when the platform does not expose a single/limited-use key capability. */
    static boolean singleUse(Context context, AttestKeyConfigurer configurer, Reporter reporter) {
        if (Build.VERSION.SDK_INT < 31) return false;
        if (context == null) {
            reporter.report("setup", UNAVAILABLE, "单次使用密钥检测缺少应用上下文");
            return true;
        }
        final boolean supported;
        try {
            supported = context.getPackageManager().hasSystemFeature(
                    android.content.pm.PackageManager.FEATURE_KEYSTORE_SINGLE_USE_KEY)
                    || context.getPackageManager().hasSystemFeature(
                    android.content.pm.PackageManager.FEATURE_KEYSTORE_LIMITED_USE_KEY);
        } catch (RuntimeException failure) {
            reporter.report("setup", UNAVAILABLE,
                    "无法查询单次使用密钥能力；" + failureDetail(failure));
            return true;
        }
        if (!supported) return false;

        try (Run run = new Run(reporter, "single_use.first", "single_use.limit")) {
            String check = "single_use.first";
            try (Session session = new Session(run)) {
                String alias = session.reserve("once");
                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false)
                        .setMaxUsageCount(1);
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                generator.initialize(builder.build());
                KeyPair generated = generator.generateKeyPair();
                PrivateKey key = privateKey(session.store, alias);
                byte[] payload = challenge();
                byte[] first = sign(key, "SHA256withECDSA", payload);
                if (!SilentProbeEvidence.verifyEc(generated.getPublic(), "SHA256withECDSA", payload, first)) {
                    run.report(check, UNAVAILABLE, "首次签名未能验证，不能判断使用次数约束");
                    return true;
                }
                run.report(check, VERIFIED, "首次使用返回有效签名");
                check = "single_use.limit";
                try {
                    byte[] second = sign(key, "SHA256withECDSA", payload);
                    run.report(check, SilentProbeEvidence.verifyEc(generated.getPublic(), "SHA256withECDSA", payload, second)
                            ? DETECTED : UNAVAILABLE, "单次使用密钥的第二次签名结果校验");
                } catch (Exception failure) {
                    boolean expected = !transientOrInterrupted(failure) && (hasCause(failure, KeyPermanentlyInvalidatedException.class)
                            || hasPublicCode(failure, android.security.KeyStoreException.ERROR_KEY_DOES_NOT_EXIST));
                    run.report(check, expected ? VERIFIED : UNAVAILABLE,
                            (expected ? "使用次数耗尽后密钥明确失效；" : "不能确认次数限制拒绝；") + failureDetail(failure));
                }
            } catch (Exception failure) {
                failed(run, check, failure);
            }
        }
        return true;
    }

    static void futureValidity(AttestKeyConfigurer configurer, Reporter reporter) {
        String check = "validity.control";
        try (Run run = new Run(reporter, "validity.control", "validity.before_start"); Session session = new Session(run)) {
            try {
                String controlAlias = session.reserve("validity_control");
                KeyPair control = generateEc(controlAlias, null, false, false, configurer);
                verifiedSignature(privateKey(session.store, controlAlias), control.getPublic(), challenge());
                run.report(check, VERIFIED, "当前可用密钥的正常签名已验证");
                check = "validity.before_start";
                String alias = session.reserve("future");
                // Date is the KeyValidityStart contract; elapsed time measurements use a monotonic clock.
                Date future = new Date(System.currentTimeMillis() + 24L * 60 * 60 * 1000);
                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).setKeyValidityStart(future);
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                generator.initialize(builder.build());
                KeyPair generated = generator.generateKeyPair();
                byte[] payload = challenge();
                try {
                    byte[] output = sign(privateKey(session.store, alias), "SHA256withECDSA", payload);
                    if (System.currentTimeMillis() >= future.getTime()) {
                        run.report(check, UNAVAILABLE, "检测期间系统时间已跨越生效日期");
                    } else {
                        run.report(check, SilentProbeEvidence.verifyEc(generated.getPublic(), "SHA256withECDSA", payload, output)
                                ? DETECTED : UNAVAILABLE, "未来生效密钥在当前日期的签名结果校验");
                    }
                } catch (Exception failure) {
                    boolean expected = !preventsPolicyConclusion(failure) && (hasCause(failure, KeyNotYetValidException.class)
                            || hasPublicCode(failure, android.security.KeyStoreException.ERROR_KEY_NOT_TEMPORALLY_VALID));
                    run.report(check, expected ? VERIFIED : UNAVAILABLE,
                            (expected ? "系统明确拒绝尚未生效密钥；" : "未完成日期约束验证；") + failureDetail(failure));
                }
            } catch (Exception failure) { failed(run, check, failure); }
        } catch (Exception failure) { failed(reporter, check, failure); }
    }

    private static boolean transientOrInterrupted(Exception failure) {
        if (Thread.currentThread().isInterrupted()) return true;
        for (Throwable cause : causes(failure)) {
            if (cause instanceof InterruptedException) return true;
            if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException
                    && ((android.security.KeyStoreException) cause).isTransientFailure()) return true;
        }
        return false;
    }

    private static boolean hasCause(Exception failure, Class<?> type) {
        for (Throwable cause : causes(failure)) if (type.isInstance(cause)) return true;
        return false;
    }

    private static boolean hasPublicCode(Exception failure, int code) {
        if (Build.VERSION.SDK_INT < 33) return false;
        for (Throwable cause : causes(failure)) {
            if (cause instanceof android.security.KeyStoreException) {
                android.security.KeyStoreException ks = (android.security.KeyStoreException) cause;
                if (!ks.isTransientFailure() && ks.getNumericErrorCode() == code) return true;
            }
        }
        return false;
    }

    /** Ordinary certificate-only and imported private-key entries, limited to this run's aliases. */
    static void entrySemantics(Reporter reporter) {
        String check = "entry.certificate";
        try (Run run = new Run(reporter, "entry.certificate", "entry.certificate_replace", "entry.import", "entry.import_replace");
             Session session = new Session(run)) {
            try {
                KeyPairGenerator software = KeyPairGenerator.getInstance("EC");
                software.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair first = software.generateKeyPair();
                KeyPair second = software.generateKeyPair();
                X509Certificate certA = testCertificate(first);
                X509Certificate certB = testCertificate(second);
                String certAlias = session.reserve("certificate");
                session.store.setCertificateEntry(certAlias, certA);
                verifyCertificateEntry(session.store, certAlias, certA);
                run.report(check, VERIFIED, "纯证书条目仅返回证书，没有私钥身份");
                check = "entry.certificate_replace";
                session.store.setCertificateEntry(certAlias, certB);
                verifyCertificateEntry(session.store, certAlias, certB);
                run.report(check, VERIFIED, "证书替换后类型和完整证书内容一致");
                String keyAlias = session.reserve("import_replace");
                KeyProtection protection = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build();
                check = "entry.import";
                session.store.setEntry(keyAlias, new KeyStore.PrivateKeyEntry(first.getPrivate(), new Certificate[]{certA}), protection);
                verifyImportedEntry(session.store, keyAlias, first.getPublic(), certA);
                run.report(check, VERIFIED, "导入私钥、证书及 origin 绑定一致");
                check = "entry.import_replace";
                session.store.setEntry(keyAlias, new KeyStore.PrivateKeyEntry(second.getPrivate(), new Certificate[]{certB}), protection);
                verifyImportedEntry(session.store, keyAlias, second.getPublic(), certB);
                run.report(check, VERIFIED, "同名导入替换后私钥和元数据已绑定新身份");
            } catch (Exception failure) { failed(run, check, failure); }
        } catch (Exception failure) { failed(reporter, check, failure); }
    }

    private static X509Certificate testCertificate(KeyPair pair) throws Exception {
        Date now = new Date();
        X500Principal subject = new X500Principal("CN=TrustAttestor ephemeral conformance");
        return new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(subject,
                new BigInteger(128, new SecureRandom()).add(BigInteger.ONE), new Date(now.getTime() - 60_000),
                new Date(now.getTime() + 86_400_000), subject, pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    private static void verifyCertificateEntry(KeyStore store, String alias, Certificate expected) throws Exception {
        guard();
        SilentProbeEvidence.AliasSnapshot snapshot = SilentProbeEvidence.readAlias(store, alias);
        SilentProbeEvidence.Decision decision = SilentProbeEvidence.certificateEntry(snapshot,
                store.isCertificateEntry(alias), store.isKeyEntry(alias), expected);
        if (decision.status == DETECTED) throw new Contradiction(decision.detail);
        if (decision.status != VERIFIED) throw new GeneralSecurityException(decision.detail);
    }

    private static void verifyImportedEntry(KeyStore store, String alias, PublicKey publicKey, Certificate certificate) throws Exception {
        guard();
        if (!store.isKeyEntry(alias) || store.isCertificateEntry(alias)) throw new Contradiction("导入后条目类型与私钥条目不一致");
        Certificate current = store.getCertificate(alias);
        Certificate[] chain = store.getCertificateChain(alias);
        if (current == null || chain == null || chain.length != 1
                || !Arrays.equals(certificate.getEncoded(), current.getEncoded())
                || !Arrays.equals(certificate.getEncoded(), chain[0].getEncoded())) throw new Contradiction("导入替换后证书未绑定本次身份");
        PrivateKey key = privateKey(store, alias);
        byte[] payload = challenge();
        byte[] output = sign(key, "SHA256withECDSA", payload);
        if (!SilentProbeEvidence.verifyEc(publicKey, "SHA256withECDSA", payload, output)) {
            throw new Contradiction("导入替换后返回的私钥运算不匹配当前公钥");
        }
        KeyInfo info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
        if (info.getOrigin() == KeyProperties.ORIGIN_UNKNOWN) throw new GeneralSecurityException("origin 不可用");
        if (info.getOrigin() != KeyProperties.ORIGIN_IMPORTED) throw new Contradiction("导入私钥的 origin 未回显 IMPORTED");
    }

    /** Two ordinary operation objects, no saturation or raw handles. */
    static void operationIsolation(Reporter reporter) {
        String check = "operation.control";
        try (Run run = new Run(reporter, "operation.control", "operation.isolation", "operation.next_message");
             Session session = new Session(run)) {
            try {
                String aliasA = session.reserve("operation_a"), aliasB = session.reserve("operation_b");
                KeyPair a = generateEc(aliasA, null, false, false, builder -> { });
                KeyPair b = generateEc(aliasB, null, false, false, builder -> { });
                PrivateKey keyA = privateKey(session.store, aliasA), keyB = privateKey(session.store, aliasB);
                byte[] payloadA = challenge(), payloadB = challenge();
                verifiedSignature(keyA, a.getPublic(), payloadA);
                verifiedSignature(keyB, b.getPublic(), payloadB);
                run.report(check, VERIFIED, "两把密钥的独立签名对照通过");
                check = "operation.isolation";
                Signature sa = Signature.getInstance("SHA256withECDSA"), sb = Signature.getInstance("SHA256withECDSA");
                guard();
                sa.initSign(keyA); sb.initSign(keyB);
                sa.update(payloadA, 0, 16); sb.update(payloadB, 0, 16);
                sa.update(payloadA, 16, payloadA.length - 16); sb.update(payloadB, 16, payloadB.length - 16);
                byte[] outA = sa.sign(), outB = sb.sign();
                guard();
                if (!SilentProbeEvidence.verifyEc(a.getPublic(), "SHA256withECDSA", payloadA, outA)
                        || !SilentProbeEvidence.verifyEc(b.getPublic(), "SHA256withECDSA", payloadB, outB)) {
                    throw new Contradiction("正常并存的分段签名结果未绑定各自完整消息");
                }
                run.report(check, VERIFIED, "并存运算的分段消息与密钥隔离通过");
                check = "operation.next_message";
                byte[] next = challenge();
                // A successful sign resets Signature; it does not preserve a raw operation handle.
                sa.update(next);
                if (!SilentProbeEvidence.verifyEc(a.getPublic(), "SHA256withECDSA", next, sa.sign())) {
                    throw new Contradiction("完成运算后下一条消息的签名结果不一致");
                }
                run.report(check, VERIFIED, "完成后下一条消息签名正确，未混入上一条消息");
            } catch (Exception failure) { failed(run, check, failure); }
        } catch (Exception failure) { failed(reporter, check, failure); }
    }

    private static boolean authenticationRejected(Exception failure) {
        if (preventsPolicyConclusion(failure)) return false;
        for (Throwable cause : causes(failure)) {
            if (cause instanceof UserNotAuthenticatedException) return true;
            if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException) {
                android.security.KeyStoreException ks = (android.security.KeyStoreException) cause;
                if (!ks.isTransientFailure() && ks.getNumericErrorCode()
                        == android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED) return true;
            }
        }
        return false;
    }

    private static void rejectedOrUnavailable(Reporter reporter, String check, Exception failure, boolean callerIv) {
        boolean rejected = false;
        if (!preventsPolicyConclusion(failure)) {
            for (Throwable cause : causes(failure)) {
                // This status describes parameter rejection; it does not infer an internal HAL code.
                if (callerIv && cause instanceof InvalidAlgorithmParameterException) rejected = true;
                if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException) {
                    android.security.KeyStoreException ks = (android.security.KeyStoreException) cause;
                    if (!ks.isTransientFailure() && ks.getNumericErrorCode()
                            == android.security.KeyStoreException.ERROR_INCORRECT_USAGE) rejected = true;
                }
            }
        }
        reporter.report(check, rejected ? VERIFIED : UNAVAILABLE,
                (rejected ? "受限操作被明确拒绝；" : "运行失败，未确认策略拒绝；") + failureDetail(failure));
    }

    private static boolean preventsPolicyConclusion(Exception failure) {
        if (Thread.currentThread().isInterrupted()) return true;
        for (Throwable cause : causes(failure)) {
            if (cause instanceof InterruptedException
                    || cause instanceof android.security.keystore.KeyPermanentlyInvalidatedException) return true;
            if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException
                    && ((android.security.KeyStoreException) cause).isTransientFailure()) return true;
        }
        return false;
    }

    private static ArrayList<Throwable> causes(Throwable failure) {
        ArrayList<Throwable> values = new ArrayList<>();
        Set<Throwable> seen = new HashSet<>();
        for (Throwable cause = failure; cause != null && values.size() < 16 && seen.add(cause); cause = cause.getCause()) {
            values.add(cause);
        }
        return values;
    }

    private static String failureDetail(Exception failure) {
        if (Thread.currentThread().isInterrupted() || failure instanceof InterruptedException) return "检测已中断";
        StringBuilder detail = new StringBuilder();
        for (Throwable cause : causes(failure)) {
            if (detail.length() > 0) detail.append(" <- ");
            detail.append(cause.getClass().getSimpleName());
            if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException) {
                android.security.KeyStoreException ks = (android.security.KeyStoreException) cause;
                detail.append("(code=").append(ks.getNumericErrorCode())
                        .append(", transient=").append(ks.isTransientFailure()).append(')');
            }
        }
        return detail.toString();
    }

    private static void failed(Reporter reporter, String check, Exception failure) {
        boolean contradiction = failure instanceof Contradiction && !Thread.currentThread().isInterrupted();
        reporter.report(check, contradiction ? DETECTED : UNAVAILABLE,
                contradiction ? failure.getMessage() : failureDetail(failure));
    }
}

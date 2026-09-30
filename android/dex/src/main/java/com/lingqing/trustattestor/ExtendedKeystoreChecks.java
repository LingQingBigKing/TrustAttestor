package com.lingqing.trustattestor;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;

/** Bounded, silent conformance checks. All keys and messages belong to this invocation. */
final class ExtendedKeystoreChecks {
    private ExtendedKeystoreChecks() { }

    static void run(SilentKeystoreChecks.Reporter reporter) {
        rsaPss(reporter);
        rsaOaep(reporter);
        hmac(reporter);
        ecdh(reporter);
        generatedAes(reporter);
        aesAuthorization(reporter);
    }

    private static final class Run implements AutoCloseable {
        final SilentKeystoreChecks.Reporter reporter;
        final LinkedHashSet<String> pending;
        final LinkedHashSet<String> owned = new LinkedHashSet<>();
        final String family;
        KeyStore store;

        Run(SilentKeystoreChecks.Reporter reporter, String family, String... checks) {
            this.reporter = reporter;
            this.family = family;
            pending = new LinkedHashSet<>(Arrays.asList(checks));
        }

        String alias() throws Exception {
            guard();
            if (store == null) {
                store = KeyStore.getInstance("AndroidKeyStore");
                store.load(null);
            }
            String alias = "TrustAttestor_extended_" + family + "_" + UUID.randomUUID();
            if (store.containsAlias(alias)) throw new GeneralSecurityException("temporary alias collision");
            owned.add(alias);
            return alias;
        }

        void report(String check, SilentProbeEvidence.Status status, String detail) {
            pending.remove(check);
            if (Thread.currentThread().isInterrupted()) {
                reporter.report(check, UNAVAILABLE, "检测已中断");
            } else reporter.report(check, status, detail);
        }

        void unavailable(String check, Exception failure) {
            report(check, UNAVAILABLE, failureDetail(failure));
        }

        @Override public void close() {
            for (String check : pending) reporter.report(check, UNAVAILABLE,
                    Thread.currentThread().isInterrupted() ? "检测已中断" : "前置步骤未完成");
            pending.clear();
            if (store != null) for (String alias : owned) {
                try { store.deleteEntry(alias); }
                catch (Exception failure) { reporter.report(family + ".cleanup", UNAVAILABLE, failureDetail(failure)); }
            }
        }
    }

    private static void guard() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException("silent check interrupted");
    }

    private static byte[] random(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static PrivateKey privateKey(Run run, String alias) throws Exception {
        guard();
        Key key = run.store.getKey(alias, null);
        if (!(key instanceof PrivateKey)) throw new GeneralSecurityException("private key unavailable");
        return (PrivateKey) key;
    }

    private static SecretKey secretKey(Run run, String alias) throws Exception {
        guard();
        Key key = run.store.getKey(alias, null);
        if (!(key instanceof SecretKey)) throw new GeneralSecurityException("secret key unavailable");
        return (SecretKey) key;
    }

    private static String level(Key key) {
        KeyInfo info;
        try {
            info = keyInfo(key);
        } catch (Exception failure) {
            return "KeyInfo=不可用（不推断硬件级别）";
        }
        return describeLevel(info);
    }

    private static KeyInfo keyInfo(Key key) throws Exception {
        if (key instanceof SecretKey) {
            return (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore")
                    .getKeySpec((SecretKey) key, KeyInfo.class);
        }
        return KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore")
                .getKeySpec(key, KeyInfo.class);
    }

    private static String describeLevel(KeyInfo info) {
        if (Build.VERSION.SDK_INT < 31) {
            return info.isInsideSecureHardware()
                    ? "KeyInfo=SecureHardware（未区分 TEE/StrongBox）"
                    : "KeyInfo=Software";
        }
        int level = info.getSecurityLevel();
        if (level == KeyProperties.SECURITY_LEVEL_SOFTWARE) return "KeyInfo=Software";
        if (level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) return "KeyInfo=TEE";
        if (level == KeyProperties.SECURITY_LEVEL_STRONGBOX) return "KeyInfo=StrongBox";
        return "KeyInfo=未知(" + level + ")";
    }

    private static KeyPair rsa(String alias, boolean pss) throws Exception {
        guard();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias,
                pss ? KeyProperties.PURPOSE_SIGN : KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048).setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false);
        if (pss) builder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS);
        else builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
        generator.initialize(builder.build());
        KeyPair pair = generator.generateKeyPair();
        guard();
        return pair;
    }

    private static byte[] signRsa(PrivateKey key, String digest, boolean pss, byte[] message, boolean chunked)
            throws Exception {
        guard();
        Signature signer = Signature.getInstance(digest.replace("-", "") + (pss ? "withRSA/PSS" : "withRSA"));
        // AndroidKeyStore's named PSS implementations fix digest/MGF1/salt. Calling setParameter
        // before initSign may select a software provider or be unsupported by the Keystore SPI.
        // The independent verifier explicitly enforces the intended PSS parameters on the output.
        signer.initSign(key);
        if (chunked) {
            int split = message.length / 2;
            signer.update(message, 0, split);
            guard();
            signer.update(message, split, message.length - split);
        } else signer.update(message);
        byte[] signed = signer.sign();
        guard();
        return signed;
    }

    private static void rsaPss(SilentKeystoreChecks.Reporter reporter) {
        String check = "rsa.pss.control";
        try (Run run = new Run(reporter, "rsa", check, "rsa.pss.chunked", "rsa.pss.digest", "rsa.pss.padding")) {
            try {
                String alias = run.alias();
                KeyPair generated = rsa(alias, true);
                PrivateKey key = privateKey(run, alias);
                byte[] message = random(67);
                byte[] output = signRsa(key, "SHA-256", true, message, false);
                if (!ExtendedProbeEvidence.verifyRsa(generated.getPublic(), "SHA-256", true, message, output)) {
                    run.report(check, UNAVAILABLE, "合法 RSA-PSS 签名未通过独立公钥验证");
                    return;
                }
                run.report(check, VERIFIED, "RSA-PSS SHA-256 已独立验签；MGF1=SHA-256；" + level(key));
                check = "rsa.pss.chunked";
                byte[] chunks = signRsa(key, "SHA-256", true, message, true);
                run.report(check, ExtendedProbeEvidence.verifyRsa(generated.getPublic(), "SHA-256", true, message, chunks)
                        ? VERIFIED : DETECTED, "分段输入的 PSS 签名按完整消息独立验证（不比较随机签名字节）");
                restrictedSign(run, "rsa.pss.digest", generated.getPublic(), key, "SHA-512", true, message);
                restrictedSign(run, "rsa.pss.padding", generated.getPublic(), key, "SHA-256", false, message);
            } catch (Exception failure) { run.unavailable(check, failure); }
        }
    }

    private static void restrictedSign(Run run, String check, PublicKey publicKey, PrivateKey key,
                                       String digest, boolean pss, byte[] message) {
        try {
            byte[] signed;
            try { signed = signRsa(key, digest, pss, message, false); }
            catch (Exception failure) { rejected(run, check, failure); return; }
            boolean verified = ExtendedProbeEvidence.verifyRsa(publicKey, digest, pss, message, signed);
            run.report(check, verified ? DETECTED : UNAVAILABLE,
                    verified ? "仅授权 SHA-256/PSS 的私钥完成了未授权签名，且独立验签成功"
                            : "受限签名返回值无法独立验证");
        } catch (Exception failure) { run.unavailable(check, failure); }
    }

    private static byte[] decryptRsa(PrivateKey key, byte[] ciphertext, String digest, boolean oaep) throws Exception {
        guard();
        Cipher cipher = Cipher.getInstance(oaep ? "RSA/ECB/OAEPPadding" : "RSA/ECB/PKCS1Padding");
        if (oaep) cipher.init(Cipher.DECRYPT_MODE, key, ExtendedProbeEvidence.oaep(digest));
        else cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plaintext = cipher.doFinal(ciphertext);
        guard();
        return plaintext;
    }

    private static void rsaOaep(SilentKeystoreChecks.Reporter reporter) {
        String check = "rsa.oaep.control";
        try (Run run = new Run(reporter, "rsa", check, "rsa.oaep.digest", "rsa.oaep.padding")) {
            try {
                String alias = run.alias();
                KeyPair generated = rsa(alias, false);
                PrivateKey key = privateKey(run, alias);
                byte[] message = random(43);
                byte[] encrypted = ExtendedProbeEvidence.rsaEncrypt(generated.getPublic(), message, "SHA-256", true);
                byte[] plaintext = decryptRsa(key, encrypted, "SHA-256", true);
                if (!MessageDigest.isEqual(message, plaintext)) {
                    run.report(check, UNAVAILABLE, "合法 RSA-OAEP 解密未返回软件公钥加密的原文");
                    return;
                }
                run.report(check, VERIFIED, "软件公钥加密与 Keystore 私钥解密原文一致；OAEP=SHA-256，MGF1=SHA-1；" + level(key));
                restrictedDecrypt(run, "rsa.oaep.digest", generated.getPublic(), key, message, "SHA-1", true);
                restrictedDecrypt(run, "rsa.oaep.padding", generated.getPublic(), key, message, "SHA-256", false);
            } catch (Exception failure) { run.unavailable(check, failure); }
        }
    }

    private static void restrictedDecrypt(Run run, String check, PublicKey publicKey, PrivateKey key,
                                          byte[] message, String digest, boolean oaep) {
        try {
            byte[] encrypted = ExtendedProbeEvidence.rsaEncrypt(publicKey, message, digest, oaep);
            byte[] output;
            try { output = decryptRsa(key, encrypted, digest, oaep); }
            catch (Exception failure) { rejected(run, check, failure); return; }
            boolean matches = output != null && MessageDigest.isEqual(message, output);
            run.report(check, matches ? DETECTED : UNAVAILABLE,
                    matches ? "仅授权 SHA-256/OAEP 的私钥完成了受限解密，原文与独立软件输入一致"
                            : "受限解密返回值不对应原文");
        } catch (Exception failure) { run.unavailable(check, failure); }
    }

    private static void hmac(SilentKeystoreChecks.Reporter reporter) {
        String check = "hmac.reference";
        byte[] material = random(32);
        try (Run run = new Run(reporter, "hmac", check, "hmac.chunked")) {
            try {
                String alias = run.alias();
                run.store.setEntry(alias, new KeyStore.SecretKeyEntry(new SecretKeySpec(material, "HmacSHA256")),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256)
                                .setUserAuthenticationRequired(false).build());
                SecretKey key = secretKey(run, alias);
                byte[] message = random(73);
                byte[] expected = ExtendedProbeEvidence.hmac(material, message);
                guard();
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);
                byte[] actual = mac.doFinal(message);
                guard();
                if (actual == null) {
                    run.report(check, UNAVAILABLE, "HMAC 未返回可比较的结果");
                    return;
                }
                boolean matches = MessageDigest.isEqual(expected, actual);
                run.report(check, matches ? VERIFIED : DETECTED,
                        "本应用导入 HMAC 的完整输出与独立软件参考" + (matches ? "一致" : "不一致") + "；" + level(key));
                if (!matches) return;
                check = "hmac.chunked";
                Mac split = Mac.getInstance("HmacSHA256");
                split.init(key);
                split.update(message, 0, 17);
                guard();
                split.update(message, 17, message.length - 17);
                byte[] chunked = split.doFinal();
                guard();
                run.report(check, MessageDigest.isEqual(expected, chunked) ? VERIFIED : DETECTED,
                        "分段 HMAC 按完整消息与独立参考结果比较");
            } catch (Exception failure) { run.unavailable(check, failure); }
        } finally { Arrays.fill(material, (byte) 0); }
    }

    private static void ecdh(SilentKeystoreChecks.Reporter reporter) {
        String check = "ecdh.reference";
        try (Run run = new Run(reporter, "ecdh", check)) {
            try {
                guard();
                if (Build.VERSION.SDK_INT < 31) {
                    run.report(check, UNAVAILABLE, "Keystore ECDH 需要 Android 12 或更新版本");
                    return;
                }
                String alias = run.alias();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setUserAuthenticationRequired(false).build());
                KeyPair generated = generator.generateKeyPair();
                PrivateKey key = privateKey(run, alias);
                KeyPair peer = ExtendedProbeEvidence.softwareEc();
                KeyPair referencePeer = ExtendedProbeEvidence.softwareEc();
                if (!ExtendedProbeEvidence.sameSecret(ExtendedProbeEvidence.ecdh(peer.getPrivate(), referencePeer.getPublic()),
                        ExtendedProbeEvidence.ecdh(referencePeer.getPrivate(), peer.getPublic()))) {
                    run.report(check, UNAVAILABLE, "软件 ECDH 双侧对照失败");
                    return;
                }
                byte[] expected = ExtendedProbeEvidence.ecdh(peer.getPrivate(), generated.getPublic());
                guard();
                KeyAgreement agreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore");
                agreement.init(key);
                agreement.doPhase(ExtendedProbeEvidence.detached(peer.getPublic()), true);
                byte[] actual = agreement.generateSecret();
                guard();
                if (actual == null) {
                    run.report(check, UNAVAILABLE, "ECDH 未返回可比较的共享秘密");
                    return;
                }
                boolean matches = ExtendedProbeEvidence.sameSecret(expected, actual);
                run.report(check, matches ? VERIFIED : DETECTED,
                        "P-256 ECDH 与独立软件 peer 的完整共享秘密" + (matches ? "一致" : "不一致") + "；" + level(key));
                Arrays.fill(expected, (byte) 0);
                Arrays.fill(actual, (byte) 0);
            } catch (Exception failure) { run.unavailable(check, failure); }
        }
    }

    private static final class GcmRecord {
        final byte[] iv;
        final byte[] ciphertext;
        GcmRecord(byte[] iv, byte[] ciphertext) { this.iv = iv; this.ciphertext = ciphertext; }
    }

    private static GcmRecord gcmEncrypt(SecretKey key, byte[] message, byte[] aad, boolean chunked) throws Exception {
        guard();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key); // A new provider-generated IV for each encryption.
        cipher.updateAAD(aad);
        byte[] ciphertext = ExtendedProbeEvidence.collectCipher(cipher, message, chunked);
        guard();
        GCMParameterSpec actual = cipher.getParameters().getParameterSpec(GCMParameterSpec.class);
        if (actual.getTLen() != 128 || actual.getIV().length != 12)
            throw new GeneralSecurityException("GCM control parameters unavailable or unsupported");
        return new GcmRecord(actual.getIV(), ciphertext);
    }

    private static byte[] gcmDecrypt(SecretKey key, byte[] iv, byte[] ciphertext, byte[] aad, boolean chunked) throws Exception {
        guard();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad);
        byte[] plaintext = ExtendedProbeEvidence.collectCipher(cipher, ciphertext, chunked);
        guard();
        return plaintext;
    }

    private static void generatedAes(SilentKeystoreChecks.Reporter reporter) {
        String check = "aes.generated.control";
        try (Run run = new Run(reporter, "aes", check, "aes.generated.chunked", "aes.generated.aad_integrity",
                "aes.generated.tag_integrity", "aes.generated.recovery")) {
            try {
                String alias = run.alias();
                KeyGenerator generator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
                generator.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(128).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false).build());
                generator.generateKey();
                SecretKey key = secretKey(run, alias);
                byte[] message = random(71);
                byte[] aad = random(29);
                GcmRecord record = gcmEncrypt(key, message, aad, false);
                byte[] normal = gcmDecrypt(key, record.iv, record.ciphertext, aad, false);
                if (!MessageDigest.isEqual(message, normal)) {
                    run.report(check, UNAVAILABLE, "生成 AES 的合法 GCM 往返对照失败");
                    return;
                }
                run.report(check, VERIFIED, "生成 AES 的 GCM/AAD 正常往返通过；" + level(key));
                check = "aes.generated.chunked";
                byte[] segmented = gcmDecrypt(key, record.iv, record.ciphertext, aad, true);
                GcmRecord segmentedEncryption = gcmEncrypt(key, message, aad, true);
                byte[] joined = gcmDecrypt(key, segmentedEncryption.iv, segmentedEncryption.ciphertext, aad, false);
                boolean consistent = MessageDigest.isEqual(message, segmented) && MessageDigest.isEqual(message, joined);
                run.report(check, consistent ? VERIFIED : DETECTED, "分段输出合并后与合法 GCM 完整消息对照比较");
                integrity(run, "aes.generated.aad_integrity", key, record, ExtendedProbeEvidence.changed(aad), message);
                GcmRecord changedTag = new GcmRecord(record.iv, ExtendedProbeEvidence.changed(record.ciphertext));
                integrity(run, "aes.generated.tag_integrity", key, changedTag, aad, message);
                check = "aes.generated.recovery";
                byte[] recovered = gcmDecrypt(key, record.iv, record.ciphertext, aad, false);
                run.report(check, MessageDigest.isEqual(message, recovered) ? VERIFIED : UNAVAILABLE,
                        "完整性检查后使用全新 Cipher 验证原合法输入；恢复失败不单独推断篡改");
            } catch (Exception failure) { run.unavailable(check, failure); }
        }
    }

    private static void integrity(Run run, String check, SecretKey key, GcmRecord record, byte[] aad, byte[] plaintext) {
        try {
            byte[] output = gcmDecrypt(key, record.iv, record.ciphertext, aad, false);
            // Only accept a positive finding when complete authenticated decryption returned the known plaintext.
            boolean matches = MessageDigest.isEqual(plaintext, output);
            run.report(check, matches ? DETECTED : UNAVAILABLE,
                    matches ? "不匹配的 GCM 认证输入被完整解密接受，且返回原合法明文" : "异常输入返回值不对应合法原文");
        } catch (Exception failure) {
            boolean rejected = !preventsConclusion(failure) && causes(failure).stream().anyMatch(t -> t instanceof AEADBadTagException);
            run.report(check, rejected ? VERIFIED : UNAVAILABLE,
                    (rejected ? "GCM 完整性输入被明确拒绝；" : "完整性检查未能完成；") + failureDetail(failure));
        }
    }

    private static void aesAuthorization(SilentKeystoreChecks.Reporter reporter) {
        String check = "aes.authorization.control";
        byte[] material = random(16);
        try (Run run = new Run(reporter, "aes", check, "aes.authorization.mode", "aes.authorization.padding")) {
            try {
                String alias = run.alias();
                run.store.setEntry(alias, new KeyStore.SecretKeyEntry(new SecretKeySpec(material, "AES")),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                                .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false).build());
                SecretKey key = secretKey(run, alias);
                byte[] message = random(32);
                guard();
                Cipher control = Cipher.getInstance("AES/CBC/PKCS7Padding");
                control.init(Cipher.ENCRYPT_MODE, key);
                byte[] output = control.doFinal(message);
                guard();
                if (!ExtendedProbeEvidence.aesMatches(material, "AES/CBC/PKCS7Padding", control.getIV(), output, message)) {
                    run.report(check, UNAVAILABLE, "允许的 CBC/PKCS7 输出未通过独立软件原文验证");
                    return;
                }
                run.report(check, VERIFIED, "已知本应用 AES 材料的 CBC/PKCS7 输出独立验证通过；" + level(key));
                restrictedAes(run, "aes.authorization.mode", key, material, message, "AES/CTR/NoPadding");
                restrictedAes(run, "aes.authorization.padding", key, material, message, "AES/CBC/NoPadding");
            } catch (Exception failure) { run.unavailable(check, failure); }
        } finally { Arrays.fill(material, (byte) 0); }
    }

    private static void restrictedAes(Run run, String check, SecretKey key, byte[] material, byte[] message, String transformation) {
        try {
            Cipher cipher;
            byte[] output;
            try {
                guard();
                cipher = Cipher.getInstance(transformation);
                cipher.init(Cipher.ENCRYPT_MODE, key);
                output = cipher.doFinal(message);
                guard();
            } catch (Exception failure) { rejected(run, check, failure); return; }
            boolean matches = ExtendedProbeEvidence.aesMatches(material, transformation, cipher.getIV(), output, message);
            run.report(check, matches ? DETECTED : UNAVAILABLE,
                    matches ? "仅授权 CBC/PKCS7 的 AES 返回受限模式/填充的有效密文，独立解密确认原文"
                            : "受限 AES 返回值未通过独立原文验证");
        } catch (Exception failure) { run.unavailable(check, failure); }
    }

    private static void rejected(Run run, String check, Exception failure) {
        boolean rejected = false;
        if (!preventsConclusion(failure)) for (Throwable cause : causes(failure)) {
            if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException) {
                android.security.KeyStoreException ks = (android.security.KeyStoreException) cause;
                if (ks.getNumericErrorCode() == android.security.KeyStoreException.ERROR_INCORRECT_USAGE) rejected = true;
            }
        }
        run.report(check, rejected ? VERIFIED : UNAVAILABLE,
                (rejected ? "受限调用被明确拒绝；" : "运行失败，未确认授权拒绝；") + failureDetail(failure));
    }

    private static boolean preventsConclusion(Exception failure) {
        if (Thread.currentThread().isInterrupted()) return true;
        for (Throwable cause : causes(failure)) {
            if (cause instanceof InterruptedException || cause instanceof android.security.keystore.KeyPermanentlyInvalidatedException) return true;
            if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException
                    && ((android.security.KeyStoreException) cause).isTransientFailure()) return true;
        }
        return false;
    }

    private static ArrayList<Throwable> causes(Throwable failure) {
        ArrayList<Throwable> values = new ArrayList<>();
        Set<Throwable> seen = new HashSet<>();
        for (Throwable cause = failure; cause != null && values.size() < 16 && seen.add(cause); cause = cause.getCause()) values.add(cause);
        return values;
    }

    private static String failureDetail(Exception failure) {
        if (Thread.currentThread().isInterrupted() || failure instanceof InterruptedException) return "检测已中断";
        StringBuilder text = new StringBuilder();
        for (Throwable cause : causes(failure)) {
            if (text.length() > 0) text.append(" <- ");
            text.append(cause.getClass().getSimpleName());
            if (Build.VERSION.SDK_INT >= 33 && cause instanceof android.security.KeyStoreException) {
                android.security.KeyStoreException ks = (android.security.KeyStoreException) cause;
                text.append("(code=").append(ks.getNumericErrorCode()).append(", transient=").append(ks.isTransientFailure()).append(')');
            }
        }
        return text.toString();
    }
}

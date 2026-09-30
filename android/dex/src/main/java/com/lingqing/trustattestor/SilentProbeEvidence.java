package com.lingqing.trustattestor;

import java.security.GeneralSecurityException;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Pure Java evidence checks. No Android service calls or exception-to-success conversion. */
final class SilentProbeEvidence {
    private SilentProbeEvidence() { }

    enum Status { VERIFIED, DETECTED, UNAVAILABLE }

    static final class Decision {
        final Status status;
        final String detail;

        Decision(Status status, String detail) {
            this.status = status;
            this.detail = detail;
        }
    }

    /** A null list means unreadable; null fields in a decoded list mean absent tags. */
    static final class AuthFields {
        final Boolean noAuthRequired;
        final Integer authType;
        final Integer timeout;

        AuthFields(Boolean noAuthRequired, Integer authType, Integer timeout) {
            this.noAuthRequired = noAuthRequired;
            this.authType = authType;
            this.timeout = timeout;
        }

        @Override public String toString() {
            return "noAuth=" + noAuthRequired + ", type=" + authType + ", timeout=" + timeout;
        }
    }

    static Decision authentication(AuthFields software, AuthFields hardware, int expectedType) {
        if (software == null || hardware == null) {
            return new Decision(Status.UNAVAILABLE, "认证授权列表未完整解析");
        }
        String fields = "software={" + software + "}, hardware={" + hardware + "}";
        if (Boolean.TRUE.equals(software.noAuthRequired) || Boolean.TRUE.equals(hardware.noAuthRequired)) {
            return new Decision(Status.DETECTED, "请求认证约束却包含 NO_AUTH_REQUIRED；" + fields);
        }
        if (software.authType == null && hardware.authType == null) {
            return new Decision(Status.DETECTED, "已解析的两份授权列表均缺少请求所需的 USER_AUTH_TYPE；" + fields);
        }
        for (AuthFields field : new AuthFields[]{software, hardware}) {
            if (field.authType != null && field.authType != expectedType) {
                return new Decision(Status.DETECTED, "USER_AUTH_TYPE 与本次请求不一致；expected="
                        + expectedType + "; " + fields);
            }
            // An omitted AUTH_TIMEOUT is per-operation authentication, not an unreadable value.
            if (field.timeout != null && field.timeout != 0) {
                return new Decision(Status.DETECTED, "每次操作认证请求却返回非零 AUTH_TIMEOUT；" + fields);
            }
        }
        return new Decision(Status.VERIFIED, "本次认证请求与证明授权字段一致；" + fields);
    }

    static Decision unlockedDeviceField(boolean listsDecoded, int attestationVersion,
                                        Boolean software, Boolean hardware) {
        if (attestationVersion < 3) {
            return new Decision(Status.VERIFIED,
                    "不适用：当前证明版本不支持 UNLOCKED_DEVICE_REQUIRED");
        }
        if (!listsDecoded) {
            return new Decision(Status.UNAVAILABLE,
                    "授权列表未完整解析，无法检查 UNLOCKED_DEVICE_REQUIRED");
        }
        String fields = "software=" + software + ", hardware=" + hardware;
        if (Boolean.TRUE.equals(software) || Boolean.TRUE.equals(hardware)) {
            return new Decision(Status.VERIFIED, "UNLOCKED_DEVICE_REQUIRED 字段已回显；" + fields);
        }
        return new Decision(Status.DETECTED,
                "请求 UNLOCKED_DEVICE_REQUIRED=true，但已解析且支持该字段的证明未包含该约束；" + fields);
    }

    static boolean samePublicKey(PublicKey expected, PublicKey actual) throws GeneralSecurityException {
        return Arrays.equals(encodedPublicKey(expected), encodedPublicKey(actual));
    }

    static boolean isP256(PublicKey key) throws GeneralSecurityException {
        PublicKey detached = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encodedPublicKey(key)));
        if (!(detached instanceof ECPublicKey)) return false;
        ECParameterSpec actual = ((ECPublicKey) detached).getParams();
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
        return expected.getCurve().equals(actual.getCurve()) && expected.getGenerator().equals(actual.getGenerator())
                && expected.getOrder().equals(actual.getOrder()) && expected.getCofactor() == actual.getCofactor();
    }

    static final class AliasSnapshot {
        final boolean contains;
        final boolean enumerated;
        final Key key;
        final Certificate certificate;
        final Certificate[] chain;

        AliasSnapshot(boolean contains, boolean enumerated, Key key, Certificate certificate, Certificate[] chain) {
            this.contains = contains;
            this.enumerated = enumerated;
            this.key = key;
            this.certificate = certificate;
            this.chain = chain;
        }

        boolean absent() {
            return !contains && !enumerated && key == null && certificate == null && (chain == null || chain.length == 0);
        }
    }

    static Decision certificateEntry(AliasSnapshot snapshot, boolean certificateEntry,
                                     boolean keyEntry, Certificate expected) throws GeneralSecurityException {
        if (snapshot == null || expected == null) return new Decision(Status.UNAVAILABLE, "证书条目前置数据不可用");
        boolean valid = snapshot.contains && snapshot.enumerated && certificateEntry && !keyEntry
                && snapshot.key == null && snapshot.chain == null && snapshot.certificate != null
                && Arrays.equals(expected.getEncoded(), snapshot.certificate.getEncoded());
        return new Decision(valid ? Status.VERIFIED : Status.DETECTED,
                valid ? "证书条目类型与内容一致" : "成功查询的证书条目类型、私钥或证书内容不一致");
    }

    /** An observation exists only after every query succeeds. Exceptions never mean absence. */
    static AliasSnapshot readAlias(KeyStore store, String alias) throws GeneralSecurityException {
        boolean contains = store.containsAlias(alias);
        Enumeration<String> aliases = store.aliases();
        if (aliases == null) throw new GeneralSecurityException("alias enumeration unavailable");
        boolean enumerated = false;
        while (aliases.hasMoreElements()) {
            if (alias.equals(aliases.nextElement())) enumerated = true;
        }
        Key key = store.getKey(alias, null);
        Certificate certificate = store.getCertificate(alias);
        Certificate[] chain = store.getCertificateChain(alias);
        return new AliasSnapshot(contains, enumerated, key, certificate, chain);
    }

    private static byte[] encodedPublicKey(PublicKey key) throws GeneralSecurityException {
        if (key == null || key.getEncoded() == null || key.getEncoded().length == 0) {
            throw new GeneralSecurityException("public key encoding unavailable");
        }
        return key.getEncoded();
    }

    static boolean verifyEc(PublicKey publicKey, String algorithm, byte[] payload, byte[] signed)
            throws GeneralSecurityException {
        if (signed == null || signed.length == 0) return false;
        // Detach from AndroidKeyStore key handles before selecting the verifier provider.
        PublicKey detached = KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(encodedPublicKey(publicKey)));
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(detached);
        verifier.update(payload);
        return verifier.verify(signed);
    }

    static boolean verifyGcm(byte[] material, byte[] plaintext, byte[] ciphertext, GCMParameterSpec actual)
            throws GeneralSecurityException {
        if (ciphertext == null || actual == null || actual.getIV().length == 0) return false;
        Cipher reference = Cipher.getInstance("AES/GCM/NoPadding");
        reference.init(Cipher.DECRYPT_MODE, new SecretKeySpec(material, "AES"), actual);
        return Arrays.equals(plaintext, reference.doFinal(ciphertext));
    }
}

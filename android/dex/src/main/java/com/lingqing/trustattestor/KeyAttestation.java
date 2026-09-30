package com.lingqing.trustattestor;

import static io.github.vvb2060.keyattestation.attestation.CertificateInfo.parseCertificateChain;
import static io.github.vvb2060.keyattestation.attestation.RootOfTrust.KM_VERIFIED_BOOT_VERIFIED;
import static io.github.vvb2060.keyattestation.attestation.RootOfTrust.verifiedBootStateToString;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;
import android.os.IBinder;
import android.os.IInterface;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.security.KeyStoreException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProtection;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.Log;
import android.util.Base64;

import com.google.common.io.BaseEncoding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.MessageDigest;
import java.security.KeyStore;
import java.security.Signature;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
// import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Objects;
import java.util.function.Supplier;

import javax.crypto.Cipher;

import io.github.vvb2060.keyattestation.attestation.Attestation;
import io.github.vvb2060.keyattestation.attestation.AttestationResult;
import io.github.vvb2060.keyattestation.attestation.AuthorizationList;
import io.github.vvb2060.keyattestation.attestation.CertificateInfo;
import io.github.vvb2060.keyattestation.attestation.RootOfTrust;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;

import javax.security.auth.x500.X500Principal;

public class KeyAttestation {
    public static String TAG = "TrustAttestorLog";
    private enum ProbeApplicability { APPLICABLE, NOT_APPLICABLE }
    private static final String ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int ATTESTATION_APPLICATION_ID_TAG = 709;
    private static final long FLAG_MAIN_CHAIN_SERVICE = 1L << 0;
    private static final long FLAG_ATTEST_CHAIN_SERVICE = 1L << 1;
    private static final long FLAG_ATTEST_CHAIN_READ = 1L << 2;
    private static final long FLAG_MAIN_CHAIN_STRUCTURE = 1L << 3;
    private static final long FLAG_ATTEST_CHAIN_STRUCTURE = 1L << 4;
    private static final long FLAG_KEYBOX_SUBJECT = 1L << 5;
    private static final long FLAG_ROOT_OF_TRUST_MISSING = 1L << 6;
    private static final long FLAG_VBMETA_DIGEST = 1L << 7;
    private static final long FLAG_VERIFIED_BOOT_STATE =
            AttestationVerdictEvidence.FLAG_VERIFIED_BOOT_STATE;
    private static final long FLAG_KEYINFO_HW = 1L << 9;
    private static final long FLAG_KEYINFO_ERROR = 1L << 10;
    private static final long FLAG_EMBEDDED_ATTEST = 1L << 11;
    private static final long FLAG_LONG_CHALLENGE = 1L << 12;
    private static final long FLAG_ATTEST_KEY_DESCRIPTOR_DELEGATION = 1L << 13;
    private static final long FLAG_ATTESTATION_TRUST =
            AttestationVerdictEvidence.FLAG_TRUST_VALIDATION;
    private static final long FLAG_ATTESTATION_SECURITY_LEVEL =
            AttestationVerdictEvidence.FLAG_SECURITY_LEVEL;

    private static final long FLAG_ATTEST_CROSS_SIGN = 1L << 16;
    private static final long FLAG_ATTEST_GRAPH = 1L << 17;
    private static final long FLAG_ATTEST_TRAP = 1L << 18;
    private static final long FLAG_KEYSTORE_STATE = 1L << 19;
    private static final long FLAG_ALIAS_CROSSTALK = 1L << 20;
    private static final long FLAG_CHALLENGE_REPLAY = 1L << 21;
    private static final long FLAG_NULL_CHALLENGE = 1L << 22;
    private static final long FLAG_ATTEST_NEGATIVE = 1L << 23;
    private static final long FLAG_CTS_LEAF = 1L << 24;
    private static final long FLAG_APP_ID = 1L << 25;
    private static final long FLAG_TIMING_SIDE_CHANNEL = 1L << 26;
    private static final long FLAG_METADATA_AUTH = 1L << 27;
    private static final long FLAG_IMPORT_KEY = 1L << 28;
    private static final long FLAG_PATCH_LEVEL = 1L << 29;
    private static final long FLAG_USER_AUTH = 1L << 30;
    private static final long FLAG_SINGLE_USE = 1L << 31;
    private static final long FLAG_FUTURE_VALIDITY = 1L << 32;
    private static final long FLAG_RUNTIME_ERROR = 1L << 33;
    private static final long FLAG_UNIQUE_ID_BYPASS = 1L << 34;
    private static final long FLAG_USER_AUTH_METADATA = 1L << 35;
    private static final long FLAG_SIGNING_LINEAGE = 1L << 36;
    private static final long FLAG_OPERATION_SEMANTICS = 1L << 37;
    // Cross-source checks added for software KeyMint implementations that can
    // present a coherent-looking certificate for a single algorithm only.
    private static final long FLAG_DEVICE_PROPERTIES = 1L << 38;
    private static final long FLAG_ALGORITHM_DIFFERENTIAL = 1L << 39;
    private static final long FLAG_STRONGBOX_DIFFERENTIAL = 1L << 40;
    private static final long FLAG_KEYMINT_BOUNDARY = 1L << 41;
    private static final long FLAG_CERT_VALIDITY = 1L << 42;
    // Bit 43 is reserved by the native build-fingerprint check.
    private static final long FLAG_RSA_CONFORMANCE = 1L << 44;
    private static final long FLAG_HMAC_CONFORMANCE = 1L << 45;
    private static final long FLAG_ECDH_CONFORMANCE = 1L << 46;
    private static final long FLAG_AES_CONFORMANCE = 1L << 47;
    private static final long FLAG_ENTRY_SEMANTICS = 1L << 48;
    private static final long FLAG_MAIN_BINDING = 1L << 49;
    private static final long FLAG_OPERATION_ISOLATION = 1L << 50;
    private static final long FLAG_ISOLATED_CHAIN = 1L << 51;
    private static final long FLAG_CHAIN_READ_STABILITY = 1L << 52;
    private static final long FLAG_CERTIFICATE_ROUND_TRIP = 1L << 53;
    private static final long FLAG_BINDER_LOCALITY = 1L << 54;
    private static final long FLAG_INTERFACE_TOKEN_DISPATCH = 1L << 55;
    private static final long FLAG_PARAMETER_FINGERPRINT = 1L << 56;
    private static final long FLAG_TEESIM_PARAMETER_FINGERPRINT = 1L << 57;
    private static final long FLAG_REPLY_LAG = 1L << 58;
    private static final long FLAG_READ_PATH_TIMING = 1L << 59;
    private static final long FLAG_KEY_ID_CONSISTENCY = 1L << 60;
    private static final long FLAG_KEYSTORE_LEDGER = 1L << 61;
    private static final String PROBE_METADATA_SECURITY_LEVEL =
            "hardware.attestation.metadata_security_level.unavailable";
    private static final String PROBE_BINDER_LOCALITY =
            "hardware.attestation.binder_locality.unavailable";
    private static final String PROBE_INTERFACE_TOKEN_DISPATCH =
            "hardware.attestation.interface_token_dispatch.unavailable";
    private static final String PROBE_PARAMETER_FINGERPRINT =
            "hardware.attestation.parameter_fingerprint.unavailable";
    private static final String PROBE_TEESIM_PARAMETER_FINGERPRINT =
            "hardware.attestation.teesim_parameter_fingerprint.unavailable";
    private static final String PROBE_REPLY_LAG =
            "hardware.attestation.reply_lag.unavailable";
    private static final String PROBE_READ_PATH_TIMING =
            "hardware.attestation.read_path_timing.unavailable";
    private static final String PROBE_KEY_ID_CONSISTENCY =
            "hardware.attestation.key_id_consistency.unavailable";
    private static final String PROBE_KEYSTORE_LEDGER =
            "hardware.attestation.keystore_ledger.unavailable";
    private static final String PROBE_ATTEST_KEY_DESCRIPTOR_DELEGATION =
            "hardware.attestation.attest_key_descriptor_delegation.unavailable";
    // PackageManager.FEATURE_DEVICE_ID_ATTESTATION is hidden through API 35,
    // but the feature-string contract has been stable since ID attestation was added.
    private static final String FEATURE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";

    private static String unavailableProbeIdForFlag(long flag) {
        if (flag == FLAG_ATTEST_KEY_DESCRIPTOR_DELEGATION) {
            return PROBE_ATTEST_KEY_DESCRIPTOR_DELEGATION;
        }
        if (flag == FLAG_ATTEST_CROSS_SIGN) return "hardware.attestation.cross_sign.unavailable";
        if (flag == FLAG_ATTEST_GRAPH) return "hardware.attestation.certificate_graph.unavailable";
        if (flag == FLAG_ATTEST_TRAP) return "hardware.attestation.trap_probe.unavailable";
        if (flag == FLAG_KEYSTORE_STATE) return "hardware.attestation.keystore_state_machine.unavailable";
        if (flag == FLAG_ALIAS_CROSSTALK) return "hardware.attestation.alias_cross_talk.unavailable";
        if (flag == FLAG_CHALLENGE_REPLAY) return "hardware.attestation.challenge_replay.unavailable";
        if (flag == FLAG_NULL_CHALLENGE) return "hardware.attestation.null_challenge.unavailable";
        if (flag == FLAG_ATTEST_NEGATIVE) return "hardware.attestation.negative_probe.unavailable";
        if (flag == FLAG_CTS_LEAF) return "hardware.attestation.leaf_constraints.unavailable";
        if (flag == FLAG_APP_ID) return "hardware.attestation.application_id.unavailable";
        if (flag == FLAG_METADATA_AUTH) return "hardware.attestation.key_metadata.unavailable";
        if (flag == FLAG_IMPORT_KEY) return "hardware.attestation.imported_key.unavailable";
        if (flag == FLAG_PATCH_LEVEL) return "hardware.attestation.patch_level.unavailable";
        if (flag == FLAG_USER_AUTH) return "hardware.attestation.user_auth_policy.unavailable";
        if (flag == FLAG_SINGLE_USE) return "hardware.attestation.single_use_policy.unavailable";
        if (flag == FLAG_FUTURE_VALIDITY) return "hardware.attestation.future_validity_policy.unavailable";
        if (flag == FLAG_UNIQUE_ID_BYPASS) return "hardware.attestation.unique_id_permission.unavailable";
        if (flag == FLAG_USER_AUTH_METADATA) return "hardware.attestation.user_auth_metadata.unavailable";
        if (flag == FLAG_SIGNING_LINEAGE) return "hardware.attestation.signing_lineage.unavailable";
        if (flag == FLAG_OPERATION_SEMANTICS) return "hardware.attestation.operation_semantics.unavailable";
        if (flag == FLAG_DEVICE_PROPERTIES) return "hardware.attestation.device_properties.unavailable";
        if (flag == FLAG_ALGORITHM_DIFFERENTIAL) return "hardware.attestation.algorithm_differential.unavailable";
        if (flag == FLAG_STRONGBOX_DIFFERENTIAL) return "hardware.attestation.strongbox_differential.unavailable";
        if (flag == FLAG_KEYMINT_BOUNDARY) return "hardware.attestation.keymint_boundary.unavailable";
        if (flag == FLAG_RSA_CONFORMANCE) return "hardware.attestation.rsa_conformance.unavailable";
        if (flag == FLAG_HMAC_CONFORMANCE) return "hardware.attestation.hmac_conformance.unavailable";
        if (flag == FLAG_ECDH_CONFORMANCE) return "hardware.attestation.ecdh_conformance.unavailable";
        if (flag == FLAG_AES_CONFORMANCE) return "hardware.attestation.aes_conformance.unavailable";
        if (flag == FLAG_ENTRY_SEMANTICS) return "hardware.attestation.entry_semantics.unavailable";
        if (flag == FLAG_MAIN_BINDING) return "hardware.attestation.main_binding.unavailable";
        if (flag == FLAG_OPERATION_ISOLATION) return "hardware.attestation.operation_isolation.unavailable";
        return null;
    }
    private static volatile int lastIsolatedChainStatus = 7;
    // Two 2-bit states: read consistency, then round trip. 0=verified, 1=detected,
    // 2=unavailable, 3=not run. Cleanup cannot erase a confirmed contradiction.
    private static volatile int lastCertificateRecordStatus = 15;
    // 0=completed, 1=detected, 2=unavailable, 3=not run.
    private static volatile int lastTimingProbeStatus = 3;
    private static final long FLAG_UNKNOWN = 1L << 62;

    private static final Map<String, Certificate[]> ks2GeneratedCertificateChain = new HashMap<>();
    private static final Map<String, Certificate[]> ks2CertificateChain = new HashMap<>();
    private static final Map<String, KeyMetadata> ks2GeneratedMetadata = new HashMap<>();
    private static final Map<String, KeyMetadata> ks2EntryMetadata = new HashMap<>();
    private static final Map<String, byte[]> ks1Certificates = new HashMap<>();

    private static boolean useKs2 = true;

    private static final String alias = "TrustAttestor";
    private static final String attestAlias = alias + "_persistent";

    private static boolean hasAttestKey = false;
    /** True only after the per-scan App AttestKey was actually generated. */
    private static boolean attestAliasReady = false;

    private static final String EMBEDDED_FAKE_ATTEST_KEY_B64 =
            "MHcCAQEEIOdY+b8FqRVCvRnubq1V/yjdCn5oYRZO3Gm6DhlogiDFoAoGCCqGSM49AwEHoUQDQgAEzqASW1XuU+ru4xr7Z+9kJQ+pvd2aCJ7lbKPRDe8TmjdNzmtOdQ8oTxUZ8oqVgBMRBFgQVvpIq14uR3EKuJR70Q==";

    private static final String EMBEDDED_FAKE_ATTEST_CERT_B64 =
            "MIICBzCCAa2gAwIBAgIUEapMlNL73USuoqfWhn00uiax9XIwCgYIKoZIzj0EAwIwWDELMAkGA1UEBhMCQ04xETAPBgNVBAoMCExpbmdRaW5nMREwDwYDVQQDDAhMaW5nUWluZzEjMCEGCSqGSIb3DQEJARYUbGluZ19xaW5nX2xxQDE2My5jb20wIBcNMjUxMDE4MTIwMjM0WhgPMjEyNTA5MjQxMjAyMzRaMFgxCzAJBgNVBAYTAkNOMREwDwYDVQQKDAhMaW5nUWluZzERMA8GA1UEAwwITGluZ1FpbmcxIzAhBgkqhkiG9w0BCQEWFGxpbmdfcWluZ19scUAxNjMuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzqASW1XuU+ru4xr7Z+9kJQ+pvd2aCJ7lbKPRDe8TmjdNzmtOdQ8oTxUZ8oqVgBMRBFgQVvpIq14uR3EKuJR70aNTMFEwHQYDVR0OBBYEFCzCEk65Qdpfq8+ZolOsCAaxc61GMB8GA1UdIwQYMBaAFCzCEk65Qdpfq8+ZolOsCAaxc61GMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgYu1DbBbNmvLLnILOvTR8aCVGZTgeEPn5C/iPdLrKLrACIQC0Fx6wFyFkFmHzWuORq8lDTDrL4MEuisdCA6xGO1TQlg==";

    private static volatile Context appContext;
    private static volatile long lastProbeFlags;
    private static volatile String[] lastUnavailableProbeIds = new String[0];
    private static final String PREF_NAME = "trust_attestor_shared_data";
    private static final ThreadLocal<KeyStore> ACTIVE_KEY_STORE = new ThreadLocal<>();
    private static final Object RUN_LOCK = new Object();
    private static final ThreadLocal<Map<String, GeneratedKeyBinding>> ACTIVE_BINDINGS =
            ThreadLocal.withInitial(HashMap::new);

    private static final class GeneratedKeyBinding {
        final java.security.PublicKey publicKey;
        final byte[] challenge;
        GeneratedKeyBinding(java.security.PublicKey publicKey, byte[] challenge) {
            this.publicKey = publicKey;
            this.challenge = challenge.clone();
        }
    }
    private static final ThreadLocal<Object> ACTIVE_PROGRESS_CALLBACK = new ThreadLocal<>();
    private static final ThreadLocal<Method> ACTIVE_PROGRESS_METHOD = new ThreadLocal<>();

    private static PrivateKey readPrivateKey(String text) throws Exception {
        byte[] bytes = Base64.decode(text, Base64.DEFAULT);
        ASN1Sequence sequence = ASN1Sequence.getInstance(bytes);
        ECPrivateKey ecKey = ECPrivateKey.getInstance(sequence);
        AlgorithmIdentifier id = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                ecKey.getParameters()
        );
        byte[] data = new PrivateKeyInfo(id, ecKey).getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(data);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    private static Certificate[] readCertificateChain(String text, CertificateFactory factory) throws Exception {
        ArrayList<Certificate> chain = new ArrayList<>();
        byte[] bytes = Base64.decode(text, Base64.DEFAULT);
        chain.add(factory.generateCertificate(new ByteArrayInputStream(bytes)));
        return chain.toArray(new Certificate[0]);
    }

    private static void safeDeleteEntry(KeyStore keyStore, String alias) {
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
            }
        } catch (Throwable t) {
            Log.w(TAG, "safeDeleteEntry failed for alias " + alias, t);
        }
    }

    private static KeyStore acquireKeyStore() throws Exception {
        KeyStore keyStore = ACTIVE_KEY_STORE.get();
        if (keyStore == null) {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            ACTIVE_KEY_STORE.set(keyStore);
        }
        return keyStore;
    }

    private static void postProgress(int permille, String text) {
        Object callback = ACTIVE_PROGRESS_CALLBACK.get();
        Method method = ACTIVE_PROGRESS_METHOD.get();
        if (callback == null || method == null) return;
        try {
            method.invoke(callback, 3, 3, Math.max(0, Math.min(1000, permille)), text);
        } catch (Throwable t) {
            Log.w(TAG, "hardware attestation progress callback failed", t);
        }
    }

    private static X509Certificate asX509Certificate(
            Certificate certificate,
            CertificateFactory factory
    ) throws CertificateException, CertificateEncodingException {
        if (certificate instanceof X509Certificate x509Certificate) {
            return x509Certificate;
        }
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certificate.getEncoded()));
    }

    public static void initSharedData(Context context) {
        if (context != null) {
            appContext = context.getApplicationContext();
        }
    }

    public static boolean setSharedData(String key, String value) {
        var ctx = appContext;
        if (ctx == null || key == null) return false;
        SharedPreferences sp = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return sp.edit().putString(key, value).commit();
    }

    public static String getSharedData(String key) {
        var ctx = appContext;
        if (ctx == null || key == null) return null;
        SharedPreferences sp = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return sp.getString(key, null);
    }

    public static long getLastProbeFlags() {
        return lastProbeFlags;
    }

    /** Stable probe IDs whose individual checks could not reach a verdict. */
    public static String[] getLastUnavailableProbeIds() {
        return lastUnavailableProbeIds.clone();
    }

    public static int getLastIsolatedChainStatus() {
        return lastIsolatedChainStatus;
    }

    public static int getLastCertificateRecordStatus() {
        return lastCertificateRecordStatus;
    }

    public static int getLastTimingProbeStatus() {
        return lastTimingProbeStatus;
    }

    private static void updateKeyAttestationDetail(String detail) {
        setSharedData("key_attestation_detail", detail == null ? "" : detail);
    }

    private static String issuerToString(int status) {
        return switch (status) {
            case CertificateInfo.KEY_GOOGLE -> "Google";
            case CertificateInfo.KEY_GOOGLE_RKP -> "Google RKP";
            case CertificateInfo.KEY_AOSP -> "AOSP";
            case CertificateInfo.KEY_KNOX -> "Knox";
            case CertificateInfo.KEY_OEM -> "OEM";
            case CertificateInfo.KEY_UNKNOWN -> "Unknown";
            default -> "Failed";
        };
    }

    private static String certStatusToString(int status) {
        return switch (status) {
            case CertificateInfo.CERT_SIGN -> "签名校验失败";
            case CertificateInfo.CERT_REVOKED -> "已吊销";
            case CertificateInfo.CERT_EXPIRED -> "有效期异常";
            case CertificateInfo.CERT_UNAVAILABLE -> "吊销状态不可用";
            case CertificateInfo.CERT_NORMAL -> "正常";
            default -> "未知";
        };
    }

    private static String securityLabel(boolean sw) {
        return sw ? "Software" : "TEE / StrongBox";
    }

    private static String buildCertificateChainSummary(AttestationResult result) {
        var certInfos = result.getCerts();
        var attestation = result.showAttestation;
        var rootOfTrust = result.getRootOfTrust();
        var sb = new StringBuilder(1024);
        sb.append("证书链与 Attestation 信息\n");
        sb.append("证书总数：").append(certInfos.size()).append('\n');
        sb.append("根证书来源：").append(issuerToString(result.getIssuer())).append('\n');
        var revocationSnapshot = result.getRevocationSnapshotMetadata();
        if (revocationSnapshot != null) {
            sb.append("吊销数据：").append(revocationSnapshot.source())
                    .append("；时效：").append(revocationSnapshot.freshness())
                    .append("；可用：").append(result.isRevocationStatusAvailable()).append('\n');
            if (revocationSnapshot.retrievedAt() != null) sb.append("吊销缓存时间：").append(revocationSnapshot.retrievedAt()).append('\n');
        }
        for (var info : certInfos) {
            if (info.getValidatedAttestedEntity() != null) sb.append("RKP 认证实体：").append(info.getValidatedAttestedEntity())
                    .append("；来源证书：").append(info.getProvisioningInfoCertificateIndex()).append('\n');
            if (info.getLostDevice() != null) sb.append("RKP 丢失状态记录：").append(info.getLostDevice()).append('\n');
        }
        if (result.getIssuer() == CertificateInfo.KEY_GOOGLE_RKP) {
            sb.append("证明类型：Google Remote Key Provisioning (RKP)\n");
            for (var info : certInfos) {
                if (info.hasProvisioningInfo() && info.getCertsIssued() != null) {
                    sb.append("RKP 已签发证书数：").append(info.getCertsIssued()).append('\n');
                    break;
                }
            }
        }
        if (attestation != null) {
            sb.append("Attestation 版本：")
                    .append(Attestation.attestationVersionToString(attestation.getAttestationVersion()))
                    .append('\n');
            sb.append("Keymaster / KeyMint：")
                    .append(Attestation.keymasterVersionToString(attestation.getKeymasterVersion()))
                    .append('\n');
            sb.append("安全级别：")
                    .append(Attestation.securityLevelToString(attestation.getAttestationSecurityLevel()))
                    .append(" / ")
                    .append(Attestation.securityLevelToString(attestation.getKeymasterSecurityLevel()))
                    .append('\n');
            sb.append("唯一 ID：")
                    .append(attestation.getUniqueId() == null || attestation.getUniqueId().length == 0 ? "(空)" : "存在")
                    .append('\n');
        }
        if (rootOfTrust != null) {
            sb.append("引导加载程序锁定：").append(rootOfTrust.isDeviceLocked() ? "是" : "否").append('\n');
            sb.append("Verified Boot：")
                    .append(verifiedBootStateToString(rootOfTrust.getVerifiedBootState()))
                    .append('\n');
            var vbHash = rootOfTrust.getVerifiedBootHash();
            if (vbHash != null) {
                sb.append("VBMeta Digest：")
                        .append(BaseEncoding.base16().encode(vbHash))
                        .append('\n');
            }
        }
        sb.append('\n').append("证书链：");
        for (int i = 0; i < certInfos.size(); i++) {
            var info = certInfos.get(i);
            var cert = info.getCert();
            sb.append("\n\n#").append(i + 1)
                    .append(i == 0 ? " 根证书" : (i == certInfos.size() - 1 ? " 叶子证书" : " 中间证书"))
                    .append('\n');
            sb.append("使用者：").append(cert.getSubjectX500Principal().getName()).append('\n');
            sb.append("签发者：").append(cert.getIssuerX500Principal().getName()).append('\n');
            sb.append("序列号：").append(cert.getSerialNumber().toString(16)).append('\n');
            sb.append("状态：").append(certStatusToString(info.getStatus())).append('\n');
            if (info.isValidityExempted()) sb.append("日期政策：适用官方旧 factory 根过期豁免，签名和吊销检查仍有效\n");
            sb.append("不早于：").append(cert.getNotBefore()).append('\n');
            sb.append("不晚于：").append(cert.getNotAfter());
        }
        return sb.toString();
    }


    /** Key prefix for CA certificates. */
    public static final String CA_CERTIFICATE = "CACERT_";

    /** Key prefix for user certificates. */
    public static final String USER_CERTIFICATE = "USRCERT_";

    /* Key prefix for user private and secret keys. */
    // public static final String USER_PRIVATE_KEY = "USRPKEY_";

    /** Key prefix for user secret keys.
     *  @deprecated use {@code USER_PRIVATE_KEY} for this category instead.
     */
    @Deprecated
    public static final String USER_SECRET_KEY = "USRSKEY_";


    static X509Certificate toCertificate(byte[] bytes) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Log.w(TAG, "Couldn't parse certificate in keystore", e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Collection<X509Certificate> toCertificates(byte[] bytes) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (Collection<X509Certificate>) certFactory.generateCertificates(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Log.w(TAG, "Couldn't parse certificates in keystore", e);
            return new ArrayList<>();
        }
    }

    @SuppressLint("PrivateApi")
    private static Object createAidlInterfaceCompat(String interfaceClassName, IBinder binder) throws Throwable {
        Throwable proxyError = null;
        Throwable asInterfaceError = null;

        Class<?> interfaceClass = Class.forName(interfaceClassName);

        // 方案 1：旧写法，优先尝试 Stub$Proxy(IBinder)
        try {
            Class<?> proxyClass = Class.forName(interfaceClassName + "$Stub$Proxy");
            var ctor = proxyClass.getDeclaredConstructor(IBinder.class);
            ctor.setAccessible(true);
            Object proxy = ctor.newInstance(binder);
            Log.d(TAG, "createAidlInterfaceCompat: use Stub$Proxy ctor for " + interfaceClassName);
            return proxy;
        } catch (Throwable t) {
            proxyError = t;
            Log.w(TAG, "createAidlInterfaceCompat: Stub$Proxy ctor failed for " + interfaceClassName, t);
        }

        // 方案 2：新写法，尝试 Stub.asInterface(IBinder)
        try {
            Class<?> stubClass = Class.forName(interfaceClassName + "$Stub");
            var asInterface = stubClass.getDeclaredMethod("asInterface", IBinder.class);
            asInterface.setAccessible(true);
            Object iface = asInterface.invoke(null, binder);
            if (iface != null) {
                Log.d(TAG, "createAidlInterfaceCompat: use Stub.asInterface for " + interfaceClassName);
                return iface;
            }
            throw new NullPointerException("Stub.asInterface returned null");
        } catch (Throwable t) {
            asInterfaceError = t;
            Log.w(TAG, "createAidlInterfaceCompat: Stub.asInterface failed for " + interfaceClassName, t);
        }

        // 方案 3：弱兜底，queryLocalInterface
        try {
            var descriptorMethod = interfaceClass.getDeclaredMethod("getInterfaceDescriptor");
            descriptorMethod.setAccessible(true);
            Object descriptorObj = descriptorMethod.invoke(null);
            if (descriptorObj instanceof String descriptor) {
                IInterface local = binder.queryLocalInterface(descriptor);
                if (local != null && interfaceClass.isInstance(local)) {
                    Log.d(TAG, "createAidlInterfaceCompat: use queryLocalInterface for " + interfaceClassName);
                    return local;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "createAidlInterfaceCompat: queryLocalInterface fallback failed for " + interfaceClassName, t);
        }

        NoSuchMethodException finalError = new NoSuchMethodException(
                "Unable to create AIDL interface for " + interfaceClassName
        );
        if (proxyError != null) finalError.addSuppressed(proxyError);
        if (asInterfaceError != null) finalError.addSuppressed(asInterfaceError);
        throw finalError;
    }

    private static boolean hasClass(String name) {
        try {
            Class.forName(name);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    @SuppressLint("PrivateApi")
    @SuppressWarnings("unchecked")
    private static boolean installHookForKs2() {
        try {
            final String interfaceName = "android.system.keystore2.IKeystoreService";
            if (!hasClass(interfaceName)) {
                Log.w(TAG, "ks2 interface class not found: " + interfaceName);
                return false;
            }

            var keyStore2Class = Class.forName(interfaceName);

            var sCache = ServiceManager.class.getDeclaredField("sCache");
            sCache.setAccessible(true);
            var cache = (Map<String, IBinder>) sCache.get(null);

            final String serviceName = "android.system.keystore2.IKeystoreService/default";
            cache.remove(serviceName);

            var binder = ServiceManager.getService(serviceName);
            if (binder == null) {
                Log.e(TAG, "ks2 binder is null");
                return false;
            }
            Keystore2ProbeAccess.publishRawBinder(binder);

            var interfaceStubProxy = createAidlInterfaceCompat(interfaceName, binder);

            ClassLoader proxyLoader = keyStore2Class.getClassLoader();
            if (proxyLoader == null) proxyLoader = ClassLoader.getSystemClassLoader();

            var interfaceProxy = Proxy.newProxyInstance(
                    proxyLoader,
                    new Class[]{keyStore2Class},
                    (proxy, method, args) -> {
                        try {
                            var result = method.invoke(interfaceStubProxy, args);

                            if ("getKeyEntry".equals(method.getName())) {
                                if (!isPrimaryAttestationAlias(args)) return result;
                                var response = (KeyEntryResponse) result;
                                if (response == null || response.metadata == null || response.metadata.certificate == null) {
                                    return result;
                                }

                                var leaf = toCertificate(response.metadata.certificate);
                                Certificate[] chain;
                                if (response.metadata.certificateChain != null) {
                                    var certs = toCertificates(response.metadata.certificateChain);
                                    chain = new Certificate[certs.size() + 1];
                                    int i = 1;
                                    for (X509Certificate cert : certs) {
                                        chain[i++] = cert;
                                    }
                                } else {
                                    chain = new Certificate[1];
                                }
                                chain[0] = leaf;

                                var alias = (KeyDescriptor) args[0];
                                if (alias != null && alias.alias != null) {
                                    ks2CertificateChain.put(alias.alias, chain);
                                    ks2EntryMetadata.put(alias.alias, response.metadata);
                                    Log.d(TAG, "put chain/metadata for alias " + alias.alias);
                                }
                            } else if ("getSecurityLevel".equals(method.getName())) {
                                return installSecurityLevelHookForKs2(result);
                            }

                            return result;
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    }
            );

            var binderProxy = Proxy.newProxyInstance(
                    IBinder.class.getClassLoader(),
                    new Class[]{IBinder.class},
                    (proxy, method, args) -> {
                        if ("queryLocalInterface".equals(method.getName())) {
                            return interfaceProxy;
                        }
                        try {
                            return method.invoke(binder, args);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    }
            );

            cache.put(serviceName, (IBinder) binderProxy);
            Log.d(TAG, "install for ks2 success");
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "failed to install ks2 hook: ", t);
        }
        return false;
    }

    private static Object installSecurityLevelHookForKs2(Object securityLevel) {
        try {
            if (securityLevel == null) return null;

            ClassLoader proxyLoader = securityLevel.getClass().getClassLoader();
            if (proxyLoader == null) proxyLoader = ClassLoader.getSystemClassLoader();

            var interfaceProxy = Proxy.newProxyInstance(
                    proxyLoader,
                    securityLevel.getClass().getInterfaces(),
                    (proxy, method, args) -> {
                        try {
                            var result = method.invoke(securityLevel, args);
                            if ("generateKey".equals(method.getName())) {
                                if (!isPrimaryAttestationAlias(args)) return result;
                                var response = (KeyMetadata) result;
                                if (response == null || response.certificate == null) return result;

                                var leaf = toCertificate(response.certificate);
                                Certificate[] chain;
                                if (response.certificateChain != null) {
                                    var certs = toCertificates(response.certificateChain);
                                    chain = new Certificate[certs.size() + 1];
                                    int i = 1;
                                    for (X509Certificate cert : certs) {
                                        chain[i++] = cert;
                                    }
                                } else {
                                    chain = new Certificate[1];
                                }
                                chain[0] = leaf;

                                var alias = (KeyDescriptor) args[0];
                                if (alias != null && alias.alias != null) {
                                    ks2GeneratedCertificateChain.put(alias.alias, chain);
                                    ks2GeneratedMetadata.put(alias.alias, response);
                                    Log.d(TAG, "put generated chain/metadata for alias " + alias.alias);
                                }
                            } else if ("getSecurityLevel".equals(method.getName())) {
                                return installSecurityLevelHookForKs2(result);
                            }
                            return result;
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    }
            );
            Log.d(TAG, "install hook for ks2 securitylevel success");
            return interfaceProxy;
        } catch (Throwable t) {
            Log.e(TAG, "failed to install securitylevel hook: ", t);
        }
        return securityLevel;
    }

    private static boolean isPrimaryAttestationAlias(Object[] args) {
        if (args == null || args.length == 0 || !(args[0] instanceof KeyDescriptor descriptor)) {
            return false;
        }
        return alias.equals(descriptor.alias) || attestAlias.equals(descriptor.alias);
    }

    @SuppressLint("PrivateApi")
    @SuppressWarnings("unchecked")
    private static boolean installHookForKs1() {
        useKs2 = false;
        try {
            String interfaceName;
            if (hasClass("android.security.keystore.IKeystoreService")) {
                interfaceName = "android.security.keystore.IKeystoreService";
            } else if (hasClass("android.security.IKeystoreService")) {
                interfaceName = "android.security.IKeystoreService";
            } else {
                Log.w(TAG, "ks1 interface class not found");
                return false;
            }

            var keyStoreClass = Class.forName(interfaceName);

            var sCache = ServiceManager.class.getDeclaredField("sCache");
            sCache.setAccessible(true);
            var cache = (Map<String, IBinder>) sCache.get(null);

            final String serviceName = "android.security.keystore";
            cache.remove(serviceName);

            var binder = ServiceManager.getService(serviceName);
            if (binder == null) {
                Log.e(TAG, "ks1 binder is null");
                return false;
            }

            var interfaceStubProxy = createAidlInterfaceCompat(interfaceName, binder);

            ClassLoader proxyLoader = keyStoreClass.getClassLoader();
            if (proxyLoader == null) proxyLoader = ClassLoader.getSystemClassLoader();

            var interfaceProxy = Proxy.newProxyInstance(
                    proxyLoader,
                    new Class[]{keyStoreClass},
                    (proxy, method, args) -> {
                        try {
                            var result = method.invoke(interfaceStubProxy, args);
                            if ("get".equals(method.getName())) {
                                var name = (String) args[0];
                                ks1Certificates.put(name, (byte[]) result);
                                Log.d(TAG, "put for name " + name);
                            }
                            return result;
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    }
            );

            var binderProxy = Proxy.newProxyInstance(
                    IBinder.class.getClassLoader(),
                    new Class[]{IBinder.class},
                    (proxy, method, args) -> {
                        if ("queryLocalInterface".equals(method.getName())) {
                            return interfaceProxy;
                        }
                        try {
                            return method.invoke(binder, args);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    }
            );

            cache.put(serviceName, (IBinder) binderProxy);
            Log.d(TAG, "install for ks1 success");
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "failed to install ks1 hook: ", t);
        }
        return false;
    }

    private static boolean installHook() {
        boolean ks2Ok = false;
        boolean ks1Ok = false;

        if (hasClass("android.system.keystore2.IKeystoreService")) {
            ks2Ok = installHookForKs2();
        }

        if (!ks2Ok && (hasClass("android.security.keystore.IKeystoreService")
                || hasClass("android.security.IKeystoreService"))) {
            ks1Ok = installHookForKs1();
        }

        return ks2Ok || ks1Ok;
    }

    private static boolean compareCerts(Certificate[] cs1, Certificate[] cs2) {
        try {
            if (cs1 == null || cs2 == null || cs1.length != cs2.length) {
                return false;
            }
            for (int i = 0; i < cs1.length; i++) {
                if (cs1[i] == null || cs2[i] == null) return false;
                if (!Arrays.equals(cs1[i].getEncoded(), cs2[i].getEncoded())) return false;
            }
            return true;
        } catch (CertificateEncodingException e) {
            Log.e(TAG, "failed to compare", e);
            return false;
        }
    }

    private static boolean checkCertificate(String alias, Certificate[] cert) throws CertificateEncodingException, IOException {
        Certificate[] chainFromService;
        // compare certificate chain between binder interface and keystore class
        if (useKs2) {
            chainFromService = ks2CertificateChain.get(alias);
            if (chainFromService == null) {
                Log.e(TAG, "no chain from service found!");
                return true;
            }
        } else {
            // https://cs.android.com/android/platform/superproject/+/android-11.0.0_r21:frameworks/base/keystore/java/android/security/keystore/AndroidKeyStoreSpi.java;l=115;drc=09e3d8c3eb7869df54e692ed8588e05ec445964b
            List<Certificate> chain = new ArrayList<>();
            var leaf = ks1Certificates.get(USER_CERTIFICATE + alias);
            if (leaf != null) {
                chain.add(toCertificate(leaf));
            } else {
                leaf = ks1Certificates.get(CA_CERTIFICATE + alias);
                if (leaf != null) {
                    chain.add(toCertificate(leaf));
                } else {
                    Log.e(TAG, "no leaf!");
                    return true;
                }
            }
            var bytes = ks1Certificates.get(CA_CERTIFICATE + alias);
            if (bytes != null) {
                chain.addAll(toCertificates(bytes));
            }
            chainFromService = new Certificate[chain.size()];
            for (int i = 0; i < chain.size(); i++) {
                chainFromService[i] = chain.get(i);
            }
        }
        if (!compareCerts(chainFromService, cert)) {
            Log.e(TAG, "chain from binder and from keystore class not match!");
            return true;
        }
        // detect a bug in FrameworkPatch
        // https://github.com/chiteroman/FrameworkPatch/blob/09544bba826fdcc4d0ce6702bfd9036d5ba97c11/app/src/main/java/com/android/internal/util/framework/Android.java#L178
        // which uses wrong subject public key (it uses its signer's instead of itself's)
        var isAttestKey = Objects.equals(alias, attestAlias);
        if ((!attestAliasReady || isAttestKey) && cert != null && cert.length > 1) {
            X509CertificateHolder leafCertHolder = new X509CertificateHolder(cert[0].getEncoded());
            X509CertificateHolder previousCertHolder = new X509CertificateHolder(cert[1].getEncoded());
            if (leafCertHolder.getSubjectPublicKeyInfo().getPublicKeyData().equals(previousCertHolder.getSubjectPublicKeyInfo().getPublicKeyData())) {
                Log.e(TAG, "wrong subject public key found!");
                return true;
            }
        }
        // detect old tricky store hack leaf mode
        if (useKs2) {
            var chainFromGenerate = ks2GeneratedCertificateChain.get(alias);
            if (!compareCerts(chainFromGenerate, chainFromService)) {
                Log.e(TAG, "chain from generateKey and from getKeyEntry not match!");
                return true;
            }
        }
        return false;
    }


    private static final class ActiveProbeResult {
        boolean suspicious;
        int highCount;
        int warnCount;
        long flags;
        boolean activeForgeryProbesRun;
        boolean timingSuiteRun;
        boolean omkExtensionsRun;
        private long currentFlag;
        private String currentUnavailableProbeId;
        private final List<String> highFindings = new ArrayList<>();
        private final List<String> diagnosticEntries = new ArrayList<>();
        private final LinkedHashSet<String> unavailableProbeIds = new LinkedHashSet<>();

        void beginProbe(long flag) {
            beginProbe(flag, unavailableProbeIdForFlag(flag));
        }

        void beginProbe(long flag, String unavailableProbeId) {
            currentFlag = flag;
            currentUnavailableProbeId = unavailableProbeId;
        }

        void endProbe() {
            currentFlag = 0L;
            currentUnavailableProbeId = null;
        }

        void high(String text) {
            high(currentFlag != 0L ? currentFlag : FLAG_UNKNOWN, text);
        }

        void high(long flag, String text) {
            suspicious = true;
            highCount++;
            flags |= flag == 0L ? FLAG_UNKNOWN : flag;
            if (BuildConfig.DEBUG && text != null && !text.isBlank() && !highFindings.contains(text)) {
                highFindings.add(text);
                addDiagnostic("DETECTED", flag, text);
            }
        }

        void high(long flag) {
            suspicious = true;
            highCount++;
            flags |= flag == 0L ? FLAG_UNKNOWN : flag;
        }

        void normal(String text) {
            normal(currentFlag, text);
        }

        void normal(long flag, String text) {
            if (BuildConfig.DEBUG) addDiagnostic("VERIFIED", flag, text);
        }

        void warn(String text) {
            warn(currentFlag, text);
        }

        void warn(long flag, String text) {
            warnCount++;
            // 关注项不计入高危 flag，避免把兼容性差异作为异常返回。
            if (BuildConfig.DEBUG) addDiagnostic("WARNING", flag, text);
        }

        void skipped(String text) {
            skipped(currentFlag, currentUnavailableProbeId, text);
        }

        void skipped(long flag, String probeId, String text) {
            if (probeId != null && !probeId.isBlank()) unavailableProbeIds.add(probeId);
            if (BuildConfig.DEBUG) addDiagnostic("UNAVAILABLE", flag, text);
        }

        void unavailable(String probeId, String text) {
            unavailable(currentFlag, probeId, text);
        }

        void unavailable(long flag, String probeId, String text) {
            if (probeId != null && !probeId.isBlank()) unavailableProbeIds.add(probeId);
            if (BuildConfig.DEBUG) addDiagnostic("UNAVAILABLE", flag, text);
        }

        void merge(ActiveProbeResult other) {
            if (other == null) return;
            suspicious |= other.suspicious;
            highCount += other.highCount;
            warnCount += other.warnCount;
            flags |= other.flags;
            activeForgeryProbesRun |= other.activeForgeryProbesRun;
            timingSuiteRun |= other.timingSuiteRun;
            omkExtensionsRun |= other.omkExtensionsRun;
            for (String finding : other.highFindings) {
                if (!highFindings.contains(finding)) highFindings.add(finding);
            }
            for (String entry : other.diagnosticEntries) {
                if (!diagnosticEntries.contains(entry)) diagnosticEntries.add(entry);
            }
            unavailableProbeIds.addAll(other.unavailableProbeIds);
        }

        String text() {
            return BuildConfig.DEBUG ? String.join("\n", diagnosticEntries) : "";
        }

        private void addDiagnostic(String status, long flag, String text) {
            if (text == null || text.isBlank()) return;
            long normalizedFlag = flag == 0L ? FLAG_UNKNOWN : flag;
            String entry = "[" + status + "] {flag=0x"
                    + Long.toHexString(normalizedFlag).toUpperCase(java.util.Locale.US)
                    + "} " + text;
            if (!diagnosticEntries.contains(entry)) diagnosticEntries.add(entry);
        }

        String flagHex() {
            return "0x" + Long.toHexString(flags).toUpperCase(java.util.Locale.US);
        }

        String[] unavailableProbeIds() {
            return unavailableProbeIds.toArray(new String[0]);
        }
    }

    private static byte[] makeProbeChallenge(String tag) {
        byte[] rnd = new byte[16];
        new SecureRandom().nextBytes(rnd);
        return ("TrustAttestor:" + tag + ":" + System.nanoTime() + ":" +
                BaseEncoding.base16().encode(rnd)).getBytes(StandardCharsets.UTF_8);
    }

    private static String makeProbeAlias(String tag) {
        return alias + "_probe_" + tag + "_" + Long.toHexString(System.nanoTime());
    }

    private static void applyProbeAttestKeyIfAvailable(KeyGenParameterSpec.Builder builder) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && attestAliasReady) {
            builder.setAttestKeyAlias(attestAlias);
        }
    }

    /** The Unique-ID builder setter is hidden until newer platform stubs; use a guarded bridge. */
    @SuppressLint({"PrivateApi", "SoonBlockedPrivateApi"})
    private static boolean requestUniqueIdAttestation(KeyGenParameterSpec.Builder builder) {
        try {
            Method setter = builder.getClass().getMethod("setUniqueIdIncluded", boolean.class);
            setter.invoke(builder, true);
            return true;
        } catch (Throwable ignored) {
            // Android 15 carries the backing field but omits the public/test stub method.
            try {
                Field field = builder.getClass().getDeclaredField("mUniqueIdIncluded");
                field.setAccessible(true);
                field.setBoolean(builder, true);
                return true;
            } catch (Throwable unavailable) {
                return false;
            }
        }
    }

    private static SilentKeystoreChecks.Reporter silentReporter(ActiveProbeResult result, long flag) {
        return (check, status, detail) -> {
            if (Thread.currentThread().isInterrupted()) {
                status = SilentProbeEvidence.Status.UNAVAILABLE;
                detail = "检测已中断";
            }
            String evidence = "[" + check + "] " + detail;
            if (status == SilentProbeEvidence.Status.DETECTED) {
                result.high(flag, evidence);
            } else if (status == SilentProbeEvidence.Status.UNAVAILABLE) {
                String unavailableProbeId = unavailableProbeIdForFlag(flag);
                result.unavailable(flag, unavailableProbeId, evidence);
            } else {
                result.normal(flag, evidence);
            }
        };
    }

    private static SilentKeystoreChecks.Reporter namedSilentReporter(
            ActiveProbeResult result,
            long flag,
            String unavailableProbeId
    ) {
        return (check, status, detail) -> {
            if (Thread.currentThread().isInterrupted()) {
                status = SilentProbeEvidence.Status.UNAVAILABLE;
                detail = "检测已中断";
            }
            String evidence = "[" + check + "] " + detail;
            if (status == SilentProbeEvidence.Status.DETECTED) {
                result.high(flag, evidence);
            } else if (status == SilentProbeEvidence.Status.UNAVAILABLE) {
                result.unavailable(flag, unavailableProbeId, evidence);
                Log.w(TAG, unavailableProbeId + ": " + detail);
            } else {
                result.normal(flag, evidence);
            }
        };
    }

    private static void applyStructuralProbeResult(
            ActiveProbeResult result,
            long flag,
            String unavailableProbeId,
            StructuralKeystoreProbes.Result observation
    ) {
        if (observation == null) {
            result.unavailable(unavailableProbeId, "结构探针未返回结果");
            Log.w(TAG, unavailableProbeId + ": null result");
            return;
        }
        String detail = BuildConfig.DEBUG ? observation.debugDetail() : observation.summary;
        if (observation.status == SilentProbeEvidence.Status.DETECTED) {
            result.high(flag, detail);
        } else if (observation.status == SilentProbeEvidence.Status.UNAVAILABLE) {
            result.unavailable(unavailableProbeId, detail);
            if (observation.failure != null) {
                Log.w(TAG, unavailableProbeId + ": " + observation.summary, observation.failure);
            } else {
                Log.w(TAG, unavailableProbeId + ": " + observation.detail);
            }
        } else {
            result.normal(detail);
        }
    }

    private static void applyTimingProbeResult(
            ActiveProbeResult result,
            long flag,
            String unavailableProbeId,
            OmkTimingProbes.Result observation
    ) {
        if (observation == null) {
            result.unavailable(unavailableProbeId, "时序探针未返回结果");
            Log.w(TAG, unavailableProbeId + ": null result");
            return;
        }
        String detail = BuildConfig.DEBUG ? observation.debugDetail() : observation.summary;
        if (observation.status == SilentProbeEvidence.Status.DETECTED) {
            result.high(flag, detail);
        } else if (observation.status == SilentProbeEvidence.Status.UNAVAILABLE) {
            result.unavailable(unavailableProbeId, detail);
            if (observation.failure != null) {
                Log.w(TAG, unavailableProbeId + ": " + observation.summary, observation.failure);
            } else {
                Log.w(TAG, unavailableProbeId + ": " + observation.detail);
            }
        } else {
            result.normal(detail);
        }
    }

    private static void applyStatePlaneProbeResult(
            ActiveProbeResult result,
            long flag,
            String unavailableProbeId,
            KeystoreStatePlaneProbes.Result observation
    ) {
        if (observation == null) {
            result.unavailable(unavailableProbeId, "Keystore 状态平面探针未返回结果");
            Log.w(TAG, unavailableProbeId + ": null result");
            return;
        }
        String detail = BuildConfig.DEBUG ? observation.debugDetail() : observation.summary;
        if (observation.status == SilentProbeEvidence.Status.DETECTED) {
            result.high(flag, detail);
        } else if (observation.status == SilentProbeEvidence.Status.UNAVAILABLE) {
            result.unavailable(unavailableProbeId, detail);
            if (observation.failure != null) {
                Log.w(TAG, unavailableProbeId + ": " + observation.summary, observation.failure);
            } else {
                Log.w(TAG, unavailableProbeId + ": " + observation.detail);
            }
        } else {
            result.normal(detail);
        }
    }

    private static void runUserAuthBypassProbe(Context context, ActiveProbeResult result) {
        // User-auth semantics do not depend on App Attest Key delegation. Avoid making this probe
        // unavailable on otherwise normal OEMs whose AttestKey cannot sign an auth-bound child.
        SilentKeystoreChecks.authentication(context, builder -> { },
                silentReporter(result, FLAG_USER_AUTH_METADATA), silentReporter(result, FLAG_USER_AUTH));
    }

    private static void runUniqueIdPermissionBypassProbe(
            Context context,
            ActiveProbeResult result
    ) {
        final String permission = "android.permission.REQUEST_UNIQUE_ID_ATTESTATION";
        if (context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED) {
            result.skipped("应用具有 Unique-ID attestation 权限，无法建立无权限负对照");
            return;
        }

        KeyStore keyStore = null;
        var probeAliases = new ArrayList<String>(2);
        int strippedResponses = 0;
        try {
            keyStore = acquireKeyStore();
            for (int attempt = 0; attempt < 2; ++attempt) {
                String probeAlias = makeProbeAlias("uniqueid_" + attempt);
                probeAliases.add(probeAlias);
                safeDeleteEntry(keyStore, probeAlias);

                try {
                    KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                            probeAlias,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
                    )
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAttestationChallenge(makeProbeChallenge("uniqueid"));
                    if (!requestUniqueIdAttestation(builder)) {
                        result.skipped("当前平台未暴露 Unique-ID attestation 请求接口");
                        return;
                    }
                    applyProbeAttestKeyIfAvailable(builder);

                    KeyPairGenerator generator = KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_EC,
                            "AndroidKeyStore"
                    );
                    generator.initialize(builder.build());
                    generator.generateKeyPair();

                    Certificate[] chain = keyStore.getCertificateChain(probeAlias);
                    if (chain == null || chain.length == 0 ||
                            !(chain[0] instanceof X509Certificate leaf)) {
                        result.skipped("Unique-ID 探针未返回可解析的证明叶证书");
                        return;
                    }
                    Attestation attestation = Attestation.loadFromCertificate(leaf);
                    byte[] uniqueId = attestation.getUniqueId();
                    if (uniqueId != null && uniqueId.length != 0) {
                        result.skipped("Unique-ID 请求成功但证明记录包含非空 Unique ID");
                        return;
                    }
                    ++strippedResponses;
                } catch (Throwable expected) {
                    // A clean keystore rejects this privileged tag for an ordinary app.
                    Log.d(TAG, "Unique-ID permission negative control rejected: " + expected);
                    return;
                }
            }

            if (strippedResponses == 2) {
                result.high("无 Unique-ID attestation 权限时连续两次生成成功，且证明记录中的 Unique ID 均为空");
            }
        } catch (Throwable t) {
            result.skipped("Unique-ID 权限探针无法执行：" + t.getClass().getSimpleName());
            Log.w(TAG, "runUniqueIdPermissionBypassProbe failed", t);
        } finally {
            if (keyStore != null) {
                for (String probeAlias : probeAliases) {
                    safeDeleteEntry(keyStore, probeAlias);
                }
            }
        }
    }

    private static ProbeApplicability runSingleUseProbe(Context context, ActiveProbeResult result) {
        return SilentKeystoreChecks.singleUse(context, KeyAttestation::applyProbeAttestKeyIfAvailable,
                silentReporter(result, FLAG_SINGLE_USE))
                ? ProbeApplicability.APPLICABLE : ProbeApplicability.NOT_APPLICABLE;
    }

    private static void runFutureValidityProbe(ActiveProbeResult result) {
        SilentKeystoreChecks.futureValidity(KeyAttestation::applyProbeAttestKeyIfAvailable,
                silentReporter(result, FLAG_FUTURE_VALIDITY));
    }

    private static void runExtendedCryptoProbe(ActiveProbeResult result) {
        ExtendedKeystoreChecks.run((check, status, detail) -> {
            long flag = check.startsWith("rsa.") ? FLAG_RSA_CONFORMANCE
                    : check.startsWith("hmac.") ? FLAG_HMAC_CONFORMANCE
                    : check.startsWith("ecdh.") ? FLAG_ECDH_CONFORMANCE : FLAG_AES_CONFORMANCE;
            silentReporter(result, flag).report(check, status, detail);
        });
    }

    private static boolean verifyMainBinding(KeyStore store, String keyAlias, boolean canSign, ActiveProbeResult result) {
        GeneratedKeyBinding binding = ACTIVE_BINDINGS.get().get(keyAlias);
        if (binding == null) {
            result.skipped("主证明本轮生成记录不可用");
            return false;
        }
        return SilentKeystoreChecks.mainBinding(store, keyAlias, binding.publicKey, binding.challenge,
                canSign, silentReporter(result, FLAG_MAIN_BINDING));
    }

    private static void runOperationAuthorizationProbe(ActiveProbeResult result) {
        SilentKeystoreChecks.operations(silentReporter(result, FLAG_OPERATION_SEMANTICS));
    }


    private static final int TIMING_SIDE_CHANNEL_WARMUP_COUNT = 2;
    private static final int TIMING_SIDE_CHANNEL_PAIRS_PER_BATCH = 16;
    private static final int TIMING_SIDE_CHANNEL_THROTTLE_EVERY_PAIRS = 8;
    private static final long TIMING_SIDE_CHANNEL_THROTTLE_SLEEP_MS = 3L;
    // Stops scheduling more work; it cannot interrupt an in-flight Binder/KeyMint operation.
    private static final long TIMING_SIDE_CHANNEL_SAMPLE_BUDGET_MS = 2_500L;
    // Crypto operations are intentionally given an absolute-effect floor. This prevents a large
    // ratio on a tiny Java/Binder interval from becoming a high-confidence timing finding.
    private static final double TIMING_CRYPTO_MIN_ABS_EFFECT_MS = 0.10D;
    private static final double TIMING_METADATA_MIN_ABS_EFFECT_MS = 0.03D;
    // Bounded operation pressure is corroborating evidence only; it never intentionally saturates
    // the global operation table.
    private static final int TIMING_OPERATION_PRESSURE_HOLDERS = 8;
    private static final int TIMING_OPERATION_PRESSURE_SAMPLES = 5;

    private interface TimingMeasurement {
        void run() throws Throwable;
        String source();
    }

    private static final class TimingSampleSeries {
        final ArrayList<KeystoreTimingStatistics.Sample> samples = new ArrayList<>();
        final ArrayList<Double> elapsedMillis = new ArrayList<>();
        final ArrayList<Double> threadCpuMillis = new ArrayList<>();
        int clockWindowFailures;
        int warmupFailures;
        boolean interrupted;
        boolean budgetExceeded;
        String firstFailure;

        void failed(Throwable failure) {
            if (failure != null && firstFailure == null) {
                firstFailure = failure.getClass().getSimpleName();
            }
        }

        boolean complete() {
            // Warm-up is deliberately disposable. A transient scheduling gap before the measured
            // batches must not turn an otherwise complete run into an unavailable finding.
            return !interrupted && !budgetExceeded && clockWindowFailures == 0;
        }
    }

    private static final class TimingWindowException extends Exception {
        TimingWindowException(String message) { super(message); }
    }

    /**
     * One low-priority, persistent Keystore crypto worker. The measured key and the load key are
     * distinct so a positive result cannot be explained by a per-key lock alone.
     */
    private static final class KeystoreLoadWorker implements AutoCloseable {
        private final PrivateKey key;
        private final byte[] payload;
        private final Thread thread;
        private volatile boolean running = true;
        private volatile boolean enabled;
        private volatile boolean active;
        private volatile boolean paused = true;
        private volatile long completions;
        private volatile Throwable failure;

        KeystoreLoadWorker(PrivateKey key, byte[] payload) {
            this.key = key;
            this.payload = payload.clone();
            this.thread = new Thread(this::loop, "TrustAttestor-KeyMintTimingLoad");
            this.thread.setDaemon(true);
            this.thread.setPriority(Thread.MIN_PRIORITY);
        }

        void start() {
            thread.start();
        }

        private void loop() {
            try {
                while (running) {
                    if (!enabled) {
                        active = false;
                        paused = true;
                        java.util.concurrent.locks.LockSupport.parkNanos(250_000L);
                        continue;
                    }
                    paused = false;
                    active = true;
                    try {
                        performKeystoreSignature(key, payload);
                        completions++;
                    } finally {
                        active = false;
                    }
                }
            } catch (Throwable t) {
                failure = t;
                running = false;
            } finally {
                active = false;
                paused = true;
            }
        }

        boolean setEnabled(boolean value, long deadlineMs) throws InterruptedException {
            Throwable workerFailure = failure;
            if (workerFailure != null) {
                throw new IllegalStateException("Keystore load worker failed", workerFailure);
            }
            long before = completions;
            enabled = value;
            java.util.concurrent.locks.LockSupport.unpark(thread);
            while (SystemClock.elapsedRealtime() < deadlineMs) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Keystore timing scan interrupted");
                }
                workerFailure = failure;
                if (workerFailure != null) {
                    throw new IllegalStateException("Keystore load worker failed", workerFailure);
                }
                if (value) {
                    if (active || completions > before) return true;
                } else if (paused && !active) {
                    return true;
                }
                Thread.yield();
            }
            return false;
        }

        void disableWithoutWait() {
            enabled = false;
            java.util.concurrent.locks.LockSupport.unpark(thread);
        }

        Throwable failure() {
            return failure;
        }

        @Override
        public void close() {
            enabled = false;
            running = false;
            java.util.concurrent.locks.LockSupport.unpark(thread);
            thread.interrupt();
            try {
                thread.join(250L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static final class OperationPressureObservation {
        int heldOperations;
        int baselineSamples;
        int pressuredSamples;
        boolean holderCreationFailed;
        boolean probeFailed;
        boolean pressureVisible;
        double baselineMedianMillis = Double.NaN;
        double pressuredMedianMillis = Double.NaN;
        String firstFailure;
    }

    private static void throwIfTimingInterrupted() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Keystore timing scan interrupted");
        }
    }

    private static boolean timingBudgetAvailable(TimingSampleSeries series, long deadline) {
        if (Thread.currentThread().isInterrupted()) {
            series.interrupted = true;
            return false;
        }
        if (SystemClock.elapsedRealtime() >= deadline) {
            series.budgetExceeded = true;
            return false;
        }
        return true;
    }

    private static void performKeystoreSignature(PrivateKey key, byte[] payload) throws Exception {
        throwIfTimingInterrupted();
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key);
        signature.update(payload);
        byte[] signed = signature.sign();
        if (signed == null || signed.length == 0) {
            throw new GeneralSecurityException("AndroidKeyStore returned an empty ECDSA signature");
        }
        throwIfTimingInterrupted();
    }

    private static double measureTimingMillis(TimingMeasurement measurement,
            KeystoreTimingClock clock, TimingSampleSeries series) throws Throwable {
        long elapsedStart = SystemClock.elapsedRealtimeNanos();
        long cpuStart = Debug.threadCpuTimeNanos();
        long start = clock.read();
        measurement.run();
        long end = clock.read();
        long cpuEnd = Debug.threadCpuTimeNanos();
        long elapsedEnd = SystemClock.elapsedRealtimeNanos();
        double primaryMillis = clock.elapsedMillis(start, end);
        double elapsedMillis = (elapsedEnd - elapsedStart) / 1_000_000.0D;
        if (elapsedMillis <= 0.0D || elapsedMillis < primaryMillis * 0.95D ||
                elapsedMillis - primaryMillis > Math.max(5.0D, primaryMillis * 0.25D)) {
            series.clockWindowFailures++;
            throw new TimingWindowException(
                    "Timing windows disagree or include a suspend/scheduling gap");
        }
        series.elapsedMillis.add(elapsedMillis);
        // Client CPU time does not include remote Keystore/KeyMint work. Never subtract it.
        if (cpuStart >= 0 && cpuEnd >= cpuStart) {
            series.threadCpuMillis.add((cpuEnd - cpuStart) / 1_000_000.0D);
        }
        return primaryMillis;
    }

    private static double measureCondition(
            KeystoreLoadWorker worker,
            TimingMeasurement measurement,
            boolean loaded,
            TimingSampleSeries series,
            long deadline, KeystoreTimingClock clock) {
        if (!timingBudgetAvailable(series, deadline)) return Double.NaN;
        try {
            if (!worker.setEnabled(loaded, deadline)) {
                series.budgetExceeded = true;
                return Double.NaN;
            }
            if (!timingBudgetAvailable(series, deadline)) return Double.NaN;
            return measureTimingMillis(measurement, clock, series);
        } catch (Throwable failure) {
            // Suspend/scheduler gaps invalidate only this timing window. They do not mean that
            // AndroidKeyStore failed, and are therefore kept separate from provider failures.
            if (!(failure instanceof TimingWindowException)) series.failed(failure);
            if (failure instanceof InterruptedException) {
                series.interrupted = true;
                Thread.currentThread().interrupt();
            }
            return Double.NaN;
        }
    }

    /**
     * treatment = the same probe while a second ordinary Keystore key is continuously signing.
     * control   = the same probe after the worker has acknowledged a quiescent state.
     *
     * The loaded/idle order is balanced and randomized in every pair. Failed attempts remain as
     * NaN samples so failures cannot be silently filtered into a directional result.
     */
    private static TimingSampleSeries sampleContentionSeries(
            KeystoreLoadWorker worker, TimingMeasurement measurement, SecureRandom random,
            KeystoreTimingClock clock) {
        TimingSampleSeries series = new TimingSampleSeries();
        long deadline = SystemClock.elapsedRealtime() + TIMING_SIDE_CHANNEL_SAMPLE_BUDGET_MS;
        try {
            for (int i = 0; i < TIMING_SIDE_CHANNEL_WARMUP_COUNT; i++) {
                boolean loadedFirst = (i & 1) == 0;
                double first = measureCondition(worker, measurement, loadedFirst, series, deadline, clock);
                double second = measureCondition(worker, measurement, !loadedFirst, series, deadline, clock);
                if (!Double.isFinite(first) || !Double.isFinite(second)) {
                    series.warmupFailures++;
                    if (!clock.usable() || !timingBudgetAvailable(series, deadline)) return series;
                }
            }

            // Do not let a disposable warm-up timing-window failure poison the measured series.
            // A real worker/provider failure repeats in the measured batches and is retained.
            series.firstFailure = null;
            series.clockWindowFailures = 0;
            series.elapsedMillis.clear();
            series.threadCpuMillis.clear();

            for (int batch = 0; batch < 2; batch++) {
                boolean firstInBalancedPair = false;
                for (int i = 0; i < TIMING_SIDE_CHANNEL_PAIRS_PER_BATCH; i++) {
                    if (!timingBudgetAvailable(series, deadline)) return series;
                    if ((i & 1) == 0) firstInBalancedPair = random.nextBoolean();
                    boolean loadedFirst = (i & 1) == 0 ? firstInBalancedPair : !firstInBalancedPair;

                    double first = measureCondition(worker, measurement, loadedFirst, series, deadline, clock);
                    if (!timingBudgetAvailable(series, deadline)) return series;
                    double second = measureCondition(worker, measurement, !loadedFirst, series, deadline, clock);

                    series.samples.add(new KeystoreTimingStatistics.Sample(
                            loadedFirst ? first : second,
                            loadedFirst ? second : first,
                            loadedFirst,
                            batch));
                    if (!clock.usable()) return series;

                    if ((i + 1) % TIMING_SIDE_CHANNEL_THROTTLE_EVERY_PAIRS == 0) {
                        worker.disableWithoutWait();
                        SystemClock.sleep(TIMING_SIDE_CHANNEL_THROTTLE_SLEEP_MS);
                    }
                }
            }
            timingBudgetAvailable(series, deadline);
            return series;
        } finally {
            worker.disableWithoutWait();
        }
    }

    private static void generateTimingKey(String keyAlias) throws Exception {
        throwIfTimingInterrupted();
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(keyAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build();
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        generator.initialize(spec);
        generator.generateKeyPair();
        throwIfTimingInterrupted();
    }

    private static PrivateKey requireTimingPrivateKey(KeyStore keyStore, String keyAlias) throws Exception {
        Key key = keyStore.getKey(keyAlias, null);
        if (!(key instanceof PrivateKey privateKey)) {
            throw new GeneralSecurityException("AndroidKeyStore private key unavailable for " + keyAlias);
        }
        return privateKey;
    }

    private static Signature openHeldTimingOperation(PrivateKey key, byte[] payload) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key);
        // Force AndroidKeyStore to create/use the backing operation instead of only preparing the
        // Java object. One byte is enough and keeps the held operation cheap.
        signature.update(payload, 0, 1);
        return signature;
    }

    private static double measureOperationBeginMillis(PrivateKey key, byte[] payload,
            KeystoreTimingClock clock) throws Exception {
        long start = clock.read();
        Signature signature = openHeldTimingOperation(key, payload);
        try {
            return clock.elapsedMillis(start, clock.read());
        } finally {
            signature.sign();
        }
    }

    private static double medianTimingValues(ArrayList<Double> values) {
        if (values == null || values.isEmpty()) return Double.NaN;
        double[] copy = new double[values.size()];
        for (int i = 0; i < copy.length; i++) copy[i] = values.get(i);
        Arrays.sort(copy);
        int middle = copy.length / 2;
        return (copy.length & 1) != 0
                ? copy[middle]
                : copy[middle - 1] + (copy[middle] - copy[middle - 1]) / 2.0D;
    }

    /**
     * Bounded operation-state observation. We deliberately stop at eight held operations rather
     * than trying to exhaust the device-wide table. This can corroborate an externally observable
     * operation-state response without turning the detector itself into a resource-exhaustion test.
     */
    private static OperationPressureObservation observeOperationPressure(
            PrivateKey probeKey, PrivateKey holderKey, byte[] payload, KeystoreTimingClock clock) {
        OperationPressureObservation observation = new OperationPressureObservation();
        ArrayList<Double> baseline = new ArrayList<>();
        ArrayList<Double> pressured = new ArrayList<>();
        ArrayList<Signature> held = new ArrayList<>();
        try {
            for (int i = 0; i < TIMING_OPERATION_PRESSURE_SAMPLES; i++) {
                baseline.add(measureOperationBeginMillis(probeKey, payload, clock));
            }
            observation.baselineSamples = baseline.size();
            observation.baselineMedianMillis = medianTimingValues(baseline);

            for (int i = 0; i < TIMING_OPERATION_PRESSURE_HOLDERS; i++) {
                try {
                    held.add(openHeldTimingOperation(holderKey, payload));
                    observation.heldOperations = held.size();
                } catch (Throwable failure) {
                    observation.holderCreationFailed = true;
                    if (observation.firstFailure == null) {
                        observation.firstFailure = failure.getClass().getSimpleName();
                    }
                    break;
                }
            }

            if (observation.heldOperations > 0) {
                for (int i = 0; i < TIMING_OPERATION_PRESSURE_SAMPLES; i++) {
                    try {
                        pressured.add(measureOperationBeginMillis(probeKey, payload, clock));
                    } catch (Throwable failure) {
                        observation.probeFailed = true;
                        if (observation.firstFailure == null) {
                            observation.firstFailure = failure.getClass().getSimpleName();
                        }
                        break;
                    }
                }
            }
            observation.pressuredSamples = pressured.size();
            observation.pressuredMedianMillis = medianTimingValues(pressured);

            if (observation.probeFailed || observation.holderCreationFailed) {
                observation.pressureVisible = observation.heldOperations >= 2;
            } else if (Double.isFinite(observation.baselineMedianMillis)
                    && Double.isFinite(observation.pressuredMedianMillis)
                    && observation.baselineMedianMillis > 0.0D) {
                double diff = observation.pressuredMedianMillis - observation.baselineMedianMillis;
                double ratio = observation.pressuredMedianMillis / observation.baselineMedianMillis;
                observation.pressureVisible = observation.heldOperations >= 4
                        && diff >= 0.10D && ratio >= 1.25D;
            }
        } catch (Throwable failure) {
            if (observation.firstFailure == null) {
                observation.firstFailure = failure.getClass().getSimpleName();
            }
        } finally {
            for (Signature signature : held) {
                try {
                    signature.sign();
                } catch (Throwable ignored) {
                }
            }
        }
        return observation;
    }

    private static String formatTimingDouble(double value, int decimals) {
        if (!Double.isFinite(value)) return "n/a";
        return String.format(java.util.Locale.US, "%." + decimals + "f", value);
    }

    private static String timingStatsSummary(
            KeystoreTimingStatistics.Result stats,
            TimingSampleSeries series,
            String source) {
        return source + "{pairs=" + stats.validPairs + "/" + series.samples.size()
                + ", invalid=" + stats.invalidPairs
                + ", warmupFailures=" + series.warmupFailures
                + ", medianLoaded=" + formatTimingDouble(stats.medianTreatmentMillis, 3) + "ms"
                + ", medianIdle=" + formatTimingDouble(stats.medianControlMillis, 3) + "ms"
                + ", medianDiff=" + formatTimingDouble(stats.medianDifferenceMillis, 3) + "ms"
                + ", relative=" + formatTimingDouble(stats.medianRelativePercent, 1) + "%"
                + ", signedLogRatio=" + formatTimingDouble(stats.medianLogRatio, 3)
                + ", madLogRatio=" + formatTimingDouble(stats.madLogRatio, 3)
                + ", direction=" + stats.direction
                + ", clockWindowFailures=" + series.clockWindowFailures
                + ", medianElapsed=" + formatTimingDouble(medianTimingValues(series.elapsedMillis), 3) + "ms"
                + ", medianClientThreadCpu=" + formatTimingDouble(medianTimingValues(series.threadCpuMillis), 3) + "ms"
                + ", quality=" + stats.reason
                + ", interrupted=" + series.interrupted
                + ", budgetExceeded=" + series.budgetExceeded + "}";
    }

    private static String timingPressureSummary(OperationPressureObservation pressure) {
        return "operationPressure{held=" + pressure.heldOperations
                + ", baseline=" + formatTimingDouble(pressure.baselineMedianMillis, 3) + "ms"
                + ", pressured=" + formatTimingDouble(pressure.pressuredMedianMillis, 3) + "ms"
                + ", baselineSamples=" + pressure.baselineSamples
                + ", pressuredSamples=" + pressure.pressuredSamples
                + ", holderFailure=" + pressure.holderCreationFailed
                + ", probeFailure=" + pressure.probeFailed
                + ", visible=" + pressure.pressureVisible
                + (pressure.firstFailure == null ? "" : ", firstFailure=" + pressure.firstFailure)
                + "}";
    }

    private static boolean timingSeriesUsable(
            KeystoreTimingStatistics.Result stats, TimingSampleSeries series) {
        return stats.usable && series.complete() && series.firstFailure == null;
    }

    private static void runKeystoreTimingSideChannelProbe(ActiveProbeResult result) {
        lastTimingProbeStatus = 2;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            result.skipped("Keystore 时序竞争检测需要 Android 12+ API");
            return;
        }

        String suffix = java.util.UUID.randomUUID().toString();
        String probeAlias = makeProbeAlias("timing_probe_" + suffix);
        String loadAlias = makeProbeAlias("timing_load_" + suffix);
        KeyStore keyStore = null;
        boolean ownsProbe = false;
        boolean ownsLoad = false;

        try {
            throwIfTimingInterrupted();
            keyStore = acquireKeyStore();
            if (keyStore.containsAlias(probeAlias) || keyStore.containsAlias(loadAlias)) {
                result.skipped("Keystore 时序临时 alias 冲突");
                return;
            }

            // Both keys are intentionally identical plain EC keys. No attestation challenge and no
            // certificate-size asymmetry is present in the primary timing comparison.
            ownsProbe = true;
            generateTimingKey(probeAlias);
            ownsLoad = true;
            generateTimingKey(loadAlias);

            PrivateKey probeKey = requireTimingPrivateKey(keyStore, probeAlias);
            PrivateKey loadKey = requireTimingPrivateKey(keyStore, loadAlias);
            SecureRandom random = new SecureRandom();
            byte[] probePayload = new byte[64];
            byte[] loadPayload = new byte[64];
            random.nextBytes(probePayload);
            random.nextBytes(loadPayload);

            // Establish that both keys work before timing anything.
            performKeystoreSignature(probeKey, probePayload);
            performKeystoreSignature(loadKey, loadPayload);

            KeystoreTimingClock clock = KeystoreTimingClock.create();
            if (!clock.usable()) {
                result.skipped("Keystore 时钟校准不可用：" + clock.summary());
                return;
            }

            final KeyStore timingStore = keyStore;
            TimingMeasurement cryptoMeasurement = new TimingMeasurement() {
                @Override
                public void run() throws Throwable {
                    performKeystoreSignature(probeKey, probePayload);
                }

                @Override
                public String source() {
                    return "AndroidKeyStore.ECDSA(load-vs-idle)";
                }
            };
            TimingMeasurement metadataControl = new TimingMeasurement() {
                @Override
                public void run() throws Throwable {
                    Certificate certificate = timingStore.getCertificate(probeAlias);
                    if (certificate == null) {
                        throw new GeneralSecurityException("timing metadata certificate unavailable");
                    }
                    // Touch the encoded bytes so a lazy certificate wrapper cannot make the
                    // control degenerate into a null/reference-only Java operation.
                    byte[] encoded = certificate.getEncoded();
                    if (encoded.length == 0) {
                        throw new GeneralSecurityException("timing metadata certificate is empty");
                    }
                }

                @Override
                public String source() {
                    return "AndroidKeyStore.getCertificate(load-vs-idle control)";
                }
            };

            TimingSampleSeries cryptoSeries;
            TimingSampleSeries metadataSeries = null;
            KeystoreTimingStatistics.Result cryptoStats;
            KeystoreTimingStatistics.Result metadataStats = null;
            try (KeystoreLoadWorker worker = new KeystoreLoadWorker(loadKey, loadPayload)) {
                worker.start();
                SystemClock.sleep(4L);
                cryptoSeries = sampleContentionSeries(worker, cryptoMeasurement, random, clock);
                throwIfTimingInterrupted();
                if (worker.failure() != null) {
                    cryptoSeries.failed(worker.failure());
                }
                cryptoStats = KeystoreTimingStatistics.analyze(
                        cryptoSeries.samples,
                        TIMING_SIDE_CHANNEL_PAIRS_PER_BATCH,
                        clock.minimumEffectMillis(TIMING_CRYPTO_MIN_ABS_EFFECT_MS));

                // The metadata path is an attribution control, not a second unconditional
                // detector. If the ECDSA treatment has no stable slower candidate, metadata
                // timing cannot turn the result positive and is skipped to halve the normal
                // device cost. Every possible positive still executes this independent control.
                boolean needsAttributionControl = timingSeriesUsable(cryptoStats, cryptoSeries)
                        && cryptoStats.positive
                        && "TREATMENT_SLOWER".equals(cryptoStats.direction);
                if (needsAttributionControl) {
                    SystemClock.sleep(4L);
                    metadataSeries = sampleContentionSeries(
                            worker, metadataControl, random, clock);
                    if (worker.failure() != null) metadataSeries.failed(worker.failure());
                    metadataStats = KeystoreTimingStatistics.analyze(
                            metadataSeries.samples,
                            TIMING_SIDE_CHANNEL_PAIRS_PER_BATCH,
                            clock.minimumEffectMillis(TIMING_METADATA_MIN_ABS_EFFECT_MS));
                }
            }

            if (!clock.usable()) {
                result.skipped("Keystore 采样期间时钟失效：" + clock.summary());
                return;
            }
            String detail = timingStatsSummary(cryptoStats, cryptoSeries, cryptoMeasurement.source())
                    + (metadataStats == null
                    ? "; metadataControl{skipped=no-primary-slower-candidate}"
                    : "; " + timingStatsSummary(
                            metadataStats, metadataSeries, metadataControl.source()))
                    + "; " + clock.summary();
            Log.i(TAG, "Keystore contention timing observation: " + detail);

            throwIfTimingInterrupted();
            if (!timingSeriesUsable(cryptoStats, cryptoSeries)) {
                boolean interfaceHealthy = cryptoSeries.firstFailure == null;
                lastTimingProbeStatus = KeystoreTimingProbeDecision.status(
                        interfaceHealthy, false, false, cryptoSeries.interrupted);
                if (lastTimingProbeStatus == KeystoreTimingProbeDecision.UNAVAILABLE) {
                    result.skipped("Keystore 时序竞争检测接口执行失败：" + detail);
                } else {
                    result.warn("Keystore 接口工作正常，但在限定时间内未取得完整双批次时序样本；"
                            + "本轮按中性结果处理，不判定异常：" + detail);
                }
                return;
            }

            boolean cryptoLoadedSlower = cryptoStats.positive
                    && "TREATMENT_SLOWER".equals(cryptoStats.direction);
            if (!cryptoLoadedSlower) {
                lastTimingProbeStatus = KeystoreTimingProbeDecision.status(
                        true, true, false, false);
                if (cryptoStats.positive) {
                    result.warn("Keystore 加密时序存在反向稳定差异，不支持 KeyMint contention "
                            + "归因：" + detail);
                } else if (cryptoStats.noisy) {
                    result.warn("Keystore 时序受批次、顺序或系统噪声影响，不作异常判定：" + detail);
                } else {
                    result.normal("Keystore 时序未观察到稳定的 KeyMint/HAL 竞争分离：" + detail);
                }
                return;
            }

            // A primary candidate without its negative control is inconclusive, but the probe and
            // AndroidKeyStore interface did execute. Do not expose it as an unavailable finding on
            // a slow otherwise-normal device.
            if (metadataStats == null || metadataSeries == null
                    || !timingSeriesUsable(metadataStats, metadataSeries)) {
                lastTimingProbeStatus = KeystoreTimingProbeDecision.status(
                        true, false, false, false);
                result.warn("Keystore 加密路径出现候选时序差异，但独立元数据负对照未在限定时间内"
                        + "形成完整样本；本轮不作异常判定：" + detail);
                return;
            }

            boolean metadataLoadedSlower = metadataStats.positive
                    && "TREATMENT_SLOWER".equals(metadataStats.direction);

            // Remove the part of the slowdown also seen by the non-KeyMint metadata control.
            // Requiring at least ~8% residual effect makes a high finding harder to explain by
            // generic Binder/CPU scheduling pressure alone.
            double metadataContribution = Double.isFinite(metadataStats.medianLogRatio)
                    ? Math.max(0.0D, metadataStats.medianLogRatio) : 0.0D;
            double residualLogEffect = Double.isFinite(cryptoStats.medianLogRatio)
                    ? cryptoStats.medianLogRatio - metadataContribution : Double.NaN;
            boolean cryptoSpecificResidual = Double.isFinite(residualLogEffect)
                    && residualLogEffect >= Math.log(1.08D);

            // Reaching this point means that both randomized batches and the clock calibration
            // completed successfully.  Statistical noise is an inconclusive completed result,
            // not an unavailable probe.  Keep status=2 exclusively for an execution/calibration
            // failure so the native bridge cannot turn ordinary scheduler noise into a release
            // finding saying that the check did not complete.
            boolean timingAnomaly = cryptoLoadedSlower
                    && cryptoSpecificResidual
                    && !metadataStats.noisy;
            lastTimingProbeStatus = KeystoreTimingProbeDecision.status(
                    true,
                    true,
                    timingAnomaly,
                    false);
            if (timingAnomaly) {
                result.high(FLAG_TIMING_SIDE_CHANNEL,
                        "Keystore/KeyMint 竞争时序可观测：独立负载使另一把普通 Keystore 私钥的 ECDSA "
                                + "操作稳定变慢，且减去同条件元数据读取负对照后仍保留显著差异。"
                                + "该结论只表示存在可观测的内部负载/串行化指纹，不表示私钥、PIN 或生物信息可被恢复；"
                                + detail);
            } else if (cryptoLoadedSlower && metadataLoadedSlower) {
                result.warn("Keystore 加载时加密与元数据路径同时变慢，更像 Binder/调度或 Keystore2 "
                        + "整体竞争，无法归因到 KeyMint channel：" + detail);
            } else if (cryptoStats.positive) {
                result.warn("Keystore 加密时序出现稳定差异，但方向或独立负对照不支持 KeyMint "
                        + "contention 归因：" + detail);
            } else if (cryptoStats.noisy || metadataStats.noisy) {
                result.warn("Keystore 时序受批次、顺序或系统噪声影响，不作异常判定：" + detail);
            } else {
                result.normal("Keystore 时序未观察到稳定的 KeyMint/HAL 竞争分离：" + detail);
            }
        } catch (Throwable unavailable) {
            if (unavailable instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            if (lastTimingProbeStatus != 1) lastTimingProbeStatus = 2;
            result.skipped("Keystore 时序竞争检测不可用：" + unavailable.getClass().getSimpleName());
            Log.w(TAG, "runKeystoreTimingSideChannelProbe unavailable", unavailable);
        } finally {
            if (keyStore != null) {
                if (ownsProbe) safeDeleteEntry(keyStore, probeAlias);
                if (ownsLoad) safeDeleteEntry(keyStore, loadAlias);
            }
        }
    }

    private static void runFlaggedProbe(ActiveProbeResult result, long flag, Runnable probe) {
        runFlaggedProbe(result, flag, null, probe);
    }

    private static void runFlaggedProbe(
            ActiveProbeResult result,
            long flag,
            String unavailableProbeId,
            Runnable probe
    ) {
        result.beginProbe(flag, unavailableProbeId == null
                ? unavailableProbeIdForFlag(flag) : unavailableProbeId);
        try {
            probe.run();
        } catch (Throwable unavailable) {
            String detail = "子检测未完成：" + unavailable.getClass().getSimpleName()
                    + (unavailable.getMessage() == null ? "" : ": " + unavailable.getMessage());
            if (unavailableProbeId == null) result.skipped(detail);
            else result.unavailable(unavailableProbeId, detail);
            Log.w(TAG, "active probe unavailable"
                    + (unavailableProbeId == null ? "" : " [" + unavailableProbeId + "]"),
                    unavailable);
        } finally {
            result.endProbe();
        }
    }

    private static void runProgressProbe(
            ActiveProbeResult result,
            long flag,
            int permille,
            String progress,
            Runnable probe
    ) {
        postProgress(permille, progress);
        long startedAt = SystemClock.elapsedRealtime();
        runFlaggedProbe(result, flag, probe);
        Log.i(TAG, progress + " completed in "
                + (SystemClock.elapsedRealtime() - startedAt) + " ms");
    }

    /**
     * Runs a capability-dependent probe without counting an unsupported check as passed. The
     * generic progress event keeps the scan moving while only an applicable probe publishes its
     * concrete, counted completion event.
     */
    private static void runOptionalProgressProbe(
            ActiveProbeResult result,
            long flag,
            int permille,
            String progress,
            Supplier<ProbeApplicability> probe
    ) {
        postProgress(permille, "progress.hardware.active_probes");
        long startedAt = SystemClock.elapsedRealtime();
        result.beginProbe(flag, unavailableProbeIdForFlag(flag));
        ProbeApplicability applicability = ProbeApplicability.APPLICABLE;
        try {
            applicability = Objects.requireNonNull(probe.get(), "probe applicability");
        } catch (Throwable unavailable) {
            String detail = "子检测未完成：" + unavailable.getClass().getSimpleName()
                    + (unavailable.getMessage() == null ? "" : ": " + unavailable.getMessage());
            result.skipped(detail);
            Log.w(TAG, "optional active probe unavailable", unavailable);
        } finally {
            result.endProbe();
        }
        if (applicability == ProbeApplicability.APPLICABLE) {
            postProgress(permille, progress);
        }
        Log.i(TAG, progress + (applicability == ProbeApplicability.APPLICABLE
                ? " completed in " : " not applicable; evaluated in ")
                + (SystemClock.elapsedRealtime() - startedAt) + " ms");
    }

    private static void runProgressProbe(
            ActiveProbeResult result,
            long flag,
            String unavailableProbeId,
            int permille,
            String progress,
            Runnable probe
    ) {
        postProgress(permille, progress);
        long startedAt = SystemClock.elapsedRealtime();
        runFlaggedProbe(result, flag, unavailableProbeId, probe);
        Log.i(TAG, progress + " completed in "
                + (SystemClock.elapsedRealtime() - startedAt) + " ms");
    }

    private static SilentKeystoreChecks.Reporter certificateRecordReporter(
            ActiveProbeResult result, boolean roundTrip) {
        final long flag = roundTrip ? FLAG_CERTIFICATE_ROUND_TRIP : FLAG_CHAIN_READ_STABILITY;
        final int shift = roundTrip ? 2 : 0;
        return (check, status, detail) -> {
            int incoming = status == SilentProbeEvidence.Status.DETECTED ? 1
                    : status == SilentProbeEvidence.Status.VERIFIED ? 0 : 2;
            int previous = (lastCertificateRecordStatus >> shift) & 3;
            int merged = previous == 1 || incoming == 1 ? 1
                    : previous == 2 || incoming == 2 ? 2 : incoming;
            lastCertificateRecordStatus = (lastCertificateRecordStatus & ~(3 << shift)) | (merged << shift);
            String evidence = "[" + check + "] " + detail;
            if (incoming == 1) result.high(flag, evidence);
            else if (incoming == 0) result.normal(flag, evidence);
            else result.skipped(flag, null, evidence);
        };
    }

    private static ProbeApplicability runIsolatedChainProbe(Context context, ActiveProbeResult result) {
        lastIsolatedChainStatus = 7;
        try {
            if (context == null) {
                result.skipped("隔离证明链检测缺少应用上下文");
                return ProbeApplicability.APPLICABLE;
            }
            Class<?> bridge = context.getClassLoader().loadClass(
                    "com.lingqing.trustattestor.IsolatedAttestationProbe");
            Object returned = bridge.getMethod("run", Context.class).invoke(null, context);
            if (!(returned instanceof Integer status) || status < 0 || status > 7) {
                result.skipped("隔离证明链检测结果不完整");
                return ProbeApplicability.APPLICABLE;
            }
            lastIsolatedChainStatus = status;
            if (status == 1) result.high(FLAG_ISOLATED_CHAIN, "同一临时证明密钥在主进程与隔离 UID 下返回不同证书链");
            else if (status == 0) result.normal("隔离 UID 授权证明链与主进程稳定快照一致");
            else if (status == 2) return ProbeApplicability.NOT_APPLICABLE;
            else result.skipped("隔离证明链检测不可用，状态=" + status);
        } catch (Throwable unavailable) {
            result.skipped("隔离证明链检测接口不可用：" + unavailable.getClass().getSimpleName());
        }
        return ProbeApplicability.APPLICABLE;
    }

    private static void runActiveForgeryProbes(Context context, String targetAlias, Certificate[] targetChain, Certificate[] mainAliasChain, Certificate[] attestKeyChain, AttestationResult attestationResult, ActiveProbeResult result) {
        if (result.activeForgeryProbesRun) return;
        // Set before executing the first child so an unexpected outer failure can never replay
        // stateful probes against the same aliases. Every child has its own failure boundary.
        result.activeForgeryProbesRun = true;

        runOmkTimingSuiteOnce(result);

        // Fast path: keep the independent, low-cost checks that cover the
        // certificate, authorization and operation surfaces on every scan.
        runOptionalProgressProbe(result, FLAG_ATTEST_CROSS_SIGN, 510,
                "progress.hardware.probe.attest_cross_sign",
                () -> runAttestKeyCrossSigningProbe(mainAliasChain, attestKeyChain, result));
        runProgressProbe(result, FLAG_CHALLENGE_REPLAY, 540, "progress.hardware.probe.challenge_replay", () -> runChallengeReplayProbe(result));
        runProgressProbe(result, FLAG_NULL_CHALLENGE, 565, "progress.hardware.probe.null_challenge", () -> runNullChallengeNegativeProbe(result));
        runProgressProbe(result, FLAG_CTS_LEAF, 590, "progress.hardware.probe.leaf_profile", () -> runCtsLeafProfileProbe(targetChain, result));
        runProgressProbe(result, FLAG_APP_ID, 610, "progress.hardware.probe.application_id", () -> runAttestationApplicationIdProbe(context, targetChain, result));
        runOptionalProgressProbe(result, FLAG_SIGNING_LINEAGE, 625, "progress.hardware.probe.signing_lineage", () -> runSigningLineageProbe(context, targetChain, result));
        runProgressProbe(result, FLAG_METADATA_AUTH, 645, "progress.hardware.probe.metadata_auth", () -> runKeyMetadataAuthorizationProbe(targetAlias, attestationResult, result));
        runProgressProbe(result, FLAG_IMPORT_KEY, 670, "progress.hardware.probe.import_key", () -> runImportKeyProbe(result));
        runProgressProbe(result, FLAG_PATCH_LEVEL, 695, "progress.hardware.probe.patch_level", () -> runPatchLevelConsistencyProbe(attestationResult, result));
        runOptionalProgressProbe(result, FLAG_DEVICE_PROPERTIES, 715,
                "progress.hardware.probe.device_properties",
                () -> runDevicePropertiesProbe(context, result));
        runProgressProbe(result, FLAG_USER_AUTH, 760, "progress.hardware.probe.user_auth", () -> runUserAuthBypassProbe(context, result));
        runOptionalProgressProbe(result, FLAG_SINGLE_USE, 780, "progress.hardware.probe.single_use", () -> runSingleUseProbe(context, result));
        runProgressProbe(result, FLAG_FUTURE_VALIDITY, 800, "progress.hardware.probe.validity", () -> runFutureValidityProbe(result));
        runProgressProbe(result, FLAG_UNIQUE_ID_BYPASS, 820, "progress.hardware.probe.unique_id", () -> runUniqueIdPermissionBypassProbe(context, result));
        runOptionalProgressProbe(result, FLAG_STRONGBOX_DIFFERENTIAL, 840, "progress.hardware.probe.strongbox", () -> runStrongBoxDifferentialProbe(context, result));
        runProgressProbe(result, FLAG_KEYMINT_BOUNDARY, 860, "progress.hardware.probe.keymint_boundary", () -> runKeyMintBoundaryProbe(result));
        runProgressProbe(result, FLAG_OPERATION_SEMANTICS, 880, "progress.hardware.probe.operation_auth", () -> runOperationAuthorizationProbe(result));

        // The selected silent lifecycle check runs even when earlier probes were normal.
        runProgressProbe(result, FLAG_KEYSTORE_STATE, 890, "progress.hardware.probe.keystore_state", () -> runKeystoreStateMachineProbe(result));
        runProgressProbe(result, FLAG_RSA_CONFORMANCE, 891, "progress.hardware.probe.extended_crypto", () -> runExtendedCryptoProbe(result));
        runProgressProbe(result, FLAG_ENTRY_SEMANTICS, 892, "progress.hardware.probe.entry_semantics",
                () -> SilentKeystoreChecks.entrySemantics(silentReporter(result, FLAG_ENTRY_SEMANTICS)));
        runProgressProbe(result, FLAG_OPERATION_ISOLATION, 893, "progress.hardware.probe.operation_isolation",
                () -> SilentKeystoreChecks.operationIsolation(silentReporter(result, FLAG_OPERATION_ISOLATION)));
        runProgressProbe(result, FLAG_CHAIN_READ_STABILITY, 894, "progress.hardware.probe.certificate_record",
                () -> CertificateRecordChecks.run(certificateRecordReporter(result, false),
                        certificateRecordReporter(result, true)));
        // Multi-key graphs and the RSA differential are confirmation probes.
        // They account for most of the extra TEE key generations on slow vendor
        // KeyMint implementations. Both build types execute them only after the
        // independent fast probes have found a concrete inconsistency; debug
        // differs only in retaining detailed evidence, not in timing cost.
        // Timing side channels are independent verdicts. A timing hit is already a finding and
        // must not trigger graph/trap rechecks whose extra key generations cannot confirm or
        // refute the timing observation.
        long nonTimingFindings = result.flags
                & ~(FLAG_REPLY_LAG | FLAG_READ_PATH_TIMING | FLAG_TIMING_SIDE_CHANNEL);
        boolean runDeepConfirmation = result.suspicious && nonTimingFindings != 0L;
        Log.i(TAG, "KeyMint active-probe path: "
                + (runDeepConfirmation ? "deep-confirmation" : "fast"));
        if (runDeepConfirmation) {
            runProgressProbe(result, FLAG_ATTEST_GRAPH, 900, "progress.hardware.probe.attest_graph", () -> runMultiLayerAttestKeyGraphProbe(result));
            runProgressProbe(result, FLAG_ATTEST_TRAP, 905, "progress.hardware.probe.attest_trap", () -> runAttestKeyTrapProbe(context, result));
            runProgressProbe(result, FLAG_ALIAS_CROSSTALK, 910, "progress.hardware.probe.alias_isolation", () -> runMultiAliasCrosstalkProbe(result));
            runProgressProbe(result, FLAG_ATTEST_NEGATIVE, 915, "progress.hardware.probe.attest_negative", () -> runAttestKeyNegativeControlProbe(result));
            runProgressProbe(result, FLAG_ALGORITHM_DIFFERENTIAL, 920, "progress.hardware.probe.algorithm", () -> runAlgorithmDifferentialProbe(attestationResult, result));
        }
        // Start the new process/key-sharing workload after the independent timing sample.
        runOptionalProgressProbe(result, FLAG_ISOLATED_CHAIN, 945, "progress.hardware.probe.isolated_chain",
                () -> runIsolatedChainProbe(context, result));

        runOmkExtensionProbesOnce(context, targetAlias, result);
    }

    /**
     * Executes the independent timing detectors before generation-heavy active probes. Reply-lag
     * keeps the cold generation/visibility edge; the raw-read and contention probes use their own
     * controls and remain independent findings rather than confirmation steps.
     */
    private static void runOmkTimingSuiteOnce(ActiveProbeResult result) {
        if (result.timingSuiteRun) return;
        result.timingSuiteRun = true;

        runProgressProbe(result, FLAG_REPLY_LAG, PROBE_REPLY_LAG, 501,
                "progress.hardware.probe.reply_lag",
                () -> applyTimingProbeResult(result, FLAG_REPLY_LAG, PROBE_REPLY_LAG,
                        OmkTimingProbes.runReplyLag()));
        runProgressProbe(result, FLAG_READ_PATH_TIMING, PROBE_READ_PATH_TIMING, 504,
                "progress.hardware.probe.read_path_timing",
                () -> applyTimingProbeResult(result, FLAG_READ_PATH_TIMING,
                        PROBE_READ_PATH_TIMING, OmkTimingProbes.runReadPathTiming()));
        runProgressProbe(result, FLAG_TIMING_SIDE_CHANNEL, 507,
                "progress.hardware.probe.timing", () -> runKeystoreTimingSideChannelProbe(result));
    }

    /**
     * Runs every new OMK-derived check exactly once, including when the primary certificate path
     * exits early. The risky private-protocol families remain last and each family owns its own
     * timeout and health guards.
     */
    private static ProbeApplicability runAttestKeyDescriptorDelegationProbe(
            Context context,
            ActiveProbeResult result
    ) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return ProbeApplicability.NOT_APPLICABLE;
        }
        if (context == null) {
            result.skipped("AttestKey KeyDescriptor 直接委派检测缺少应用上下文");
            return ProbeApplicability.APPLICABLE;
        }
        boolean featureDeclared = context.getPackageManager().hasSystemFeature(
                OmkAttestKeyProbeSpec.FEATURE_KEYSTORE_APP_ATTEST_KEY);
        if (!OmkAttestKeyProbeSpec.shouldRun(Build.VERSION.SDK_INT, featureDeclared)) {
            if (BuildConfig.DEBUG) {
                Log.d(TAG, "AttestKey descriptor delegation not applicable: "
                        + "FEATURE_KEYSTORE_APP_ATTEST_KEY is not declared");
            }
            return ProbeApplicability.NOT_APPLICABLE;
        }
        OmkRiskyProbes.runAttestKeyDescriptorDelegation(namedSilentReporter(result,
                FLAG_ATTEST_KEY_DESCRIPTOR_DELEGATION,
                PROBE_ATTEST_KEY_DESCRIPTOR_DELEGATION));
        return ProbeApplicability.APPLICABLE;
    }

    private static void runOmkExtensionProbesOnce(
            Context context,
            String targetAlias,
            ActiveProbeResult result
    ) {
        if (result.omkExtensionsRun) return;
        result.omkExtensionsRun = true;

        runProgressProbe(result, FLAG_METADATA_AUTH, PROBE_METADATA_SECURITY_LEVEL, 946,
                "progress.hardware.probe.metadata_security_level",
                () -> applyStructuralProbeResult(result, FLAG_METADATA_AUTH,
                        PROBE_METADATA_SECURITY_LEVEL,
                        StructuralKeystoreProbes.runMetadataSecurityLevels(
                                ks2GeneratedMetadata.get(targetAlias),
                                ks2EntryMetadata.get(targetAlias))));
        runOptionalProgressProbe(result, FLAG_ATTEST_KEY_DESCRIPTOR_DELEGATION, 947,
                "progress.hardware.probe.attest_key_descriptor_delegation",
                () -> runAttestKeyDescriptorDelegationProbe(context, result));
        runProgressProbe(result, FLAG_BINDER_LOCALITY, PROBE_BINDER_LOCALITY, 948,
                "progress.hardware.probe.binder_locality",
                () -> applyStructuralProbeResult(result, FLAG_BINDER_LOCALITY,
                        PROBE_BINDER_LOCALITY, StructuralKeystoreProbes.runBinderLocality()));
        runProgressProbe(result, FLAG_KEY_ID_CONSISTENCY,
                PROBE_KEY_ID_CONSISTENCY, 950,
                "progress.hardware.probe.key_id_consistency",
                () -> applyStatePlaneProbeResult(result, FLAG_KEY_ID_CONSISTENCY,
                        PROBE_KEY_ID_CONSISTENCY,
                        KeystoreStatePlaneProbes.runAliasKeyIdConsistency()));
        runProgressProbe(result, FLAG_KEYSTORE_LEDGER,
                PROBE_KEYSTORE_LEDGER, 952,
                "progress.hardware.probe.keystore_ledger",
                () -> applyStatePlaneProbeResult(result, FLAG_KEYSTORE_LEDGER,
                        PROBE_KEYSTORE_LEDGER,
                        KeystoreStatePlaneProbes.runLedgerStatePlane()));
        runProgressProbe(result, FLAG_INTERFACE_TOKEN_DISPATCH,
                PROBE_INTERFACE_TOKEN_DISPATCH, 970,
                "progress.hardware.probe.interface_token_dispatch",
                () -> OmkRiskyProbes.runTokenDispatch(namedSilentReporter(result,
                        FLAG_INTERFACE_TOKEN_DISPATCH, PROBE_INTERFACE_TOKEN_DISPATCH)));
        runProgressProbe(result, FLAG_PARAMETER_FINGERPRINT,
                PROBE_PARAMETER_FINGERPRINT, 975,
                "progress.hardware.probe.parameter_fingerprint",
                () -> OmkRiskyProbes.runParameterFingerprint(namedSilentReporter(result,
                        FLAG_PARAMETER_FINGERPRINT, PROBE_PARAMETER_FINGERPRINT)));
        runProgressProbe(result, FLAG_TEESIM_PARAMETER_FINGERPRINT,
                PROBE_TEESIM_PARAMETER_FINGERPRINT, 980,
                "progress.hardware.probe.teesim_parameter_fingerprint",
                () -> OmkRiskyProbes.runTeeSimFingerprint(namedSilentReporter(result,
                        FLAG_TEESIM_PARAMETER_FINGERPRINT,
                        PROBE_TEESIM_PARAMETER_FINGERPRINT)));
    }

    private static final class AttestationProfile {
        final Attestation attestation;
        final RootOfTrust rootOfTrust;
        final String brand;
        final String device;
        final String product;
        final String manufacturer;
        final String model;
        final Integer osVersion;
        final Integer osPatchLevel;
        final Integer vendorPatchLevel;
        final Integer bootPatchLevel;

        AttestationProfile(Attestation attestation) {
            this.attestation = attestation;
            this.rootOfTrust = attestation == null ? null : attestation.getRootOfTrust();
            AuthorizationList tee = attestation == null ? null : attestation.getTeeEnforced();
            AuthorizationList software = attestation == null ? null : attestation.getSoftwareEnforced();
            this.brand = firstNonBlank(
                    tee == null ? null : tee.getBrand(),
                    software == null ? null : software.getBrand());
            this.device = firstNonBlank(
                    tee == null ? null : tee.getDevice(),
                    software == null ? null : software.getDevice());
            this.product = firstNonBlank(
                    tee == null ? null : tee.getProduct(),
                    software == null ? null : software.getProduct());
            this.manufacturer = firstNonBlank(
                    tee == null ? null : tee.getManufacturer(),
                    software == null ? null : software.getManufacturer());
            this.model = firstNonBlank(
                    tee == null ? null : tee.getModel(),
                    software == null ? null : software.getModel());
            this.osVersion = attestation == null ? null : attestation.getOsVersion();
            this.osPatchLevel = attestation == null ? null : attestation.getOsPatchLevel();
            this.vendorPatchLevel = attestation == null ? null : attestation.getVendorPatchLevel();
            this.bootPatchLevel = attestation == null ? null : attestation.getBootPatchLevel();
        }

        int devicePropertyCount() {
            int count = 0;
            if (isUsableDeviceProperty(brand)) count++;
            if (isUsableDeviceProperty(device)) count++;
            if (isUsableDeviceProperty(product)) count++;
            if (isUsableDeviceProperty(manufacturer)) count++;
            if (isUsableDeviceProperty(model)) count++;
            return count;
        }

        String missingDeviceProperties() {
            StringBuilder missing = new StringBuilder();
            appendMissingProperty(missing, "brand", brand);
            appendMissingProperty(missing, "device", device);
            appendMissingProperty(missing, "product", product);
            appendMissingProperty(missing, "manufacturer", manufacturer);
            appendMissingProperty(missing, "model", model);
            return missing.toString();
        }

        private static void appendMissingProperty(
                StringBuilder missing,
                String name,
                String value
        ) {
            if (isUsableDeviceProperty(value)) return;
            if (missing.length() > 0) missing.append(", ");
            missing.append(name);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String firstNonBlank(String primary, String fallback) {
        if (isUsableDeviceProperty(primary)) return primary.trim();
        return isUsableDeviceProperty(fallback) ? fallback.trim() : null;
    }

    private static boolean isUsableDeviceProperty(String value) {
        return !isBlank(value) && !Build.UNKNOWN.equalsIgnoreCase(value.trim());
    }

    private static String normalizedIdentity(String value) {
        return isUsableDeviceProperty(value)
                ? value.trim().toLowerCase(java.util.Locale.ROOT) : null;
    }

    private static int parseReleaseMajor(String release) {
        if (isBlank(release)) return -1;
        int end = 0;
        while (end < release.length() && Character.isDigit(release.charAt(end))) end++;
        if (end == 0) return -1;
        try {
            return Integer.parseInt(release.substring(0, end));
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }

    private static String devicePropertyExpectedByKeystore(
            String property,
            String frameworkFallback
    ) {
        String overrideProperty = DevicePropertiesProbeDecision.attestationOverrideProperty(
                Build.VERSION.SDK_INT, property);
        if (overrideProperty == null) return frameworkFallback;

        String override = SystemProperties.get(overrideProperty, "");
        if (isUsableDeviceProperty(override)) return override;

        // On Android 14+ an AOSP/GSI build may deliberately attest the hidden
        // *_for_attestation value instead of Build.*. An ordinary app cannot reliably tell
        // "property absent" from "property not readable", so Build.* is not a safe mismatch
        // oracle for these three fields when the exact override cannot be observed.
        return null;
    }

    private static String compareDeviceProperties(AttestationProfile profile) {
        if (profile == null || profile.devicePropertyCount() == 0) return "";
        StringBuilder mismatch = new StringBuilder();
        String[][] values = {
                {"brand", profile.brand,
                        devicePropertyExpectedByKeystore("brand", Build.BRAND)},
                {"device", profile.device,
                        devicePropertyExpectedByKeystore("device", Build.DEVICE)},
                {"product", profile.product,
                        devicePropertyExpectedByKeystore("name", Build.PRODUCT)},
                {"manufacturer", profile.manufacturer,
                        devicePropertyExpectedByKeystore("manufacturer", Build.MANUFACTURER)},
                {"model", profile.model,
                        devicePropertyExpectedByKeystore("model", Build.MODEL)},
        };
        for (String[] item : values) {
            String attested = normalizedIdentity(item[1]);
            String framework = normalizedIdentity(item[2]);
            // A missing framework value or an omitted attested ID is a capability
            // limitation, not evidence of tampering. Only compare complete pairs.
            if (attested != null && framework != null && !attested.equals(framework)) {
                if (mismatch.length() > 0) mismatch.append(", ");
                mismatch.append(item[0]).append("=").append(item[1])
                        .append(" vs requested=").append(item[2]);
            }
        }
        return mismatch.toString();
    }

    private static String describeProbeFailure(Throwable failure) {
        if (failure == null) return "unknown failure";
        StringBuilder summary = new StringBuilder();
        Set<Throwable> seen = new HashSet<>();
        Throwable current = failure;
        int depth = 0;
        while (current != null && depth++ < 6 && seen.add(current)) {
            if (summary.length() > 0) summary.append(" <- ");
            summary.append(current.getClass().getSimpleName());
            String message = current.getMessage();
            if (!isBlank(message)) summary.append(": ").append(message.trim());
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                    && current instanceof KeyStoreException keyStoreFailure) {
                summary.append(" [publicErrorCode=")
                        .append(keyStoreFailure.getNumericErrorCode())
                        .append(", transient=")
                        .append(keyStoreFailure.isTransientFailure())
                        .append(']');
            }
            current = current.getCause();
        }
        return summary.toString();
    }

    /**
     * Generates the canonical Device Properties request with the system-provided attestation key.
     * App AttestKey behaviour is covered by independent probes; coupling it here makes an optional
     * signing-key path indistinguishable from Device-ID capability failure.
     */
    @TargetApi(Build.VERSION_CODES.S)
    private static void generateDevicePropertiesProbeKey(
            String probeAlias,
            String challengeTag,
            boolean includeDeviceProperties
    ) throws Exception {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                probeAlias,
                KeyProperties.PURPOSE_SIGN
        )
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(makeProbeChallenge(challengeTag));
        if (includeDeviceProperties) {
            builder.setDevicePropertiesAttestationIncluded(true);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        generator.initialize(builder.build());
        generator.generateKeyPair();
    }

    private static final class DevicePropertiesControlResult {
        final boolean baselineSucceeded;
        final String evidence;

        DevicePropertiesControlResult(boolean baselineSucceeded, String evidence) {
            this.baselineSucceeded = baselineSucceeded;
            this.evidence = evidence;
        }
    }

    private static AttestationProfile readAttestationProfile(Certificate[] chain)
            throws Exception {
        if (chain == null || chain.length == 0) return null;
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        ArrayList<X509Certificate> certificates = new ArrayList<>(chain.length);
        for (Certificate certificate : chain) {
            certificates.add(asX509Certificate(certificate, factory));
        }
        AttestationResult parsed = parseCertificateChain(certificates);
        return parsed == null ? null : new AttestationProfile(parsed.showAttestation);
    }

    private static DevicePropertiesControlResult runDevicePropertiesFailureControl(
            KeyStore keyStore,
            String phase
    ) {
        String controlAlias = makeProbeAlias("device_properties_control_" + phase);
        try {
            safeDeleteEntry(keyStore, controlAlias);
            generateDevicePropertiesProbeKey(
                    controlAlias, "device-properties-control-" + phase, false);
            Certificate[] controlChain = keyStore.getCertificateChain(controlAlias);
            if (controlChain == null || controlChain.length == 0) {
                return new DevicePropertiesControlResult(false,
                        phase + "基础证明对照未返回证书链");
            }
            AttestationProfile controlProfile = readAttestationProfile(controlChain);
            if (controlProfile == null || controlProfile.attestation == null) {
                return new DevicePropertiesControlResult(false,
                        phase + "基础证明对照证书链不含可解析的 Android Key Attestation 扩展");
            }
            return new DevicePropertiesControlResult(true,
                    phase + "基础证明对照成功");
        } catch (Throwable controlFailure) {
            return new DevicePropertiesControlResult(false,
                    phase + "基础证明对照失败："
                            + describeProbeFailure(controlFailure));
        } finally {
            safeDeleteEntry(keyStore, controlAlias);
        }
    }

    private static final class DevicePropertiesAttempt {
        final boolean keyGenerated;
        final AttestationProfile profile;
        final Throwable failure;
        final String unavailableEvidence;

        DevicePropertiesAttempt(
                boolean keyGenerated,
                AttestationProfile profile,
                Throwable failure,
                String unavailableEvidence
        ) {
            this.keyGenerated = keyGenerated;
            this.profile = profile;
            this.failure = failure;
            this.unavailableEvidence = unavailableEvidence;
        }
    }

    private static DevicePropertiesAttempt runDevicePropertiesAttempt(
            KeyStore keyStore,
            String phase
    ) {
        String probeAlias = makeProbeAlias("device_properties_" + phase);
        boolean keyGenerated = false;
        try {
            safeDeleteEntry(keyStore, probeAlias);
            generateDevicePropertiesProbeKey(
                    probeAlias, "device-properties-" + phase, true);
            keyGenerated = true;

            Certificate[] chain = keyStore.getCertificateChain(probeAlias);
            if (chain == null || chain.length == 0) {
                return new DevicePropertiesAttempt(true, null, null,
                        phase + " Device Properties 请求未返回证书链");
            }
            AttestationProfile profile = readAttestationProfile(chain);
            if (profile == null) {
                return new DevicePropertiesAttempt(true, null, null,
                        phase + " Device Properties 证书链无法解析");
            }
            return new DevicePropertiesAttempt(true, profile, null, "");
        } catch (Throwable failure) {
            if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
            return new DevicePropertiesAttempt(keyGenerated, null, failure,
                    phase + (keyGenerated
                            ? " Device Properties 证书读取或解析失败："
                            : " Device Properties 密钥生成失败：")
                            + describeProbeFailure(failure));
        } finally {
            safeDeleteEntry(keyStore, probeAlias);
        }
    }

    private static boolean hasTransientOrUnclassifiedKeyStoreFailure(Throwable failure) {
        Set<Throwable> seen = new HashSet<>();
        Throwable current = failure;
        int depth = 0;
        boolean sawKeyStoreFailure = false;
        while (current != null && depth++ < 8 && seen.add(current)) {
            if (current instanceof KeyStoreException keyStoreFailure) {
                sawKeyStoreFailure = true;
                // Android 12 cannot expose the public transient classification. Treat that
                // uncertainty as inconclusive instead of turning an RKP recovery window into
                // a positive tampering verdict.
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true;
                if (keyStoreFailure.isTransientFailure()) return true;
            }
            current = current.getCause();
        }
        // Without a public KeyStoreException classification, a repeated provider or binder
        // exception is still an unknown failure, not proof that it is permanent.
        return !sawKeyStoreFailure;
    }

    private static String devicePropertiesFailureSignature(Throwable failure) {
        if (failure == null) return "none";
        StringBuilder signature = new StringBuilder();
        Set<Throwable> seen = new HashSet<>();
        Throwable current = failure;
        int depth = 0;
        while (current != null && depth++ < 8 && seen.add(current)) {
            if (signature.length() > 0) signature.append("<-");
            signature.append(current.getClass().getName());
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                    && current instanceof KeyStoreException keyStoreFailure) {
                signature.append('#').append(keyStoreFailure.getNumericErrorCode());
            }
            if ("android.os.ServiceSpecificException".equals(
                    current.getClass().getName())) {
                try {
                    Object errorCode = current.getClass().getField("errorCode").get(current);
                    signature.append('#').append(errorCode);
                } catch (ReflectiveOperationException ignored) {
                    // The throwable class still remains part of the stable signature.
                }
            }
            current = current.getCause();
        }
        return signature.toString();
    }

    private static String devicePropertiesProfileIssue(AttestationProfile profile) {
        int propertyCount = profile == null ? 0 : profile.devicePropertyCount();
        if (!DevicePropertiesProbeDecision.hasCompletePropertySet(propertyCount)) {
            String missing = profile == null ? "brand, device, product, manufacturer, model"
                    : profile.missingDeviceProperties();
            return "Device Properties 请求已成功，但证书扩展仅返回 "
                    + propertyCount + "/" + DevicePropertiesProbeDecision.REQUIRED_PROPERTY_COUNT
                    + " 个必要身份属性；缺少=" + missing;
        }
        String mismatch = compareDeviceProperties(profile);
        if (!mismatch.isEmpty()) {
            return "硬件 Device Properties 与 Keystore 提交的设备属性不一致：" + mismatch;
        }
        return "";
    }

    private static void reportRepeatedDevicePropertiesProfiles(
            AttestationProfile first,
            AttestationProfile retry,
            ActiveProbeResult result
    ) {
        String firstIssue = devicePropertiesProfileIssue(first);
        if (firstIssue.isEmpty()) {
            result.normal("硬件 Device Properties 完整，且与可可靠观测的 Keystore 请求值一致");
            return;
        }
        String retryIssue = devicePropertiesProfileIssue(retry);
        if (DevicePropertiesProbeDecision.isRepeatableReturnedAnomaly(firstIssue, retryIssue)) {
            result.high(firstIssue + "；独立重试返回同一异常，已排除单次读取或解析抖动");
        } else if (retryIssue.isEmpty()) {
            result.warn("首次 Device Properties 返回差异未能复现，重试结果正常；不判定异常");
        } else {
            result.warn("两次 Device Properties 返回的异常不一致，证据不可重复；不判定异常");
        }
    }

    private static ProbeApplicability runDevicePropertiesProbe(
            Context context,
            ActiveProbeResult result
    ) {
        boolean featureDeclared = context.getPackageManager().hasSystemFeature(
                FEATURE_DEVICE_ID_ATTESTATION);
        if (!AttestationStateEvidence.shouldRunDeviceProperties(
                Build.VERSION.SDK_INT, featureDeclared)) {
            result.normal("设备未声明可选的 Device ID Attestation 能力，本项不适用");
            return ProbeApplicability.NOT_APPLICABLE;
        }

        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            DevicePropertiesControlResult baselineBefore =
                    runDevicePropertiesFailureControl(keyStore, "前置");

            DevicePropertiesAttempt first =
                    runDevicePropertiesAttempt(keyStore, "首次");
            if (first.profile != null) {
                String firstIssue = devicePropertiesProfileIssue(first.profile);
                if (firstIssue.isEmpty()) {
                    reportRepeatedDevicePropertiesProfiles(first.profile, null, result);
                    return ProbeApplicability.APPLICABLE;
                }
                DevicePropertiesAttempt retry =
                        runDevicePropertiesAttempt(keyStore, "返回异常复核");
                if (retry.profile == null) {
                    result.warn("首次 Device Properties 返回差异，但独立复核未取得可解析证书；"
                            + "单次证据不足，不判定异常");
                    return ProbeApplicability.APPLICABLE;
                }
                reportRepeatedDevicePropertiesProfiles(first.profile, retry.profile, result);
                return ProbeApplicability.APPLICABLE;
            }
            if (first.keyGenerated || first.failure == null) {
                result.skipped("Device Properties Attestation 探针无法完成："
                        + first.unavailableEvidence + "；" + baselineBefore.evidence);
                return ProbeApplicability.APPLICABLE;
            }

            DevicePropertiesControlResult baselineAfter =
                    runDevicePropertiesFailureControl(keyStore, "后置");

            DevicePropertiesAttempt retry =
                    runDevicePropertiesAttempt(keyStore, "重试");
            if (retry.profile != null) {
                String retryIssue = devicePropertiesProfileIssue(retry.profile);
                if (retryIssue.isEmpty()) {
                    result.normal("首次属性请求失败、健康基础对照后重试成功；"
                            + "硬件 Device Properties 完整且与可可靠观测的请求值一致");
                } else {
                    result.warn("首次属性请求失败，重试虽成功但返回差异；缺少第二份成功响应复核，"
                            + "不判定异常：" + retryIssue);
                }
                return ProbeApplicability.APPLICABLE;
            }
            if (retry.keyGenerated || retry.failure == null) {
                result.skipped("Device Properties Attestation 重试仍无法完成："
                        + retry.unavailableEvidence + "；" + baselineBefore.evidence
                        + "；" + baselineAfter.evidence);
                return ProbeApplicability.APPLICABLE;
            }

            boolean transientOrUnclassified =
                    hasTransientOrUnclassifiedKeyStoreFailure(first.failure)
                            || hasTransientOrUnclassifiedKeyStoreFailure(retry.failure);
            String firstSignature = devicePropertiesFailureSignature(first.failure);
            String retrySignature = devicePropertiesFailureSignature(retry.failure);
            boolean sameFailureSignature = firstSignature.equals(retrySignature);
            if (DevicePropertiesProbeDecision.isRepeatableDifferential(
                    baselineBefore.baselineSucceeded,
                    true,
                    baselineAfter.baselineSucceeded,
                    true,
                    transientOrUnclassified,
                    sameFailureSignature)) {
                result.high("设备声明支持 Device ID Attestation；前后基础证明对照均成功，"
                        + "但 Device Properties 请求以相同、非瞬态错误连续失败："
                        + describeProbeFailure(first.failure)
                        + "；该可重复差分表明属性请求路径行为异常，"
                        + "但不能单独归因于 TrickyStore 或其他具体拦截器");
            } else {
                String reason;
                if (!baselineBefore.baselineSucceeded || !baselineAfter.baselineSucceeded) {
                    reason = "前后基础证明对照未同时保持健康，无法排除证明服务波动";
                } else if (transientOrUnclassified) {
                    reason = "错误属于瞬态故障，或当前 Android 版本无法可靠分类其瞬态性质";
                } else if (!sameFailureSignature) {
                    reason = "两次失败签名不同，未形成可重复差分";
                } else {
                    reason = "未满足可重复差分的全部判定条件";
                }
                result.skipped("Device Properties Attestation 探针无法执行："
                        + first.unavailableEvidence + "；" + retry.unavailableEvidence
                        + "；" + baselineBefore.evidence + "；" + baselineAfter.evidence
                        + "；" + reason);
            }
        } catch (Throwable t) {
            result.skipped("Device Properties Attestation 探针无法执行："
                    + describeProbeFailure(t));
            Log.w(TAG, "runDevicePropertiesProbe failed", t);
        }
        return ProbeApplicability.APPLICABLE;
    }

    private static AttestationResult generateAlgorithmProbe(
            KeyStore keyStore,
            String algorithm,
            boolean rsa
    ) throws Exception {
        String probeAlias = makeProbeAlias(rsa ? "rsa" : "ec");
        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    probeAlias,
                    KeyProperties.PURPOSE_SIGN
            )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(makeProbeChallenge(rsa ? "rsa-differential" : "ec-differential"));
            if (rsa) {
                builder.setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
            } else {
                builder.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"));
            }
            applyProbeAttestKeyIfAvailable(builder);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore");
            generator.initialize(builder.build());
            generator.generateKeyPair();
            Certificate[] chain = keyStore.getCertificateChain(probeAlias);
            if (chain == null || chain.length == 0) return null;
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            ArrayList<X509Certificate> certificates = new ArrayList<>(chain.length);
            for (Certificate certificate : chain) certificates.add(asX509Certificate(certificate, factory));
            return parseCertificateChain(certificates);
        } finally {
            safeDeleteEntry(keyStore, probeAlias);
        }
    }

    private static String compareAlgorithmProfiles(AttestationProfile first, AttestationProfile second) {
        if (first == null || second == null) return "";
        StringBuilder mismatch = new StringBuilder();
        String[][] properties = {
                {"brand", first.brand, second.brand},
                {"device", first.device, second.device},
                {"product", first.product, second.product},
                {"manufacturer", first.manufacturer, second.manufacturer},
                {"model", first.model, second.model},
        };
        for (String[] item : properties) {
            String left = normalizedIdentity(item[1]);
            String right = normalizedIdentity(item[2]);
            if (left != null && right != null && !left.equals(right)) {
                if (mismatch.length() > 0) mismatch.append(", ");
                mismatch.append(item[0]).append(" differs");
            }
        }
        if (first.osVersion != null && second.osVersion != null && !first.osVersion.equals(second.osVersion)) {
            if (mismatch.length() > 0) mismatch.append(", ");
            mismatch.append("osVersion differs");
        }
        if (first.osPatchLevel != null && second.osPatchLevel != null && !first.osPatchLevel.equals(second.osPatchLevel)) {
            if (mismatch.length() > 0) mismatch.append(", ");
            mismatch.append("osPatchLevel differs");
        }
        if (first.vendorPatchLevel != null && second.vendorPatchLevel != null
                && !first.vendorPatchLevel.equals(second.vendorPatchLevel)) {
            if (mismatch.length() > 0) mismatch.append(", ");
            mismatch.append("vendorPatchLevel differs");
        }
        if (first.bootPatchLevel != null && second.bootPatchLevel != null
                && !first.bootPatchLevel.equals(second.bootPatchLevel)) {
            if (mismatch.length() > 0) mismatch.append(", ");
            mismatch.append("bootPatchLevel differs");
        }
        if (first.rootOfTrust != null && second.rootOfTrust != null) {
            if (first.rootOfTrust.isDeviceLocked() != second.rootOfTrust.isDeviceLocked()
                    || first.rootOfTrust.getVerifiedBootState() != second.rootOfTrust.getVerifiedBootState()) {
                if (mismatch.length() > 0) mismatch.append(", ");
                mismatch.append("RootOfTrust state differs");
            }
            byte[] firstHash = first.rootOfTrust.getVerifiedBootHash();
            byte[] secondHash = second.rootOfTrust.getVerifiedBootHash();
            if (firstHash != null && secondHash != null && !Arrays.equals(firstHash, secondHash)) {
                if (mismatch.length() > 0) mismatch.append(", ");
                mismatch.append("verifiedBootHash differs");
            }
        }
        if (first.attestation != null && second.attestation != null) {
            int firstLevel = first.attestation.getAttestationSecurityLevel();
            int secondLevel = second.attestation.getAttestationSecurityLevel();
            int firstKeymasterLevel = first.attestation.getKeymasterSecurityLevel();
            int secondKeymasterLevel = second.attestation.getKeymasterSecurityLevel();
            // A secure EC key silently falling back to software for RSA (or the
            // reverse) is not a normal representation of one KeyMint backend.
            boolean firstSoftware = firstLevel == Attestation.KM_SECURITY_LEVEL_SOFTWARE
                    || firstKeymasterLevel == Attestation.KM_SECURITY_LEVEL_SOFTWARE;
            boolean secondSoftware = secondLevel == Attestation.KM_SECURITY_LEVEL_SOFTWARE
                    || secondKeymasterLevel == Attestation.KM_SECURITY_LEVEL_SOFTWARE;
            if (firstSoftware != secondSoftware) {
                if (mismatch.length() > 0) mismatch.append(", ");
                mismatch.append("securityLevel differs");
            }
        }
        return mismatch.toString();
    }

    private static void runAlgorithmDifferentialProbe(AttestationResult primary, ActiveProbeResult result) {
        if (primary == null || primary.showAttestation == null) {
            result.skipped("RSA / EC 对照缺少主证明结果");
            return;
        }
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            AttestationResult rsa = generateAlgorithmProbe(keyStore, KeyProperties.KEY_ALGORITHM_RSA, true);
            if (rsa == null || rsa.showAttestation == null) {
                result.skipped("当前 KeyMint 未返回 RSA 证明链，跳过 RSA / EC 对照");
                return;
            }
            String mismatch = compareAlgorithmProfiles(
                    new AttestationProfile(primary.showAttestation),
                    new AttestationProfile(rsa.showAttestation));
            if (!mismatch.isEmpty()) {
                result.high("RSA / EC Attestation 画像不一致：" + mismatch
                        + "；疑似按算法分流到不同的伪造或软件 KeyMint 后端");
            } else {
                result.normal("RSA / EC Attestation 画像一致");
            }
        } catch (Throwable t) {
            result.skipped("RSA / EC 对照无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runAlgorithmDifferentialProbe failed", t);
        }
    }

    private static ProbeApplicability runStrongBoxDifferentialProbe(Context context, ActiveProbeResult result) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (BuildConfig.DEBUG) Log.d(TAG, "StrongBox differential not applicable below Android 9");
            return ProbeApplicability.NOT_APPLICABLE;
        }
        if (context == null) {
            result.skipped("StrongBox 对照缺少应用上下文");
            return ProbeApplicability.APPLICABLE;
        }
        if (!context.getPackageManager().hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            if (BuildConfig.DEBUG) Log.d(TAG, "StrongBox differential not applicable: feature not declared");
            return ProbeApplicability.NOT_APPLICABLE;
        }
        String probeAlias = makeProbeAlias("strongbox");
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, probeAlias);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    probeAlias,
                    KeyProperties.PURPOSE_SIGN
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(makeProbeChallenge("strongbox-differential"))
                    .setIsStrongBoxBacked(true);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(builder.build());
            generator.generateKeyPair();
            Certificate[] chain = keyStore.getCertificateChain(probeAlias);
            if (chain == null || chain.length == 0) {
                result.skipped("StrongBox 请求未返回证书链");
                return ProbeApplicability.APPLICABLE;
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            ArrayList<X509Certificate> certificates = new ArrayList<>(chain.length);
            for (Certificate certificate : chain) certificates.add(asX509Certificate(certificate, factory));
            AttestationResult parsed = parseCertificateChain(certificates);
            Attestation attestation = parsed == null ? null : parsed.showAttestation;
            if (attestation == null) {
                result.skipped("StrongBox 请求已成功但证书中没有可解析的 Attestation 记录");
                return ProbeApplicability.APPLICABLE;
            }

            int attestationLevel = attestation.getAttestationSecurityLevel();
            int keymasterLevel = attestation.getKeymasterSecurityLevel();
            boolean keymasterStrongBox = keymasterLevel == Attestation.KM_SECURITY_LEVEL_STRONG_BOX;

            // attestationSecurityLevel describes the keymaster instance that
            // signed the attestation certificate. It may legitimately be TEE
            // while the key being attested is stored in StrongBox.
            if (!keymasterStrongBox) {
                result.high("显式请求 StrongBox 后，Attestation 的被测密钥安全级别仍为非 StrongBox"
                        + "：attestation=" + Attestation.securityLevelToString(attestationLevel)
                        + ", keymaster=" + Attestation.securityLevelToString(keymasterLevel));
            } else if (attestationLevel == Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
                result.warn("StrongBox 密钥由 TEE Attestation 签名，属于允许的跨安全级别组合"
                        + "：attestation=TEE, keymaster=StrongBox");
            } else if (attestationLevel != Attestation.KM_SECURITY_LEVEL_STRONG_BOX) {
                result.high("StrongBox 被测密钥的 Attestation 签名安全级别异常"
                        + "：attestation=" + Attestation.securityLevelToString(attestationLevel)
                        + ", keymaster=StrongBox");
            }

            // API 31+ exposes the storage level of the actual key object. Read
            // it back by alias so a generated KeyPair wrapper cannot mask a
            // provider-side downgrade or key/certificate substitution.
            boolean keyInfoConsistent = true;
            try {
                var privateKey = keyStore.getKey(probeAlias, null);
                if (!(privateKey instanceof PrivateKey)) {
                    result.skipped("StrongBox 请求后无法读回私钥，跳过 KeyInfo 安全级别对照");
                    return ProbeApplicability.APPLICABLE;
                }
                var keyInfo = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore")
                        .getKeySpec(privateKey, KeyInfo.class);
                if (!keyInfo.isInsideSecureHardware()) {
                    keyInfoConsistent = false;
                    result.high("显式请求 StrongBox 后，读回密钥未由安全硬件支持");
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                        && keyInfo.getSecurityLevel() != KeyProperties.SECURITY_LEVEL_STRONGBOX) {
                    keyInfoConsistent = false;
                    result.high("显式请求 StrongBox 后，KeyInfo 返回的实际安全级别不是 StrongBox"
                            + "：securityLevel=" + keyInfo.getSecurityLevel());
                }
            } catch (Throwable t) {
                keyInfoConsistent = false;
                result.skipped("StrongBox 请求后的 KeyInfo 对照无法执行："
                        + t.getClass().getSimpleName() + ": " + t.getMessage());
                Log.w(TAG, "StrongBox KeyInfo comparison failed", t);
            }

            if (keymasterStrongBox
                    && (attestationLevel == Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                    || attestationLevel == Attestation.KM_SECURITY_LEVEL_STRONG_BOX)
                    && keyInfoConsistent) {
                result.normal("StrongBox 请求、被测密钥 Attestation 和 KeyInfo 对照通过");
            }
        } catch (Throwable t) {
            // FEATURE_STRONGBOX_KEYSTORE is a capability declaration. A provider
            // may still have no slot, reject attestation for this key profile, or expose StrongBox
            // only to privileged callers. Those normal capability limits make the differential
            // inapplicable; they are not an execution failure and must not become an UNAVAILABLE
            // finding on ordinary devices.
            result.normal("StrongBox 差分不适用：系统未接受本次 StrongBox 证明请求（"
                    + t.getClass().getSimpleName() + ")");
            Log.w(TAG, "runStrongBoxDifferentialProbe failed", t);
            return ProbeApplicability.NOT_APPLICABLE;
        } finally {
            if (keyStore != null) safeDeleteEntry(keyStore, probeAlias);
        }
        return ProbeApplicability.APPLICABLE;
    }

    private static void runKeyMintBoundaryProbe(ActiveProbeResult result) {
        // The requested authorization is independent of App Attest Key delegation. Some normal
        // OEM AttestKeys reject this child profile, so use the platform's default signer.
        SilentKeystoreChecks.unlockedDeviceField(builder -> { },
                silentReporter(result, FLAG_KEYMINT_BOUNDARY));
    }

    private static byte[] getSubjectKeyIdentifier(X509Certificate cert) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            Extension ext = holder.getExtension(Extension.subjectKeyIdentifier);
            if (ext == null) return null;
            return SubjectKeyIdentifier.getInstance(ext.getParsedValue()).getKeyIdentifier();
        } catch (Throwable t) {
            Log.d(TAG, "getSubjectKeyIdentifier failed: " + t);
            return null;
        }
    }

    private static byte[] getAuthorityKeyIdentifier(X509Certificate cert) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            Extension ext = holder.getExtension(Extension.authorityKeyIdentifier);
            if (ext == null) return null;
            return AuthorityKeyIdentifier.getInstance(ext.getParsedValue()).getKeyIdentifier();
        } catch (Throwable t) {
            Log.d(TAG, "getAuthorityKeyIdentifier failed: " + t);
            return null;
        }
    }

    private static String checkCertificateChainStructure(Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            return "证书链为空";
        }

        // 注意：使用 App Attest Key / setAttestKeyAlias(attestAlias) 时，业务 key 的
        // getCertificateChain(alias) 在部分 ROM 上可能只返回业务 key 的 leaf，
        // 完整上级链在 attestAlias 里。单独 leaf 不代表伪造，不能直接判定风险。
        if (chain.length == 1) {
            if (!(chain[0] instanceof X509Certificate)) {
                return "证书链中包含非 X.509 证书";
            }
            Log.d(TAG, "checkCertificateChainStructure: single-leaf chain, skip continuity check");
            return null;
        }

        try {
            for (int i = 0; i < chain.length - 1; i++) {
                if (!(chain[i] instanceof X509Certificate child) || !(chain[i + 1] instanceof X509Certificate parent)) {
                    return "证书链中包含非 X.509 证书";
                }
                if (!child.getIssuerX500Principal().equals(parent.getSubjectX500Principal())) {
                    return "证书链 issuer/subject 不连续：index=" + i
                            + ", issuer=" + child.getIssuerX500Principal().getName()
                            + ", parentSubject=" + parent.getSubjectX500Principal().getName();
                }
                try {
                    child.verify(parent.getPublicKey());
                } catch (Throwable verifyError) {
                    return "证书链签名无法由上级证书验证：index=" + i + ", "
                            + verifyError.getClass().getSimpleName() + ": " + verifyError.getMessage();
                }
                byte[] aki = getAuthorityKeyIdentifier(child);
                byte[] ski = getSubjectKeyIdentifier(parent);
                if (aki != null && ski != null && !Arrays.equals(aki, ski)) {
                    return "证书链 AuthorityKeyIdentifier 与上级 SubjectKeyIdentifier 不匹配：index=" + i;
                }
            }
            return null;
        } catch (Throwable t) {
            return "证书链结构检查异常：" + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }


    private static boolean hasAndroidKeyAttestationExtension(Certificate[] chain) {
        if (chain == null) return false;
        for (Certificate certificate : chain) {
            if (!(certificate instanceof X509Certificate cert)) continue;
            try {
                if (cert.getExtensionValue(ANDROID_KEY_ATTESTATION_OID) != null) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private static Object readField(Object obj, String fieldName) {
        if (obj == null || fieldName == null) return null;
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.get(obj);
            } catch (Throwable ignored) {
                c = c.getSuperclass();
            }
        }
        return null;
    }

    private static int objectArraySize(Object value) {
        if (value == null) return -1;
        if (value instanceof Collection<?> collection) return collection.size();
        Class<?> c = value.getClass();
        if (c.isArray()) return Array.getLength(value);
        return -1;
    }

    private static int keyMetadataAuthorizationCount(KeyMetadata metadata) {
        if (metadata == null) return -1;
        return objectArraySize(readField(metadata, "authorizations"));
    }

    private static int keyMetadataSecurityLevel(KeyMetadata metadata) {
        if (metadata == null) return -1;
        Object value = readField(metadata, "keySecurityLevel");
        if (value instanceof Number number) return number.intValue();
        return -1;
    }

    private static String collectAuthorizationTagPreview(KeyMetadata metadata) {
        Object auths = metadata == null ? null : readField(metadata, "authorizations");
        if (auths == null) return "";
        int size = objectArraySize(auths);
        if (size <= 0) return "";
        StringBuilder sb = new StringBuilder(96);
        int max = Math.min(size, 12);
        for (int i = 0; i < max; i++) {
            Object auth;
            if (auths instanceof Collection<?> collection) {
                int j = 0;
                Object found = null;
                for (Object item : collection) {
                    if (j++ == i) {
                        found = item;
                        break;
                    }
                }
                auth = found;
            } else {
                auth = Array.get(auths, i);
            }
            Object keyParameter = readField(auth, "keyParameter");
            if (keyParameter == null) keyParameter = readField(auth, "parameter");
            Object tagObj = readField(keyParameter, "tag");
            if (tagObj instanceof Number tag) {
                if (sb.length() > 0) sb.append(',');
                sb.append("0x").append(Integer.toHexString(tag.intValue()));
            }
        }
        if (size > max) sb.append("...");
        return sb.toString();
    }

    private static void runKeyMetadataAuthorizationProbe(String targetAlias, AttestationResult attestationResult, ActiveProbeResult result) {
        if (!useKs2) {
            result.skipped("KeyMetadata 授权一致性探针需要 Keystore2");
            return;
        }
        KeyMetadata generated = ks2GeneratedMetadata.get(targetAlias);
        KeyMetadata entry = ks2EntryMetadata.get(targetAlias);
        if (generated == null && entry == null) {
            result.skipped("未捕获到 Keystore2 KeyMetadata，无法比较 authorizations 与证书扩展");
            return;
        }

        int genCount = keyMetadataAuthorizationCount(generated);
        int entryCount = keyMetadataAuthorizationCount(entry);
        int genLevel = keyMetadataSecurityLevel(generated);
        int entryLevel = keyMetadataSecurityLevel(entry);
        boolean certificateClaimsHardware = attestationResult != null
                && attestationResult.showAttestation != null
                && !attestationResult.isSoftwareLevel();

        if (certificateClaimsHardware) {
            if (genLevel == 0 || entryLevel == 0) {
                result.high("证书 Attestation 声称 TEE / StrongBox，但 Keystore2 KeyMetadata.keySecurityLevel 出现 SOFTWARE：generate="
                        + genLevel + ", entry=" + entryLevel);
                return;
            }
            if ((genCount >= 0 && genCount <= 6) || (entryCount >= 0 && entryCount <= 6)) {
                result.warn("KeyMetadata.authorizations 数量较少，仅记录为兼容性观测：generate="
                        + genCount + ", entry=" + entryCount
                        + "；数量与排列顺序不构成授权语义矛盾"
                        + "；tags(generate)=" + collectAuthorizationTagPreview(generated)
                        + "；tags(entry)=" + collectAuthorizationTagPreview(entry));
                return;
            }
        }

        if (genCount >= 0 && entryCount >= 0 && Math.abs(genCount - entryCount) >= 6) {
            result.warn("generateKey 与 getKeyEntry 返回的 KeyMetadata.authorizations 数量不同，仅记录：generate="
                    + genCount + ", entry=" + entryCount);
            return;
        }

        result.normal("KeyMetadata.authorizations 与证书安全级别未发现明显冲突：generate="
                + genCount + ", entry=" + entryCount
                + ", securityLevel(generate/entry)=" + genLevel + "/" + entryLevel);
    }

    private static void runImportKeyProbe(ActiveProbeResult result) {
        String probeAlias = makeProbeAlias("import");
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, probeAlias);

            PrivateKey fakePrivateKey = readPrivateKey(EMBEDDED_FAKE_ATTEST_KEY_B64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate[] suppliedChain = readCertificateChain(EMBEDDED_FAKE_ATTEST_CERT_B64, cf);
            KeyStore.PrivateKeyEntry keyEntry = new KeyStore.PrivateKeyEntry(fakePrivateKey, suppliedChain);
            KeyProtection protection = new KeyProtection.Builder(
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build();

            keyStore.setEntry(probeAlias, keyEntry, protection);
            Certificate[] importedChain = keyStore.getCertificateChain(probeAlias);

            if (importedChain == null || importedChain.length == 0) {
                result.skipped("importKey 探针导入后未取回证书链");
                return;
            }

            boolean chainChanged = !compareCerts(suppliedChain, importedChain);
            boolean hasAttestationOid = hasAndroidKeyAttestationExtension(importedChain);
            if (chainChanged || hasAttestationOid) {
                result.high("导入普通软件私钥后，AndroidKeyStore 返回的证书链被替换或出现 Android Key Attestation 扩展；"
                        + "chainChanged=" + chainChanged + ", hasAttestationOid=" + hasAttestationOid
                        + "；疑似 TrickyStore importKey fallback 将导入私钥包装成伪硬件 Attestation");
                return;
            }

            if (importedChain[0] instanceof X509Certificate cert) {
                String subject = cert.getSubjectX500Principal().getName();
                if (subject == null || !subject.contains("LingQing")) {
                    result.high("导入普通软件私钥后，叶子证书主题不再是预置测试证书：" + subject);
                    return;
                }
            }
            result.normal("importKey 软件私钥探针未发现证书链被替换或伪造 Attestation OID");
        } catch (Throwable t) {
            result.skipped("importKey 软件私钥探针无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runImportKeyProbe failed", t);
        } finally {
            if (keyStore != null) safeDeleteEntry(keyStore, probeAlias);
        }
    }

    private static int patchMonthIndexFromString(String value) {
        if (value == null || value.isEmpty()) return -1;
        try {
            String[] parts = value.split("-");
            if (parts.length >= 2) {
                int year = Integer.parseInt(parts[0]);
                int month = Integer.parseInt(parts[1]);
                if (month >= 1 && month <= 12) return year * 12 + month;
            }
        } catch (Throwable ignored) {
        }
        return -1;
    }

    private static int patchMonthIndexFromAttestation(Integer patch) {
        if (patch == null || patch <= 0) return -1;
        int raw = patch;
        int yyyymm;
        if (raw >= 10000000) {
            yyyymm = raw / 100;
        } else if (raw >= 100000) {
            yyyymm = raw;
        } else {
            return -1;
        }
        int year = yyyymm / 100;
        int month = yyyymm % 100;
        if (month < 1 || month > 12) return -1;
        return year * 12 + month;
    }

    private static int currentMonthIndex() {
        java.util.Calendar calendar = java.util.Calendar.getInstance();
        return calendar.get(java.util.Calendar.YEAR) * 12 + calendar.get(java.util.Calendar.MONTH) + 1;
    }

    private static void checkPatchDifference(String label, Integer attPatch, int referenceMonthIndex, String referenceText, ActiveProbeResult result) {
        int attMonth = patchMonthIndexFromAttestation(attPatch);
        if (attMonth < 0 || referenceMonthIndex < 0) return;
        if (Math.abs(attMonth - referenceMonthIndex) > 1) {
            result.high(label + " 与系统可见补丁级别相差超过一个月：Attestation=" + attPatch
                    + ", Reference=" + referenceText
                    + "；可能存在旧 Keybox、TrickyStore/PIF 属性改写或补丁元数据不同步");
        }
    }

    private static void runPatchLevelConsistencyProbe(AttestationResult attestationResult, ActiveProbeResult result) {
        if (attestationResult == null || attestationResult.showAttestation == null) {
            result.skipped("PatchLevel 一致性探针无法读取 Attestation 对象");
            return;
        }
        Attestation att = attestationResult.showAttestation;
        Integer osVersion = att.getOsVersion();
        Integer osPatch = att.getOsPatchLevel();
        Integer vendorPatch = att.getVendorPatchLevel();
        Integer bootPatch = att.getBootPatchLevel();
        if (osPatch == null && vendorPatch == null && bootPatch == null) {
            result.skipped("未能从 Attestation / teeEnforced / softwareEnforced 中读取 OS/Vendor/Boot PatchLevel 字段，跳过补丁级别一致性探针");
            return;
        }

        int highCountBefore = result.highCount;
        int currentMonth = currentMonthIndex();
        checkPatchDifference("OS PatchLevel", osPatch,
                patchMonthIndexFromString(Build.VERSION.SECURITY_PATCH),
                Build.VERSION.SECURITY_PATCH,
                result);

        String vendorPatchProp = SystemProperties.get("ro.vendor.build.security_patch", "");
        if (vendorPatchProp.isEmpty()) vendorPatchProp = SystemProperties.get("vendor.build.security_patch", "");
        checkPatchDifference("Vendor PatchLevel", vendorPatch,
                patchMonthIndexFromString(vendorPatchProp),
                vendorPatchProp,
                result);

        int frameworkMajor = parseReleaseMajor(Build.VERSION.RELEASE);
        int attestedMajor = osVersion == null ? -1 : osVersion / 10000;
        if (frameworkMajor > 0 && attestedMajor > 0 && frameworkMajor != attestedMajor) {
            result.high("TEE osVersion 与用户态 Android 主版本不一致：Attestation=" + osVersion
                    + ", ro.build.version.release=" + Build.VERSION.RELEASE);
        }

        String bootBuildUtc = SystemProperties.get("ro.bootimage.build.date.utc", "");
        if (!bootBuildUtc.isEmpty()) {
            try {
                long seconds = Long.parseLong(bootBuildUtc);
                java.util.Calendar calendar = java.util.Calendar.getInstance();
                calendar.setTimeInMillis(seconds * 1000L);
                int bootBuildMonth = calendar.get(java.util.Calendar.YEAR) * 12
                        + calendar.get(java.util.Calendar.MONTH) + 1;
                checkPatchDifference("Boot PatchLevel", bootPatch, bootBuildMonth, bootBuildUtc, result);
            } catch (Throwable ignored) {
                result.warn("ro.bootimage.build.date.utc 无法解析");
            }
        }

        int bootMonth = patchMonthIndexFromAttestation(bootPatch);
        if (bootMonth > currentMonth + 1) {
            result.high("Boot PatchLevel 晚于当前日期超过一个月：Attestation=" + bootPatch);
        }
        int osMonth = patchMonthIndexFromAttestation(osPatch);
        int vendorMonth = patchMonthIndexFromAttestation(vendorPatch);
        if (osMonth > currentMonth + 1) result.high("OS PatchLevel 晚于当前日期超过一个月：Attestation=" + osPatch);
        if (vendorMonth > currentMonth + 1) result.high("Vendor PatchLevel 晚于当前日期超过一个月：Attestation=" + vendorPatch);

        if (result.highCount == highCountBefore) {
            result.normal("PatchLevel 多源一致性未发现明显异常：os=" + osPatch
                    + ", vendor=" + vendorPatch
                    + ", boot=" + bootPatch
                    + ", Build.SECURITY_PATCH=" + Build.VERSION.SECURITY_PATCH
                    + ", ro.vendor.build.security_patch=" + vendorPatchProp);
        }
    }


    private static byte[] getX509ExtensionInnerBytes(X509Certificate cert, String oid) {
        try {
            if (cert == null || oid == null) return null;
            byte[] wrapped = cert.getExtensionValue(oid);
            if (wrapped == null) return null;
            ASN1Primitive outer = ASN1Primitive.fromByteArray(wrapped);
            if (outer instanceof ASN1OctetString octetString) {
                return octetString.getOctets();
            }
            return wrapped;
        } catch (Throwable t) {
            Log.d(TAG, "getX509ExtensionInnerBytes failed for " + oid + ": " + t);
            return null;
        }
    }

    private static X509Certificate firstX509(Certificate[] chain) {
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate cert)) return null;
        return cert;
    }

    private static String shortHex(byte[] data, int maxBytes) {
        if (data == null) return "(null)";
        int len = Math.min(data.length, Math.max(0, maxBytes));
        byte[] prefix = Arrays.copyOf(data, len);
        String hex = BaseEncoding.base16().encode(prefix);
        return data.length > len ? hex + "..." : hex;
    }

    private static boolean generateTemporaryAttestKey(String attestAliasName) {
        return generateTemporaryAttestKey(attestAliasName, null, "temp-attest");
    }

    private static boolean generateTemporaryAttestKey(String attestAliasName, String parentAttestAliasName, String challengeTag) {
        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    attestAliasName,
                    KeyProperties.PURPOSE_ATTEST_KEY
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateSubject(new X500Principal("CN=TrustAttestor Temporary Attest Key"))
                    .setAttestationChallenge(makeProbeChallenge(challengeTag == null ? "temp-attest" : challengeTag));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && parentAttestAliasName != null) {
                builder.setAttestKeyAlias(parentAttestAliasName);
            }

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
            );
            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            return true;
        } catch (Throwable t) {
            Log.d(TAG, "generateTemporaryAttestKey failed: " + t);
            return false;
        }
    }

    private static boolean generateChildWithAttestKey(String childAlias, String attestAliasName) {
        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    childAlias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(makeProbeChallenge("attest-child"));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                builder.setAttestKeyAlias(attestAliasName);
            }

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
            );
            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            return true;
        } catch (Throwable t) {
            Log.d(TAG, "generateChildWithAttestKey failed: " + t);
            return false;
        }
    }

    private static boolean tryDirectSignPrivateKey(PrivateKey privateKey, byte[] payload) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(payload);
            signature.sign();
            return true;
        } catch (Throwable t) {
            Log.d(TAG, "tryDirectSignPrivateKey expected/failed: " + t);
            return false;
        }
    }

    private static boolean generateEcSigningKey(String keyAlias, byte[] challenge, boolean useExistingAttestKey) {
        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256);

            if (challenge != null) {
                builder.setAttestationChallenge(challenge);
            }
            if (useExistingAttestKey) {
                applyProbeAttestKeyIfAvailable(builder);
            }

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
            );
            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            return true;
        } catch (Throwable t) {
            Log.d(TAG, "generateEcSigningKey failed for " + keyAlias + ": " + t);
            return false;
        }
    }

    private static boolean generateEcSigningKeyWithSpecificAttestAlias(String keyAlias, byte[] challenge, String attestAliasName) {
        try {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256);

            if (challenge != null) {
                builder.setAttestationChallenge(challenge);
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && attestAliasName != null) {
                builder.setAttestKeyAlias(attestAliasName);
            }

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
            );
            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            return true;
        } catch (Throwable t) {
            Log.d(TAG, "generateEcSigningKeyWithSpecificAttestAlias failed for " + keyAlias + ": " + t);
            return false;
        }
    }

    private static byte[] certificateDigest(Certificate certificate) {
        try {
            if (certificate == null) return null;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(certificate.getEncoded());
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] publicKeyBytes(X509Certificate certificate) {
        try {
            return certificate == null || certificate.getPublicKey() == null
                    ? null
                    : certificate.getPublicKey().getEncoded();
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] extractAttestationChallenge(X509Certificate leaf) {
        try {
            byte[] keyDescriptionBytes = getX509ExtensionInnerBytes(leaf, ANDROID_KEY_ATTESTATION_OID);
            if (keyDescriptionBytes == null) return null;
            ASN1Sequence keyDescription = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(keyDescriptionBytes));
            if (keyDescription.size() < 5) return null;
            ASN1OctetString challenge = ASN1OctetString.getInstance(keyDescription.getObjectAt(4));
            return challenge.getOctets();
        } catch (Throwable t) {
            Log.d(TAG, "extractAttestationChallenge failed: " + t);
            return null;
        }
    }

    private static void checkChildSignedByAttestKey(String label, Certificate[] childChain, Certificate[] attestKeyChain, ActiveProbeResult result) {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !hasAttestKey) {
                result.skipped(label + "：设备不支持 App Attest Key，跳过 AttestKey 交叉签名验证");
                return;
            }
            X509Certificate childLeaf = firstX509(childChain);
            X509Certificate attestLeaf = firstX509(attestKeyChain);
            if (childLeaf == null || attestLeaf == null) {
                result.skipped(label + "：缺少业务 leaf 或 AttestKey leaf，无法做交叉签名验证");
                return;
            }
            if (childLeaf.getExtensionValue(ANDROID_KEY_ATTESTATION_OID) == null) {
                result.skipped(label + "：业务 leaf 不含 Android Key Attestation 扩展，无法完成 setAttestKeyAlias 链路验证");
                return;
            }

            boolean issuerMatch = childLeaf.getIssuerX500Principal().equals(attestLeaf.getSubjectX500Principal());
            try {
                childLeaf.verify(attestLeaf.getPublicKey());
                if (!issuerMatch) {
                    result.warn(label + "：业务 leaf 可被 AttestKey 公钥验证，但 issuer/subject 不连续；可能是厂商证书字段差异或证书重签痕迹");
                } else {
                    result.normal(label + "：业务 leaf 确认由当前 App AttestKey 公钥签发");
                }
            } catch (Throwable verifyError) {
                String childIssuer = childLeaf.getIssuerX500Principal() == null ? "(null)" : childLeaf.getIssuerX500Principal().getName();
                String attestSubject = attestLeaf.getSubjectX500Principal() == null ? "(null)" : attestLeaf.getSubjectX500Principal().getName();
                result.high(label + "：已使用 setAttestKeyAlias 的业务 key leaf 不能被 App AttestKey 公钥验证；"
                        + "childIssuer=" + childIssuer
                        + "，attestSubject=" + attestSubject
                        + "，verifyError=" + verifyError.getClass().getSimpleName() + ": " + verifyError.getMessage()
                        + "。这符合 leaf hack 将业务 leaf 重新签到 keybox/其他 CA 链上的特征");
            }
        } catch (Throwable t) {
            result.skipped(label + "：AttestKey 交叉签名验证未完成："
                    + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "checkChildSignedByAttestKey failed", t);
        }
    }

    private static ProbeApplicability runAttestKeyCrossSigningProbe(
            Certificate[] mainAliasChain,
            Certificate[] attestKeyChain,
            ActiveProbeResult result
    ) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            result.normal("AttestKey 交叉签名验证需要 Android 12+，本项不适用");
            return ProbeApplicability.NOT_APPLICABLE;
        }
        if (!hasAttestKey) {
            result.normal("设备未声明 FEATURE_KEYSTORE_APP_ATTEST_KEY，本项不适用");
            return ProbeApplicability.NOT_APPLICABLE;
        }
        if (!attestAliasReady) {
            // A feature declaration does not guarantee that this caller/profile can create an
            // App AttestKey. The parent generation path reports its own failure; cross-signing has
            // no evidence to inspect and must not create a second UNAVAILABLE finding.
            result.normal("本轮未生成可用的 App AttestKey，交叉签名验证不适用");
            return ProbeApplicability.NOT_APPLICABLE;
        }
        checkChildSignedByAttestKey("主业务 key / App AttestKey 交叉验证", mainAliasChain, attestKeyChain, result);
        return ProbeApplicability.APPLICABLE;
    }

    private static void runMultiLayerAttestKeyGraphProbe(ActiveProbeResult result) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            result.skipped("多层 AttestKey 链路图探针需要 Android 12+");
            return;
        }
        if (!hasAttestKey) {
            result.skipped("设备未声明 FEATURE_KEYSTORE_APP_ATTEST_KEY，跳过多层 AttestKey 链路图探针");
            return;
        }

        String attestA = makeProbeAlias("graph_attest_a");
        String attestB = makeProbeAlias("graph_attest_b");
        String childC = makeProbeAlias("graph_child_c");
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, attestA);
            safeDeleteEntry(keyStore, attestB);
            safeDeleteEntry(keyStore, childC);

            if (!generateTemporaryAttestKey(attestA, null, "graph-A")) {
                result.skipped("多层 AttestKey 链路图探针：A 层 PURPOSE_ATTEST_KEY 生成失败");
                return;
            }
            if (!generateTemporaryAttestKey(attestB, attestA, "graph-B")) {
                result.skipped("多层 AttestKey 链路图探针：B 层 AttestKey 由 A 签发失败；该 ROM 可能不支持 AttestKey 签发 AttestKey");
                return;
            }
            if (!generateChildWithAttestKey(childC, attestB)) {
                result.skipped("多层 AttestKey 链路图探针：C 层业务 key 由 B 签发失败");
                return;
            }

            Certificate[] chainA = keyStore.getCertificateChain(attestA);
            Certificate[] chainB = keyStore.getCertificateChain(attestB);
            Certificate[] chainC = keyStore.getCertificateChain(childC);

            int highBefore = result.highCount;
            checkChildSignedByAttestKey("多层 AttestKey 图 A→B 验证", chainB, chainA, result);
            checkChildSignedByAttestKey("多层 AttestKey 图 B→C 验证", chainC, chainB, result);

            X509Certificate leafA = firstX509(chainA);
            X509Certificate leafB = firstX509(chainB);
            X509Certificate leafC = firstX509(chainC);
            byte[] pubA = publicKeyBytes(leafA);
            byte[] pubB = publicKeyBytes(leafB);
            byte[] pubC = publicKeyBytes(leafC);
            if (pubA != null && pubB != null && Arrays.equals(pubA, pubB)) {
                result.high("多层 AttestKey 图异常：A/B 两层 leaf publicKey 完全相同，疑似证书模板或 key 缓存复用");
            }
            if (pubB != null && pubC != null && Arrays.equals(pubB, pubC)) {
                result.high("多层 AttestKey 图异常：B/C 两层 leaf publicKey 完全相同，疑似证书模板或 key 缓存复用");
            }
            if (result.highCount == highBefore) {
                result.normal("多层 AttestKey 链路图探针完成：A→B、B→C 未发现明确 leaf hack 断链");
            }
        } catch (Throwable t) {
            result.skipped("多层 AttestKey 链路图探针无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runMultiLayerAttestKeyGraphProbe failed", t);
        } finally {
            if (keyStore != null) {
                safeDeleteEntry(keyStore, attestA);
                safeDeleteEntry(keyStore, attestB);
                safeDeleteEntry(keyStore, childC);
            }
        }
    }

    private static void runChallengeReplayProbe(ActiveProbeResult result) {
        String probeAlias = makeProbeAlias("replay_fixed");
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, probeAlias);

            byte[] challengeA = makeProbeChallenge("replay-A");
            byte[] challengeB = makeProbeChallenge("replay-B");
            if (!generateEcSigningKey(probeAlias, challengeA, true)) {
                result.skipped("challenge 回放探针第一次 key 生成失败");
                return;
            }
            Certificate[] chainA = keyStore.getCertificateChain(probeAlias);
            X509Certificate leafA = firstX509(chainA);
            byte[] parsedA = extractAttestationChallenge(leafA);
            byte[] pubA = publicKeyBytes(leafA);
            byte[] certDigestA = leafA == null ? null : certificateDigest(leafA);

            safeDeleteEntry(keyStore, probeAlias);

            if (!generateEcSigningKey(probeAlias, challengeB, true)) {
                result.skipped("challenge 回放探针第二次 key 生成失败");
                return;
            }
            Certificate[] chainB = keyStore.getCertificateChain(probeAlias);
            X509Certificate leafB = firstX509(chainB);
            byte[] parsedB = extractAttestationChallenge(leafB);
            byte[] pubB = publicKeyBytes(leafB);
            byte[] certDigestB = leafB == null ? null : certificateDigest(leafB);

            boolean high = false;
            if (parsedA == null || parsedB == null) {
                result.skipped("challenge 回放探针无法解析两次 leaf 中的 attestationChallenge；检测未完成");
                return;
            }
            if (!Arrays.equals(parsedA, challengeA)) {
                high = true;
                result.high("challenge 回放探针第一次证书 challenge 与请求不一致：expected="
                        + shortHex(challengeA, 16) + "，actual=" + shortHex(parsedA, 16));
            }
            if (!Arrays.equals(parsedB, challengeB)) {
                high = true;
                result.high("challenge 回放探针第二次证书 challenge 与请求不一致：expected="
                        + shortHex(challengeB, 16) + "，actual=" + shortHex(parsedB, 16));
            }
            if (Arrays.equals(parsedB, challengeA)) {
                high = true;
                result.high("challenge 回放探针第二次生成仍返回第一次 challenge，疑似 alias/blob 证书缓存或 leaf hack 回放");
            }
            if (pubA != null && pubB != null && Arrays.equals(pubA, pubB)) {
                high = true;
                result.high("deleteEntry 后使用同一 alias 重新生成 key，但两次 leaf publicKey 完全相同；疑似删除语义或证书/密钥缓存异常");
            }
            if (certDigestA != null && certDigestB != null && Arrays.equals(certDigestA, certDigestB)) {
                high = true;
                result.high("deleteEntry 后使用同一 alias 和不同 challenge 重新生成 key，但两次 leaf 证书完全相同；疑似证书链缓存回放");
            }
            if (!high) {
                result.normal("challenge 回放探针通过：同 alias 重建后 challenge 与 publicKey 均随请求变化");
            }
        } catch (Throwable t) {
            result.skipped("challenge 回放探针无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runChallengeReplayProbe failed", t);
        } finally {
            if (keyStore != null) safeDeleteEntry(keyStore, probeAlias);
        }
    }

    private static void runNullChallengeNegativeProbe(ActiveProbeResult result) {
        String probeAlias = makeProbeAlias("null_challenge");
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, probeAlias);

            // 负对照：不调用 setAttestationChallenge，也不绑定 setAttestKeyAlias。
            // 正常 AndroidKeyStore 不应为这种 key 返回 Android Key Attestation 扩展。
            if (!generateEcSigningKey(probeAlias, null, false)) {
                result.skipped("null challenge 负对照 key 生成失败");
                return;
            }
            Certificate[] chain = keyStore.getCertificateChain(probeAlias);
            boolean hasAttestationOid = hasAndroidKeyAttestationExtension(chain);
            if (hasAttestationOid) {
                result.high("null challenge 负对照命中：未设置 setAttestationChallenge 的普通 AndroidKeyStore key 仍返回 Android Key Attestation 扩展；"
                        + "疑似存在过度 hook、全局证书链替换或 leaf hack 模板误用");
                return;
            }
            if (chain != null && chain.length > 1) {
                result.warn("null challenge 负对照返回了多级证书链但未含 Android Key Attestation OID；多数正常设备应返回单 leaf/self-signed 证书，仅作为关注项：chainLength=" + chain.length);
            } else {
                result.normal("null challenge 负对照通过：未设置 attestationChallenge 时未出现 Android Key Attestation OID");
            }
        } catch (Throwable t) {
            result.skipped("null challenge 负对照无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runNullChallengeNegativeProbe failed", t);
        } finally {
            if (keyStore != null) safeDeleteEntry(keyStore, probeAlias);
        }
    }

    private static void runAttestKeyNegativeControlProbe(ActiveProbeResult result) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            result.skipped("AttestKey 负对照探针需要 Android 12+");
            return;
        }
        if (!hasAttestKey) {
            result.skipped("设备未声明 FEATURE_KEYSTORE_APP_ATTEST_KEY，跳过 AttestKey 负对照探针");
            return;
        }

        String tempAttestAlias = makeProbeAlias("neg_attest");
        String noChallengeChild = makeProbeAlias("neg_no_chal_child");
        String invalidAliasChild = makeProbeAlias("neg_invalid_child");
        String invalidAttestAlias = makeProbeAlias("definitely_missing_attest");
        String signOnlyAlias = makeProbeAlias("neg_sign_only_attest");
        String signOnlyChild = makeProbeAlias("neg_sign_only_child");
        String importedAlias = makeProbeAlias("neg_imported_attest");
        String importedChild = makeProbeAlias("neg_imported_child");
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, tempAttestAlias);
            safeDeleteEntry(keyStore, noChallengeChild);
            safeDeleteEntry(keyStore, invalidAliasChild);
            safeDeleteEntry(keyStore, invalidAttestAlias);
            safeDeleteEntry(keyStore, signOnlyAlias);
            safeDeleteEntry(keyStore, signOnlyChild);
            safeDeleteEntry(keyStore, importedAlias);
            safeDeleteEntry(keyStore, importedChild);

            if (!generateTemporaryAttestKey(tempAttestAlias, null, "neg-temp-attest")) {
                result.skipped("AttestKey 负对照探针：临时 attest key 生成失败");
                return;
            }

            boolean noChallengeGenerated = generateEcSigningKeyWithSpecificAttestAlias(
                    noChallengeChild,
                    null,
                    tempAttestAlias
            );
            if (noChallengeGenerated) {
                Certificate[] chain = keyStore.getCertificateChain(noChallengeChild);
                boolean hasAttestationOid = hasAndroidKeyAttestationExtension(chain);
                result.high("AttestKey 负对照命中：设置 setAttestKeyAlias(valid) 但未设置 setAttestationChallenge 时仍然生成 key；"
                        + "hasAttestationOid=" + hasAttestationOid
                        + "。正常实现应拒绝该组合，否则说明 leaf hack/Hook 层可能绕过了参数校验");
            } else {
                result.normal("AttestKey 负对照通过：setAttestKeyAlias(valid) 但无 attestationChallenge 时生成被拒绝");
            }

            boolean invalidAliasGenerated = generateEcSigningKeyWithSpecificAttestAlias(
                    invalidAliasChild,
                    makeProbeChallenge("neg-invalid-attest"),
                    invalidAttestAlias
            );
            if (invalidAliasGenerated) {
                Certificate[] chain = keyStore.getCertificateChain(invalidAliasChild);
                boolean hasAttestationOid = hasAndroidKeyAttestationExtension(chain);
                result.high("AttestKey 负对照命中：setAttestKeyAlias(不存在的 alias) 但 key 仍然生成成功；"
                        + "hasAttestationOid=" + hasAttestationOid
                        + "。正常实现应因 attest key 不存在而失败，成功通常意味着 Hook 层忽略或替换了 attestKeyAlias");
            } else {
                result.normal("AttestKey 负对照通过：setAttestKeyAlias(不存在的 alias) 时生成被拒绝");
            }

            boolean signKeyReady = generateEcSigningKey(signOnlyAlias, makeProbeChallenge("neg-sign-only-source"), false);
            if (signKeyReady) {
                boolean signOnlyGenerated = generateEcSigningKeyWithSpecificAttestAlias(
                        signOnlyChild,
                        makeProbeChallenge("neg-sign-only-attest"),
                        signOnlyAlias
                );
                if (signOnlyGenerated) {
                    Certificate[] chain = keyStore.getCertificateChain(signOnlyChild);
                    boolean hasAttestationOid = hasAndroidKeyAttestationExtension(chain);
                    result.high("AttestKey 负对照命中：setAttestKeyAlias 指向普通 PURPOSE_SIGN key 时仍然生成成功；"
                            + "hasAttestationOid=" + hasAttestationOid
                            + "。正常实现应要求 attestKeyAlias 指向 PURPOSE_ATTEST_KEY，成功通常说明 Hook 层没有校验 alias 的真实 purpose");
                } else {
                    result.normal("AttestKey 负对照通过：普通 PURPOSE_SIGN key 不能作为 attestKeyAlias 使用");
                }
            } else {
                result.skipped("AttestKey 负对照：普通 PURPOSE_SIGN 源 key 生成失败，跳过 sign-only alias 测试");
            }

            try {
                PrivateKey fakePrivateKey = readPrivateKey(EMBEDDED_FAKE_ATTEST_KEY_B64);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate[] suppliedChain = readCertificateChain(EMBEDDED_FAKE_ATTEST_CERT_B64, cf);
                KeyStore.PrivateKeyEntry keyEntry = new KeyStore.PrivateKeyEntry(fakePrivateKey, suppliedChain);
                KeyProtection protection = new KeyProtection.Builder(
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
                )
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build();
                keyStore.setEntry(importedAlias, keyEntry, protection);

                boolean importedAliasGenerated = generateEcSigningKeyWithSpecificAttestAlias(
                        importedChild,
                        makeProbeChallenge("neg-imported-attest"),
                        importedAlias
                );
                if (importedAliasGenerated) {
                    Certificate[] chain = keyStore.getCertificateChain(importedChild);
                    boolean hasAttestationOid = hasAndroidKeyAttestationExtension(chain);
                    result.high("AttestKey 负对照命中：setAttestKeyAlias 指向导入的软件私钥 entry 时仍然生成成功；"
                            + "hasAttestationOid=" + hasAttestationOid
                            + "。正常实现不应允许导入软件 key 作为硬件 AttestKey 签发 Android Key Attestation");
                } else {
                    result.normal("AttestKey 负对照通过：导入的软件私钥不能作为 attestKeyAlias 使用");
                }
            } catch (Throwable t) {
                result.skipped("AttestKey 负对照：导入软件私钥作为 attestKeyAlias 的测试无法执行："
                        + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        } catch (Throwable t) {
            result.skipped("AttestKey 负对照探针无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runAttestKeyNegativeControlProbe failed", t);
        } finally {
            if (keyStore != null) {
                safeDeleteEntry(keyStore, tempAttestAlias);
                safeDeleteEntry(keyStore, noChallengeChild);
                safeDeleteEntry(keyStore, invalidAliasChild);
                safeDeleteEntry(keyStore, invalidAttestAlias);
                safeDeleteEntry(keyStore, signOnlyAlias);
                safeDeleteEntry(keyStore, signOnlyChild);
                safeDeleteEntry(keyStore, importedAlias);
                safeDeleteEntry(keyStore, importedChild);
            }
        }
    }

    private static void runAttestKeyTrapProbe(Context context, ActiveProbeResult result) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            result.skipped("AttestKey 语义陷阱需要 Android 12+");
            return;
        }
        if (!hasAttestKey) {
            result.skipped("设备未声明 FEATURE_KEYSTORE_APP_ATTEST_KEY，跳过 AttestKey 语义陷阱");
            return;
        }

        String tempAttestAlias = makeProbeAlias("attest_trap");
        String childAliasA = makeProbeAlias("attest_child_a");
        String childAliasB = makeProbeAlias("attest_child_b");
        KeyStore keyStore = null;
        try {
            keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, tempAttestAlias);
            safeDeleteEntry(keyStore, childAliasA);
            safeDeleteEntry(keyStore, childAliasB);

            if (!generateTemporaryAttestKey(tempAttestAlias)) {
                result.skipped("临时 PURPOSE_ATTEST_KEY 生成失败，跳过 AttestKey 陷阱");
                return;
            }

            try {
                var key = keyStore.getKey(tempAttestAlias, null);
                if (key instanceof PrivateKey privateKey) {
                    boolean attestKeyCanSign = tryDirectSignPrivateKey(
                            privateKey,
                            "TrustAttestor attest-key misuse probe".getBytes(StandardCharsets.UTF_8)
                    );
                    if (attestKeyCanSign) {
                        result.high("PURPOSE_ATTEST_KEY 可以被普通 Signature.initSign() 直接用于 ECDSA 签名；"
                                + "正常 KeyMint 应只允许其用于签发 Attestation，不应作为 PURPOSE_SIGN 私钥使用");
                    } else {
                        result.normal("PURPOSE_ATTEST_KEY 无法被普通 Signature 直接签名");
                    }
                } else {
                    result.normal("PURPOSE_ATTEST_KEY 不能作为普通 PrivateKey 取出使用");
                }
            } catch (Throwable t) {
                result.normal("PURPOSE_ATTEST_KEY 普通签名路径被拒绝：" + t.getClass().getSimpleName());
            }

            boolean childA = generateChildWithAttestKey(childAliasA, tempAttestAlias);
            if (!childA) {
                result.skipped("临时 AttestKey 无法签发子 key，跳过删除语义陷阱");
                return;
            }

            try {
                Certificate[] childAChain = keyStore.getCertificateChain(childAliasA);
                Certificate[] tempAttestChain = keyStore.getCertificateChain(tempAttestAlias);
                checkChildSignedByAttestKey("临时 AttestKey 签发链路交叉验证", childAChain, tempAttestChain, result);
            } catch (Throwable t) {
                result.skipped("临时 AttestKey 交叉签名验证未完成："
                        + t.getClass().getSimpleName() + ": " + t.getMessage());
            }

            safeDeleteEntry(keyStore, tempAttestAlias);
            boolean childBAfterDelete = generateChildWithAttestKey(childAliasB, tempAttestAlias);
            if (childBAfterDelete) {
                result.high("deleteEntry(attestKey) 后，setAttestKeyAlias(已删除 alias) 仍然能签发新的 Attestation key；"
                        + "疑似存在 AndroidKeyStore 外部私钥缓存或 AttestKey 删除语义被伪造");
            } else {
                result.normal("deleteEntry(attestKey) 后无法继续使用该 alias 签发子 key");
            }
        } catch (Throwable t) {
            result.skipped("AttestKey 语义陷阱无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runAttestKeyTrapProbe failed", t);
        } finally {
            if (keyStore != null) {
                safeDeleteEntry(keyStore, tempAttestAlias);
                safeDeleteEntry(keyStore, childAliasA);
                safeDeleteEntry(keyStore, childAliasB);
            }
        }
    }


    private static void runKeystoreStateMachineProbe(ActiveProbeResult result) {
        SilentKeystoreChecks.lifecycle(KeyAttestation::applyProbeAttestKeyIfAvailable,
                silentReporter(result, FLAG_KEYSTORE_STATE));
    }

    private static void runMultiAliasCrosstalkProbe(ActiveProbeResult result) {
        SilentKeystoreChecks.aliasIsolation(KeyAttestation::applyProbeAttestKeyIfAvailable,
                silentReporter(result, FLAG_ALIAS_CROSSTALK));
    }

    private static void runCtsLeafProfileProbe(Certificate[] chain, ActiveProbeResult result) {
        try {
            X509Certificate leaf = firstX509(chain);
            if (leaf == null) {
                result.skipped("CTS leaf profile 探针未找到叶子 X.509 证书");
                return;
            }
            if (leaf.getExtensionValue(ANDROID_KEY_ATTESTATION_OID) == null) {
                result.skipped("叶子证书未直接包含 Android Key Attestation 扩展，跳过 CTS leaf profile");
                return;
            }

            int highBefore = result.highCount;
            int warnBefore = result.warnCount;

            if (leaf.getBasicConstraints() >= 0) {
                result.high("Attestation leaf 证书被标记为 CA，BasicConstraints=" + leaf.getBasicConstraints()
                        + "；正常 Android Keystore leaf 不应具备 CA 能力");
            }

            boolean[] keyUsage = leaf.getKeyUsage();
            if (keyUsage != null) {
                if (keyUsage.length > 5 && keyUsage[5]) {
                    result.high("Attestation leaf KeyUsage 包含 keyCertSign，疑似被当作 CA/签发证书使用");
                }
                if (keyUsage.length > 6 && keyUsage[6]) {
                    result.high("Attestation leaf KeyUsage 包含 cRLSign，疑似异常证书用途");
                }
                if (keyUsage.length > 0 && !keyUsage[0]) {
                    result.warn("Attestation leaf KeyUsage 未声明 digitalSignature。部分厂商可能省略/差异实现，仅作为关注项");
                }
                StringBuilder extra = new StringBuilder();
                for (int i = 1; i < keyUsage.length; i++) {
                    if (i == 5 || i == 6) continue;
                    if (keyUsage[i]) {
                        if (extra.length() > 0) extra.append(',');
                        extra.append(i);
                    }
                }
                if (extra.length() > 0) {
                    result.warn("Attestation leaf KeyUsage 存在非 digitalSignature 用途 bit：" + extra
                            + "。这可能是重签 leaf 时证书模板不严谨，仅作为关注项");
                }
            }

            if (leaf.getVersion() != 3) {
                result.warn("Attestation leaf 版本不是 v3：version=" + leaf.getVersion());
            }

            if (!BigInteger.ONE.equals(leaf.getSerialNumber())) {
                result.warn("Attestation leaf serialNumber 不是规范常见值 1：serial="
                        + leaf.getSerialNumber().toString(16)
                        + "。为兼容厂商差异，仅作为关注项");
            }

            String subject = leaf.getSubjectX500Principal().getName();
            if (subject == null || !subject.contains("Android Keystore Key")) {
                result.warn("Attestation leaf subject 不是常见的 CN=Android Keystore Key：subject="
                        + subject + "。如果未显式 setCertificateSubject，这可能是 leaf 重签模板痕迹");
            }

            try {
                List<String> eku = leaf.getExtendedKeyUsage();
                if (eku != null && !eku.isEmpty()) {
                    result.warn("Attestation leaf 出现 ExtendedKeyUsage：" + eku
                            + "。正常 Key Attestation leaf 通常不需要 TLS/clientAuth 等 EKU，仅作为关注项");
                }
            } catch (Throwable ignored) {
            }

            Set<String> critical = leaf.getCriticalExtensionOIDs();
            if (critical != null && critical.contains(ANDROID_KEY_ATTESTATION_OID)) {
                result.warn("Android Key Attestation 扩展被标记为 critical，存在兼容性/模板异常可能");
            }

            if (result.highCount == highBefore && result.warnCount == warnBefore) {
                result.normal("CTS leaf profile 未发现明显异常");
            }
        } catch (Throwable t) {
            result.skipped("CTS leaf profile 探针未完成："
                    + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runCtsLeafProfileProbe failed", t);
        }
    }

    private static ASN1Primitive getTaggedObjectPrimitive(ASN1TaggedObject tagged) {
        if (tagged == null) return null;
        // BouncyCastle is bundled with the embedded DEX.  Use a typed call so R8 can rewrite the
        // method reference when release names are obfuscated; reflecting on the source method name
        // made this parser work in Debug but return null in Release.
        try {
            ASN1Encodable value = tagged.getBaseObject();
            return value == null ? null : value.toASN1Primitive();
        } catch (Throwable ignored) {
        }
        try {
            ASN1Encodable value = tagged.getExplicitBaseObject();
            return value == null ? null : value.toASN1Primitive();
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static ASN1TaggedObject findTaggedObject(ASN1Primitive primitive, int tagNo) {
        if (primitive == null) return null;
        try {
            if (primitive instanceof ASN1TaggedObject tagged) {
                if (tagged.getTagNo() == tagNo) return tagged;
                ASN1Primitive inner = getTaggedObjectPrimitive(tagged);
                ASN1TaggedObject found = findTaggedObject(inner, tagNo);
                if (found != null) return found;
            } else if (primitive instanceof ASN1Sequence sequence) {
                for (int i = 0; i < sequence.size(); i++) {
                    ASN1TaggedObject found = findTaggedObject(sequence.getObjectAt(i).toASN1Primitive(), tagNo);
                    if (found != null) return found;
                }
            } else if (primitive instanceof ASN1Set set) {
                for (int i = 0; i < set.size(); i++) {
                    ASN1TaggedObject found = findTaggedObject(set.getObjectAt(i).toASN1Primitive(), tagNo);
                    if (found != null) return found;
                }
            }
        } catch (Throwable t) {
            Log.d(TAG, "findTaggedObject failed: " + t);
        }
        return null;
    }

    private static final class ApplicationIdInfo {
        final List<String> packageNames = new ArrayList<>();
        final List<Long> versionCodes = new ArrayList<>();
        final Set<String> signatureDigestsHex = new HashSet<>();
    }

    private static void parsePackageInfos(ASN1Encodable packageInfosEnc, ApplicationIdInfo info) {
        if (packageInfosEnc == null || info == null) return;
        ASN1Primitive primitive = packageInfosEnc.toASN1Primitive();
        int size = 0;
        if (primitive instanceof ASN1Set set) {
            size = set.size();
            for (int i = 0; i < size; i++) parseOnePackageInfo(set.getObjectAt(i), info);
        } else if (primitive instanceof ASN1Sequence sequence) {
            size = sequence.size();
            for (int i = 0; i < size; i++) parseOnePackageInfo(sequence.getObjectAt(i), info);
        }
    }

    private static void parseOnePackageInfo(ASN1Encodable encodable, ApplicationIdInfo info) {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(encodable);
            if (seq.size() < 2) return;
            ASN1OctetString nameOctets = ASN1OctetString.getInstance(seq.getObjectAt(0));
            ASN1Integer versionInt = ASN1Integer.getInstance(seq.getObjectAt(1));
            String packageName = new String(nameOctets.getOctets(), StandardCharsets.UTF_8);
            info.packageNames.add(packageName);
            info.versionCodes.add(versionInt.getValue().longValue());
        } catch (Throwable t) {
            Log.d(TAG, "parseOnePackageInfo failed: " + t);
        }
    }

    private static void parseSignatureDigests(ASN1Encodable digestsEnc, ApplicationIdInfo info) {
        if (digestsEnc == null || info == null) return;
        ASN1Primitive primitive = digestsEnc.toASN1Primitive();
        if (primitive instanceof ASN1Set set) {
            for (int i = 0; i < set.size(); i++) parseOneSignatureDigest(set.getObjectAt(i), info);
        } else if (primitive instanceof ASN1Sequence sequence) {
            for (int i = 0; i < sequence.size(); i++) parseOneSignatureDigest(sequence.getObjectAt(i), info);
        }
    }

    private static void parseOneSignatureDigest(ASN1Encodable encodable, ApplicationIdInfo info) {
        try {
            ASN1OctetString octets = ASN1OctetString.getInstance(encodable);
            info.signatureDigestsHex.add(BaseEncoding.base16().encode(octets.getOctets()));
        } catch (Throwable t) {
            Log.d(TAG, "parseOneSignatureDigest failed: " + t);
        }
    }

    private static ApplicationIdInfo parseAttestationApplicationId(X509Certificate leaf) {
        try {
            byte[] keyDescriptionBytes = getX509ExtensionInnerBytes(leaf, ANDROID_KEY_ATTESTATION_OID);
            if (keyDescriptionBytes == null) return null;
            ASN1Primitive keyDescription = ASN1Primitive.fromByteArray(keyDescriptionBytes);
            ASN1TaggedObject appIdTag = findTaggedObject(keyDescription, ATTESTATION_APPLICATION_ID_TAG);
            if (appIdTag == null) return null;

            ASN1Primitive appIdPrimitive = getTaggedObjectPrimitive(appIdTag);
            byte[] appIdBytes = null;
            if (appIdPrimitive instanceof ASN1OctetString octetString) {
                appIdBytes = octetString.getOctets();
            } else if (appIdPrimitive != null) {
                appIdBytes = appIdPrimitive.getEncoded();
            }
            if (appIdBytes == null) return null;

            ASN1Sequence appIdSeq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(appIdBytes));
            if (appIdSeq.size() < 2) return null;

            ApplicationIdInfo info = new ApplicationIdInfo();
            parsePackageInfos(appIdSeq.getObjectAt(0), info);
            parseSignatureDigests(appIdSeq.getObjectAt(1), info);
            return info;
        } catch (Throwable t) {
            Log.d(TAG, "parseAttestationApplicationId failed: " + t);
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    private static Set<String> getCurrentApkSignatureDigests(Context context) {
        Set<String> digests = new HashSet<>();
        try {
            android.content.pm.PackageManager pm = context.getPackageManager();
            android.content.pm.PackageInfo pi;
            android.content.pm.Signature[] signatures;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pi = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                android.content.pm.SigningInfo signingInfo = pi.signingInfo;
                if (signingInfo == null) return digests;
                signatures = signingInfo.hasMultipleSigners()
                        ? signingInfo.getApkContentsSigners()
                        : signingInfo.getSigningCertificateHistory();
            } else {
                pi = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
                signatures = pi.signatures;
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (signatures != null) {
                for (android.content.pm.Signature signature : signatures) {
                    if (signature == null) continue;
                    digests.add(BaseEncoding.base16().encode(md.digest(signature.toByteArray())));
                }
            }
        } catch (Throwable t) {
            Log.d(TAG, "getCurrentApkSignatureDigests failed: " + t);
        }
        return digests;
    }

    private static Set<String> digestPackageSignatures(android.content.pm.Signature[] signatures) {
        Set<String> digests = new HashSet<>();
        if (signatures == null) return digests;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (android.content.pm.Signature signature : signatures) {
                if (signature == null) continue;
                digests.add(BaseEncoding.base16().encode(md.digest(signature.toByteArray())));
            }
        } catch (Throwable t) {
            Log.d(TAG, "digestPackageSignatures failed: " + t);
        }
        return digests;
    }

    @SuppressWarnings("deprecation")
    private static ProbeApplicability runSigningLineageProbe(
            Context context,
            Certificate[] chain,
            ActiveProbeResult result
    ) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (BuildConfig.DEBUG) Log.d(TAG, "Signing-lineage differential not applicable below Android 9");
            return ProbeApplicability.NOT_APPLICABLE;
        }
        try {
            PackageManager pm = context.getPackageManager();
            String packageName = context.getPackageName();
            android.content.pm.PackageInfo modern = pm.getPackageInfo(
                    packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            android.content.pm.SigningInfo signingInfo = modern.signingInfo;
            if (signingInfo == null) {
                result.skipped("系统未返回当前 APK 的 SigningInfo");
                return ProbeApplicability.APPLICABLE;
            }
            if (signingInfo.hasMultipleSigners()) {
                if (BuildConfig.DEBUG) {
                    Log.d(TAG, "Signing-lineage differential not applicable to multi-signer APK");
                }
                return ProbeApplicability.NOT_APPLICABLE;
            }
            if (!signingInfo.hasPastSigningCertificates()) {
                if (BuildConfig.DEBUG) {
                    Log.d(TAG, "Signing-lineage differential not applicable: no rotation history");
                }
                return ProbeApplicability.NOT_APPLICABLE;
            }

            Set<String> history = digestPackageSignatures(
                    signingInfo.getSigningCertificateHistory());
            Set<String> current = digestPackageSignatures(signingInfo.getApkContentsSigners());
            android.content.pm.PackageInfo legacy = pm.getPackageInfo(
                    packageName, PackageManager.GET_SIGNATURES);
            Set<String> legacyExpected = digestPackageSignatures(legacy.signatures);
            if (history.size() <= current.size() || legacyExpected.isEmpty()
                    || history.equals(legacyExpected)) {
                result.skipped("签名 API 未形成可区分的 legacy lineage 对照");
                return ProbeApplicability.APPLICABLE;
            }

            X509Certificate leaf = firstX509(chain);
            ApplicationIdInfo appId = leaf == null ? null : parseAttestationApplicationId(leaf);
            if (appId == null || appId.signatureDigestsHex.isEmpty()) {
                result.skipped("AttestationApplicationId 签名摘要不可用，跳过 lineage 对照");
                return ProbeApplicability.APPLICABLE;
            }

            // 只识别报告中模拟器的确定性实现特征：把完整 signing history 写入
            // AttestationApplicationId，而不是 AOSP legacy GET_SIGNATURES 结果。
            if (appId.signatureDigestsHex.equals(history)
                    && !appId.signatureDigestsHex.equals(legacyExpected)) {
                result.high(FLAG_SIGNING_LINEAGE,
                        "AttestationApplicationId 包含完整 signing history，而非系统 legacy signer 集合："
                                + "legacy=" + legacyExpected
                                + ", history=" + history);
                return ProbeApplicability.APPLICABLE;
            }

            result.normal("AttestationApplicationId 未命中完整 signing history 伪造特征");
        } catch (Throwable t) {
            result.skipped("APK signing lineage 探针无法建立确定性对照："
                    + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runSigningLineageProbe failed", t);
        }
        return ProbeApplicability.APPLICABLE;
    }

    private static long getCurrentVersionCode(Context context) {
        try {
            android.content.pm.PackageInfo pi = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) return pi.getLongVersionCode();
            return pi.versionCode;
        } catch (Throwable t) {
            return -1L;
        }
    }

    private static void runAttestationApplicationIdProbe(Context context, Certificate[] chain, ActiveProbeResult result) {
        try {
            X509Certificate leaf = firstX509(chain);
            if (leaf == null || leaf.getExtensionValue(ANDROID_KEY_ATTESTATION_OID) == null) {
                result.skipped("AttestationApplicationId 探针未找到带 Android Key Attestation 扩展的叶子证书");
                return;
            }

            ApplicationIdInfo appId = parseAttestationApplicationId(leaf);
            if (appId == null) {
                result.skipped("未能解析 AttestationApplicationId，包名与签名摘要检测未完成");
                return;
            }

            String currentPackage = context.getPackageName();
            if (!appId.packageNames.contains(currentPackage)) {
                result.high("AttestationApplicationId 不包含当前包名：current=" + currentPackage
                        + ", packages=" + appId.packageNames
                        + "；疑似证书模板、远程中继或目标 UID 伪造错误");
                return;
            }

            for (String packageName : appId.packageNames) {
                if (("com.google.android.gms".equals(packageName)
                        || "com.android.vending".equals(packageName)
                        || "com.google.android.gsf".equals(packageName))
                        && !currentPackage.equals(packageName)) {
                    result.high("AttestationApplicationId 混入 GMS/Play 相关包名：" + appId.packageNames
                            + "；这符合按目标包伪造/复用模板时的异常特征");
                    return;
                }
            }

            Set<String> currentDigests = getCurrentApkSignatureDigests(context);
            if (!currentDigests.isEmpty() && !appId.signatureDigestsHex.isEmpty()) {
                boolean matched = false;
                for (String digest : currentDigests) {
                    if (appId.signatureDigestsHex.contains(digest)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    result.high("AttestationApplicationId 签名摘要不包含当前 APK 签名：current="
                            + currentDigests + ", attestation=" + appId.signatureDigestsHex
                            + "；疑似证书中 AppID 被伪造或复用");
                    return;
                }
            } else {
                result.skipped("AttestationApplicationId 包名可解析但签名摘要为空或当前签名不可读，签名对照未完成：packages="
                        + appId.packageNames + ", digests=" + appId.signatureDigestsHex);
                return;
            }

            long currentVersion = getCurrentVersionCode(context);
            if (currentVersion >= 0 && appId.packageNames.contains(currentPackage)) {
                int idx = appId.packageNames.indexOf(currentPackage);
                if (idx >= 0 && idx < appId.versionCodes.size()) {
                    long attVersion = appId.versionCodes.get(idx);
                    if (attVersion != currentVersion) {
                        result.warn("AttestationApplicationId 版本号与当前安装版本不一致：current="
                                + currentVersion + ", attestation=" + attVersion
                                + "。升级/降级或厂商差异可能导致该项变化，仅作为关注项");
                    }
                }
            }

            result.normal("AttestationApplicationId 与当前应用包名/签名匹配：packages=" + appId.packageNames);
        } catch (Throwable t) {
            result.skipped("AttestationApplicationId 探针未完成："
                    + t.getClass().getSimpleName() + ": " + t.getMessage());
            Log.w(TAG, "runAttestationApplicationIdProbe failed", t);
        }
    }


    public static int run(Context context) {
        return run(context, null);
    }

    public static int run(Context context, Object callback) {
        synchronized (RUN_LOCK) {
            return runExclusive(context, callback);
        }
    }

    private static int runExclusive(Context context, Object callback) {
        initSharedData(context);
        ACTIVE_BINDINGS.get().clear();
        ks2GeneratedCertificateChain.clear();
        ks2CertificateChain.clear();
        ks2GeneratedMetadata.clear();
        ks2EntryMetadata.clear();
        ks1Certificates.clear();
        Keystore2ProbeAccess.clear();
        lastProbeFlags = 0L;
        lastUnavailableProbeIds = new String[0];
        lastIsolatedChainStatus = 7;
        lastCertificateRecordStatus = 15;
        lastTimingProbeStatus = 3;
        useKs2 = true;
        hasAttestKey = false;
        attestAliasReady = false;
        setSharedData("key_attestation_flags", "0");
        // The native bridge already invokes us from its dedicated scan worker.
        // Returning the result synchronously removes cross-JNI polling and the
        // fixed 250 ms wait granularity without moving work onto the UI thread.
        ACTIVE_PROGRESS_CALLBACK.set(callback);
        if (callback != null) {
            try {
                Method method = callback.getClass().getMethod(
                        "onNativeEvent", int.class, int.class, int.class, String.class);
                method.setAccessible(true);
                ACTIVE_PROGRESS_METHOD.set(method);
            } catch (Throwable t) {
                Log.w(TAG, "hardware attestation progress callback unavailable", t);
            }
        }
        long startedAt = SystemClock.elapsedRealtime();
        try {
            return doAttest(context);
        } finally {
            postProgress(1000, "progress.hardware.complete");
            Log.i(TAG, "hardware attestation completed in "
                    + (SystemClock.elapsedRealtime() - startedAt) + " ms");
            ACTIVE_PROGRESS_CALLBACK.remove();
            ACTIVE_PROGRESS_METHOD.remove();
            ACTIVE_KEY_STORE.remove();
            ACTIVE_BINDINGS.remove();
        }
    }

    private static int doAttest(Context context) {
        ActiveProbeResult collectedResult = new ActiveProbeResult();
        AttestationResult result = null;
        int resultValue = 0;
        boolean hookSuccess = false;

        try {
            postProgress(60, "progress.hardware.chain_integrity");
            hookSuccess = installHook();
            var pm = context.getPackageManager();
            hasAttestKey = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) && pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY);
            var keyStore = acquireKeyStore();
            safeDeleteEntry(keyStore, alias);
            safeDeleteEntry(keyStore, attestAlias);

            // 生成失败属于流程无法继续，不是“检测命中后提前返回”。这里保留快速失败。
            postProgress(140, hasAttestKey ? "progress.hardware.generate_attest_key" : "progress.hardware.generate_attestation_key");
            if (hasAttestKey && !generateKey(attestAlias)) {
                runActiveForgeryProbes(context, alias, null, null, null, null,
                        collectedResult);
                updateKeyAttestationDetail("Key Attestation：AttestKey 生成失败或签名验证失败，无法继续完整检测\n"
                        + collectedResult.text());
                return collectedResult.suspicious ? 64 : 2;
            }
            attestAliasReady = hasAttestKey;
            postProgress(260, "progress.hardware.generate_business_key");
            if (!generateKey(alias)) {
                runActiveForgeryProbes(context, alias, null, null, null, null,
                        collectedResult);
                updateKeyAttestationDetail("Key Attestation：密钥生成失败或签名验证失败，无法继续完整检测\n"
                        + collectedResult.text());
                return collectedResult.suspicious ? 64 : 2;
            }

            postProgress(380, "progress.hardware.read_chain");
            var certificates = Objects.requireNonNull(keyStore.getCertificateChain(alias), "Unable to get certificate chain");
            Log.d(TAG, "alias = " + alias);
            if (hookSuccess && checkCertificate(alias, certificates)) {
                collectedResult.high(FLAG_MAIN_CHAIN_SERVICE, "");
            }

            var certs = new ArrayList<X509Certificate>(certificates.length + 4);
            var cf = CertificateFactory.getInstance("X.509");
            for (var certificate : certificates) {
                certs.add(asX509Certificate(certificate, cf));
            }

            Certificate[] attestCertificates = null;
            if (attestAliasReady) {
                try {
                    attestCertificates = Objects.requireNonNull(keyStore.getCertificateChain(attestAlias), "Unable to get certificate chain");
                    Log.d(TAG, "attestAlias = " + attestAlias);
                    if (hookSuccess && checkCertificate(attestAlias, attestCertificates)) {
                        collectedResult.high(FLAG_ATTEST_CHAIN_SERVICE, "");
                    }
                    for (var certificate : attestCertificates) {
                        var parentCertificate = asX509Certificate(certificate, cf);
                        // Some providers already return this delegated path with the business leaf.
                        // Append only missing certificates; original chains are checked separately below.
                        if (!certs.contains(parentCertificate)) certs.add(parentCertificate);
                    }
                } catch (Throwable t) {
                    collectedResult.skipped("AttestKey 证书链读取不可用：" + t.getClass().getSimpleName());
                    Log.w(TAG, "read attest key chain failed", t);
                }
            }

            boolean mainBindingVerified = verifyMainBinding(keyStore, alias, true, collectedResult);
            if (attestAliasReady) {
                mainBindingVerified &= verifyMainBinding(keyStore, attestAlias, false, collectedResult);
            }
            postProgress(460, "progress.hardware.parse_root_of_trust");
            var mainChainStructureIssue = checkCertificateChainStructure(certificates);
            if (mainChainStructureIssue != null) {
                collectedResult.high(FLAG_MAIN_CHAIN_STRUCTURE, "");
            }
            if (attestCertificates != null) {
                var attestChainStructureIssue = checkCertificateChainStructure(attestCertificates);
                if (attestChainStructureIssue != null) {
                    collectedResult.high(FLAG_ATTEST_CHAIN_STRUCTURE, "");
                }
            }

            var combinedCertificates = certs.toArray(new Certificate[0]);
            try {
                result = parseCertificateChain(certs);
            } catch (Throwable t) {
                // A parser incompatibility or malformed optional extension means the
                // attestation result is unavailable, not proof of key forgery.
                Log.w(TAG, "certificate attestation parsing failed", t);
                runActiveForgeryProbes(context, alias, combinedCertificates, certificates,
                        attestCertificates, null, collectedResult);
                updateKeyAttestationDetail("Key Attestation 证书解析失败：" + t + "\n" + collectedResult.text());
                return collectedResult.suspicious ? 64 : 2;
            }
            var keyStatus = result.getStatus();
            var untrusted = keyStatus == CertificateInfo.KEY_FAILED
                    || keyStatus == CertificateInfo.KEY_AOSP
                    || keyStatus == CertificateInfo.KEY_UNKNOWN;

            for (var certInfo : result.getCerts()) {
                if (certInfo.getStatus() == CertificateInfo.CERT_EXPIRED) {
                    var cert = certInfo.getCert();
                    var now = new Date();
                    var validity = now.after(cert.getNotAfter())
                            ? "已过期"
                            : (now.before(cert.getNotBefore()) ? "尚未生效" : "有效期校验失败");
                    collectedResult.high(FLAG_CERT_VALIDITY,
                            "Attestation 证书链包含有效期异常证书（" + validity + "）："
                                    + cert.getSubjectX500Principal().getName()
                                    + ", notAfter=" + cert.getNotAfter());
                }
            }

            for (var cert : certs) {
                var subject = cert.getSubjectX500Principal().getName();
                if (subject != null && subject.toLowerCase(java.util.Locale.ROOT).contains("keybox")) {
                    collectedResult.high(FLAG_KEYBOX_SUBJECT, "");
                }
            }

            var rootOfTrust = result.getRootOfTrust();
            boolean isDeviceLocked = false;
            int verifiedBootState = -1;
            if (rootOfTrust == null) {
                collectedResult.high(FLAG_ROOT_OF_TRUST_MISSING,
                        "未能从证书链中解析出 RootOfTrust");
                runActiveForgeryProbes(context, alias, combinedCertificates, certificates,
                        attestCertificates, result, collectedResult);
                updateKeyAttestationDetail(buildCertificateChainSummary(result)
                        + "\n\n未能从证书链中解析出 RootOfTrust\n" + collectedResult.text());
                return 64;
            } else {
                isDeviceLocked = rootOfTrust.isDeviceLocked();
                verifiedBootState = rootOfTrust.getVerifiedBootState();
                var verifiedBootHash = rootOfTrust.getVerifiedBootHash();
                if (verifiedBootHash != null && (verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_VERIFIED
                        || verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED)) {
                    var hashFromAttestation = BaseEncoding.base16().encode(verifiedBootHash);
                    var hashFromProp = SystemProperties.get("ro.boot.vbmeta.digest", null);
                    if (hashFromProp != null && !hashFromProp.isBlank() && !hashFromAttestation.matches("0+") && !hashFromProp.equalsIgnoreCase(hashFromAttestation)) {
                        String evidence = "VBMeta Digest 与系统属性 ro.boot.vbmeta.digest 不一致"
                                + "\n系统属性：" + hashFromProp
                                + "\nAttestation：" + hashFromAttestation;
                        collectedResult.high(FLAG_VBMETA_DIGEST, evidence);
                        runActiveForgeryProbes(context, alias, combinedCertificates, certificates,
                                attestCertificates, result, collectedResult);
                        updateKeyAttestationDetail(buildCertificateChainSummary(result)
                                + "\n\n" + evidence + "\n" + collectedResult.text());
                        return 64;
                    }
                }

                var deviceStateProp = SystemProperties.get("ro.boot.vbmeta.device_state", "");
                if (deviceStateProp.isEmpty()) deviceStateProp = SystemProperties.get("vendor.boot.vbmeta.device_state", "");
                var bootStateProp = SystemProperties.get("ro.boot.verifiedbootstate", "");
                if (bootStateProp.isEmpty()) bootStateProp = SystemProperties.get("vendor.boot.verifiedbootstate", "");
                boolean lockedPropConsistent = AttestationStateEvidence.isDeviceStateConsistent(
                        verifiedBootState, isDeviceLocked, deviceStateProp);
                boolean bootStatePropConsistent = AttestationStateEvidence.isBootStateConsistent(
                        verifiedBootState, bootStateProp);
                if (!lockedPropConsistent || !bootStatePropConsistent) {
                    String evidence = "RootOfTrust 与系统属性状态不一致"
                            + "\nro.boot.vbmeta.device_state=" + deviceStateProp
                            + "\nro.boot.verifiedbootstate=" + bootStateProp
                            + "\nAttestation.deviceLocked=" + isDeviceLocked
                            + "\nAttestation.verifiedBootState="
                            + verifiedBootStateToString(verifiedBootState);
                    collectedResult.high(FLAG_VERIFIED_BOOT_STATE, evidence);
                    runActiveForgeryProbes(context, alias, combinedCertificates, certificates,
                            attestCertificates, result, collectedResult);
                    updateKeyAttestationDetail(buildCertificateChainSummary(result)
                            + "\n\n" + evidence + "\n" + collectedResult.text());
                    return 64;
                }
            }

            Log.i(TAG, "untrusted: " + untrusted);
            Log.i(TAG, "Device locked: " + isDeviceLocked);
            Log.i(TAG, "Verified boot state: " + (verifiedBootState >= 0 ? verifiedBootStateToString(verifiedBootState) : "unknown"));
            boolean proofHardware = result.showAttestation != null
                    && isHardwareLevel(result.showAttestation.getAttestationSecurityLevel())
                    && isHardwareLevel(result.showAttestation.getKeymasterSecurityLevel());
            long baseVerdictFlags = AttestationVerdictEvidence.detectedFlags(
                    keyStatus != CertificateInfo.KEY_FAILED,
                    proofHardware,
                    isDeviceLocked,
                    verifiedBootState == KM_VERIFIED_BOOT_VERIFIED);
            if ((baseVerdictFlags & FLAG_ATTESTATION_TRUST) != 0) {
                collectedResult.high(FLAG_ATTESTATION_TRUST,
                        "硬件证明证书链未通过可信根、签名、吊销或有效性校验");
            }
            if ((baseVerdictFlags & FLAG_ATTESTATION_SECURITY_LEVEL) != 0) {
                collectedResult.high(FLAG_ATTESTATION_SECURITY_LEVEL,
                        "Attestation 或 Keymaster / KeyMint 未返回可信硬件安全级别");
            }
            if ((baseVerdictFlags & FLAG_VERIFIED_BOOT_STATE) != 0) {
                collectedResult.high(FLAG_VERIFIED_BOOT_STATE,
                        "RootOfTrust 未报告锁定设备与 Verified 启动状态：deviceLocked="
                                + isDeviceLocked + ", verifiedBootState="
                                + verifiedBootStateToString(verifiedBootState));
            }
            resultValue = (!untrusted && mainBindingVerified && result.isRevocationStatusAvailable()
                    && proofHardware && isDeviceLocked && verifiedBootState == KM_VERIFIED_BOOT_VERIFIED) ? 1 : 0;
            if (!mainBindingVerified || !result.isRevocationStatusAvailable()) resultValue |= 2;
            if (!hookSuccess) resultValue |= 4;
            if (keyStatus == CertificateInfo.KEY_AOSP) resultValue |= 8;
            if (keyStatus == CertificateInfo.KEY_UNKNOWN) resultValue |= 16;

            try {
                var privateKey = keyStore.getKey(attestAliasReady ? attestAlias : alias, null);
                var keyInfo = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore")
                        .getKeySpec(privateKey, KeyInfo.class);
                if (!keyInfo.isInsideSecureHardware()) {
                    collectedResult.high(FLAG_KEYINFO_HW, "");
                }
            } catch (Throwable t) {
                resultValue = (resultValue & ~1) | 2;
                collectedResult.skipped("主 KeyInfo 不可用：" + t.getClass().getSimpleName());
                Log.w(TAG, "KeyInfo check failed", t);
            }

            postProgress(500, "progress.hardware.active_probes");
            runActiveForgeryProbes(context, alias, combinedCertificates, certificates, attestCertificates, result, collectedResult);

            postProgress(985, "progress.hardware.boundary");
            if (attestAliasReady) {
                try {
                    PrivateKey fakePrivateKey = readPrivateKey(EMBEDDED_FAKE_ATTEST_KEY_B64);
                    Certificate[] certificateArray = readCertificateChain(EMBEDDED_FAKE_ATTEST_CERT_B64, cf);

                    KeyStore.PrivateKeyEntry keyEntry = new KeyStore.PrivateKeyEntry(fakePrivateKey, certificateArray);
                    keyStore.setEntry(attestAlias, keyEntry, null);

                    Certificate certificate = keyStore.getCertificate(attestAlias);
                    if (certificate != null) {
                        String desc = certificate.toString();
                        Log.d(TAG, "embedded attest cert: " + desc);
                        if (!desc.contains("LingQing")) {
                            collectedResult.high(FLAG_EMBEDDED_ATTEST, "");
                        }
                    }
                } catch (Throwable t) {
                    collectedResult.skipped("内置测试 AttestKey 写入/读取探针无法执行：" + t.getClass().getSimpleName() + ": " + t.getMessage());
                    Log.w(TAG, "embedded attest key probe failed", t);
                }
            }

            try {
                Date now = new Date();
                byte[] longChallenge = "LingQing".repeat(32).getBytes(StandardCharsets.UTF_8);

                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_SIGN
                )
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setCertificateNotBefore(now)
                        .setAttestationChallenge(longChallenge);

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC,
                        "AndroidKeyStore"
                );
                keyPairGenerator.initialize(builder.build());
                keyPairGenerator.generateKeyPair();

                collectedResult.high(FLAG_LONG_CHALLENGE, "");
            } catch (Throwable t) {
                Log.e(TAG, "long size Challenge failed", t);
                collectedResult.normal("超长 Challenge 被拒绝或生成失败");
            }

            postProgress(995, "progress.hardware.summarize");
            String conclusion;
            int finalReturn;
            if (collectedResult.suspicious) {
                conclusion = "发现高危异常，疑似 KeyMint / TEE / Attestation 被伪造或拦截 (" + collectedResult.flagHex() + ")";
                finalReturn = 64;
            } else {
                conclusion = (resultValue == 1 ? "证书链与 Attestation 状态正常" : "证书链或 Attestation 存在需关注项") + " (" + collectedResult.flagHex() + ")";
                finalReturn = resultValue;
            }


            var summary = buildCertificateChainSummary(result)
                    + "\n\n综合结论：" + conclusion
                    + "\n证明安全等级：" + securityLabel(result.isSoftwareLevel());
            if (!collectedResult.text().isEmpty()) {
                summary += "\n\n主动探针证据\n" + collectedResult.text();
            }
            updateKeyAttestationDetail(summary);
            return finalReturn;
        } catch (Throwable t) {
            Log.e(TAG, "Error while loading keystore", t);
            collectedResult.skipped("主检测流程未能完成：" + t.getClass().getSimpleName());
            runActiveForgeryProbes(context, alias, null, null, null, result, collectedResult);
            String base = result == null ? "" : buildCertificateChainSummary(result);
            updateKeyAttestationDetail(base
                    + "\n\nKey Attestation 执行失败：" + t + " (" + collectedResult.flagHex() + ")\n" + collectedResult.text());
            return collectedResult.suspicious ? 64 : 2;
        } finally {
            // Publish established evidence even when later parsing or optional data is unavailable.
            lastProbeFlags = collectedResult.flags;
            lastUnavailableProbeIds = collectedResult.unavailableProbeIds();
            setSharedData("key_attestation_flags", collectedResult.flagHex());
        }
    }

    private static boolean isHardwareLevel(int level) {
        return level == Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                || level == Attestation.KM_SECURITY_LEVEL_STRONG_BOX;
    }

    private static boolean generateKey(String alias) throws Throwable {
        var now = new Date();
        byte[] request = new byte[32];
        new SecureRandom().nextBytes(request);
        var isAttestKey = Objects.equals(alias, attestAlias);
        var purposes = isAttestKey ? KeyProperties.PURPOSE_ATTEST_KEY : KeyProperties.PURPOSE_SIGN;

        var builder = new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateNotBefore(now)
                .setAttestationChallenge(request);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (isAttestKey) {
                builder.setCertificateSubject(new X500Principal("CN=App Attest Key"));
            } else if (attestAliasReady) {
                builder.setAttestKeyAlias(attestAlias);
            } else {
                builder.setAttestKeyAlias(null);
            }
        }

        var keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        keyPairGenerator.initialize(builder.build());
        var keypair = keyPairGenerator.generateKeyPair();
        ACTIVE_BINDINGS.get().put(alias, new GeneratedKeyBinding(keypair.getPublic(), request));
        return true;
    }
}

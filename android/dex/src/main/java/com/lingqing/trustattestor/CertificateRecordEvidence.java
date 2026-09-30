package com.lingqing.trustattestor;

import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

/** Pure comparisons of completed reads of one application-owned certificate record. */
final class CertificateRecordEvidence {
    static final int MAX_CERTIFICATES = 16;
    static final int MAX_CERTIFICATE_BYTES = 32768;
    static final int MAX_CHAIN_BYTES = 131072;
    private CertificateRecordEvidence() { }

    static final class Chain {
        private final byte[][] certificates;

        Chain(byte[][] certificates) throws GeneralSecurityException {
            if (!complete(certificates) || certificates.length < 2)
                throw new GeneralSecurityException("initial certificate chain unavailable");
            this.certificates = copy(certificates);
        }

        byte[][] encoded() { return copy(certificates); }
        int size() { return certificates.length; }
    }

    static byte[][] encode(Certificate[] certificates) throws GeneralSecurityException {
        if (certificates == null) return null;
        if (certificates.length > MAX_CERTIFICATES)
            throw new GeneralSecurityException("certificate chain exceeds evidence limit");
        byte[][] encoded = new byte[certificates.length][];
        int total = 0;
        for (int i = 0; i < certificates.length; i++) {
            if (certificates[i] != null) {
                byte[] value = certificates[i].getEncoded();
                if (value != null) {
                    if (value.length > MAX_CERTIFICATE_BYTES || total + value.length > MAX_CHAIN_BYTES)
                        throw new GeneralSecurityException("certificate encoding exceeds evidence limit");
                    total += value.length;
                }
                set(encoded, i, value == null ? null : value.clone());
            }
        }
        return encoded;
    }

    /** Keystore providers may absorb service failures and return null, so missing data is unavailable. */
    static SilentProbeEvidence.Decision compare(Chain expected, byte[][] observed, boolean completed) {
        if (expected == null || !completed || !complete(observed))
            return decision(SilentProbeEvidence.Status.UNAVAILABLE, "完整证书链读取未完成");
        if (observed.length != expected.certificates.length)
            return decision(SilentProbeEvidence.Status.DETECTED, "完整读取的非空证书链张数发生变化");
        for (int i = 0; i < observed.length; i++) {
            if (!Arrays.equals(at(expected.certificates, i), at(observed, i)))
                return decision(SilentProbeEvidence.Status.DETECTED,
                        "成功读取的证书链 DER 发生变化，位置=" + i + "（从 0 开始）");
        }
        return decision(SilentProbeEvidence.Status.VERIFIED, "全部 " + observed.length + " 张证书 DER 一致");
    }

    static final class Metadata {
        private final Map<String, String> fields;

        Metadata(Map<String, String> fields) {
            this.fields = new LinkedHashMap<>(fields);
        }
    }

    static SilentProbeEvidence.Decision compare(Metadata expected, Metadata observed) {
        if (expected == null || observed == null || expected.fields.isEmpty())
            return decision(SilentProbeEvidence.Status.UNAVAILABLE, "KeyInfo 稳定字段未完整读取");
        boolean unknown = false;
        for (Map.Entry<String, String> entry : expected.fields.entrySet()) {
            String actual = observed.fields.get(entry.getKey());
            // Losing a previously known value makes the comparison unavailable, never confirmed.
            if (actual == null || entry.getValue() == null) {
                unknown = true;
                continue;
            }
            if (!entry.getValue().equals(actual))
                return decision(SilentProbeEvidence.Status.DETECTED,
                        "同一密钥的 KeyInfo 稳定字段发生变化：" + entry.getKey());
        }
        if (unknown) return decision(SilentProbeEvidence.Status.UNAVAILABLE, "先前已知的 KeyInfo 字段失去可比性");
        return decision(SilentProbeEvidence.Status.VERIFIED, "已知 KeyInfo 身份及授权字段保持一致");
    }

    static String unordered(String[] values) throws GeneralSecurityException {
        if (values == null) throw new GeneralSecurityException("KeyInfo authorization array unavailable");
        for (String value : values) if (value == null)
            throw new GeneralSecurityException("KeyInfo authorization value unavailable");
        return new TreeSet<>(Arrays.asList(values)).toString();
    }

    private static boolean complete(byte[][] certificates) {
        if (certificates == null || certificates.length == 0 || certificates.length > MAX_CERTIFICATES) return false;
        int total = 0;
        for (int i = 0; i < certificates.length; i++) {
            byte[] value = at(certificates, i);
            if (value == null || value.length == 0 || value.length > MAX_CERTIFICATE_BYTES) return false;
            total += value.length;
            if (total > MAX_CHAIN_BYTES) return false;
        }
        return true;
    }

    private static byte[][] copy(byte[][] values) {
        byte[][] result = new byte[values.length][];
        for (int i = 0; i < values.length; i++) {
            byte[] value = at(values, i);
            set(result, i, value == null ? null : value.clone());
        }
        return result;
    }

    // Maple IR currently loses an array dimension for direct byte[][] AALOAD/
    // AASTORE instructions. Reflective access keeps the byte[] reference type.
    private static byte[] at(byte[][] values, int index) {
        return (byte[]) java.lang.reflect.Array.get(values, index);
    }

    private static void set(byte[][] values, int index, byte[] value) {
        java.lang.reflect.Array.set(values, index, value);
    }

    private static SilentProbeEvidence.Decision decision(SilentProbeEvidence.Status status, String detail) {
        return new SilentProbeEvidence.Decision(status, detail);
    }
}

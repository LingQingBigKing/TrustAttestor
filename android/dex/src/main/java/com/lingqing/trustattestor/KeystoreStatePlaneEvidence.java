package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Pure classification rules for the APP-alias/KEY_ID and Keystore2-ledger probes.
 *
 * <p>The runtime code deliberately keeps reflection, Binder and cleanup failures out of these
 * rules. A positive result is possible only after both read paths returned complete metadata and
 * certificate material. Missing fields and incomplete cleanup are always UNAVAILABLE.</p>
 */
final class KeystoreStatePlaneEvidence {
    private KeystoreStatePlaneEvidence() { }

    enum Status { VERIFIED, DETECTED, UNAVAILABLE }

    static final class Decision {
        final Status status;
        final String summary;
        final String detail;

        Decision(Status status, String summary, String detail) {
            this.status = status;
            this.summary = summary == null ? "" : summary;
            this.detail = detail == null ? "" : detail;
        }
    }

    /** One successfully decoded KeyEntryResponse.metadata record. */
    static final class RouteSnapshot {
        final String route;
        final Integer metadataDomain;
        final Long metadataKeyId;
        final byte[] certificate;
        final byte[] certificateChain;

        RouteSnapshot(String route, Integer metadataDomain, Long metadataKeyId,
                      byte[] certificate, byte[] certificateChain) {
            this.route = route == null ? "unknown" : route;
            this.metadataDomain = metadataDomain;
            this.metadataKeyId = metadataKeyId;
            this.certificate = copy(certificate);
            this.certificateChain = copy(certificateChain);
        }

        boolean complete() {
            return metadataDomain != null && metadataKeyId != null
                    && certificate != null && certificate.length > 0;
        }
    }

    /** APP and KEY_ID views of the same currently-live temporary alias. */
    static final class AliasObservation {
        final String label;
        final int keyIdDomain;
        final long requestedKeyId;
        final RouteSnapshot app;
        final RouteSnapshot keyId;
        final byte[] publicApiLeaf;

        AliasObservation(String label, int keyIdDomain, long requestedKeyId,
                         RouteSnapshot app, RouteSnapshot keyId, byte[] publicApiLeaf) {
            this.label = label == null ? "alias" : label;
            this.keyIdDomain = keyIdDomain;
            this.requestedKeyId = requestedKeyId;
            this.app = app;
            this.keyId = keyId;
            this.publicApiLeaf = copy(publicApiLeaf);
        }
    }

    static Decision aliasKeyId(AliasObservation observation, boolean cleanupVerified) {
        if (!cleanupVerified) {
            return unavailable("临时别名未能完整清理", "cleanupVerified=false");
        }
        return compareLiveAlias(observation);
    }

    /**
     * Classifies a two-key ledger trajectory. Counts must have been sampled stably by the caller.
     * A count mismatch is a finding only when both keys were also read successfully through APP
     * and KEY_ID, and final cleanup restored the original count.
     */
    static Decision ledger(long before, long afterFirst, long afterSecond, long afterCleanup,
                           AliasObservation first, AliasObservation second,
                           boolean cleanupVerified) {
        if (!cleanupVerified) {
            return unavailable("账本探针的临时别名未能完整清理",
                    "cleanupVerified=false; counts=" + counts(before, afterFirst, afterSecond,
                            afterCleanup));
        }
        if (before < 0 || afterFirst < 0 || afterSecond < 0 || afterCleanup < 0) {
            return unavailable("Keystore2 返回了无效的条目计数",
                    counts(before, afterFirst, afterSecond, afterCleanup));
        }
        if (afterCleanup != before) {
            return unavailable("清理后 Keystore2 条目计数没有回到稳定基线",
                    counts(before, afterFirst, afterSecond, afterCleanup));
        }

        Decision firstDecision = compareLiveAlias(first);
        Decision secondDecision = compareLiveAlias(second);
        if (firstDecision.status == Status.UNAVAILABLE
                || secondDecision.status == Status.UNAVAILABLE) {
            return unavailable("APP/KEY_ID 双路径前提不完整",
                    "first={" + firstDecision.detail + "}; second={"
                            + secondDecision.detail + "}; "
                            + counts(before, afterFirst, afterSecond, afterCleanup));
        }

        List<String> contradictions = new ArrayList<>();
        if (firstDecision.status == Status.DETECTED) {
            contradictions.add("first=" + firstDecision.detail);
        }
        if (secondDecision.status == Status.DETECTED) {
            contradictions.add("second=" + secondDecision.detail);
        }

        if (first != null && second != null && first.requestedKeyId == second.requestedKeyId) {
            contradictions.add("两个不同临时别名返回了同一个 KEY_ID=" + first.requestedKeyId);
        }

        long expectedFirst;
        long expectedSecond;
        try {
            expectedFirst = Math.addExact(before, 1L);
            expectedSecond = Math.addExact(before, 2L);
        } catch (ArithmeticException overflow) {
            return unavailable("条目计数溢出，无法建立账本增量",
                    counts(before, afterFirst, afterSecond, afterCleanup));
        }
        if (afterFirst != expectedFirst || afterSecond != expectedSecond) {
            contradictions.add("两把可经 APP/KEY_ID 双路径读取的临时密钥只产生账本轨迹 "
                    + before + "->" + afterFirst + "->" + afterSecond
                    + "，预期 " + before + "->" + expectedFirst + "->" + expectedSecond);
        }

        String detail = counts(before, afterFirst, afterSecond, afterCleanup)
                + "; firstKeyId=" + keyId(first) + "; secondKeyId=" + keyId(second);
        if (!contradictions.isEmpty()) {
            return new Decision(Status.DETECTED,
                    "Keystore2 的 alias、KEY_ID 与账本状态出现确定矛盾",
                    join(contradictions) + "; " + detail);
        }
        return new Decision(Status.VERIFIED,
                "两把临时密钥的 APP/KEY_ID 视图与 Keystore2 账本增量一致", detail);
    }

    private static Decision compareLiveAlias(AliasObservation observation) {
        if (observation == null) {
            return unavailable("缺少双路径观测", "observation=null");
        }
        if (observation.requestedKeyId == 0) {
            return unavailable("APP 路径没有给出可用的 KEY_ID",
                    observation.label + ": requestedKeyId=0");
        }
        if (observation.app == null || observation.keyId == null
                || !observation.app.complete() || !observation.keyId.complete()) {
            return unavailable("APP/KEY_ID 路径的证书或元数据不完整",
                    observation.label + ": app=" + routeShape(observation.app)
                            + "; keyId=" + routeShape(observation.keyId));
        }
        if (observation.publicApiLeaf == null || observation.publicApiLeaf.length == 0) {
            return unavailable("公开 AndroidKeyStore 路径没有返回叶证书",
                    observation.label + ": publicLeaf=missing");
        }

        List<String> contradictions = new ArrayList<>();
        checkDescriptor(contradictions, observation.app, observation.keyIdDomain,
                observation.requestedKeyId);
        checkDescriptor(contradictions, observation.keyId, observation.keyIdDomain,
                observation.requestedKeyId);
        if (!Arrays.equals(observation.app.certificate, observation.keyId.certificate)) {
            contradictions.add("APP 与 KEY_ID 返回的叶证书字节不同");
        }
        if (!sameNullableBytes(observation.app.certificateChain,
                observation.keyId.certificateChain)) {
            contradictions.add("APP 与 KEY_ID 返回的证书链尾字节不同");
        }
        if (!Arrays.equals(observation.publicApiLeaf, observation.app.certificate)) {
            contradictions.add("公开 API 叶证书与 APP KeyMetadata.certificate 不同");
        }
        if (!Arrays.equals(observation.publicApiLeaf, observation.keyId.certificate)) {
            contradictions.add("公开 API 叶证书与 KEY_ID KeyMetadata.certificate 不同");
        }

        String shape = observation.label + ": requestedKeyId=" + observation.requestedKeyId
                + "; app=" + routeShape(observation.app)
                + "; keyId=" + routeShape(observation.keyId)
                + "; publicLeafBytes=" + observation.publicApiLeaf.length;
        if (!contradictions.isEmpty()) {
            return new Decision(Status.DETECTED,
                    "同一临时密钥的 APP alias 与 KEY_ID 视图不一致",
                    join(contradictions) + "; " + shape);
        }
        return new Decision(Status.VERIFIED,
                "同一临时密钥的 APP alias、KEY_ID 与公开证书视图一致", shape);
    }

    private static void checkDescriptor(List<String> contradictions, RouteSnapshot route,
                                        int keyIdDomain, long requestedKeyId) {
        if (route.metadataDomain != keyIdDomain) {
            contradictions.add(route.route + " metadata.key.domain=" + route.metadataDomain
                    + "，预期 KEY_ID(" + keyIdDomain + ")");
        }
        if (route.metadataKeyId != requestedKeyId) {
            contradictions.add(route.route + " metadata.key.nspace=" + route.metadataKeyId
                    + "，请求 KEY_ID=" + requestedKeyId);
        }
    }

    private static String routeShape(RouteSnapshot route) {
        if (route == null) return "missing";
        return route.route + "{domain=" + route.metadataDomain + ", keyId="
                + route.metadataKeyId + ", certBytes=" + length(route.certificate)
                + ", chainBytes=" + length(route.certificateChain) + "}";
    }

    private static String counts(long before, long afterFirst, long afterSecond,
                                 long afterCleanup) {
        return "counts={before=" + before + ", afterFirst=" + afterFirst
                + ", afterSecond=" + afterSecond + ", afterCleanup=" + afterCleanup + "}";
    }

    private static long keyId(AliasObservation observation) {
        return observation == null ? 0 : observation.requestedKeyId;
    }

    private static Decision unavailable(String summary, String detail) {
        return new Decision(Status.UNAVAILABLE, summary, detail);
    }

    private static boolean sameNullableBytes(byte[] left, byte[] right) {
        if ((left == null || left.length == 0) && (right == null || right.length == 0)) {
            return true;
        }
        return Arrays.equals(left, right);
    }

    private static int length(byte[] value) {
        return value == null ? 0 : value.length;
    }

    private static byte[] copy(byte[] value) {
        return value == null ? null : value.clone();
    }

    private static String join(List<String> values) {
        List<String> safe = values == null ? Collections.emptyList() : values;
        StringBuilder out = new StringBuilder();
        for (String value : safe) {
            if (out.length() > 0) out.append("; ");
            out.append(value);
        }
        return out.toString();
    }
}

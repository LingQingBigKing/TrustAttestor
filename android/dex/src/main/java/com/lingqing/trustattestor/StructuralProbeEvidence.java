package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Pure decision logic for structural Keystore probes. */
final class StructuralProbeEvidence {
    private StructuralProbeEvidence() { }

    static final class SecurityLevelValue {
        final String source;
        final Long value;
        final String unavailableReason;

        private SecurityLevelValue(String source, Long value, String unavailableReason) {
            this.source = source == null ? "unknown" : source;
            this.value = value;
            this.unavailableReason = unavailableReason;
        }

        static SecurityLevelValue observed(String source, long value) {
            return new SecurityLevelValue(source, value, null);
        }

        static SecurityLevelValue unavailable(String source, String reason) {
            return new SecurityLevelValue(source, null, reason == null ? "unreadable" : reason);
        }
    }

    static final class BinderLeg {
        enum Disposition { LOCAL, REMOTE, UNAVAILABLE }

        final String name;
        final Disposition disposition;
        final String detail;

        BinderLeg(String name, Disposition disposition, String detail) {
            this.name = name == null ? "unknown" : name;
            this.disposition = disposition == null ? Disposition.UNAVAILABLE : disposition;
            this.detail = detail == null ? "" : detail;
        }
    }

    static final class Decision {
        final SilentProbeEvidence.Status status;
        final String summary;
        final String detail;

        Decision(SilentProbeEvidence.Status status, String summary, String detail) {
            this.status = status;
            this.summary = summary;
            this.detail = detail;
        }
    }

    static boolean isDefinedSecurityLevel(long value) {
        return value == 0L || value == 1L || value == 2L || value == 100L;
    }

    /**
     * A successfully decoded value outside the stable AIDL enum is a contradiction. Missing or
     * inaccessible fields remain unavailable and can never create a finding.
     */
    static Decision securityLevels(List<SecurityLevelValue> values) {
        List<SecurityLevelValue> safe = values == null ? Collections.emptyList() : values;
        int observed = 0;
        int unavailable = 0;
        List<String> invalid = new ArrayList<>();
        StringBuilder detail = new StringBuilder();
        for (SecurityLevelValue value : safe) {
            if (value == null) continue;
            if (value.value == null) {
                unavailable++;
                append(detail, value.source + "=unavailable(" + value.unavailableReason + ")");
                continue;
            }
            observed++;
            append(detail, value.source + "=" + value.value);
            if (!isDefinedSecurityLevel(value.value)) {
                invalid.add(value.source + "=" + value.value);
            }
        }
        if (!invalid.isEmpty()) {
            return new Decision(SilentProbeEvidence.Status.DETECTED,
                    "KeyMetadata 包含 AIDL 契约之外的 securityLevel",
                    "invalid=" + invalid + "; observed=" + observed + "; " + detail);
        }
        if (observed == 0) {
            return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                    "没有成功读取任何 KeyMetadata securityLevel",
                    "unavailable=" + unavailable + (detail.length() == 0 ? "" : "; " + detail));
        }
        return new Decision(SilentProbeEvidence.Status.VERIFIED,
                "已读取的 KeyMetadata securityLevel 均属于 AIDL 定义范围",
                "observed=" + observed + "; unavailable=" + unavailable + "; " + detail);
    }

    /**
     * A local Binder in any successfully obtained Keystore reply is sufficient evidence. A clean
     * result, however, requires a remote Binder from a core path: either getKeyEntry's returned
     * IKeystoreSecurityLevel or a live IKeystoreOperation. The optional getSecurityLevel path alone
     * cannot verify the probe because it does not exercise the reply objects under test.
     */
    static Decision binderLocality(List<BinderLeg> legs) {
        List<BinderLeg> safe = legs == null ? Collections.emptyList() : legs;
        int local = 0;
        int remote = 0;
        int coreRemote = 0;
        int unavailable = 0;
        StringBuilder detail = new StringBuilder();
        for (BinderLeg leg : safe) {
            if (leg == null) continue;
            switch (leg.disposition) {
                case LOCAL -> local++;
                case REMOTE -> {
                    remote++;
                    if (isCoreBinderLeg(leg.name)) coreRemote++;
                }
                case UNAVAILABLE -> unavailable++;
            }
            append(detail, leg.name + "=" + leg.disposition +
                    (leg.detail.isEmpty() ? "" : "(" + leg.detail + ")"));
        }
        if (local > 0) {
            return new Decision(SilentProbeEvidence.Status.DETECTED,
                    "Keystore 回复中出现当前进程的本地 Binder 对象",
                    "local=" + local + "; coreRemote=" + coreRemote + "; remote=" + remote +
                            "; unavailable=" + unavailable + "; " + detail);
        }
        if (coreRemote > 0) {
            return new Decision(SilentProbeEvidence.Status.VERIFIED,
                    "至少一个核心 Keystore 回复 Binder 为远端对象",
                    "coreRemote=" + coreRemote + "; remote=" + remote +
                            "; unavailable=" + unavailable + "; " + detail);
        }
        return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                "没有取得可判定本地性的核心 Keystore Binder 对象",
                "coreRemote=0; remote=" + remote + "; unavailable=" + unavailable +
                        (detail.length() == 0 ? "" : "; " + detail));
    }

    private static boolean isCoreBinderLeg(String name) {
        return "getKeyEntry.iSecurityLevel".equals(name) || "IKeystoreOperation".equals(name);
    }

    private static void append(StringBuilder builder, String value) {
        if (builder.length() > 0) builder.append("; ");
        builder.append(value);
    }
}

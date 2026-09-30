package com.lingqing.trustattestor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.lingqing.trustattestor.SilentProbeEvidence.Status.DETECTED;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.UNAVAILABLE;
import static com.lingqing.trustattestor.SilentProbeEvidence.Status.VERIFIED;

/** Pure classification rules for the bounded OMK protocol fingerprints. */
final class OmkRiskyProbeEvidence {
    private OmkRiskyProbeEvidence() { }

    static final class Decision {
        final SilentProbeEvidence.Status status;
        final String summary;

        Decision(SilentProbeEvidence.Status status, String summary) {
            this.status = status;
            this.summary = summary;
        }
    }

    static final class Observation {
        final String name;
        final Integer serviceCode;
        final boolean success;
        final String outcome;
        final long elapsedMicros;

        Observation(String name, Integer serviceCode, boolean success,
                    String outcome, long elapsedMicros) {
            this.name = name;
            this.serviceCode = serviceCode;
            this.success = success;
            this.outcome = outcome;
            this.elapsedMicros = elapsedMicros;
        }

        String bucket() {
            if (success) return "success";
            return serviceCode == null ? "other:" + outcome : "code=" + serviceCode;
        }
    }

    static Decision tokenDispatch(boolean healthBefore, boolean migrateAnswered,
                                  boolean undefinedAnswered, boolean healthAfter) {
        if (!healthBefore) {
            return new Decision(UNAVAILABLE, "正确接口对照在探测前不可用");
        }
        if (!healthAfter) {
            return new Decision(UNAVAILABLE, "探测后正确接口对照失败，结果作废");
        }
        if (undefinedAnswered) {
            return new Decision(UNAVAILABLE, "未定义事务号也得到回复，接口令牌判据不可分辨");
        }
        if (migrateAnswered) {
            return new Decision(DETECTED,
                    "IKeystoreService binder 回答了 IKeystoreMaintenance 的 migrateKeyNamespace 事务");
        }
        return new Decision(VERIFIED, "伪装 maintenance interface token 的事务被拒绝");
    }

    static Decision parameterFingerprint(boolean healthBefore, boolean healthAfter,
                                         List<Observation> rows, Boolean taPatchTagsPresent) {
        if (!healthBefore) return new Decision(UNAVAILABLE, "参数探针前证明金丝雀失败");
        if (!healthAfter) return new Decision(UNAVAILABLE, "参数探针后证明金丝雀失败，读数作废");
        if (rows == null) return new Decision(UNAVAILABLE, "没有参数指纹读数");

        Map<String, Integer> distribution = new LinkedHashMap<>();
        int valid = 0;
        int tagSpecificKinds = 0;
        int[] tagSpecific = {-2, -4, -7, -10, -12, -17, -61};
        for (Observation row : rows) {
            if (row == null) continue;
            if (!row.success && row.serviceCode == null) continue;
            valid++;
            distribution.merge(row.bucket(), 1, Integer::sum);
        }
        if (valid < 6) {
            return new Decision(VERIFIED,
                    "本机私有 KeyMint ABI 仅返回 " + valid + " 条可分类向量，参数指纹判据不适用");
        }
        for (int code : tagSpecific) {
            if (distribution.containsKey("code=" + code)) tagSpecificKinds++;
        }

        String evidence = valid + " 条有效向量；分布=" + distribution
                + "；tag 专属错误种类=" + tagSpecificKinds
                + "；TA补丁标签=" + taPatchTagsPresent;
        if (tagSpecificKinds >= 3 && Boolean.FALSE.equals(taPatchTagsPresent)) {
            return new Decision(DETECTED,
                    "参数错误走 AOSP 逐 tag 映射，且证明中未发现 TA 追加的 vendor/boot patch 标签；"
                            + evidence);
        }
        if (distribution.size() == 1) {
            String only = distribution.keySet().iterator().next();
            if ("code=-21".equals(only) || "code=4".equals(only)) {
                return new Decision(VERIFIED, "全部向量落入已知厂商统一兜底；" + evidence);
            }
        }
        return new Decision(VERIFIED, "参数指纹已完整执行，但没有形成可安全归因的异常；" + evidence);
    }

    static Decision teeSimFingerprint(boolean healthBefore, boolean healthAfter,
                                      List<Observation> rows, boolean evidenceInvalidated) {
        if (!healthBefore) return new Decision(UNAVAILABLE, "TeeSim 探针前证明金丝雀失败");
        if (!healthAfter) return new Decision(UNAVAILABLE, "TeeSim 探针后证明金丝雀失败，读数作废");
        if (rows == null || rows.isEmpty()) return new Decision(UNAVAILABLE, "没有 TeeSim 指纹读数");
        if (evidenceInvalidated) {
            return new Decision(UNAVAILABLE, "临时密钥清理失败，TeeSim 读数已作废");
        }

        Observation baseline = null;
        Map<String, String> values = new LinkedHashMap<>();
        for (Observation row : rows) {
            if (row == null) continue;
            values.put(row.name, row.bucket());
            if ("V0".equals(row.name)) baseline = row;
            // A type-confused ALGORITHM tag is deliberately present in every vector. A generated
            // key therefore establishes a validation bypass without relying on an error-code map.
            if (row.success) {
                return new Decision(DETECTED,
                        "包含类型错配 KeyParameter 的原始 generateKey 请求被接受：" + row.name);
            }
        }
        if (baseline == null || baseline.serviceCode == null) {
            return new Decision(UNAVAILABLE, "V0 非法 tag 基线没有稳定服务错误码；读数=" + values);
        }

        boolean differential = false;
        for (Observation row : rows) {
            if (row != null && !"V0".equals(row.name)
                    && row.serviceCode != null
                    && !row.serviceCode.equals(baseline.serviceCode)) {
                differential = true;
                break;
            }
        }
        if (differential) {
            // The upstream project labels V0..V4 as measurement-only. Its V5 attribution leg is
            // intentionally omitted because it has repeatedly broken clean devices. Do not turn
            // an unattributed differential into a positive verdict.
            return new Decision(VERIFIED,
                    "观察到已执行向量的错误码差分；安全版本不运行会损坏设备的 V5 归因腿，"
                            + "因此该读数保持中性；读数=" + values);
        }
        return new Decision(VERIFIED, "已执行向量均被非法 tag 路径拒绝；读数=" + values);
    }

    static Decision attestKeyDescriptorDelegation(boolean sourceGenerated,
                                                   boolean sourceDescriptorValid,
                                                   boolean delegatedGenerated,
                                                   long delegatedKeyId,
                                                   boolean invalidAttestKeyAlias,
                                                   boolean cleanupVerified) {
        if (!cleanupVerified) {
            return new Decision(UNAVAILABLE, "直接委派探针的临时密钥未能完整清理");
        }
        if (!sourceGenerated) {
            return new Decision(UNAVAILABLE, "PURPOSE_ATTEST_KEY 源密钥未成功生成");
        }
        if (!sourceDescriptorValid) {
            return new Decision(UNAVAILABLE, "AttestKey 没有返回可用的 KEY_ID 描述符");
        }
        if (invalidAttestKeyAlias) {
            return new Decision(DETECTED,
                    "有效 AttestKey 描述符直接委派时被报告为 Invalid attestKeyAlias");
        }
        if (delegatedGenerated && isUsableKeyId(delegatedKeyId)) {
            return new Decision(VERIFIED,
                    "直接委派成功并返回有效随机 keyId=" + delegatedKeyId);
        }
        return new Decision(UNAVAILABLE,
                delegatedGenerated
                        ? "直接委派完成，但签名密钥返回了保留的未分配 keyId=-1"
                        : "直接委派未完成，错误不符合可确认的 Invalid attestKeyAlias 特征");
    }

    static boolean isUsableKeyId(long keyId) {
        // Keystore2 allocates database IDs from a random signed i64. Positive, zero, and
        // negative values are valid; only -1 is reserved as UNASSIGNED_KEY_ID.
        return keyId != -1L;
    }
}

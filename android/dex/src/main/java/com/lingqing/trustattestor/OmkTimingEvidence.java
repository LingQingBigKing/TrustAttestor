package com.lingqing.trustattestor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** Pure-Java decisions for the OMK reply-lag and raw-read timing probes. */
final class OmkTimingEvidence {
    private static final int REPLY_BATCHES = 2;
    private static final int REPLY_PAIRS_PER_BATCH = 4;
    private static final double REPLY_EARLY_MILLIS = 25.0;
    private static final double REPLY_MIN_PAIRED_MARGIN_MILLIS = 20.0;
    private static final int REPLY_REQUIRED_TARGET_HITS = 3;
    private static final int REPLY_MAX_CONTROL_HITS = 1;

    private static final double READ_MIN_RATIO = 1.30;
    private static final double READ_MIN_MARGIN_PERCENT = 15.0;

    private OmkTimingEvidence() { }

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

    static final class ReplyPair {
        final int batch;
        final boolean targetFirst;
        final double targetGapMillis;
        final double controlGapMillis;

        ReplyPair(int batch, boolean targetFirst, double targetGapMillis,
                  double controlGapMillis) {
            this.batch = batch;
            this.targetFirst = targetFirst;
            this.targetGapMillis = targetGapMillis;
            this.controlGapMillis = controlGapMillis;
        }
    }

    static Decision replyLag(List<ReplyPair> samples) {
        if (samples == null) {
            return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                    "回复提前可见检测没有样本", "samples=null");
        }
        StringBuilder detail = new StringBuilder();
        boolean[] strongBatch = new boolean[REPLY_BATCHES];
        boolean[] stableControlEarlyBatch = new boolean[REPLY_BATCHES];
        double pooledTargetMax = 0.0;
        for (int batch = 0; batch < REPLY_BATCHES; batch++) {
            List<ReplyPair> group = new ArrayList<>();
            for (ReplyPair sample : samples) {
                if (sample != null && sample.batch == batch) group.add(sample);
            }
            if (group.size() != REPLY_PAIRS_PER_BATCH) {
                return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                        "回复提前可见检测的批次不完整",
                        "batch=" + batch + ", pairs=" + group.size()
                                + ", expected=" + REPLY_PAIRS_PER_BATCH);
            }
            int targetFirst = 0;
            int targetHits = 0;
            int controlHits = 0;
            double[] target = new double[group.size()];
            double[] control = new double[group.size()];
            double[] margin = new double[group.size()];
            for (int i = 0; i < group.size(); i++) {
                ReplyPair sample = group.get(i);
                if (!finiteNonNegative(sample.targetGapMillis)
                        || !finiteNonNegative(sample.controlGapMillis)) {
                    return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                            "回复提前可见检测包含无效计时样本",
                            "batch=" + batch + ", index=" + i + ", target="
                                    + sample.targetGapMillis + ", control="
                                    + sample.controlGapMillis);
                }
                if (sample.targetFirst) targetFirst++;
                target[i] = sample.targetGapMillis;
                control[i] = sample.controlGapMillis;
                margin[i] = target[i] - control[i];
                if (target[i] >= REPLY_EARLY_MILLIS) targetHits++;
                if (control[i] >= REPLY_EARLY_MILLIS) controlHits++;
                pooledTargetMax = Math.max(pooledTargetMax, target[i]);
            }
            if (targetFirst != REPLY_PAIRS_PER_BATCH / 2) {
                return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                        "回复提前可见检测没有保持顺序平衡",
                        "batch=" + batch + ", targetFirst=" + targetFirst);
            }
            double targetMedian = median(target);
            double controlMedian = median(control);
            double marginMedian = median(margin);
            strongBatch[batch] = targetHits >= REPLY_REQUIRED_TARGET_HITS
                    && controlHits <= REPLY_MAX_CONTROL_HITS
                    && targetMedian >= REPLY_EARLY_MILLIS
                    && marginMedian >= REPLY_MIN_PAIRED_MARGIN_MILLIS;
            stableControlEarlyBatch[batch] = controlHits >= REPLY_REQUIRED_TARGET_HITS
                    && controlMedian >= REPLY_EARLY_MILLIS;
            detail.append(String.format(Locale.US,
                    "batch%d{targetMedian=%.3fms, controlMedian=%.3fms, "
                            + "pairedMarginMedian=%.3fms, targetHits=%d/%d, "
                            + "controlHits=%d/%d, strong=%s, stableControlEarly=%s}",
                    batch + 1, targetMedian, controlMedian, marginMedian,
                    targetHits, group.size(), controlHits, group.size(), strongBatch[batch],
                    stableControlEarlyBatch[batch]));
            if (batch + 1 < REPLY_BATCHES) detail.append("; ");
        }
        if (stableControlEarlyBatch[0] && stableControlEarlyBatch[1]) {
            return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                    "普通密钥负对照也在两个批次稳定提前可见，当前环境不适合判定",
                    detail.toString());
        }
        if (strongBatch[0] && strongBatch[1]) {
            return new Decision(SilentProbeEvidence.Status.DETECTED,
                    String.format(Locale.US,
                            "带挑战密钥在生成返回前稳定提前可见，最大窗口 %.3f ms",
                            pooledTargetMax), detail.toString());
        }
        if (strongBatch[0] || strongBatch[1]) {
            return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                    "回复提前可见信号只在一个批次出现，无法稳定判定", detail.toString());
        }
        return new Decision(SilentProbeEvidence.Status.VERIFIED,
                "未发现带挑战生成特有的稳定回复延迟窗口", detail.toString());
    }

    static Decision readPath(KeystoreTimingStatistics.Result target,
                             KeystoreTimingStatistics.Result negativeControl) {
        if (target == null || negativeControl == null
                || !target.usable || !negativeControl.usable) {
            return new Decision(SilentProbeEvidence.Status.UNAVAILABLE,
                    "原始读取路径计时样本不完整",
                    "target=" + describe(target) + "; negativeControl="
                            + describe(negativeControl));
        }
        String detail = "target=" + describe(target) + "; negativeControl="
                + describe(negativeControl);
        if (target.noisy) {
            return new Decision(SilentProbeEvidence.Status.VERIFIED,
                    "原始读取路径检测已完成；读取差异未稳定复现，不作异常判定",
                    detail);
        }
        if (negativeControl.noisy || negativeControl.positive) {
            return new Decision(SilentProbeEvidence.Status.VERIFIED,
                    "原始读取路径检测已完成；普通密钥负对照存在波动，不作异常判定",
                    detail);
        }
        double targetRatio = Math.exp(target.medianLogRatio);
        double controlMagnitude = Math.abs(negativeControl.medianRelativePercent);
        boolean detected = target.positive
                && "TREATMENT_SLOWER".equals(target.direction)
                && targetRatio >= READ_MIN_RATIO
                && target.medianRelativePercent - controlMagnitude >= READ_MIN_MARGIN_PERCENT;
        if (detected) {
            return new Decision(SilentProbeEvidence.Status.DETECTED,
                    String.format(Locale.US,
                            "带挑战密钥的原始读取路径稳定慢于普通密钥 %.3f 倍",
                            targetRatio), detail);
        }
        return new Decision(SilentProbeEvidence.Status.VERIFIED,
                "未发现带挑战密钥特有的稳定原始读取延迟", detail);
    }

    private static String describe(KeystoreTimingStatistics.Result result) {
        if (result == null) return "null";
        return String.format(Locale.US,
                "{usable=%s, positive=%s, noisy=%s, pairs=%d, invalid=%d, "
                        + "treatmentMedian=%.6fms, controlMedian=%.6fms, "
                        + "differenceMedian=%.6fms, relative=%.3f%%, "
                        + "madLogRatio=%.6f, direction=%s, reason=%s}",
                result.usable, result.positive, result.noisy, result.validPairs,
                result.invalidPairs, result.medianTreatmentMillis,
                result.medianControlMillis, result.medianDifferenceMillis,
                result.medianRelativePercent, result.madLogRatio,
                result.direction, result.reason);
    }

    private static boolean finiteNonNegative(double value) {
        return Double.isFinite(value) && value >= 0.0;
    }

    private static double median(double[] values) {
        double[] copy = Arrays.copyOf(values, values.length);
        Arrays.sort(copy);
        int middle = copy.length / 2;
        if ((copy.length & 1) != 0) return copy[middle];
        return copy[middle - 1] + (copy[middle] - copy[middle - 1]) / 2.0;
    }
}

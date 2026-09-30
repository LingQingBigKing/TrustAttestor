package com.lingqing.trustattestor

enum class AssessmentOutcome {
    PASS,
    WARNING,
    BREACH,
    INCOMPLETE
}

data class TrustAssessment(
    val abnormalCount: Int,
    val warningCount: Int,
    val trustLabel: String,
    val summary: String,
    val outcome: AssessmentOutcome
)

/**
 * Keeps completed low-confidence observations separate from confirmed anomalies
 * and from probes that did not complete.
 */
internal object ScanAssessment {
    fun build(abnormalCount: Int, warningCount: Int, success: Boolean): TrustAssessment {
        val normalizedAbnormal = abnormalCount.coerceAtLeast(0)
        val normalizedWarning = warningCount.coerceAtLeast(0)
        val outcome = when {
            normalizedAbnormal > 0 -> AssessmentOutcome.BREACH
            !success -> AssessmentOutcome.INCOMPLETE
            normalizedWarning > 0 -> AssessmentOutcome.WARNING
            else -> AssessmentOutcome.PASS
        }
        val trustLabel = when (outcome) {
            AssessmentOutcome.PASS -> "未见异常"
            AssessmentOutcome.WARNING -> "需关注"
            AssessmentOutcome.BREACH -> "发现异常"
            AssessmentOutcome.INCOMPLETE -> "流程未完成"
        }
        val summary = when (outcome) {
            AssessmentOutcome.PASS -> "未发现异常项"
            AssessmentOutcome.WARNING -> "发现 $normalizedWarning 项需关注线索（未计入异常）"
            AssessmentOutcome.BREACH -> if (normalizedWarning > 0) {
                "共发现 $normalizedAbnormal 项异常，另有 $normalizedWarning 项需关注线索"
            } else {
                "共发现 $normalizedAbnormal 项异常"
            }
            AssessmentOutcome.INCOMPLETE -> "检测流程未正常完成"
        }
        return TrustAssessment(
            abnormalCount = normalizedAbnormal,
            warningCount = normalizedWarning,
            trustLabel = trustLabel,
            summary = summary,
            outcome = outcome
        )
    }
}

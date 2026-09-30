package com.lingqing.trustattestor

object ScanAssessmentWarningTest {
    @JvmStatic
    fun main(args: Array<String>) {
        var assertions = 0

        val warning = ScanAssessment.build(abnormalCount = 0, warningCount = 1, success = true)
        check(warning.outcome == AssessmentOutcome.WARNING)
        check(warning.abnormalCount == 0)
        check(warning.warningCount == 1)
        check(warning.trustLabel == "需关注")
        check(!warning.summary.contains("未发现异常"))
        assertions += 5

        val noFinding = ScanAssessment.build(
            abnormalCount = 0,
            warningCount = 0,
            success = true
        )
        check(noFinding.outcome == AssessmentOutcome.PASS)
        check(noFinding.warningCount == 0)
        assertions += 2

        val incomplete = ScanAssessment.build(abnormalCount = 0, warningCount = 1, success = false)
        check(incomplete.outcome == AssessmentOutcome.INCOMPLETE)
        check(incomplete.trustLabel == "流程未完成")
        assertions += 2

        val breach = ScanAssessment.build(abnormalCount = 2, warningCount = 1, success = true)
        check(breach.outcome == AssessmentOutcome.BREACH)
        check(breach.abnormalCount == 2)
        check(breach.warningCount == 1)
        check(breach.summary.contains("另有 1 项需关注线索"))
        assertions += 4

        println("ScanAssessmentWarningTest: $assertions assertions")
    }
}

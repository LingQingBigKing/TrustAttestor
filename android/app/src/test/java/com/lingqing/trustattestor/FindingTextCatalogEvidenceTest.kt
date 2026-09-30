package com.lingqing.trustattestor

/** Small host-side contract test for the release evidence allow-list and redaction. */
object FindingTextCatalogEvidenceTest {
    @JvmStatic
    fun main(args: Array<String>) {
        val id = "device.root.kernelsu.throne_hunt.unavailable"
        val evidence = FindingTextCatalog.formatThroneHuntUnavailableEvidence(
            stageKey = "watch_setup",
            errno = 13,
            counts = mapOf("baselineOpen" to 1L, "finalNamedNoise" to 4L, "secret" to 9L),
            english = false
        )
        check(evidence.contains("监视器初始化"))
        check(evidence.contains("errno=13"))
        check(evidence.contains("基线 open=1"))
        check(evidence.contains("最终 named-noise=4"))
        check(!evidence.contains("/data/app"))
        check(!evidence.contains("secret"))
        check(FindingTextCatalog.throneHuntUnavailableEvidence(
            "device.root.kernelsu.uapi",
            0,
            FindingStatus.UNAVAILABLE,
            "not-json",
            english = false
        ).isEmpty())
        check(FindingTextCatalog.shouldShowEvidenceInRelease(id))
        check(!FindingTextCatalog.shouldShowEvidenceInRelease("device.root.kernelsu.uapi"))
        println("FindingTextCatalogEvidenceTest: 9 assertions passed")
    }
}

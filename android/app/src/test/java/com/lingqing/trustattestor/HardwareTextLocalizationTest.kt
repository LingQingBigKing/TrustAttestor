package com.lingqing.trustattestor

/** Run main on the host JDK; no Android runtime or JUnit dependency is required. */
object HardwareTextLocalizationTest {
    private var assertions = 0

    @JvmStatic
    fun main(args: Array<String>) {
        certificateSummaryIsFullyEnglish()
        timingEvidenceIsFullyEnglish()
        unknownChineseProseIsNotLeaked()
        println("HardwareTextLocalizationTest: $assertions assertions passed")
    }

    private fun certificateSummaryIsFullyEnglish() {
        val cases = mapOf(
            "吊销数据：CACHED；时效：CACHED_NOT_REVALIDATED；可用：true" to
                "Revocation data: CACHED; freshness: CACHED_NOT_REVALIDATED; available: true",
            "吊销缓存时间：2026-09-19 09:45:55" to
                "Revocation cache time: 2026-09-19 09:45:55",
            "Attestation 版本：KeyMint 1.0" to "Attestation version: KeyMint 1.0",
            "安全级别：TEE / TEE" to "Security levels: TEE / TEE",
            "唯一 ID：(空)" to "Unique ID: Empty",
            "状态：正常" to "Status: Valid",
        )
        cases.forEach { (source, expected) ->
            check(
                HardwareTextLocalization.certificateLine(source, true) == expected,
                "certificate line: $source"
            )
        }
    }

    private fun timingEvidenceIsFullyEnglish() {
        val rawRead = HardwareTextLocalization.evidence(
            "H.raw_read_path_timing: DETECTED; 带挑战密钥的原始读取路径稳定慢于普通密钥 1.857 倍",
            true
        )
        check(!containsHan(rawRead), "raw-read evidence contains no Chinese")
        check(rawRead.contains("1.857x slower"), "raw-read ratio retained")

        val keystore = HardwareTextLocalization.evidence(
            "Keystore 加密时序出现稳定差异，但方向或独立负对照不支持 KeyMint contention 归因：AndroidKeyStore.ECDSA(load-vs-idle)",
            true
        )
        check(!containsHan(keystore), "Keystore timing evidence contains no Chinese")
        check(keystore.contains("AndroidKeyStore.ECDSA(load-vs-idle)"), "technical timing identity retained")
    }

    private fun unknownChineseProseIsNotLeaked() {
        val localized = HardwareTextLocalization.evidence(
            "无法本地化的诊断说明：ProviderException: failed",
            true
        )
        check(localized == "ProviderException: failed", "technical suffix retained")
        check(!containsHan(localized), "unknown Chinese prose omitted")
    }

    private fun containsHan(value: String): Boolean =
        value.any { it.code in 0x3400..0x9fff }

    private fun check(value: Boolean, description: String) {
        assertions++
        if (!value) throw AssertionError(description)
    }
}

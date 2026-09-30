package com.lingqing.trustattestor

/**
 * Localizes legacy, line-oriented hardware-attestation diagnostics.
 *
 * New findings use stable message keys, but the embedded DEX also emits a
 * detailed Chinese diagnostic stream for Debug builds. Keep that transport
 * language independent from the UI locale here instead of changing probe IDs
 * or parsing translated text in the detector.
 */
internal object HardwareTextLocalization {
    private val han = Regex("[\\u3400-\\u9fff]")

    fun certificateLine(source: String, english: Boolean): String {
        if (!english) return source
        var result = source
        certificateReplacements.forEach { (from, to) -> result = result.replace(from, to) }
        result = result
            .replace(Regex("(?<=Unique ID: )存在$"), "Present")
            .replace(Regex("(?<=Unique ID: )\\(空\\)$"), "Empty")
            .replace(Regex("(?<=Bootloader locked: )是$"), "Yes")
            .replace(Regex("(?<=Bootloader locked: )否$"), "No")
            .replace(Regex("(?<=Status: )签名校验失败$"), "Signature verification failed")
            .replace(Regex("(?<=Status: )已吊销$"), "Revoked")
            .replace(Regex("(?<=Status: )有效期异常$"), "Invalid validity period")
            .replace(Regex("(?<=Status: )吊销状态不可用$"), "Revocation status unavailable")
            .replace(Regex("(?<=Status: )正常$"), "Valid")
            .replace(Regex("(?<=Status: )未知$"), "Unknown")
        return result.takeUnless(::containsHan).orEmpty()
    }

    fun evidence(source: String, english: Boolean): String {
        if (!english || source.isBlank()) return source
        return source.lineSequence()
            .mapNotNull { localizeEvidenceLine(it) }
            .joinToString("\n")
    }

    private fun localizeEvidenceLine(source: String): String? {
        var result = source
            .replace(
                Regex("带挑战密钥的原始读取路径稳定慢于普通密钥 ([0-9.]+) 倍"),
                "The attested-key raw read path was consistently \$1x slower than the ordinary-key control"
            )
            .replace(
                "Keystore 加密时序出现稳定差异，但方向或独立负对照不支持 KeyMint contention 归因：",
                "Keystore cryptographic timing differed consistently, but its direction or the independent negative control did not support KeyMint contention attribution: "
            )
            .replace(
                "Keystore 加载时加密与元数据路径同时变慢，更像 Binder/调度或 Keystore2 整体竞争，无法归因到 KeyMint channel：",
                "Both cryptographic and metadata paths slowed under load, which is more consistent with Binder, scheduling, or general Keystore2 contention than a KeyMint channel: "
            )
            .replace(
                "Keystore 时序受批次、顺序或系统噪声影响，不作异常判定：",
                "Keystore timing was affected by batch, ordering, or system noise; no anomaly was determined: "
            )
            .replace(
                "未观察到稳定 channel contention，但有限数量并存 operation 已产生可观测资源压力；仅记录为 operation-state 佐证，不判定异常：",
                "No stable channel contention was observed, although a limited number of concurrent operations produced measurable resource pressure; this is operation-state evidence, not an anomaly: "
            )
            .replace(
                "Keystore 时序未观察到稳定的 KeyMint/HAL 竞争分离：",
                "Keystore timing showed no stable KeyMint/HAL contention separation: "
            )
            .replace(
                "Keystore/KeyMint 竞争时序可观测：独立负载使另一把普通 Keystore 私钥的 ECDSA 操作稳定变慢，且减去同条件元数据读取负对照后仍保留显著差异。",
                "Keystore/KeyMint contention timing was observable: an independent load consistently slowed ECDSA operations on another ordinary Keystore private key, with a material residual after subtracting the matching metadata-read control. "
            )
            .replace(
                "该结论只表示存在可观测的内部负载/串行化指纹，不表示私钥、PIN 或生物信息可被恢复；",
                "This only establishes an observable internal load or serialization fingerprint; it does not imply recovery of a private key, PIN, or biometric data; "
            )

        if (!containsHan(result)) return result

        // Do not leak transport-language prose into an English UI. Preserve a
        // machine-readable suffix (exception, ratios, batches, etc.) when one
        // exists; otherwise the already-localized finding title remains enough.
        val technical = result.substringAfterLast('：', "").trim()
        return technical.takeIf { it.isNotEmpty() && !containsHan(it) }
    }

    private fun containsHan(value: String): Boolean = han.containsMatchIn(value)

    private val certificateReplacements = listOf(
        "证书链与 Attestation 信息" to "Certificate chain and Attestation",
        "证书总数：" to "Certificates: ",
        "根证书来源：" to "Root source: ",
        "吊销数据：" to "Revocation data: ",
        "；时效：" to "; freshness: ",
        "；可用：" to "; available: ",
        "吊销缓存时间：" to "Revocation cache time: ",
        "RKP 认证实体：" to "RKP attested entity: ",
        "；来源证书：" to "; source certificate: ",
        "RKP 丢失状态记录：" to "RKP lost-device record: ",
        "证明类型：" to "Attestation type: ",
        "RKP 已签发证书数：" to "RKP certificates issued: ",
        "Attestation 版本：" to "Attestation version: ",
        "Keymaster / KeyMint：" to "Keymaster / KeyMint: ",
        "安全级别：" to "Security levels: ",
        "唯一 ID：" to "Unique ID: ",
        "引导加载程序锁定：" to "Bootloader locked: ",
        "设备锁定：" to "Device locked: ",
        "验证启动状态：" to "Verified boot state: ",
        "Verified Boot：" to "Verified Boot: ",
        "VBMeta Digest：" to "VBMeta digest: ",
        "证书链：" to "Certificate chain:",
        " 根证书" to " Root certificate",
        " 中间证书" to " Intermediate certificate",
        " 叶子证书" to " Leaf certificate",
        "使用者：" to "Subject: ",
        "签发者：" to "Issuer: ",
        "序列号：" to "Serial number: ",
        "状态：" to "Status: ",
        "日期政策：适用官方旧 factory 根过期豁免，签名和吊销检查仍有效" to
            "Date policy: the official legacy factory-root expiry exemption applies; signature and revocation checks remain in force",
        "不早于：" to "Not before: ",
        "不晚于：" to "Not after: ",
    )
}

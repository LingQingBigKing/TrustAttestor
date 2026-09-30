package com.lingqing.trustattestor.ui

import com.lingqing.trustattestor.ScanState
import com.lingqing.trustattestor.FindingStatus
import com.lingqing.trustattestor.NativeFinding
import java.util.Locale

internal enum class EvidenceStatus {
    DETECTED,
    VERIFIED,
    ACTIVE,
    PENDING,
    WARNING,
    UNAVAILABLE,
    INFO
}

internal data class EvidenceRow(
    val label: String,
    val status: EvidenceStatus,
    val evidence: String = "",
    val probeId: String? = null
)

/**
 * Parses the line-oriented evidence protocol emitted by native and DEX checks.
 * Detection is never inferred from arbitrary words such as "anomaly" or
 * "policy": those words also occur in explanations and successful probes.
 */
internal object EvidenceStatusParser {
    private val bracketedStatus = Regex(
        "\\[\\s*(DETECTED|INFO|VERIFIED|VALID|PASS(?:ED)?|ACTIVE|RUN(?:NING)?|PENDING|STANDBY|BREACH|FAIL(?:ED|URE)?|ERROR|CRITICAL|REVOKED|EXPIRED|WARN(?:ING)?|NOTICE|UNAVAILABLE|SKIPPED)\\s*]",
        RegexOption.IGNORE_CASE
    )
    private val statusField = Regex(
        "(?:^|[\\s,;|])(?:status|state|result|severity)\\s*[:=]\\s*" +
            "(DETECTED|INFO|VERIFIED|VALID|PASS(?:ED)?|ACTIVE|RUN(?:NING)?|PENDING|STANDBY|BREACH|FAIL(?:ED|URE)?|ERROR|CRITICAL|REVOKED|EXPIRED|WARN(?:ING)?|NOTICE|UNAVAILABLE|SKIPPED)(?=$|[\\s,;|])",
        RegexOption.IGNORE_CASE
    )
    private val trailingStatus = Regex(
        "(?:^|[\\s:：])(?:DETECTED|VERIFIED|VALID|PASS(?:ED)?|ACTIVE|RUN(?:NING)?|PENDING|STANDBY|BREACH|FAIL(?:ED|URE)?|ERROR|CRITICAL|REVOKED|EXPIRED|WARN(?:ING)?|NOTICE|UNAVAILABLE|SKIPPED)\\s*$",
        RegexOption.IGNORE_CASE
    )
    private val explicitFindingPrefix = Regex(
        "^(?:发现|检测到|命中|存在)\\s*",
        RegexOption.IGNORE_CASE
    )
    private val negativeMarkers = listOf(
        "未发现", "没有发现", "未检测到", "没有检测到", "未命中", "未见异常",
        "无异常", "不存在异常", "未新增", "状态正常", "校验成功", "检查通过",
        "未发现明显异常", "not detected", "none detected", "no anomaly",
        "no anomalies", "no issue", "no issues", "none found", "all clear"
    )

    fun parseRows(detail: String, state: ScanState): List<EvidenceRow> {
        var findingSection = false
        val rows = detail.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { source ->
                val status = classify(source, state, findingSection)
                sectionHeader(source)?.let { findingSection = it }
                EvidenceRow(normalizeLabel(source), status)
            }
            .toList()

        return rows.ifEmpty {
            listOf(EvidenceRow("暂无原始证据", fallbackStatus(state)))
        }
    }

    fun parseFindings(findings: List<NativeFinding>): List<EvidenceRow> {
        return findings.map { finding ->
            EvidenceRow(
                label = finding.title,
                status = when (finding.status) {
                    FindingStatus.CLEAN -> EvidenceStatus.VERIFIED
                    FindingStatus.DETECTED -> EvidenceStatus.DETECTED
                    FindingStatus.WARNING -> EvidenceStatus.WARNING
                    FindingStatus.UNAVAILABLE -> EvidenceStatus.UNAVAILABLE
                },
                evidence = finding.evidence,
                probeId = finding.probeId
            )
        }
    }

    /** Classify a line. Section context is explicit and never keyword inferred. */
    fun classify(
        source: String,
        state: ScanState,
        findingSection: Boolean = false
    ): EvidenceStatus {
        val trimmed = source.trim()
        explicitStatus(trimmed)?.let { return it }

        // Legacy native issue lines use an anchored "发现/检测到/命中/存在"
        // prefix. Matching only at the beginning avoids prose false positives.
        if (explicitFindingPrefix.containsMatchIn(trimmed)) return EvidenceStatus.DETECTED
        if (isNegativeStatement(trimmed)) return EvidenceStatus.VERIFIED
        if (findingSection && isBullet(trimmed)) return EvidenceStatus.DETECTED

        // A failed native step's bullet list is its structured finding payload.
        // Non-bullet failure descriptions remain INFO rather than being promoted
        // because they often describe an unavailable or skipped probe.
        if (state == ScanState.FAIL && isBullet(trimmed)) return EvidenceStatus.DETECTED
        return fallbackStatus(state)
    }

    fun isFinding(source: String, state: ScanState, findingSection: Boolean): Boolean {
        return classify(source, state, findingSection) == EvidenceStatus.DETECTED
    }

    fun isNegativeStatement(source: String): Boolean {
        val normalized = source
            .trim()
            .trimStart('\u2022', '\u203a', '*', '-', ' ', '\t')
            .lowercase(Locale.ROOT)
        return negativeMarkers.any { marker -> normalized.contains(marker.lowercase(Locale.ROOT)) }
    }

    private fun explicitStatus(source: String): EvidenceStatus? {
        val token = bracketedStatus.find(source)?.groupValues?.getOrNull(1)
            ?: statusField.find(source)?.groupValues?.getOrNull(1)
            ?: trailingStatus.find(source)?.value?.trim()
                ?.uppercase(Locale.ROOT)
                ?.takeIf { it in knownStatusTokens }
            ?: return null
        return statusForToken(token)
    }

    private fun statusForToken(token: String): EvidenceStatus = when (token.uppercase(Locale.ROOT)) {
        "DETECTED", "BREACH", "FAIL", "FAILED", "FAILURE", "ERROR", "CRITICAL", "REVOKED", "EXPIRED" -> EvidenceStatus.DETECTED
        "VERIFIED", "VALID", "PASS", "PASSED" -> EvidenceStatus.VERIFIED
        "ACTIVE", "RUN", "RUNNING" -> EvidenceStatus.ACTIVE
        "WARN", "WARNING", "NOTICE" -> EvidenceStatus.WARNING
        "UNAVAILABLE" -> EvidenceStatus.UNAVAILABLE
        "PENDING", "STANDBY", "SKIPPED" -> EvidenceStatus.PENDING
        else -> EvidenceStatus.INFO
    }

    private fun normalizeLabel(source: String): String {
        var label = source
            .trim()
            .trimStart('\u2022', '\u203a', '*', '-', ' ', '\t')
            .replace(bracketedStatus, "")
            .replace(statusField, "")
            .replace(trailingStatus, "")
            .trim()

        label = label
            .replace(explicitFindingPrefix, "")
            .replace(Regex("^(?:检测项|探针)\\s*[:：]\\s*"), "")
            .trim()
        return label.ifBlank { "暂无原始证据" }
    }

    private fun sectionHeader(source: String): Boolean? {
        val normalized = source.trim().trimEnd(':', '：').uppercase(Locale.ROOT)
        return when {
            normalized == "HARDWARE FINDINGS" ||
                normalized == "主动探针证据" ||
                normalized == "FORENSIC FINDINGS" -> true
            normalized == "CERTIFICATE CHAIN" ||
                normalized == "证书链与 ATTESTATION 信息" ||
                normalized == "综合结论" ||
                normalized == "证明安全等级" -> false
            else -> null
        }
    }

    private fun isBullet(source: String): Boolean {
        return source.startsWith('\u2022') || source.startsWith('\u203a') ||
            source.startsWith('*') || source.startsWith('-')
    }

    private fun fallbackStatus(state: ScanState): EvidenceStatus = when (state) {
        ScanState.PASS -> EvidenceStatus.VERIFIED
        ScanState.WARNING -> EvidenceStatus.WARNING
        ScanState.RUNNING -> EvidenceStatus.ACTIVE
        ScanState.IDLE -> EvidenceStatus.PENDING
        ScanState.FAIL -> EvidenceStatus.INFO
    }

    private val knownStatusTokens = setOf(
        "DETECTED", "INFO", "VERIFIED", "VALID", "PASS", "PASSED", "ACTIVE",
        "RUN", "RUNNING", "PENDING", "STANDBY", "BREACH", "FAIL", "FAILED",
        "FAILURE", "ERROR", "CRITICAL", "REVOKED", "EXPIRED", "WARN", "WARNING", "NOTICE", "UNAVAILABLE", "SKIPPED"
    )
}

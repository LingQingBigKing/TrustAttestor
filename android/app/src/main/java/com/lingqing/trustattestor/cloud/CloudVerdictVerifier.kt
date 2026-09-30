package com.lingqing.trustattestor.cloud

import com.lingqing.trustattestor.FindingSeverity
import com.lingqing.trustattestor.FindingStatus
import com.lingqing.trustattestor.NativeFinding
import com.lingqing.trustattestor.TrustAttestorNativeBridge
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets

data class VerifiedCloudVerdict(
    val verdictId: String,
    val finding: NativeFinding,
    val findings: List<NativeFinding>,
    val keyId: String
)

object CloudVerdictVerifier {
    const val VERDICT_SCHEMA = "trustattestor.verdict/v1"
    private const val SIGNATURE_ALGORITHM = "ECDSA_P256_SHA256"

    private data class ServerPresentation(
        val titleZh: String,
        val titleEn: String,
        val evidenceZh: String,
        val evidenceEn: String
    )

    fun verify(
        payload: String,
        challenge: CloudChallenge,
        trustedPublicKey: String
    ): VerifiedCloudVerdict {
        require(trustedPublicKey.isNotBlank()) { "云端裁决公钥未配置" }
        val response = JSONObject(payload)
        require(response.getString("schema") == VERDICT_SCHEMA) { "云端裁决协议不受支持" }
        val verdict = response.getJSONObject("verdict")
        require(verdict.getString("challengeId") == challenge.challengeId) { "云端裁决挑战不匹配" }

        val signature = response.getJSONObject("signature")
        require(signature.getString("algorithm") == SIGNATURE_ALGORITHM) { "云端签名算法不受支持" }
        val keyId = signature.optString("keyId").trim()
        if (challenge.serverKeyId.isNotEmpty()) {
            require(keyId == challenge.serverKeyId) { "云端裁决密钥标识不匹配" }
        }
        val signatureBytes = CloudRequestCodec.decodeBase64(signature.getString("value"))
        val publicKeyBytes = CloudRequestCodec.decodeBase64(trustedPublicKey)
        val signedPayload = CloudRequestCodec.canonicalize(verdict)
            .toByteArray(StandardCharsets.UTF_8)
        require(
            TrustAttestorNativeBridge.verifyCloudVerdict(
                signedPayload,
                signatureBytes,
                publicKeyBytes
            )
        ) { "云端响应签名验证失败" }

        val aggregateFinding = decodeFinding(verdict)
        val detailedFindings = verdict.optJSONArray("findings")?.decodeFindings()
            ?.takeIf { it.isNotEmpty() }
            ?: listOf(aggregateFinding)
        require(aggregateCoversDetails(aggregateFinding.status, detailedFindings)) {
            "云端聚合状态与明细不一致"
        }
        val verdictId = verdict.getString("verdictId").trim()
        require(verdictId.length in 8..MAX_IDENTIFIER_LENGTH) { "云端 verdictId 无效" }
        require(keyId.length <= MAX_IDENTIFIER_LENGTH) { "云端密钥标识过长" }

        return VerifiedCloudVerdict(
            verdictId = verdictId,
            keyId = keyId,
            finding = aggregateFinding,
            findings = detailedFindings
        )
    }

    private fun decodeFinding(json: JSONObject): NativeFinding {
        val status = FindingStatus.valueOf(json.getString("status").uppercase())
        val severity = runCatching {
            FindingSeverity.valueOf(json.optString("severity", "INFO").uppercase())
        }.getOrDefault(if (status == FindingStatus.DETECTED) FindingSeverity.HIGH else FindingSeverity.INFO)
        val presentation = decodePresentation(json)
        return NativeFinding(
            probeId = json.optString("probeId", "cloud.attestation.verdict").trim()
                .ifBlank { "cloud.attestation.verdict" }
                .take(MAX_IDENTIFIER_LENGTH),
            layer = 3,
            status = status,
            severity = severity,
            title = json.optString("title", "云端证明").trim().ifBlank { "云端证明" }
                .take(MAX_TITLE_LENGTH),
            evidence = json.optString("evidence", json.optString("reason")).trim()
                .take(MAX_EVIDENCE_LENGTH),
            serverTitleZh = presentation?.titleZh.orEmpty(),
            serverTitleEn = presentation?.titleEn.orEmpty(),
            serverEvidenceZh = presentation?.evidenceZh.orEmpty(),
            serverEvidenceEn = presentation?.evidenceEn.orEmpty()
        )
    }

    private fun decodePresentation(json: JSONObject): ServerPresentation? {
        val presentation = json.optJSONObject("presentation") ?: return null
        require(presentation.optString("schema") == PRESENTATION_SCHEMA) {
            "云端 Finding 文案协议不受支持"
        }
        val zh = presentation.getJSONObject("zh-CN")
        val en = presentation.getJSONObject("en-US")
        return ServerPresentation(
            titleZh = localizedTitle(zh, "zh-CN"),
            titleEn = localizedTitle(en, "en-US"),
            evidenceZh = localizedEvidence(zh),
            evidenceEn = localizedEvidence(en)
        )
    }

    private fun localizedTitle(json: JSONObject, locale: String): String {
        val title = json.getString("title").trim()
        require(title.isNotEmpty() && title.length <= MAX_TITLE_LENGTH &&
            title.none { it == '\n' || it == '\r' || it == '\u0000' }) {
            "云端 $locale Finding 标题无效"
        }
        return title
    }

    private fun localizedEvidence(json: JSONObject): String {
        val evidence = json.optString("evidence").trim()
        require(evidence.length <= MAX_EVIDENCE_LENGTH && '\u0000' !in evidence) {
            "云端 Finding 证据过长或包含无效字符"
        }
        return evidence
    }

    private fun JSONArray.decodeFindings(): List<NativeFinding> {
        require(length() in 1..MAX_FINDINGS) { "云端 Finding 数量无效" }
        return (0 until length()).map { index -> decodeFinding(getJSONObject(index)) }
    }

    private fun aggregateCoversDetails(
        aggregateStatus: FindingStatus,
        findings: List<NativeFinding>
    ): Boolean {
        val aggregateRank = aggregateStatus.aggregateRank()
        return findings.all { aggregateRank >= it.status.aggregateRank() }
    }

    private fun FindingStatus.aggregateRank(): Int = when (this) {
        FindingStatus.UNAVAILABLE -> 0
        FindingStatus.CLEAN -> 1
        FindingStatus.WARNING -> 2
        FindingStatus.DETECTED -> 3
    }

    private const val MAX_IDENTIFIER_LENGTH = 128
    private const val MAX_TITLE_LENGTH = 128
    private const val MAX_EVIDENCE_LENGTH = 4096
    private const val MAX_FINDINGS = 32
    private const val PRESENTATION_SCHEMA = "trustattestor.finding-presentation/v1"
}

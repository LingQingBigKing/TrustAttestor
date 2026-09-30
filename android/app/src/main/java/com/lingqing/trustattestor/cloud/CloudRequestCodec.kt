package com.lingqing.trustattestor.cloud

import android.content.Context
import android.util.Base64
import com.lingqing.trustattestor.BuildConfig
import com.lingqing.trustattestor.ForensicReportCodec
import com.lingqing.trustattestor.TrustAttestorNativeBridge
import com.lingqing.trustattestor.UiState
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant

data class CloudChallenge(
    val challengeId: String,
    val nonce: String,
    val nonceBytes: ByteArray,
    val issuedAt: String,
    val expiresAt: String,
    val rulesetVersion: Long,
    val serverKeyId: String
)

data class PreparedCloudRequest(
    val body: String,
    val canonicalCore: String,
    val coreDigest: ByteArray
)

/** Stable request serialization shared with the Worker verifier. */
object CloudRequestCodec {
    const val CHALLENGE_SCHEMA = "trustattestor.challenge/v1"
    const val REQUEST_SCHEMA = "trustattestor.cloud-request/v1"

    fun decodeChallenge(payload: String): CloudChallenge {
        val json = JSONObject(payload)
        require(json.getString("schema") == CHALLENGE_SCHEMA) { "云端挑战协议不受支持" }
        val challengeId = json.getString("challengeId").trim()
        val nonce = json.getString("nonce").trim()
        val issuedAt = json.getString("issuedAt").trim()
        val expiresAt = json.getString("expiresAt").trim()
        require(challengeId.length in 8..128) { "云端 challengeId 无效" }
        val nonceBytes = decodeBase64(nonce)
        require(nonceBytes.size in 16..64) { "云端 nonce 长度无效" }
        val issued = Instant.parse(issuedAt)
        val expires = Instant.parse(expiresAt)
        val now = Instant.now()
        require(!issued.isAfter(now.plusSeconds(MAX_CLOCK_SKEW_SECONDS))) { "云端挑战签发时间无效" }
        require(expires.isAfter(now) && expires.isAfter(issued)) { "云端挑战已过期" }
        require(Duration.between(issued, expires) <= Duration.ofMinutes(MAX_CHALLENGE_TTL_MINUTES)) {
            "云端挑战有效期过长"
        }
        return CloudChallenge(
            challengeId = challengeId,
            nonce = nonce,
            nonceBytes = nonceBytes,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            rulesetVersion = json.optLong("rulesetVersion", 0L),
            serverKeyId = json.optString("serverKeyId").trim()
        )
    }

    fun prepare(context: Context, state: UiState, challenge: CloudChallenge): PreparedCloudRequest {
        val deviceEvidence = TrustAttestorNativeBridge.collectCloudDeviceEvidence()
            ?: error("Native 设备证据采集不可用")
        val localReport = ForensicReportCodec.toJson(
            context = context,
            state = state,
            includeCloudLayer = false,
            generatedAt = challenge.issuedAt
        )
        val core = JSONObject().apply {
            put("schema", REQUEST_SCHEMA)
            put("challengeId", challenge.challengeId)
            put("nonce", challenge.nonce)
            put("challengeExpiresAt", challenge.expiresAt)
            put("rulesetVersion", challenge.rulesetVersion)
            if (BuildConfig.DEBUG) put("debug", true)
            put("localReport", localReport)
            put("nativeDeviceEvidence", JSONObject(deviceEvidence))
        }
        val canonicalCore = canonicalize(core)
        val digest = TrustAttestorNativeBridge.sha256(
            canonicalCore.toByteArray(StandardCharsets.UTF_8)
        )
        require(digest.size == 32) { "Native SHA-256 结果无效" }
        val proof = TrustAttestorNativeBridge.createCloudAttestation(
            context.applicationContext,
            challenge.nonceBytes,
            digest
        ) ?: error("Native Key Attestation 证据不可用")
        val proofJson = JSONObject(proof)
        require(proofJson.optString("schema") == "trustattestor.native-cloud-proof/v1") {
            "Native 云证明协议无效"
        }
        val body = JSONObject().apply {
            put("schema", REQUEST_SCHEMA)
            // Transmit the exact text whose digest was signed. Reconstructing the
            // text from parsed JSON is not stable across Java and JavaScript for
            // values such as a whole-valued Double (1.0 versus 1).
            put("canonicalCore", canonicalCore)
            put("proof", proofJson)
        }.toString()
        return PreparedCloudRequest(body, canonicalCore, digest)
    }

    /**
     * Canonical JSON profile: object keys are lexicographically sorted, arrays keep
     * their order, and strings use JSON escaping. The Worker must use the same rules.
     */
    fun canonicalize(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(
            prefix = "{",
            postfix = "}",
            separator = ","
        ) { key -> JSONObject.quote(key) + ":" + canonicalize(value.get(key)) }
        is JSONArray -> (0 until value.length()).joinToString(
            prefix = "[",
            postfix = "]",
            separator = ","
        ) { index -> canonicalize(value.get(index)) }
        is String -> JSONObject.quote(value)
        is Boolean -> value.toString()
        is Number -> {
            val text = value.toString()
            require(text != "NaN" && text != "Infinity" && text != "-Infinity") {
                "非有限数值不能进入云端签名载荷"
            }
            text
        }
        else -> JSONObject.quote(value.toString())
    }

    internal fun decodeBase64(value: String): ByteArray {
        val normalized = value
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .filterNot(Char::isWhitespace)
        require(normalized.isNotEmpty()) { "Base64 数据为空" }
        val hasUrlAlphabet = normalized.any { it == '-' || it == '_' }
        val hasStandardAlphabet = normalized.any { it == '+' || it == '/' }
        require(!(hasUrlAlphabet && hasStandardAlphabet)) { "Base64 字母表混用" }
        require(normalized.matches(Regex("^[A-Za-z0-9_+/=-]+$"))) { "Base64 数据无效" }

        val alphabetFlag = if (hasUrlAlphabet) Base64.URL_SAFE else Base64.DEFAULT
        val decoded = runCatching {
            Base64.decode(normalized, alphabetFlag or Base64.NO_WRAP)
        }.getOrElse { throw IllegalArgumentException("Base64 数据无效", it) }
        val canonical = Base64.encodeToString(
            decoded,
            alphabetFlag or Base64.NO_WRAP or Base64.NO_PADDING
        )
        require(canonical == normalized.trimEnd('=')) { "Base64 数据不是规范编码" }
        return decoded
    }

    private const val MAX_CLOCK_SKEW_SECONDS = 60L
    private const val MAX_CHALLENGE_TTL_MINUTES = 10L
}

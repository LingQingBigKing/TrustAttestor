package com.lingqing.trustattestor.cloud

import android.content.Context
import android.os.Build
import com.lingqing.trustattestor.FindingSeverity
import com.lingqing.trustattestor.FindingStatus
import com.lingqing.trustattestor.NativeFinding
import com.lingqing.trustattestor.UiState
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

data class CloudAttestationResult(
    val finding: NativeFinding,
    val findings: List<NativeFinding> = listOf(finding),
    val signatureVerified: Boolean,
    val verdictId: String = "",
    val keyId: String = ""
) {
    init {
        require(findings.none { it.status == FindingStatus.DETECTED } || signatureVerified) {
            "未验签的云端结果不能标记为 DETECTED"
        }
    }
}

class CloudAttestationClient(
    private val endpoint: String,
    private val trustedPublicKey: String,
    private val connectTimeoutMillis: Int = 10_000,
    private val readTimeoutMillis: Int = 15_000
) {
    fun attest(context: Context, state: UiState): CloudAttestationResult {
        if (endpoint.isBlank()) return unavailable("云端服务地址未配置")
        if (trustedPublicKey.isBlank()) return unavailable("云端裁决公钥未配置")
        val baseUrl = endpoint.trim().trimEnd('/')
        val parsed = runCatching { URL(baseUrl) }.getOrElse {
            return unavailable("云端服务地址无效")
        }
        if (!parsed.protocol.equals("https", ignoreCase = true)) {
            return unavailable("云端服务必须使用 HTTPS")
        }

        return runCatching {
            val challengeRequest = JSONObject().apply {
                put("schema", "trustattestor.challenge-request/v1")
                put("package", context.packageName)
                put("sdk", Build.VERSION.SDK_INT)
            }.toString()
            val challenge = CloudRequestCodec.decodeChallenge(
                postJson("$baseUrl/v1/challenges", challengeRequest)
            )
            val prepared = CloudRequestCodec.prepare(context, state, challenge)
            val response = postJson("$baseUrl/v1/attest", prepared.body)
            val verified = CloudVerdictVerifier.verify(response, challenge, trustedPublicKey)
            CloudAttestationResult(
                finding = verified.finding,
                findings = verified.findings,
                signatureVerified = true,
                verdictId = verified.verdictId,
                keyId = verified.keyId
            )
        }.getOrElse { error ->
            unavailable(error.message?.take(240) ?: "云端检测请求失败")
        }
    }

    private fun postJson(url: String, body: String): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        return try {
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.doOutput = true
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.setRequestProperty("Cache-Control", "no-store")
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            connection.setFixedLengthStreamingMode(bytes.size)
            connection.outputStream.use { it.write(bytes) }

            val code = connection.responseCode
            require(code in 200..299) { "云端服务返回 HTTP $code" }
            val contentType = connection.contentType.orEmpty().lowercase()
            require(contentType.startsWith("application/json")) { "云端返回了非 JSON 数据" }
            readLimited(connection, MAX_RESPONSE_BYTES)
        } finally {
            connection.disconnect()
        }
    }

    private fun readLimited(connection: HttpURLConnection, limit: Int): String {
        val declaredLength = connection.contentLengthLong
        require(declaredLength < 0 || declaredLength <= limit) { "云端响应超过大小限制" }
        val output = ByteArrayOutputStream()
        connection.inputStream.use { input ->
            val buffer = ByteArray(8 * 1024)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                require(total <= limit) { "云端响应超过大小限制" }
                output.write(buffer, 0, count)
            }
        }
        return output.toString(StandardCharsets.UTF_8.name())
    }

    private fun unavailable(reason: String): CloudAttestationResult = CloudAttestationResult(
        finding = NativeFinding(
            probeId = "cloud.attestation.transport",
            layer = 3,
            status = FindingStatus.UNAVAILABLE,
            severity = FindingSeverity.INFO,
            title = "云端证明不可用",
            evidence = reason
        ),
        signatureVerified = false
    )

    private companion object {
        const val MAX_RESPONSE_BYTES = 512 * 1024
    }
}

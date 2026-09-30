package com.lingqing.trustattestor

import android.content.Context
import org.json.JSONObject
import java.util.Locale

object TrustAttestorNativeBridge {
    init {
        System.loadLibrary("TrustAttestor")
    }

    fun run(context: Context, callback: NativeScanCallback) {
        AppZygoteProbe.prepare(context.applicationContext)
        ReadProcProbe.prepare(context.applicationContext)
        try {
            nativeRun(context.applicationContext, callback)
        } finally {
            ReadProcProbe.release()
            AppZygoteProbe.release()
        }
    }

    fun collectCloudDeviceEvidence(): String? = runCatching {
        nativeCollectCloudDeviceEvidence()
    }.getOrNull()?.trim()?.takeIf { it.isNotEmpty() }

    fun createCloudAttestation(
        context: Context,
        challenge: ByteArray,
        payloadDigest: ByteArray
    ): String? = runCatching {
        require(challenge.isNotEmpty() && payloadDigest.size == 32)
        nativeCreateCloudAttestation(context.applicationContext, challenge, payloadDigest)
    }.getOrNull()?.trim()?.takeIf { it.isNotEmpty() }

    fun sha256(payload: ByteArray): ByteArray = nativeSha256(payload)

    fun verifyCloudVerdict(
        payload: ByteArray,
        signature: ByteArray,
        publicKey: ByteArray
    ): Boolean = runCatching {
        nativeVerifyCloudVerdict(payload, signature, publicKey)
    }.getOrDefault(false)

    private external fun nativeRun(context: Context, callback: NativeScanCallback)
    private external fun nativeCollectCloudDeviceEvidence(): String
    private external fun nativeCreateCloudAttestation(
        context: Context,
        challenge: ByteArray,
        payloadDigest: ByteArray
    ): String
    private external fun nativeSha256(payload: ByteArray): ByteArray
    private external fun nativeVerifyCloudVerdict(
        payload: ByteArray,
        signature: ByteArray,
        publicKey: ByteArray
    ): Boolean
}

fun interface NativeScanCallback {
    fun onNativeEvent(type: Int, stepIndex: Int, value: Int, text: String)

    companion object {
        const val STEP_STARTED = 1
        const val STEP_FINISHED = 2
        const val PROGRESS = 3
        const val FINISHED = 4
        const val FAILED = 5
        const val FINDING = 6
    }
}

enum class FindingStatus { CLEAN, DETECTED, WARNING, UNAVAILABLE }

enum class FindingSeverity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

data class NativeFinding(
    val probeId: String,
    val layer: Int,
    val status: FindingStatus,
    val severity: FindingSeverity,
    val title: String,
    val evidence: String,
    /** Stable native/server key used to re-render the finding after a locale change. */
    val messageKey: String = probeId,
    /** Machine-readable parameters returned by native finding/v2. */
    val dataJson: String = "{}",
    /** Bilingual UI copy carried inside a successfully verified cloud verdict. */
    val serverTitleZh: String = "",
    val serverTitleEn: String = "",
    val serverEvidenceZh: String = "",
    val serverEvidenceEn: String = ""
)

object NativeFindingCodec {
    const val SCHEMA = "trustattestor.finding/v2"
    const val REPORT_SCHEMA = "trustattestor.finding/v1"

    fun decode(context: Context, payload: String): NativeFinding? = runCatching {
        val json = JSONObject(payload)
        require(json.optString("schema") == SCHEMA)
        val probeId = json.getString("probeId").trim()
        val layer = json.getInt("layer")
        require(probeId.isNotEmpty() && layer in 0..MainViewModel.CLOUD_LAYER)
        val finding = NativeFinding(
            probeId = probeId,
            layer = layer,
            status = FindingStatus.valueOf(json.getString("status").uppercase(Locale.ROOT)),
            severity = FindingSeverity.valueOf(json.getString("severity").uppercase(Locale.ROOT)),
            title = "",
            evidence = "",
            messageKey = probeId,
            dataJson = json.optJSONObject("data")?.toString() ?: "{}"
        )
        FindingTextCatalog.localize(context, finding)
    }.getOrNull()
}

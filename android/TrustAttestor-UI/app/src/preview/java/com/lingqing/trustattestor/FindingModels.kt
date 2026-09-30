package com.lingqing.trustattestor

import android.content.Context
import org.json.JSONObject
import java.util.Locale

// Data/codec contract only. No native bridge or native loading.
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

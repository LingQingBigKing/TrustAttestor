package com.lingqing.trustattestor

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Shared serializer used by both the user export flow and cloud attestation. */
object ForensicReportCodec {
    const val SCHEMA = "trustattestor.forensic-report/v1"

    fun encode(
        context: Context,
        state: UiState,
        pretty: Boolean = true,
        includeCloudLayer: Boolean = true,
        generatedAt: String = isoTimestamp()
    ): String {
        val report = toJson(context, state, includeCloudLayer, generatedAt)
        return if (pretty) report.toString(2) else report.toString()
    }

    fun toJson(
        context: Context,
        state: UiState,
        includeCloudLayer: Boolean = true,
        generatedAt: String = isoTimestamp()
    ): JSONObject {
        val appContext = context.applicationContext
        val packageInfo = runCatching {
            appContext.packageManager.getPackageInfo(appContext.packageName, 0)
        }.getOrNull()
        val versionCode = packageInfo?.let {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) it.longVersionCode
            else @Suppress("DEPRECATION") it.versionCode.toLong()
        } ?: -1L

        val telemetry = JSONObject()
        val telemetryLabels = telemetryLabels(context)
        state.deviceInfo.forEachIndexed { index, item ->
            telemetry.put(telemetryLabels.getOrElse(index) { item.label }, item.value)
        }

        val layers = JSONArray()
        state.steps
            .asSequence()
            .filter { includeCloudLayer || it.index <= MainViewModel.LOCAL_LAST_LAYER }
            .forEach { step -> layers.put(stepToJson(context, step)) }

        return JSONObject().apply {
            put("schema", SCHEMA)
            put("generatedAt", generatedAt)
            put("application", JSONObject().apply {
                put("package", appContext.packageName)
                put("version", packageInfo?.versionName ?: "--")
                put("versionCode", versionCode)
                put(
                    "channel",
                    if (appContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                        "DEBUG"
                    } else {
                        "RELEASE"
                    }
                )
            })
            put("attestation", JSONObject().apply {
                put("status", state.summaryStatus.reportStatus())
                put("abnormalCount", state.abnormalCount)
                put("elapsedSeconds", state.elapsedDurationText.toDoubleOrNull() ?: 0.0)
                put("overallProgressPermille", state.overallProgressPermille)
                put("summary", localizedSummary(context, state))
            })
            put("telemetry", telemetry)
            put("layers", layers)
        }
    }

    private fun stepToJson(context: Context, step: StepUi): JSONObject = JSONObject().apply {
        val localizedFindings = step.findings.map { finding ->
            FindingTextCatalog.localize(context, finding)
        }
        put("id", "L${step.index}")
        put("title", FindingTextCatalog.layerTitle(context, step.index))
        put("status", step.cloudState?.badge ?: step.state.reportStatus())
        put("progressPermille", step.progressPermille)
        put("durationMillis", step.durationMillis)
        put("expanded", step.expanded)
        put("evidence", localizedStepEvidence(context, step, localizedFindings))
        put("findings", JSONArray().apply {
            localizedFindings.forEach { finding ->
                put(JSONObject().apply {
                    // Keep the exported/cloud report compatible with finding/v1.
                    // The native callback itself uses the data-only finding/v2 wire format.
                    put("schema", NativeFindingCodec.REPORT_SCHEMA)
                    put("probeId", finding.probeId)
                    put("layer", finding.layer)
                    put("status", finding.status.name)
                    put("severity", finding.severity.name)
                    put("title", finding.title)
                    put("evidence", localizedFindingEvidence(context, finding.evidence))
                })
            }
        })
    }

    private fun localizedSummary(context: Context, state: UiState): String {
        val elapsed = "${state.elapsedDurationText.toDoubleOrNull() ?: 0.0}s"
        return when (state.summaryStatus) {
            ScanState.IDLE -> context.getString(R.string.home_summary_idle)
            ScanState.RUNNING -> context.getString(R.string.home_summary_running, elapsed)
            ScanState.PASS -> context.getString(R.string.home_summary_pass, elapsed)
            ScanState.FAIL -> if (state.abnormalCount > 0) {
                context.getString(R.string.home_summary_fail, state.abnormalCount, elapsed)
            } else {
                context.getString(R.string.home_summary_incomplete, elapsed)
            }
        }
    }

    private fun localizedStepEvidence(
        context: Context,
        step: StepUi,
        findings: List<NativeFinding>
    ): String {
        if (findings.isNotEmpty()) {
            return findings.joinToString("\n") { finding ->
                val evidence = localizedFindingEvidence(context, finding.evidence)
                if (evidence.isBlank()) finding.title else "${finding.title}\n$evidence"
            }
        }
        if (step.index == MainViewModel.CLOUD_LAYER) {
            val res = when (step.cloudState) {
                CloudAttestationState.DISABLED -> R.string.step_cloud_disabled
                CloudAttestationState.WAITING -> R.string.step_cloud_waiting
                CloudAttestationState.SKIPPED -> R.string.step_cloud_skipped
                CloudAttestationState.VERIFYING -> R.string.step_cloud_verifying
                CloudAttestationState.PASSED -> R.string.step_cloud_pass
                CloudAttestationState.BREACH,
                CloudAttestationState.WARNING,
                CloudAttestationState.UNAVAILABLE -> R.string.step_cloud_fail
                null -> R.string.step_cloud_disabled
            }
            return context.getString(res)
        }
        return when (step.state) {
            ScanState.PASS -> FindingTextCatalog.cleanSummary(context, step.index)
            ScanState.RUNNING -> FindingTextCatalog.eventText(
                context,
                when (step.index) {
                    MainViewModel.DEVICE_LAYER -> "progress.device.environment"
                    MainViewModel.SYSTEM_LAYER -> "progress.system.collect"
                    else -> "progress.hardware.active_probes"
                }
            )
            ScanState.IDLE -> context.getString(R.string.home_summary_idle)
            ScanState.FAIL -> if (isEnglish(context)) {
                "The check did not complete"
            } else {
                "检测项未完整完成"
            }
        }
    }

    private fun localizedFindingEvidence(context: Context, evidence: String): String {
        if (!BuildConfig.DEBUG || evidence.isBlank()) return ""
        if (isEnglish(context) && evidence.any { it.code in 0x4e00..0x9fff }) return ""
        return evidence
    }

    private fun telemetryLabels(context: Context): List<String> = if (isEnglish(context)) {
        listOf("Brand", "Model", "Android", "Security patch", "Supported ABIs", "Build fingerprint")
    } else {
        listOf("品牌", "型号", "Android", "安全补丁", "支持 ABI", "Build 指纹")
    }

    private fun isEnglish(context: Context): Boolean =
        context.resources.configuration.locales[0].language.equals("en", true)

    private fun ScanState.reportStatus(): String = when (this) {
        ScanState.IDLE -> "STANDBY"
        ScanState.RUNNING -> "RUN"
        ScanState.PASS -> "PASS"
        ScanState.FAIL -> "BREACH"
    }

    private fun isoTimestamp(): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date())
}

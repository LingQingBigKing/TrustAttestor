package com.lingqing.trustattestor

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.lingqing.trustattestor.cloud.CloudAttestationClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import org.json.JSONObject
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

class MainViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(UiState.initial())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    @Volatile
    private var started = false

    private var timerJob: Job? = null
    private var cloudJob: Job? = null
    private val cloudRequestGeneration = AtomicLong(0L)
    private var scanStartedAtElapsed: Long = 0L
    private var finalizedElapsedMillis: Long? = null

    @Volatile
    private var nativeFinished = false

    @Volatile
    private var localDetectionPassed = false

    fun startIfNeeded(context: Context) {
        if (started) return
        started = true

        val appContext = context.applicationContext
        val initialDeviceInfo = buildDeviceInfo(appContext)
        val preferences = sharedPrefs(appContext)
        val configuredCloudEnabled = preferences.getBoolean(CLOUD_ENABLED_PREF, false)
        val cloudEnabled = configuredCloudEnabled && CloudDisclosure.hasAccepted(appContext)
        if (configuredCloudEnabled && !cloudEnabled) {
            preferences.edit().putBoolean(CLOUD_ENABLED_PREF, false).apply()
        }
        preferences.edit().putString("key_attestation_detail", "").apply()
        _uiState.update { current -> current.updateStep(CLOUD_LAYER) { step ->
            cloudStep(
                step,
                if (cloudEnabled) CloudAttestationState.WAITING else CloudAttestationState.DISABLED
            )
        }.copy(
            summaryTitle = "等待检测开始",
            summaryText = "正在准备检测环境",
            summaryStatus = ScanState.RUNNING,
            scanning = true,
            progressText = FindingTextCatalog.eventText(appContext, "progress.init.prepare"),
            deviceInfo = initialDeviceInfo,
            abnormalCount = 0,
            heroLabel = "检测用时",
            elapsedDurationText = formatElapsed(0L),
            elapsedDurationSummary = "检测开始后记录总秒数",
            trustLabel = "待检测",
            abnormalSummary = "检测完成后显示异常统计",
            cloudAttestationEnabled = cloudEnabled
        ) }
        startTimer()

        viewModelScope.launch(Dispatchers.IO) {
            val preferences = sharedPrefs(appContext)
            val revocationTime = preferences.getString("revocation_list_time", null)
            val revocationCount = parseRevocationEntryCount(
                preferences.getString("revocation_list_data", null)
            ) ?: DEFAULT_REVOCATION_COUNT
            _uiState.update { current -> current.copy(
                revocationListText = revocationTime?.let { "上次获取最新证书吊销列表：$it" }
                    ?: current.revocationListText,
                revocationCountText = "吊销证书总数：$revocationCount"
            ) }
        }

        viewModelScope.launch(Dispatchers.IO) {
            TrustAttestorNativeBridge.run(context.applicationContext, NativeScanCallback callback@ { type, stepIndex, value, text ->
                when (type) {
                    NativeScanCallback.STEP_STARTED -> {
                        val stepEventText = FindingTextCatalog.eventText(appContext, text)
                        if (stepIndex == 0) {
                            _uiState.update { current -> current.copy(
                                scanning = true,
                                summaryTitle = "正在初始化环境",
                                summaryText = "请稍候",
                                summaryStatus = ScanState.RUNNING,
                                progressText = "0% · $stepEventText",
                                overallProgressPermille = 0
                            ) }
                            return@callback
                        }

                        val visibleIndex = nativeStepToVisibleIndex(stepIndex) ?: return@callback
                        _uiState.update { current -> current.updateStep(visibleIndex) {
                            it.copy(
                                state = ScanState.RUNNING,
                                subtitle = stepRunningSubtitle(it.title),
                                detail = "正在准备当前检测项",
                                findings = emptyList(),
                                completedCheckIds = emptySet(),
                                expanded = false,
                                progressPermille = 0,
                                startedAtElapsedMillis = SystemClock.elapsedRealtime(),
                                durationMillis = 0L
                            )
                        }.copy(
                            scanning = true,
                                summaryTitle = stepEventText,
                                summaryText = stepRunningHeadline(stepEventText),
                            summaryStatus = ScanState.RUNNING,
                                progressText = "L${visibleIndex} · 0% · $stepEventText",
                            overallProgressPermille = overallProgress(stepIndex, 0)
                        ) }
                    }

                    NativeScanCallback.STEP_FINISHED -> {
                        if (stepIndex == 0) {
                            _uiState.update { current -> current.copy(
                                summaryText = "开始执行检测",
                                progressText = "100% · " + FindingTextCatalog.eventText(
                                    appContext,
                                    "progress.init.ready"
                                ),
                                overallProgressPermille = 150
                            ) }
                            return@callback
                        }

                        val visibleIndex = nativeStepToVisibleIndex(stepIndex) ?: return@callback
                        val ok = value != 0
                        _uiState.update { current ->
                            val updated = current.updateStep(visibleIndex) {
                                val hasWarning = it.findings.any { finding ->
                                    finding.status == FindingStatus.WARNING
                                }
                                it.copy(
                                    state = if (ok) ScanState.PASS else ScanState.FAIL,
                                    subtitle = when {
                                        ok && hasWarning -> "发现需关注线索，未计入异常"
                                        ok -> stepPassedSubtitle(it.title)
                                        it.findings.isNotEmpty() && it.findings.none { finding ->
                                            finding.status == FindingStatus.DETECTED
                                        } -> "检测未完整完成"
                                        else -> stepFailedSubtitle(it.title)
                                    },
                                    detail = text.trim(),
                                    expanded = false,
                                    progressPermille = 1000,
                                    durationMillis = (SystemClock.elapsedRealtime() - it.startedAtElapsedMillis)
                                        .coerceAtLeast(0L)
                                )
                            }
                            val detailed = if (stepIndex == NATIVE_HARDWARE_STEP) {
                                readKeyAttestationDetail(appContext)?.let { detailText ->
                                    updated.updateStep(visibleIndex) { step ->
                                        step.copy(
                                            detail = mergeHardwareDetails(
                                                detailText,
                                                step.detail,
                                                includeFallback = !ok
                                            )
                                        )
                                    }
                                } ?: updated
                            } else updated
                            val assessment = computeAssessment(detailed.steps, false)
                            detailed.copy(
                                trustLabel = assessment.trustLabel,
                                abnormalSummary = assessment.summary,
                                summaryTitle = STEP_TITLES[visibleIndex],
                                summaryText = when {
                                    assessment.abnormalCount > 0 ->
                                        "发现异常，当前共 ${assessment.abnormalCount} 项异常"
                                    assessment.warningCount > 0 ->
                                        "发现 ${assessment.warningCount} 项需关注线索，未计入异常"
                                    ok -> "未发现异常，当前共 0 项异常"
                                    else -> "检测未完整完成"
                                },
                                progressText = "L${visibleIndex} · 100%",
                                overallProgressPermille = overallProgress(stepIndex, 1000)
                            ).copyAssessment(assessment)
                        }
                    }

                    NativeScanCallback.PROGRESS -> _uiState.update { current ->
                        val normalized = FindingTextCatalog.eventText(appContext, text)
                        val progress = value.coerceIn(0, 1000)
                        val stepProgress = if (progress >= 1000) 1000 else (progress / 50) * 50
                        val visibleIndex = nativeStepToVisibleIndex(stepIndex)
                        val withStep = if (visibleIndex != null) {
                            current.updateStep(visibleIndex) { step ->
                                val completedCheckIds = if (isCountedCheckProgress(text)) {
                                    step.completedCheckIds + text
                                } else {
                                    step.completedCheckIds
                                }
                                val progressPermille = maxOf(step.progressPermille, stepProgress)
                                if (step.completedCheckIds == completedCheckIds &&
                                    step.progressPermille == progressPermille
                                ) {
                                    step
                                } else {
                                    step.copy(
                                        completedCheckIds = completedCheckIds,
                                        progressPermille = progressPermille
                                    )
                                }
                            }
                        } else current
                        withStep.copy(
                            summaryStatus = ScanState.RUNNING,
                            summaryText = if (normalized.startsWith("正在")) {
                                normalized
                            } else {
                                summarizeRunningText(current.summaryTitle, normalized)
                            },
                            summaryTitle = current.summaryTitle.ifBlank { "检测中" },
                            progressText = when {
                                stepIndex == 0 -> FindingTextCatalog.eventText(appContext, "step.init") +
                                    " · ${progress / 10}% · $normalized"
                                visibleIndex != null -> "L${visibleIndex} · ${progress / 10}% · $normalized"
                                else -> current.progressText
                            },
                            overallProgressPermille = if (stepIndex >= 0) {
                                maxOf(current.overallProgressPermille, overallProgress(stepIndex, progress))
                            } else current.overallProgressPermille
                        )
                    }

                    NativeScanCallback.FINDING -> {
                        val finding = NativeFindingCodec.decode(appContext, text) ?: return@callback
                        if (finding.layer != stepIndex) return@callback
                        _uiState.update { current -> current.updateStep(finding.layer) { step ->
                            val next = step.findings
                                .filterNot { it.probeId == finding.probeId }
                                .plus(finding)
                            step.copy(findings = next)
                        } }
                    }

                    NativeScanCallback.FINISHED -> {
                        val success = value != 0
                        _uiState.update { current ->
                            val enriched = readKeyAttestationDetail(appContext)?.let { detailText ->
                                current.updateStep(HARDWARE_LAYER) { step ->
                                    step.copy(
                                        detail = mergeHardwareDetails(
                                            detailText,
                                            step.detail,
                                            includeFallback = step.state == ScanState.FAIL
                                        )
                                    )
                                }
                            } ?: current
                            val visibleCount = maxOf(stepIndex, countVisibleIssues(enriched.steps))
                            val assessment = ScanAssessment.build(
                                visibleCount,
                                countVisibleWarnings(enriched.steps),
                                success
                            )
                            val summaryVisual = summaryVisualFor(assessment)
                            enriched.copyAssessment(assessment).copy(
                                scanning = false,
                                progressText = "",
                                overallProgressPermille = 1000,
                                summaryTitle = summaryVisual.title,
                                summaryText = summaryVisual.text,
                                summaryStatus = summaryVisual.state,
                                nativeFinalText = FindingTextCatalog.eventText(appContext, text)
                            )
                        }
                        nativeFinished = true
                        localDetectionPassed = success && _uiState.value.steps
                            .filter { it.index <= LOCAL_LAST_LAYER }
                            .all { it.state == ScanState.PASS }
                        val cloudEnabled = _uiState.value.cloudAttestationEnabled
                        when {
                            !cloudEnabled -> {
                                _uiState.update { current -> current.updateStep(CLOUD_LAYER) { step ->
                                    cloudStep(step, CloudAttestationState.DISABLED)
                                } }
                                stopTimer()
                            }
                            !localGateAllowsCloud() -> {
                                _uiState.update { current -> current.updateStep(CLOUD_LAYER) { step ->
                                    cloudStep(step, CloudAttestationState.SKIPPED)
                                } }
                                stopTimer()
                            }
                            else -> launchCloudAttestation(appContext)
                        }
                    }

                    NativeScanCallback.FAILED -> {
                        nativeFinished = true
                        localDetectionPassed = false
                        val continueWithCloud = BuildConfig.DEBUG &&
                            _uiState.value.cloudAttestationEnabled
                        _uiState.update { current -> current.copy(
                            scanning = false,
                            summaryTitle = "检测失败",
                            summaryText = FindingTextCatalog.eventText(appContext, text),
                            summaryStatus = ScanState.FAIL,
                            progressText = ""
                        ).updateStep(CLOUD_LAYER) { step ->
                            cloudStep(
                                step,
                                if (!current.cloudAttestationEnabled) {
                                    CloudAttestationState.DISABLED
                                } else if (BuildConfig.DEBUG) {
                                    CloudAttestationState.VERIFYING
                                } else {
                                    CloudAttestationState.SKIPPED
                                }
                            )
                        }.copyAssessment(computeAssessment(current.steps, false)) }
                        if (continueWithCloud) {
                            launchCloudAttestation(appContext)
                        } else {
                            stopTimer()
                        }
                    }
                }
            })
        }
    }

    fun toggleStep(stepIndex: Int) {
        _uiState.update { current ->
            val nextExpanded = current.steps.firstOrNull { it.index == stepIndex }?.expanded != true
            current.copy(steps = current.steps.map { step ->
                if (step.index == stepIndex) step.copy(expanded = nextExpanded)
                else if (nextExpanded) step.copy(expanded = false)
                else step
            })
        }
    }

    fun setCloudAttestationEnabled(context: Context, enabled: Boolean) {
        val appContext = context.applicationContext
        val consentedEnabled = enabled && CloudDisclosure.hasAccepted(appContext)
        sharedPrefs(appContext).edit().putBoolean(CLOUD_ENABLED_PREF, consentedEnabled).apply()
        cloudRequestGeneration.incrementAndGet()
        cloudJob?.cancel()
        cloudJob = null

        _uiState.update { current -> current
            .updateStep(CLOUD_LAYER) { step ->
                cloudStep(
                    step,
                    when {
                        !consentedEnabled -> CloudAttestationState.DISABLED
                        !nativeFinished -> CloudAttestationState.WAITING
                        !localGateAllowsCloud() -> CloudAttestationState.SKIPPED
                        else -> CloudAttestationState.VERIFYING
                    }
                )
            }
            .copy(cloudAttestationEnabled = consentedEnabled)
        }

        if (!nativeFinished) return
        if (consentedEnabled && localGateAllowsCloud()) {
            launchCloudAttestation(appContext)
        } else {
            finishWithoutCloud()
        }
    }

    private fun launchCloudAttestation(context: Context) {
        val requestGeneration = cloudRequestGeneration.incrementAndGet()
        cloudJob?.cancel()
        _uiState.update { current -> current.updateStep(CLOUD_LAYER) { step ->
            cloudStep(step, CloudAttestationState.VERIFYING)
        }.copy(
            scanning = true,
            summaryTitle = "云端证明",
            summaryText = "正在请求云端签名与风险评估",
            summaryStatus = ScanState.RUNNING,
            progressText = "L3 · VERIFYING · " + context.getString(R.string.step_cloud_verifying)
        ) }

        cloudJob = viewModelScope.launch(Dispatchers.IO) {
            val startedAt = SystemClock.elapsedRealtime()
            val result = CloudAttestationClient(
                endpoint = BuildConfig.CLOUD_ATTESTATION_URL,
                trustedPublicKey = BuildConfig.CLOUD_VERDICT_PUBLIC_KEY
            ).attest(context.applicationContext, _uiState.value)
            val duration = (SystemClock.elapsedRealtime() - startedAt).coerceAtLeast(0L)
            if (!isCurrentCloudRequest(requestGeneration)) return@launch

            val finding = result.finding
            val cloudFindings = if (result.findings.any { it.status == finding.status }) {
                result.findings
            } else {
                listOf(finding) + result.findings
            }
            val cloudState = when {
                !result.signatureVerified -> CloudAttestationState.UNAVAILABLE
                finding.status == FindingStatus.DETECTED -> CloudAttestationState.BREACH
                finding.status == FindingStatus.WARNING -> CloudAttestationState.WARNING
                finding.status == FindingStatus.UNAVAILABLE -> CloudAttestationState.UNAVAILABLE
                else -> CloudAttestationState.PASSED
            }
            val subtitle = when (cloudState) {
                CloudAttestationState.PASSED -> "Cloud Attestation 校验成功"
                CloudAttestationState.BREACH -> "Cloud Attestation 校验失败"
                CloudAttestationState.WARNING -> "Cloud Attestation 返回需关注项"
                CloudAttestationState.UNAVAILABLE -> "Cloud Attestation 暂不可用"
                else -> "Cloud Attestation 校验已结束"
            } + " · ${formatCloudDuration(duration)}"
            val detail = buildString {
                append(finding.title)
                if (finding.evidence.isNotBlank()) {
                    append('\n')
                    append(finding.evidence)
                }
                if (cloudFindings.size > 1) {
                    append("\n\nSIGNED FINDINGS")
                    cloudFindings.forEach { item ->
                        append("\n[")
                        append(item.status.name)
                        append("] ")
                        append(item.title)
                        if (item.evidence.isNotBlank()) {
                            append("\n")
                            append(item.evidence)
                        }
                    }
                }
                if (result.signatureVerified) {
                    if (result.verdictId.isNotBlank()) {
                        append("\nVERDICT ID: ")
                        append(result.verdictId)
                    }
                    if (result.keyId.isNotBlank()) {
                        append("\nSERVER KEY: ")
                        append(result.keyId)
                    }
                }
                append("\nLATENCY: ")
                append(duration)
                append("ms")
            }
            _uiState.update { current ->
                if (requestGeneration != cloudRequestGeneration.get() ||
                    !current.cloudAttestationEnabled) {
                    return@update current
                }
                val withCloud = current.updateStep(CLOUD_LAYER) { step ->
                    cloudStep(
                        step = step,
                        state = cloudState,
                        subtitle = subtitle,
                        detail = detail,
                        findings = cloudFindings,
                        durationMillis = duration
                    )
                }
                val assessment = computeAssessment(
                    withCloud.steps,
                    localDetectionPassed && cloudState != CloudAttestationState.UNAVAILABLE
                )
                val summaryVisual = summaryVisualFor(assessment)
                withCloud.copyAssessment(assessment).copy(
                    scanning = false,
                    progressText = "",
                    summaryTitle = summaryVisual.title,
                    summaryText = when (finding.status) {
                        FindingStatus.CLEAN -> if (localDetectionPassed) {
                            if (assessment.warningCount > 0) {
                                "云端检测通过；${assessment.summary}"
                            } else {
                                "云端检测通过"
                            }
                        } else {
                            "本地检测未通过；云端检测已完成"
                        }
                        FindingStatus.DETECTED -> assessment.summary
                        FindingStatus.WARNING -> if (localDetectionPassed) {
                            assessment.summary
                        } else {
                            "本地检测未通过；云端返回需关注项"
                        }
                        FindingStatus.UNAVAILABLE -> if (localDetectionPassed) {
                            "云端检测不可用"
                        } else {
                            "本地检测未通过；云端检测不可用"
                        }
                    },
                    summaryStatus = summaryVisual.state
                )
            }
            if (isCurrentCloudRequest(requestGeneration)) stopTimer()
        }
    }

    private fun isCurrentCloudRequest(generation: Long): Boolean {
        return generation == cloudRequestGeneration.get() &&
            _uiState.value.cloudAttestationEnabled
    }

    private fun finishWithoutCloud() {
        _uiState.update { current ->
            val assessment = computeAssessment(current.steps, localDetectionPassed)
            val visual = summaryVisualFor(assessment)
            current.copyAssessment(assessment).copy(
                scanning = false,
                progressText = "",
                summaryTitle = visual.title,
                summaryText = visual.text,
                summaryStatus = visual.state
            )
        }
        stopTimer()
    }

    private fun localGateAllowsCloud(): Boolean {
        return localDetectionPassed || BuildConfig.DEBUG
    }

    private fun cloudStep(
        step: StepUi,
        state: CloudAttestationState,
        subtitle: String? = null,
        detail: String? = null,
        findings: List<NativeFinding> = emptyList(),
        durationMillis: Long = 0L
    ): StepUi {
        val defaultSubtitle = when (state) {
            CloudAttestationState.DISABLED -> "Cloud Attestation 未启用"
            CloudAttestationState.WAITING -> "Cloud Attestation 等待本地检测"
            CloudAttestationState.SKIPPED -> "Cloud Attestation 已跳过"
            CloudAttestationState.VERIFYING -> "Cloud Attestation 正在校验"
            CloudAttestationState.PASSED -> "Cloud Attestation 校验成功"
            CloudAttestationState.BREACH -> "Cloud Attestation 校验失败"
            CloudAttestationState.WARNING -> "Cloud Attestation 返回需关注项"
            CloudAttestationState.UNAVAILABLE -> "Cloud Attestation 暂不可用"
        }
        val scanState = when (state) {
            CloudAttestationState.VERIFYING -> ScanState.RUNNING
            CloudAttestationState.PASSED -> ScanState.PASS
            CloudAttestationState.BREACH -> ScanState.FAIL
            CloudAttestationState.WARNING -> ScanState.WARNING
            else -> ScanState.IDLE
        }
        return step.copy(
            subtitle = subtitle ?: defaultSubtitle,
            detail = detail ?: "[${state.badge}] $defaultSubtitle",
            findings = findings,
            state = scanState,
            expanded = false,
            progressPermille = when (state) {
                CloudAttestationState.PASSED,
                CloudAttestationState.BREACH,
                CloudAttestationState.WARNING,
                CloudAttestationState.UNAVAILABLE -> 1000
                else -> 0
            },
            startedAtElapsedMillis = if (state == CloudAttestationState.VERIFYING) {
                SystemClock.elapsedRealtime()
            } else {
                step.startedAtElapsedMillis
            },
            durationMillis = durationMillis,
            cloudState = state
        )
    }

    fun fetchRevocationList(context: Context) {
        if (_uiState.value.fetchingRevocationList) return
        _uiState.update { current -> current.copy(fetchingRevocationList = true) }
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val conn = URL("https://android.googleapis.com/attestation/status").openConnection() as HttpURLConnection
                    conn.connectTimeout = 10_000
                    conn.readTimeout = 10_000
                    conn.requestMethod = "GET"
                    val code = conn.responseCode
                    require(code == 200) { "Google 服务器返回错误：$code" }
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    val time = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
                    val count = parseRevocationEntryCount(body) ?: 0
                    require(sharedPrefs(context.applicationContext).edit()
                        .putString("revocation_list_time", time)
                        .putString("revocation_list_data", body)
                        .commit()) { "保存吊销列表失败" }
                    time to count
                }
            }.onSuccess { (time, count) ->
                _uiState.update { current -> current.copy(
                    fetchingRevocationList = false,
                    revocationListText = "上次获取最新证书吊销列表：$time",
                    revocationCountText = "吊销证书总数：$count",
                    lastToast = "已成功获取最新证书吊销列表"
                ) }
            }.onFailure { e ->
                _uiState.update { current -> current.copy(
                    fetchingRevocationList = false,
                    lastToast = e.message ?: e.toString()
                ) }
            }
        }
    }

    fun consumeToast() {
        if (_uiState.value.lastToast != null) {
            _uiState.update { current -> current.copy(lastToast = null) }
        }
    }

    private fun startTimer() {
        timerJob?.cancel()
        scanStartedAtElapsed = SystemClock.elapsedRealtime()
        finalizedElapsedMillis = null
        _uiState.update { current -> current.copy(
            elapsedDurationText = formatElapsed(0L),
            elapsedDurationSummary = "检测开始后记录总秒数"
        ) }
        timerJob = viewModelScope.launch {
            while (true) {
                val elapsed = (SystemClock.elapsedRealtime() - scanStartedAtElapsed).coerceAtLeast(0L)
                val summary = if (_uiState.value.scanning) {
                    "检测已进行 ${formatElapsedVerbose(elapsed)}"
                } else {
                    "本次检测总时长 ${formatElapsedVerbose(elapsed)}"
                }
                _uiState.update { current -> current.copy(
                    elapsedDurationText = formatElapsed(elapsed),
                    elapsedDurationSummary = summary
                ) }
                delay(TIMER_UPDATE_INTERVAL_MILLIS)
            }
        }
    }

    private fun stopTimer() {
        val elapsed = finalizedElapsedMillis ?: (SystemClock.elapsedRealtime() - scanStartedAtElapsed)
            .coerceAtLeast(0L)
            .also { finalizedElapsedMillis = it }
        timerJob?.cancel()
        timerJob = null
        _uiState.update { current -> current.copy(
            elapsedDurationText = formatElapsed(elapsed),
            elapsedDurationSummary = "本次检测总时长 ${formatElapsedVerbose(elapsed)}"
        ) }
    }

    private fun formatElapsed(elapsedMillis: Long): String {
        return String.format(Locale.US, "%.1f", elapsedMillis.coerceAtLeast(0L) / 1000.0)
    }

    private fun formatElapsedVerbose(elapsedMillis: Long): String {
        return formatElapsed(elapsedMillis) + "秒"
    }

    private fun formatCloudDuration(durationMillis: Long): String {
        return if (durationMillis < 1000L) {
            "${durationMillis.coerceAtLeast(0L)}ms"
        } else {
            String.format(Locale.US, "%.1fs", durationMillis / 1000.0)
        }
    }

    private fun buildDeviceInfo(context: Context): List<DeviceInfoItem> {
        val unknown = context.getString(R.string.common_unknown)
        val securityPatch = runCatching { Build.VERSION.SECURITY_PATCH }
            .getOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: unknown
        val abis = Build.SUPPORTED_ABIS?.joinToString(" / ").orEmpty().ifBlank { unknown }
        val androidVersion = buildString {
            append(Build.VERSION.RELEASE ?: unknown)
            append(" (SDK ")
            append(Build.VERSION.SDK_INT)
            append(')')
        }
        val brandText = listOfNotNull(
            Build.MANUFACTURER?.takeIf { it.isNotBlank() },
            Build.BRAND?.takeIf { it.isNotBlank() && !it.equals(Build.MANUFACTURER, true) }
        ).joinToString(" / ").ifBlank { unknown }

        return listOf(
            DeviceInfoItem("品牌", brandText),
            DeviceInfoItem("型号", listOfNotNull(Build.MODEL, Build.DEVICE).filter { it.isNotBlank() }.joinToString(" / ").ifBlank { unknown }),
            DeviceInfoItem("Android", androidVersion),
            DeviceInfoItem("安全补丁", securityPatch),
            DeviceInfoItem("支持 ABI", abis),
            DeviceInfoItem("Build 指纹", Build.FINGERPRINT?.ifBlank { unknown } ?: unknown)
        )
    }


    private fun sharedPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(SHARED_DATA_PREF_NAME, Context.MODE_PRIVATE)
    }

    private fun getSharedData(context: Context, key: String): String? {
        return sharedPrefs(context).getString(key, null)
    }

    private fun readKeyAttestationDetail(context: Context): String? {
        return getSharedData(context, "key_attestation_detail")?.trim()?.takeIf { it.isNotBlank() }
    }

    private fun mergeHardwareDetails(
        attestationDetail: String,
        existingDetail: String,
        includeFallback: Boolean
    ): String {
        val existingFindings = if (existingDetail.contains(HARDWARE_FINDINGS_MARKER)) {
            existingDetail.substringAfter(HARDWARE_FINDINGS_MARKER).trim()
        } else {
            existingDetail.trim()
        }
        val hasBulletFinding = existingFindings.lineSequence().any { line ->
            val trimmed = line.trimStart()
            trimmed.startsWith("\u2022") || trimmed.startsWith("-") || trimmed.startsWith("*")
        }
        if (existingFindings.isBlank() || (!includeFallback && !hasBulletFinding)) {
            return attestationDetail.trim()
        }
        return buildString {
            append(attestationDetail.trim())
            append("\n\n")
            append(HARDWARE_FINDINGS_MARKER)
            append('\n')
            append(existingFindings)
        }
    }

    private fun parseRevocationEntryCount(text: String?): Int? {
        if (text.isNullOrBlank()) return null
        return runCatching {
            JSONObject(text).getJSONObject("entries").length()
        }.getOrNull()
    }

    private fun normalizeDetail(detail: String): String {
        return detail.trim().ifBlank { "未返回额外信息" }
    }

    private fun summarizeRunningText(title: String, raw: String): String {
        return when {
            raw.contains("异常") || raw.contains("风险") || raw.contains("检测到") || raw.contains("发现") || raw.contains("不匹配") -> "已发现阶段性问题，检测仍在继续"
            title.contains("硬件证明") || title.contains("Attestation") -> "正在校验证书链与硬件证明"
            title.contains("系统完整性") -> "正在检查系统完整性"
            title.contains("设备环境") -> "正在检查设备环境"
            else -> "正在执行当前检测项"
        }
    }

    private fun stepRunningSubtitle(title: String): String {
        return when {
            title.contains("设备环境") -> "正在检查设备环境"
            title.contains("系统完整性") -> "正在分析系统完整性"
            title.contains("硬件证明") -> "正在校验证书链、吊销状态与硬件证明"
            else -> "正在检测"
        }
    }

    private fun stepRunningHeadline(title: String): String {
        return when {
            title.contains("设备环境") -> "正在汇总设备环境信息"
            title.contains("系统完整性") -> "正在分析系统完整性"
            title.contains("硬件证明") -> "正在校验证书链、吊销状态与硬件证明结果"
            else -> "正在执行$title"
        }
    }

    private fun stepPassedSubtitle(title: String): String {
        return when {
            title.contains("设备环境") -> "设备环境正常"
            title.contains("系统完整性") -> "系统完整性校验成功"
            title.contains("硬件证明") -> "Key Attestation 校验成功"
            else -> "未发现新的明显异常"
        }
    }

    private fun stepFailedSubtitle(title: String): String {
        return when {
            title.contains("设备环境") -> "发现设备环境存在异常"
            title.contains("系统完整性") -> "系统完整性校验失败"
            title.contains("硬件证明") -> "Key Attestation 校验失败"
            else -> "发现异常线索"
        }
    }

    private fun computeAssessment(steps: List<StepUi>, success: Boolean): TrustAssessment {
        val abnormalCount = countVisibleIssues(steps)
        return ScanAssessment.build(abnormalCount, countVisibleWarnings(steps), success)
    }

    private fun countVisibleIssues(steps: List<StepUi>): Int {
        val lines = linkedSetOf<String>()
        steps.forEach { step ->
            if (step.findings.isNotEmpty()) {
                step.findings
                    .filter { it.status == FindingStatus.DETECTED }
                    .forEach { lines += it.probeId }
                return@forEach
            }
            if (step.state != ScanState.FAIL) return@forEach
            normalizeDetail(step.detail)
                .lineSequence()
                .map { it.trim() }
                .filter { it.startsWith("•") }
                .map { it.removePrefix("•").trim() }
                .filter { it.isNotEmpty() }
                .forEach { lines += it }
        }
        return if (lines.isNotEmpty()) lines.size else steps.count {
            it.state == ScanState.FAIL && it.findings.isEmpty()
        }
    }

    private fun countVisibleWarnings(steps: List<StepUi>): Int {
        return steps.asSequence()
            .flatMap { it.findings.asSequence() }
            .filter { it.status == FindingStatus.WARNING }
            .distinctBy { it.probeId }
            .count()
    }

    private fun summaryVisualFor(assessment: TrustAssessment): SummaryVisual {
        return when (assessment.outcome) {
            AssessmentOutcome.BREACH -> SummaryVisual(
                title = "检测完成",
                text = assessment.summary,
                state = ScanState.FAIL
            )
            AssessmentOutcome.INCOMPLETE -> SummaryVisual(
                title = "检测失败",
                text = assessment.summary,
                state = ScanState.FAIL
            )
            AssessmentOutcome.WARNING -> SummaryVisual(
                title = "检测完成·需关注",
                text = assessment.summary,
                state = ScanState.WARNING
            )
            AssessmentOutcome.PASS -> SummaryVisual(
                title = "检测完成",
                text = assessment.summary,
                state = ScanState.PASS
            )
        }
    }

    private fun nativeStepToVisibleIndex(stepIndex: Int): Int? {
        if (stepIndex <= 0) return null
        val visible = stepIndex - 1
        return visible.takeIf { it in 0..LOCAL_LAST_LAYER }
    }

    private fun overallProgress(nativeStepIndex: Int, stepProgressPermille: Int): Int {
        val progress = stepProgressPermille.coerceIn(0, 1000)
        return when (nativeStepIndex) {
            0 -> progress * 150 / 1000
            1 -> 150 + progress * 283 / 1000
            2 -> 433 + progress * 283 / 1000
            3 -> 716 + progress * 284 / 1000
            else -> 0
        }.coerceIn(0, 1000)
    }

    private fun isCountedCheckProgress(eventCode: String): Boolean {
        return eventCode.startsWith("progress.hardware.probe.") ||
            eventCode in COUNTED_CHECK_PROGRESS_EVENTS
    }

    override fun onCleared() {
        timerJob?.cancel()
        cloudJob?.cancel()
        super.onCleared()
    }

    companion object {
        private const val TIMER_UPDATE_INTERVAL_MILLIS = 100L
        private const val SHARED_DATA_PREF_NAME = "trust_attestor_shared_data"
        private const val CLOUD_ENABLED_PREF = "cloud_attestation_enabled"
        private const val HARDWARE_FINDINGS_MARKER = "HARDWARE FINDINGS"
        private val COUNTED_CHECK_PROGRESS_EVENTS = setOf(
            "progress.hardware.chain_integrity",
            "progress.hardware.read_chain",
            "progress.hardware.parse_root_of_trust",
            "progress.hardware.boundary",
            "progress.system.zygote",
            "progress.system.collect",
            "progress.system.teesim",
            "progress.device.mount_namespace",
            "progress.device.process_access",
            "progress.device.kernel_patch",
            "progress.device.environment"
        )
        const val DEFAULT_REVOCATION_COUNT = 1736
        const val DEVICE_LAYER = 0
        const val SYSTEM_LAYER = 1
        const val HARDWARE_LAYER = 2
        const val LOCAL_LAST_LAYER = 2
        const val CLOUD_LAYER = 3
        private const val NATIVE_HARDWARE_STEP = 3

        val STEP_TITLES = listOf(
            "设备环境",
            "系统完整性",
            "硬件证明",
            "云端证明"
        )

        val STEP_SUBTITLES = listOf(
            "对设备环境进行检测",
            "对系统完整性进行校验",
            "通过设备硬件进行校验",
            "未启用云端检测"
        )
    }
}

enum class ScanState { IDLE, RUNNING, PASS, WARNING, FAIL }

enum class CloudAttestationState(val badge: String) {
    DISABLED("DISABLED"),
    WAITING("STANDBY"),
    SKIPPED("SKIPPED"),
    VERIFYING("VERIFYING"),
    PASSED("PASSED"),
    BREACH("BREACH"),
    WARNING("WARNING"),
    UNAVAILABLE("UNAVAILABLE")
}

data class StepUi(
    val index: Int,
    val title: String,
    val subtitle: String,
    val detail: String,
    val findings: List<NativeFinding>,
    val state: ScanState,
    val expanded: Boolean,
    val progressPermille: Int,
    val startedAtElapsedMillis: Long,
    val durationMillis: Long,
    val cloudState: CloudAttestationState? = null,
    val completedCheckIds: Set<String> = emptySet()
)

data class DeviceInfoItem(
    val label: String,
    val value: String
)

data class SummaryVisual(
    val title: String,
    val text: String,
    val state: ScanState
)

data class UiState(
    val summaryTitle: String,
    val summaryText: String,
    val summaryStatus: ScanState,
    val progressText: String,
    val overallProgressPermille: Int,
    val scanning: Boolean,
    val abnormalCount: Int,
    val warningCount: Int,
    val heroLabel: String,
    val elapsedDurationText: String,
    val elapsedDurationSummary: String,
    val trustLabel: String,
    val abnormalSummary: String,
    val steps: List<StepUi>,
    val deviceInfo: List<DeviceInfoItem>,
    val nativeFinalText: String,
    val revocationListText: String,
    val revocationCountText: String,
    val fetchingRevocationList: Boolean,
    val cloudAttestationEnabled: Boolean,
    val lastToast: String?
) {
    fun updateStep(index: Int, block: (StepUi) -> StepUi): UiState {
        return copy(steps = steps.map { if (it.index == index) block(it) else it })
    }

    fun copyAssessment(assessment: TrustAssessment): UiState {
        return copy(
            abnormalCount = assessment.abnormalCount,
            warningCount = assessment.warningCount,
            heroLabel = "检测用时",
            trustLabel = assessment.trustLabel,
            abnormalSummary = assessment.summary
        )
    }

    companion object {
        fun initial(): UiState {
            return UiState(
                summaryTitle = "等待检测",
                summaryText = "打开应用后会自动开始检测",
                summaryStatus = ScanState.IDLE,
                progressText = "",
                overallProgressPermille = 0,
                scanning = false,
                abnormalCount = 0,
                warningCount = 0,
                heroLabel = "检测用时",
                elapsedDurationText = "0",
                elapsedDurationSummary = "检测开始后记录总秒数",
                trustLabel = "待检测",
                abnormalSummary = "检测完成后显示异常统计",
                steps = MainViewModel.STEP_TITLES.mapIndexed { index, title ->
                    StepUi(
                        index = index,
                        title = title,
                        subtitle = MainViewModel.STEP_SUBTITLES[index],
                        detail = "等待检测",
                        findings = emptyList(),
                        state = ScanState.IDLE,
                        expanded = false,
                        progressPermille = 0,
                        startedAtElapsedMillis = 0L,
                        durationMillis = 0L,
                        cloudState = if (index == MainViewModel.CLOUD_LAYER) {
                            CloudAttestationState.DISABLED
                        } else {
                            null
                        }
                    )
                },
                deviceInfo = emptyList(),
                nativeFinalText = "",
                revocationListText = "上次获取最新证书吊销列表：未获取",
                revocationCountText = "吊销证书总数：1736",
                fetchingRevocationList = false,
                cloudAttestationEnabled = false,
                lastToast = null
            )
        }
    }
}

package com.lingqing.trustattestor.preview

import com.lingqing.trustattestor.*

enum class PreviewScenario(val label: String) {
    PASS("正常完成 / Passed"),
    DETECTED("多项异常 / Detected"),
    UNAVAILABLE("检测不可用 · 0 异常 / Unavailable"),
    WARNING("警告 / Warning"),
    RUNNING("扫描中定格 / Running"),
    REPLAY("完整扫描动画 / Replay"),
    IDLE("等待检测 / Idle"),
    CLOUD_PASSED("云端通过 / Cloud passed"),
    CLOUD_BREACH("云端异常 / Cloud breach"),
    CLOUD_WARNING("云端警告 / Cloud warning"),
    CLOUD_UNAVAILABLE("云端不可用 / Cloud unavailable"),
    CLOUD_VERIFYING("云端验证中 / Cloud verifying"),
    LONG_TEXT("长文案与多行证据 / Long text")
}

/** Synthetic UI states; these fixtures never query the device or a server. */
object PreviewFixtures {
    private val deviceInfo = listOf(
        DeviceInfoItem("品牌", "UI PREVIEW — SYNTHETIC DATA"),
        DeviceInfoItem("型号", "TrustAttestor / UI Sample Device"),
        DeviceInfoItem("Android", "15 (SDK 35) — sample"),
        DeviceInfoItem("安全补丁", "2026-09-01 — sample"),
        DeviceInfoItem("支持 ABI", "arm64-v8a / x86_64 — sample"),
        DeviceInfoItem("Build 指纹", "preview/sample/device:15/EXAMPLE/1:user/release-keys")
    )

    fun state(scenario: PreviewScenario): UiState {
        val initial = UiState.initial().copy(deviceInfo = deviceInfo)
        if (scenario == PreviewScenario.IDLE) return initial
        if (scenario == PreviewScenario.RUNNING || scenario == PreviewScenario.REPLAY) {
            return running(if (scenario == PreviewScenario.RUNNING) 550 else 0)
        }
        var result = initial.copy(
            summaryTitle = "检测完成",
            summaryText = "未发现异常项",
            summaryStatus = ScanState.PASS,
            overallProgressPermille = 1000,
            elapsedDurationText = "8.4",
            elapsedDurationSummary = "本次检测总时长 8.4秒",
            trustLabel = "未见异常",
            abnormalSummary = "未发现异常项",
            nativeFinalText = "UI PREVIEW: SYNTHETIC DATA",
            steps = initial.steps.map { step ->
                if (step.index == MainViewModel.CLOUD_LAYER) step else step.copy(
                    subtitle = "未发现异常项",
                    state = ScanState.PASS,
                    progressPermille = 1000,
                    durationMillis = (step.index + 1) * 1400L,
                    completedCheckIds = (1..4).map { "preview.${step.index}.$it" }.toSet(),
                    detail = if (step.index == MainViewModel.HARDWARE_LAYER) certificateDetails else "UI PREVIEW",
                    findings = listOf(finding(step.index, FindingStatus.CLEAN, "layer.${step.index}.summary"))
                )
            }
        )
        when (scenario) {
            PreviewScenario.DETECTED -> {
                result = result.updateStep(0) { it.copy(state = ScanState.FAIL,
                    findings = listOf(finding(0, FindingStatus.DETECTED, "device.bootloader.unlocked"))) }
                    .updateStep(2) { it.copy(state = ScanState.FAIL,
                        findings = listOf(finding(2, FindingStatus.DETECTED, "preview.hardware.mismatch",
                            "RootOfTrust / Verified Boot 不一致 — 示例"))) }
            }
            PreviewScenario.UNAVAILABLE -> result = result.updateStep(1) { it.copy(
                state = ScanState.FAIL, subtitle = "检测未完整完成", expanded = true,
                findings = listOf(finding(1, FindingStatus.UNAVAILABLE, "preview.unavailable"))) }
            PreviewScenario.WARNING -> result = result.updateStep(0) { it.copy(
                state = ScanState.FAIL, expanded = true,
                findings = listOf(finding(0, FindingStatus.WARNING, "preview.warning", "需要注意的环境提示 / Sample warning"))) }
            PreviewScenario.LONG_TEXT -> result = result.updateStep(0) { it.copy(
                state = ScanState.FAIL, expanded = true,
                findings = (1..12).map { index -> finding(0, FindingStatus.DETECTED,
                    "preview.long.$index", "示例 $index：较长的检测项标题用于检查换行、卡片高度、间距与滚动效果 / Long sample finding title",
                    "UI PREVIEW evidence $index\n" + "用于布局测试的多行示例证据，不代表当前设备状态。\n".repeat(3)) }) }
            else -> Unit
        }
        val cloud = when (scenario) {
            PreviewScenario.CLOUD_PASSED -> CloudAttestationState.PASSED
            PreviewScenario.CLOUD_BREACH -> CloudAttestationState.BREACH
            PreviewScenario.CLOUD_WARNING -> CloudAttestationState.WARNING
            PreviewScenario.CLOUD_UNAVAILABLE -> CloudAttestationState.UNAVAILABLE
            PreviewScenario.CLOUD_VERIFYING -> CloudAttestationState.VERIFYING
            else -> null
        }
        if (cloud != null) result = withCloud(result, cloud)
        return assess(result)
    }

    fun running(progress: Int): UiState {
        val bounded = progress.coerceIn(0, 999)
        val layer = (bounded * 3 / 1000).coerceIn(0, 2)
        val localProgress = (bounded * 3 - layer * 1000).coerceIn(0, 1000)
        return UiState.initial().copy(
            summaryTitle = "正在检测", summaryText = "正在执行当前检测项",
            summaryStatus = ScanState.RUNNING, scanning = true,
            overallProgressPermille = bounded,
            progressText = "UI PREVIEW — ${MainViewModel.STEP_TITLES[layer]}",
            elapsedDurationText = String.format(java.util.Locale.US, "%.1f", bounded * 0.012),
            deviceInfo = deviceInfo,
            steps = UiState.initial().steps.map { step ->
                when {
                    step.index < layer -> step.copy(state = ScanState.PASS, progressPermille = 1000,
                        durationMillis = 2400L, findings = listOf(finding(step.index, FindingStatus.CLEAN,
                            "layer.${step.index}.summary")))
                    step.index == layer -> step.copy(state = ScanState.RUNNING, progressPermille = localProgress,
                        expanded = true, detail = "UI PREVIEW — scanning")
                    else -> step
                }
            }
        )
    }

    fun preserveUserState(frame: UiState, current: UiState): UiState = frame.copy(
        cloudAttestationEnabled = current.cloudAttestationEnabled,
        fetchingRevocationList = current.fetchingRevocationList,
        revocationListText = current.revocationListText,
        revocationCountText = current.revocationCountText,
        lastToast = current.lastToast,
        steps = frame.steps.map { step ->
            val previous = current.steps.firstOrNull { it.index == step.index }
            if (step.index == MainViewModel.CLOUD_LAYER) previous ?: step
            else step.copy(expanded = previous?.expanded ?: step.expanded)
        }
    )

    fun withCloud(state: UiState, cloud: CloudAttestationState): UiState {
        val status = when (cloud) {
            CloudAttestationState.PASSED -> FindingStatus.CLEAN
            CloudAttestationState.BREACH -> FindingStatus.DETECTED
            CloudAttestationState.WARNING -> FindingStatus.WARNING
            else -> FindingStatus.UNAVAILABLE
        }
        val finished = cloud in setOf(CloudAttestationState.PASSED, CloudAttestationState.BREACH,
            CloudAttestationState.WARNING, CloudAttestationState.UNAVAILABLE)
        return assess(state.updateStep(MainViewModel.CLOUD_LAYER) { it.copy(
            cloudState = cloud, expanded = cloud != CloudAttestationState.DISABLED,
            state = when (cloud) {
                CloudAttestationState.PASSED -> ScanState.PASS
                CloudAttestationState.VERIFYING -> ScanState.RUNNING
                CloudAttestationState.BREACH, CloudAttestationState.WARNING,
                CloudAttestationState.UNAVAILABLE -> ScanState.FAIL
                else -> ScanState.IDLE
            },
            progressPermille = if (finished) 1000 else 0,
            durationMillis = if (finished) 820 else 0,
            detail = "UI PREVIEW — no network request",
            findings = if (finished) listOf(finding(3, status, "cloud.attestation.verdict").copy(
                serverTitleZh = "云端状态示例：${cloud.badge}",
                serverTitleEn = "Sample cloud status: ${cloud.badge}",
                serverEvidenceZh = "界面模拟数据，未向服务器提交信息。",
                serverEvidenceEn = "Synthetic UI data; no request was sent."
            )) else emptyList()
        ) }.copy(cloudAttestationEnabled = cloud != CloudAttestationState.DISABLED))
    }

    private fun assess(state: UiState): UiState {
        val count = state.steps.flatMap { it.findings }
            .filter { it.status == FindingStatus.DETECTED }.distinctBy { it.probeId }.size
        val active = state.steps.firstOrNull { it.state == ScanState.RUNNING }
        if (active != null) return state.copy(abnormalCount = count, scanning = true,
            summaryStatus = ScanState.RUNNING,
            summaryTitle = if (active.index == MainViewModel.CLOUD_LAYER) "云端证明" else "正在检测",
            summaryText = "正在执行当前检测项",
            progressText = "UI PREVIEW — ${active.title}")
        val incomplete = state.steps.any { it.index <= MainViewModel.LOCAL_LAST_LAYER && it.state == ScanState.FAIL }
        val summary = when {
            count > 0 -> "共发现 $count 项异常"
            incomplete -> "检测流程未正常完成"
            else -> "未发现异常项"
        }
        return state.copy(
            scanning = false, progressText = "", summaryTitle = "检测完成",
            abnormalCount = count, abnormalSummary = summary, summaryText = summary,
            summaryStatus = if (count > 0 || incomplete) ScanState.FAIL else ScanState.PASS,
            trustLabel = when { count > 0 -> "发现异常"; incomplete -> "流程未完成"; else -> "未见异常" }
        )
    }

    private fun finding(layer: Int, status: FindingStatus, id: String, title: String = "",
                        evidence: String = "UI PREVIEW — synthetic sample") = NativeFinding(
        probeId = id, layer = layer, status = status,
        severity = if (status == FindingStatus.DETECTED) FindingSeverity.HIGH else FindingSeverity.INFO,
        title = title, evidence = evidence
    )

    private val certificateDetails = """
        证书链与 Attestation 信息 — UI PREVIEW
        证书总数：3
        RootOfTrust: deviceLocked=true, verifiedBootState=Verified (sample)
        根证书来源：示例根证书 / SAMPLE ONLY
        证书链：
        #1 叶子证书
        Subject: CN=TA UI Preview Leaf
        Issuer: CN=TA UI Preview Intermediate
        Serial: 000001
        #2 中间证书
        Subject: CN=TA UI Preview Intermediate
        Issuer: CN=TA UI Preview Root
        Serial: 000002
        #3 根证书
        Subject: CN=TA UI Preview Root
        Issuer: CN=TA UI Preview Root
        Serial: 000003
    """.trimIndent()
}

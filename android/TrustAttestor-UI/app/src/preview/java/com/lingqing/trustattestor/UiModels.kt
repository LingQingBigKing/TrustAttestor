package com.lingqing.trustattestor

// UI contract snapshot; not part of UI source synchronization.
enum class ScanState { IDLE, RUNNING, PASS, FAIL }

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

data class TrustAssessment(
    val abnormalCount: Int,
    val trustLabel: String,
    val summary: String
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

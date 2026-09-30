package com.lingqing.trustattestor

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.lingqing.trustattestor.preview.PreviewFixtures
import com.lingqing.trustattestor.preview.PreviewScenario
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** Preview-only implementation of the five actions consumed by the original UI. */
class MainViewModel : ViewModel() {
    private val state = MutableStateFlow(UiState.initial())
    val uiState: StateFlow<UiState> = state.asStateFlow()
    private var started = false
    private var cloudJob: Job? = null

    fun startIfNeeded(context: Context) {
        if (started) return
        started = true
        val name = context.getSharedPreferences("ui_preview", Context.MODE_PRIVATE)
            .getString("scenario", PreviewScenario.PASS.name)
        val scenario = PreviewScenario.entries.firstOrNull { it.name == name } ?: PreviewScenario.PASS
        state.value = PreviewFixtures.state(scenario)
        if (scenario == PreviewScenario.REPLAY) {
            viewModelScope.launch {
                for (progress in 0..990 step 10) {
                    state.update { current ->
                        val frame = PreviewFixtures.running(progress)
                        PreviewFixtures.preserveUserState(frame, current)
                    }
                    delay(120)
                }
                state.update { current ->
                    val completed = PreviewFixtures.state(PreviewScenario.PASS)
                    PreviewFixtures.withCloud(PreviewFixtures.preserveUserState(completed, current),
                        current.steps[CLOUD_LAYER].cloudState ?: CloudAttestationState.DISABLED)
                }
                if (state.value.cloudAttestationEnabled) simulateCloud(true)
            }
        }
    }

    fun toggleStep(index: Int) {
        state.update { current -> current.updateStep(index) { it.copy(expanded = !it.expanded) } }
    }

    @Suppress("UNUSED_PARAMETER")
    fun setCloudAttestationEnabled(context: Context, enabled: Boolean) {
        simulateCloud(enabled)
    }

    private fun simulateCloud(enabled: Boolean) {
        cloudJob?.cancel()
        if (!enabled) {
            state.update { PreviewFixtures.withCloud(it, CloudAttestationState.DISABLED) }
            return
        }
        val local = state.value.steps.filter { it.index <= LOCAL_LAST_LAYER }
        if (local.any { it.state != ScanState.PASS }) {
            val waiting = local.any { it.state == ScanState.IDLE || it.state == ScanState.RUNNING }
            state.update { PreviewFixtures.withCloud(it,
                if (waiting) CloudAttestationState.WAITING else CloudAttestationState.SKIPPED) }
            return
        }
        state.update { PreviewFixtures.withCloud(it, CloudAttestationState.VERIFYING) }
        cloudJob = viewModelScope.launch {
            delay(900)
            state.update { PreviewFixtures.withCloud(it, CloudAttestationState.PASSED) }
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun fetchRevocationList(context: Context) {
        if (state.value.fetchingRevocationList) return
        state.update { it.copy(fetchingRevocationList = true) }
        viewModelScope.launch {
            delay(900)
            state.update { it.copy(fetchingRevocationList = false,
                revocationListText = "上次获取最新证书吊销列表：2026-09-12 12:00:00",
                revocationCountText = "吊销证书总数：1736",
                lastToast = "UI PREVIEW · 示例数据 / Sample data") }
        }
    }

    fun consumeToast() { state.update { it.copy(lastToast = null) } }

    companion object {
        const val DEFAULT_REVOCATION_COUNT = 1736
        const val DEVICE_LAYER = 0
        const val SYSTEM_LAYER = 1
        const val HARDWARE_LAYER = 2
        const val LOCAL_LAST_LAYER = 2
        const val CLOUD_LAYER = 3
        val STEP_TITLES = listOf("设备环境", "系统完整性", "硬件证明", "云端证明")
        val STEP_SUBTITLES = listOf("对设备环境进行检测", "对系统完整性进行校验",
            "通过设备硬件进行校验", "未启用云端检测")
    }
}

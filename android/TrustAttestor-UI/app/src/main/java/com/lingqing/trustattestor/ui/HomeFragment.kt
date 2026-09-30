package com.lingqing.trustattestor.ui

import android.app.Dialog
import android.animation.Animator
import android.animation.ObjectAnimator
import android.animation.TimeInterpolator
import android.animation.ValueAnimator
import android.graphics.drawable.Drawable
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.SystemClock
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.RelativeSizeSpan
import android.text.style.StyleSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.color.MaterialColors
import com.google.android.material.button.MaterialButton
import com.lingqing.trustattestor.BuildConfig
import com.lingqing.trustattestor.CloudAttestationState
import com.lingqing.trustattestor.CloudDisclosure
import com.lingqing.trustattestor.ForensicReportCodec
import com.lingqing.trustattestor.FindingTextCatalog
import com.lingqing.trustattestor.MainViewModel
import com.lingqing.trustattestor.FindingStatus
import com.lingqing.trustattestor.R
import com.lingqing.trustattestor.ScanState
import com.lingqing.trustattestor.StepUi
import com.lingqing.trustattestor.UiState
import com.lingqing.trustattestor.databinding.FragmentHomeBinding
import com.lingqing.trustattestor.databinding.ItemEvidenceBinding
import com.lingqing.trustattestor.databinding.ItemStepBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!
    private val viewModel: MainViewModel by activityViewModels()
    private val interpolator: TimeInterpolator = AccelerateDecelerateInterpolator()
    private var pendingReportJson: String? = null
    private val exportReportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        val report = pendingReportJson
        pendingReportJson = null
        if (uri == null || report == null) return@registerForActivityResult
        lifecycleScope.launch(Dispatchers.IO) {
            val saved = runCatching {
                val output = requireContext().contentResolver.openOutputStream(uri)
                    ?: error("Unable to open destination")
                output.bufferedWriter(Charsets.UTF_8).use { it.write(report) }
            }.isSuccess
            withContext(Dispatchers.Main.immediate) {
                if (!isAdded) return@withContext
                Toast.makeText(
                    requireContext(),
                    if (saved) R.string.export_report_saved else R.string.export_report_failed,
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    private val previousStepStates = mutableMapOf<Int, ScanState>()
    private val renderedEvidenceKeys = mutableMapOf<Int, Int>()
    private val stepBindings = mutableListOf<ItemStepBinding>()
    private var lastRenderedState: UiState? = null
    private var topologyRailSyncPosted = false
    private var pendingUiState: UiState? = null
    private var uiRenderScheduled = false
    private var lastUiRenderUptimeMillis = 0L
    private var lastHeroIndicatorTarget = Float.NaN
    private var stepPalette: StepPalette? = null
    private var cloudDisclosureDialog: Dialog? = null
    private var cloudDisclosureCountdownJob: Job? = null
    private val uiRenderRunnable = Runnable {
        uiRenderScheduled = false
        val state = pendingUiState ?: return@Runnable
        pendingUiState = null
        if (_binding == null) return@Runnable
        renderUiState(state)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        binding.btnExportReport.applyPressMotion(pressedScale = 0.992f)
        binding.btnExportReport.setOnClickListener { launchReportExport() }
        binding.stepContainer.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
            scheduleTopologyRailSync()
        }
        binding.heroIndicatorFill.post {
            binding.heroIndicatorFill.pivotX = 0f
            binding.heroIndicatorFill.pivotY = binding.heroIndicatorFill.height / 2f
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                viewModel.uiState.collect { state ->
                    enqueueUiState(state)
                }
            }
        }
    }

    private fun enqueueUiState(state: UiState) {
        if (_binding == null) return
        val rendered = lastRenderedState
        val mustRenderImmediately = rendered == null ||
            rendered.scanning != state.scanning ||
            (rendered.summaryStatus != state.summaryStatus && state.summaryStatus != ScanState.RUNNING)
        pendingUiState = state
        if (mustRenderImmediately) {
            binding.root.removeCallbacks(uiRenderRunnable)
            uiRenderScheduled = false
            pendingUiState = null
            renderUiState(state)
            return
        }
        if (uiRenderScheduled) return

        val elapsed = SystemClock.uptimeMillis() - lastUiRenderUptimeMillis
        val delayMillis = (MIN_UI_RENDER_INTERVAL_MILLIS - elapsed).coerceAtLeast(0L)
        uiRenderScheduled = true
        binding.root.postDelayed(uiRenderRunnable, delayMillis)
    }

    private fun renderUiState(state: UiState) {
        val previous = lastRenderedState
        val summaryTitle = masterStatusTitle(state)
        setAnimatedText(
            binding.tvSummaryTitle,
            summaryTitle,
            distanceDp = 5f,
            animate = previous != null && previous.summaryStatus != state.summaryStatus
        )
        binding.tvSummaryText.isVisible = true
        val meta = summaryMeta(state)
        if (binding.tvSummaryText.text.toString() != meta) binding.tvSummaryText.text = meta
        if (previous == null || previous.scanning != state.scanning ||
            previous.progressText != state.progressText) {
            updateProgressChip(state)
        }
        if (previous == null || previous.deviceInfo != state.deviceInfo) updateTelemetry(state)
        if (previous == null || previous.scanning != state.scanning) {
            binding.progressTop.isVisible = state.scanning
            binding.ivSummaryStatus.isVisible = !state.scanning
        }
        if (previous?.summaryStatus != state.summaryStatus) {
            binding.ivSummaryStatus.setImageResource(
                when (state.summaryStatus) {
                    ScanState.PASS -> R.drawable.ic_state_pass
                    ScanState.FAIL -> R.drawable.ic_state_fail
                    ScanState.RUNNING -> R.drawable.ic_state_running
                    ScanState.IDLE -> R.drawable.ic_state_idle
                }
            )
            renderHeroChrome(state.summaryStatus)
            playSummaryStateTransition(state.summaryStatus)
        }
        if (previous == null || previous.scanning != state.scanning ||
            previous.summaryStatus != state.summaryStatus ||
            previous.overallProgressPermille != state.overallProgressPermille) {
            updateHeroIndicator(state)
        }
        if (previous == null || stepsVisuallyDiffer(previous.steps, state.steps)) {
            renderSteps(state.steps, previous?.steps)
        }
        lastRenderedState = state
        lastUiRenderUptimeMillis = SystemClock.uptimeMillis()
    }

    private fun masterStatusTitle(state: UiState): String {
        val elapsed = "${state.elapsedDurationText.toDoubleOrNull() ?: 0.0}s"
        return when (state.summaryStatus) {
            ScanState.IDLE -> getString(R.string.home_summary_idle)
            ScanState.RUNNING -> getString(R.string.home_summary_running, elapsed)
            ScanState.PASS -> getString(R.string.home_summary_pass, elapsed)
            ScanState.FAIL -> if (state.abnormalCount > 0) {
                getString(R.string.home_summary_fail, state.abnormalCount, elapsed)
            } else {
                getString(R.string.home_summary_incomplete, elapsed)
            }
        }
    }

    private fun summaryMeta(state: UiState): String {
        val activeSteps = state.steps.filterNot {
            it.index == MainViewModel.CLOUD_LAYER && it.cloudState == CloudAttestationState.DISABLED
        }
        if (state.summaryStatus == ScanState.IDLE) {
            return getString(R.string.home_meta_idle, activeSteps.size)
        }
        val passedCount = activeSteps.sumOf(::passedCheckCount)
        return getString(
            R.string.home_meta_result,
            activeSteps.size,
            passedCount,
            state.abnormalCount
        )
    }

    private fun passedCheckCount(step: StepUi): Int {
        if (step.index == MainViewModel.CLOUD_LAYER) {
            if (step.cloudState != CloudAttestationState.PASSED) return 0
            return step.findings.count { it.status == FindingStatus.CLEAN }.coerceAtLeast(1)
        }
        if (step.state != ScanState.PASS && step.state != ScanState.FAIL) return 0

        val nonPassingCount = step.findings
            .asSequence()
            .filter { it.status != FindingStatus.CLEAN }
            .distinctBy { it.probeId }
            .count()
        if (step.completedCheckIds.isNotEmpty()) {
            return (step.completedCheckIds.size - nonPassingCount).coerceAtLeast(0)
        }
        return if (step.state == ScanState.PASS) 1 else 0
    }

    override fun onResume() {
        super.onResume()
        if (_binding == null) return
        enqueueUiState(viewModel.uiState.value)
    }

    private fun updateProgressChip(state: UiState) {
        val shouldShow = state.scanning && state.progressText.isNotBlank()
        val wasVisible = binding.tvProgress.isVisible
        binding.tvProgress.isVisible = shouldShow
        if (!shouldShow) {
            binding.tvProgress.animate().cancel()
            binding.tvProgress.translationY = 0f
            return
        }

        // Progress events may arrive faster than a text transition can finish.
        // Update the value synchronously so cancelling an animation can never
        // leave the previous progress label on screen.
        if (binding.tvProgress.text.toString() != state.progressText) {
            binding.tvProgress.text = state.progressText
        }

        if (!wasVisible) {
            binding.tvProgress.animate().cancel()
            binding.tvProgress.alpha = 1f
            binding.tvProgress.translationY = binding.root.dp(8f)
            binding.tvProgress.animate()
                .translationY(0f)
                .setDuration(220)
                .start()
        }

    }

    private fun setAnimatedText(view: TextView, newValue: String, distanceDp: Float = 6f, animate: Boolean = true) {
        if (view.text.toString() == newValue) return
        val hadText = !view.text.isNullOrBlank()
        view.animate().cancel()
        view.text = newValue
        if (!animate || !hadText) {
            view.alpha = 1f
            view.translationY = 0f
            return
        }

        view.alpha = 0.35f
        view.translationY = binding.root.dp(distanceDp)
        view.animate()
            .alpha(1f)
            .translationY(0f)
            .setDuration(200)
            .setInterpolator(OvershootInterpolator(0.72f))
            .start()
    }

    private fun renderHeroChrome(state: ScanState) {
        val accentColor = when (state) {
            ScanState.PASS -> ContextCompat.getColor(requireContext(), R.color.ta_success)
            ScanState.FAIL -> ContextCompat.getColor(requireContext(), R.color.ta_error)
            ScanState.RUNNING -> ContextCompat.getColor(requireContext(), R.color.ta_running)
            ScanState.IDLE -> ContextCompat.getColor(requireContext(), R.color.ta_idle)
        }
        val surface = ContextCompat.getColor(requireContext(), R.color.ta_surface)
        val textColor = ContextCompat.getColor(requireContext(), R.color.ta_text)

        tintGlass(binding.heroIndicatorTrack.background, surface, accentColor, 0.10f, 38)

        binding.tvSummaryTitle.setTextColor(if (state == ScanState.IDLE) textColor else accentColor)
        binding.tvProgress.setTextColor(accentColor)
        binding.ivSummaryStatus.setColorFilter(accentColor)
        binding.heroIndicatorFill.background.mutate().alpha = when (state) {
            ScanState.FAIL -> 255
            ScanState.PASS -> 245
            ScanState.RUNNING -> 255
            ScanState.IDLE -> 220
        }
    }

    private fun updateHeroIndicator(state: UiState) {
        val target = when {
            state.scanning -> 0.08f + (state.overallProgressPermille / 1000f) * 0.92f
            state.summaryStatus == ScanState.PASS || state.summaryStatus == ScanState.FAIL -> 1f
            else -> 0.14f
        }
        animateIndicatorTo(target)
    }

    private fun animateIndicatorTo(target: Float) {
        val normalized = target.coerceIn(0.08f, 1f)
        if (!lastHeroIndicatorTarget.isNaN() &&
            kotlin.math.abs(lastHeroIndicatorTarget - normalized) < 0.004f) return
        lastHeroIndicatorTarget = normalized
        binding.heroIndicatorFill.animate().cancel()
        binding.heroIndicatorFill.animate()
            .scaleX(normalized)
            .setDuration(110)
            .setInterpolator(interpolator)
            .start()
    }

    private fun playSummaryStateTransition(state: ScanState) {
        when (state) {
            ScanState.PASS,
            ScanState.FAIL -> {
                binding.heroCard.playPop(scaleTo = 1.014f, duration = 320)
                binding.summaryIconCard.playPop(scaleTo = 1.12f, duration = 320)
            }
            ScanState.RUNNING,
            ScanState.IDLE -> Unit
        }
    }

    private fun tintGlass(background: Drawable?, surface: Int, accentColor: Int, alpha: Float, strokeAlpha: Int) {
        (background?.mutate() as? GradientDrawable)?.apply {
            setColor(MaterialColors.layer(surface, accentColor, alpha))
            setStroke(1, MaterialColors.compositeARGBWithAlpha(accentColor, strokeAlpha))
        }
    }

    private fun updateTelemetry(state: UiState) {
        fun valueAt(index: Int) = state.deviceInfo.getOrNull(index)?.value?.ifBlank { "--" } ?: "--"

        val abiValues = valueAt(4)
            .split(" / ")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        val primaryAbi = abiValues.firstOrNull() ?: "--"
        val extraAbiCount = (abiValues.size - 1).coerceAtLeast(0)
        val compactAbi = if (extraAbiCount > 0) {
            "$primaryAbi (+$extraAbiCount 32-bit ABI)"
        } else {
            primaryAbi
        }

        setTelemetryValue(binding.tvTelemetryAbi, "ABI", compactAbi)
        setTelemetryValue(binding.tvTelemetryModel, "MOD", valueAt(1))
        setTelemetryValue(binding.tvTelemetryOs, "OS", valueAt(2))
        setTelemetryValue(binding.tvTelemetrySpl, "SPL", valueAt(3))
        setTelemetryValue(binding.tvTelemetryBuild, "BUILD", valueAt(5))
    }

    private fun setTelemetryValue(view: TextView, key: String, value: String) {
        val separator = " ".repeat((6 - key.length).coerceAtLeast(1))
        val label = "$key$separator"
        val styled = SpannableString("$label$value")
        val keyColor = ContextCompat.getColor(requireContext(), R.color.ta_telemetry_key)
        val valueColor = ContextCompat.getColor(requireContext(), R.color.ta_telemetry_value)
        styled.setSpan(ForegroundColorSpan(keyColor), 0, key.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        styled.setSpan(StyleSpan(android.graphics.Typeface.BOLD), 0, key.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        styled.setSpan(RelativeSizeSpan(0.92f), 0, key.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        styled.setSpan(
            ForegroundColorSpan(valueColor),
            label.length,
            styled.length,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        view.text = styled
    }

    private fun renderSteps(items: List<StepUi>, previousItems: List<StepUi>? = null) {
        val rebuilt = binding.stepContainer.childCount != items.size ||
            stepBindings.size != items.size
        if (rebuilt) {
            binding.stepContainer.removeAllViews()
            renderedEvidenceKeys.clear()
            stepBindings.clear()
            repeat(items.size) {
                val itemBinding = ItemStepBinding.inflate(layoutInflater, binding.stepContainer, false)
                stepBindings += itemBinding
                binding.stepContainer.addView(itemBinding.root)
            }
        }

        val palette = stepPalette ?: StepPalette(
            surface = ContextCompat.getColor(requireContext(), R.color.ta_surface),
            success = ContextCompat.getColor(requireContext(), R.color.ta_success),
            error = ContextCompat.getColor(requireContext(), R.color.ta_error),
            running = ContextCompat.getColor(requireContext(), R.color.ta_running),
            cloud = ContextCompat.getColor(requireContext(), R.color.ta_cloud),
            warning = ContextCompat.getColor(requireContext(), R.color.ta_warning),
            idle = ContextCompat.getColor(requireContext(), R.color.ta_idle),
            detailSurface = ContextCompat.getColor(requireContext(), R.color.ta_background)
        ).also { stepPalette = it }
        binding.trustChainRail.setNodeStates(items.map(::railNodeState))

        items.forEachIndexed { index, item ->
            if (!rebuilt && previousItems?.getOrNull(index)?.let { stepsVisuallyEqual(it, item) } == true) {
                return@forEachIndexed
            }
            val itemBinding = stepBindings[index]
            if (rebuilt) {
                itemBinding.tvTitle.text = FindingTextCatalog.layerTitle(requireContext(), item.index)
                itemBinding.tvStepIndex.text = "L${item.index}"
                itemBinding.tvEvidenceSource.setText(when (item.index) {
                    MainViewModel.DEVICE_LAYER -> R.string.source_device
                    MainViewModel.SYSTEM_LAYER -> R.string.source_system
                    MainViewModel.HARDWARE_LAYER -> R.string.source_hardware
                    else -> R.string.source_cloud
                })
                itemBinding.header.applyPressMotion(target = itemBinding.root, pressedScale = 0.992f)
                itemBinding.header.setOnClickListener { focusStep(item.index) }
                itemBinding.ivArrow.setOnClickListener { focusStep(item.index) }
                if (item.index == MainViewModel.CLOUD_LAYER) {
                    itemBinding.tvCloudToggle.applyPressMotion(pressedScale = 0.97f)
                    itemBinding.tvCloudToggle.setOnClickListener { requestCloudAttestationToggle() }
                }
            }
            val subtitle = localizedStepSubtitle(item)
            if (itemBinding.tvSubtitle.text.toString() != subtitle) {
                itemBinding.tvSubtitle.text = subtitle
            }
            bindCloudToggle(itemBinding, item, palette.surface, palette.success, palette.idle)
            val hasWarning = item.findings.any { it.status == FindingStatus.WARNING }
            val hasUnavailable = item.findings.any { it.status == FindingStatus.UNAVAILABLE }
            val hasDetected = item.findings.any { it.status == FindingStatus.DETECTED }
            val chipText = item.cloudState?.badge ?: when {
                hasDetected -> "BREACH"
                hasUnavailable -> "UNAVAILABLE"
                hasWarning -> "WARNING"
                item.state == ScanState.IDLE -> "STANDBY"
                item.state == ScanState.RUNNING -> {
                    val percent = ((item.progressPermille / 50) * 5).coerceIn(0, 100)
                    "RUN $percent%"
                }
                item.state == ScanState.PASS -> "PASS"
                else -> "UNAVAILABLE"
            }
            if (itemBinding.tvChip.text.toString() != chipText) itemBinding.tvChip.text = chipText
            itemBinding.progressSmall.isVisible = item.state == ScanState.RUNNING ||
                item.cloudState == CloudAttestationState.VERIFYING
            itemBinding.nodeDot.isVisible = item.state != ScanState.RUNNING &&
                item.cloudState != CloudAttestationState.VERIFYING

            val accentColor = when (item.cloudState) {
                CloudAttestationState.VERIFYING -> palette.cloud
                CloudAttestationState.PASSED -> palette.success
                CloudAttestationState.BREACH -> palette.error
                CloudAttestationState.WARNING -> palette.warning
                CloudAttestationState.DISABLED,
                CloudAttestationState.WAITING,
                CloudAttestationState.SKIPPED,
                CloudAttestationState.UNAVAILABLE -> palette.idle
                null -> when {
                    hasDetected -> palette.error
                    hasWarning -> palette.warning
                    hasUnavailable -> palette.idle
                    item.state == ScanState.PASS -> palette.success
                    item.state == ScanState.RUNNING -> palette.running
                    else -> palette.idle
                }
            }

            if (itemBinding.root.getTag(R.id.tag_step_accent) != accentColor) {
                (itemBinding.nodeHalo.background.mutate() as? GradientDrawable)?.apply {
                    setColor(ColorUtils.setAlphaComponent(accentColor, 34))
                    setStroke(
                        binding.root.dp(1f).toInt().coerceAtLeast(1),
                        ColorUtils.setAlphaComponent(accentColor, 112)
                    )
                }
                (itemBinding.nodeCore.background.mutate() as? GradientDrawable)?.apply {
                    setColor(accentColor)
                    setStroke(binding.root.dp(1f).toInt().coerceAtLeast(1), palette.surface)
                }
                (itemBinding.tvChip.background.mutate() as? GradientDrawable)?.apply {
                    setColor(palette.surface)
                    setStroke(1, MaterialColors.compositeARGBWithAlpha(accentColor, 150))
                }
                (itemBinding.detailContainer.background.mutate() as? GradientDrawable)?.apply {
                    setColor(palette.detailSurface)
                    setStroke(1, MaterialColors.compositeARGBWithAlpha(accentColor, 42))
                }
                itemBinding.tvChip.setTextColor(accentColor)
                itemBinding.tvStepIndex.setTextColor(accentColor)
                itemBinding.ivArrow.setColorFilter(MaterialColors.compositeARGBWithAlpha(accentColor, 170))
                itemBinding.root.setTag(R.id.tag_step_accent, accentColor)
            }
            itemBinding.header.alpha = when (item.cloudState) {
                CloudAttestationState.DISABLED -> 0.48f
                CloudAttestationState.WAITING,
                CloudAttestationState.SKIPPED -> 0.68f
                else -> 1f
            }

            val previousState = previousStepStates[item.index]
            if (previousState != null && previousState != item.state) {
                itemBinding.root.alpha = 1f
                itemBinding.nodeDot.playPop(scaleTo = 1.2f, duration = 240)
            }
            previousStepStates[item.index] = item.state
            if (rebuilt || previousState != item.state) {
                updateStepMotion(itemBinding, item)
            }

            val shouldShow = item.expanded
            val currentlyVisible = itemBinding.detailContainer.isVisible
            if (shouldShow) {
                val renderKey = evidenceRenderKey(item)
                if (renderedEvidenceKeys[item.index] != renderKey) {
                    renderEvidenceRows(itemBinding, item)
                    renderedEvidenceKeys[item.index] = renderKey
                }
            }
            if (shouldShow != currentlyVisible) {
                animateExpansion(itemBinding, shouldShow)
            } else {
                itemBinding.detailContainer.visibility = if (shouldShow) View.VISIBLE else View.GONE
                itemBinding.ivArrow.rotation = if (shouldShow) 180f else 0f
                itemBinding.detailContainer.translationY = 0f
                itemBinding.detailContainer.alpha = 1f
            }
        }

    }

    private fun stepsVisuallyDiffer(previous: List<StepUi>, current: List<StepUi>): Boolean {
        if (previous.size != current.size) return true
        return current.indices.any { index ->
            !stepsVisuallyEqual(previous[index], current[index])
        }
    }

    private fun stepsVisuallyEqual(previous: StepUi, current: StepUi): Boolean {
        if (previous.index != current.index ||
            previous.state != current.state ||
            previous.cloudState != current.cloudState ||
            previous.findings != current.findings ||
            previous.expanded != current.expanded ||
            previous.progressPermille != current.progressPermille ||
            previous.durationMillis != current.durationMillis
        ) {
            return false
        }
        val active = current.state == ScanState.RUNNING ||
            current.cloudState == CloudAttestationState.VERIFYING
        return !current.expanded || active || previous.detail == current.detail
    }

    private fun evidenceRenderKey(item: StepUi): Int {
        val language = resources.configuration.locales[0].toLanguageTag()
        val active = item.state == ScanState.RUNNING ||
            item.cloudState == CloudAttestationState.VERIFYING
        if (active) {
            return arrayOf(language, item.index, item.state, item.cloudState).contentHashCode()
        }
        return arrayOf(
            language,
            item.state,
            item.cloudState,
            item.detail,
            item.findings,
        ).contentHashCode()
    }

    private fun bindCloudToggle(
        itemBinding: ItemStepBinding,
        item: StepUi,
        surface: Int,
        enabledColor: Int,
        disabledColor: Int
    ) {
        val isCloudLayer = item.index == MainViewModel.CLOUD_LAYER
        itemBinding.cloudToggleBlock.isVisible = isCloudLayer
        if (!isCloudLayer) return

        val enabled = item.cloudState != CloudAttestationState.DISABLED
        val accent = if (enabled) enabledColor else disabledColor
        itemBinding.tvCloudToggle.apply {
            setText(if (enabled) R.string.cloud_badge_toggle_on else R.string.cloud_badge_toggle_off)
            setTextColor(accent)
            contentDescription = getString(
                R.string.cloud_attestation_switch_state,
                if (enabled) getString(R.string.cloud_state_on) else getString(R.string.cloud_state_off)
            )
            (background.mutate() as? GradientDrawable)?.apply {
                setColor(surface)
                setStroke(1, MaterialColors.compositeARGBWithAlpha(accent, if (enabled) 190 else 110))
            }
        }
        itemBinding.tvCloudToggleHint.setText(
            if (BuildConfig.DEBUG) {
                R.string.cloud_attestation_hint_compact_debug
            } else {
                R.string.cloud_attestation_hint_compact
            }
        )
    }

    private fun scheduleTopologyRailSync() {
        if (_binding == null || topologyRailSyncPosted) return
        topologyRailSyncPosted = true
        binding.trustChainRail.post {
            topologyRailSyncPosted = false
            if (_binding != null) syncTopologyRail()
        }
    }

    private fun syncTopologyRail() {
        if (_binding == null) return
        val rail = binding.trustChainRail
        if (binding.stepContainer.childCount < 2) {
            rail.isVisible = false
            return
        }
        val density = rail.resources.displayMetrics.density
        val centers = (0 until binding.stepContainer.childCount).mapNotNull { index ->
            val step = binding.stepContainer.getChildAt(index) ?: return@mapNotNull null
            val header = step.findViewById<View>(R.id.header)
            val nodeDot = step.findViewById<View>(R.id.nodeDot)
            val centerInContainer = step.top + if (nodeDot != null && nodeDot.height > 0) {
                nodeDot.top + nodeDot.height / 2f
            } else {
                (header?.height?.coerceAtLeast(0) ?: (48f * density).toInt()) / 2f
            }
            centerInContainer - rail.top
        }
        if (centers.size < 2) {
            rail.isVisible = false
            return
        }
        val lineHeight = centers.last().coerceAtLeast(0f).roundToInt()
        rail.isVisible = true
        if (rail.layoutParams.height != lineHeight) {
            rail.layoutParams = rail.layoutParams.apply { height = lineHeight }
        }
        rail.setNodeCenters(centers)
        rail.scaleY = 1f
    }

    private fun railNodeState(item: StepUi): TopologyRailView.NodeState {
        return when (item.cloudState) {
            CloudAttestationState.PASSED -> TopologyRailView.NodeState.SUCCESS
            CloudAttestationState.VERIFYING -> TopologyRailView.NodeState.ACTIVE
            CloudAttestationState.BREACH,
            CloudAttestationState.WARNING -> TopologyRailView.NodeState.ALERT
            CloudAttestationState.DISABLED,
            CloudAttestationState.WAITING,
            CloudAttestationState.SKIPPED,
            CloudAttestationState.UNAVAILABLE -> TopologyRailView.NodeState.MUTED
            null -> when {
                item.findings.any { it.status == FindingStatus.DETECTED } ->
                    TopologyRailView.NodeState.ALERT
                item.findings.any { it.status == FindingStatus.WARNING } ->
                    TopologyRailView.NodeState.ALERT
                item.findings.any { it.status == FindingStatus.UNAVAILABLE } ->
                    TopologyRailView.NodeState.MUTED
                item.state == ScanState.PASS -> TopologyRailView.NodeState.SUCCESS
                item.state == ScanState.RUNNING -> TopologyRailView.NodeState.ACTIVE
                else -> TopologyRailView.NodeState.MUTED
            }
        }
    }

    private fun updateStepMotion(itemBinding: ItemStepBinding, item: StepUi) {
        (itemBinding.nodeDot.getTag(R.id.tag_step_icon_anim) as? Animator)?.cancel()
        itemBinding.nodeDot.setTag(R.id.tag_step_icon_anim, null)
        (itemBinding.tvChip.getTag(R.id.tag_step_icon_anim) as? Animator)?.cancel()
        itemBinding.tvChip.setTag(R.id.tag_step_icon_anim, null)
        itemBinding.nodeDot.scaleX = 1f
        itemBinding.nodeDot.scaleY = 1f
        itemBinding.nodeDot.alpha = 1f
        itemBinding.tvChip.scaleX = 1f
        itemBinding.tvChip.scaleY = 1f
        itemBinding.tvChip.alpha = 1f

        itemBinding.root.animate().translationY(0f).setDuration(180).start()
        if (item.cloudState == CloudAttestationState.VERIFYING) {
            ObjectAnimator.ofFloat(itemBinding.tvChip, View.ALPHA, 1f, 0.48f, 1f).apply {
                duration = 900L
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.RESTART
                start()
                itemBinding.tvChip.setTag(R.id.tag_step_icon_anim, this)
            }
        }
    }

    private fun focusStep(index: Int) {
        viewModel.toggleStep(index)
    }

    private fun requestCloudAttestationToggle() {
        val enabled = viewModel.uiState.value.cloudAttestationEnabled
        when {
            enabled -> viewModel.setCloudAttestationEnabled(requireContext(), false)
            CloudDisclosure.hasAccepted(requireContext()) ->
                viewModel.setCloudAttestationEnabled(requireContext(), true)
            else -> showCloudDisclosureDialog()
        }
    }

    private fun showCloudDisclosureDialog() {
        if (cloudDisclosureDialog?.isShowing == true || _binding == null) return

        val dialog = Dialog(requireContext())
        val dialogView = layoutInflater.inflate(R.layout.dialog_user_agreement, null)
        dialog.setContentView(dialogView)
        dialog.window?.setBackgroundDrawable(ColorDrawable(android.graphics.Color.TRANSPARENT))
        dialog.window?.setDimAmount(0.32f)
        dialog.setCancelable(true)
        dialog.setCanceledOnTouchOutside(false)

        val dialogCard = dialogView.findViewById<View>(R.id.agreementCard)
        val titleView = dialogView.findViewById<TextView>(R.id.tvAgreementTitle)
        val subtitleView = dialogView.findViewById<TextView>(R.id.tvAgreementSubtitle)
        val metaView = dialogView.findViewById<TextView>(R.id.tvAgreementUpdatedAt)
        val introView = dialogView.findViewById<TextView>(R.id.tvAgreementIntro)
        val gateContainer = dialogView.findViewById<View>(R.id.agreementGateContainer)
        val gateHintView = dialogView.findViewById<TextView>(R.id.tvAgreementGateHint)
        val timerChip = dialogView.findViewById<TextView>(R.id.tvAgreementTimerChip)
        val gateSpacer = dialogView.findViewById<View>(R.id.agreementGateSpacer)
        val scrollChip = dialogView.findViewById<TextView>(R.id.tvAgreementScrollChip)
        val progressView = dialogView.findViewById<View>(R.id.vAgreementReadProgress)
        val agreementContent = dialogView.findViewById<TextView>(R.id.tvAgreementContent)
        val footerHintView = dialogView.findViewById<TextView>(R.id.tvAgreementFooterHint)
        val cancelButton = dialogView.findViewById<MaterialButton>(R.id.btnAgreementCancel)
        val actionButton = dialogView.findViewById<MaterialButton>(R.id.btnAgreementAction)

        titleView.setText(R.string.cloud_disclosure_title)
        subtitleView.setText(R.string.cloud_disclosure_subtitle)
        metaView.setText(R.string.cloud_disclosure_meta)
        introView.setText(R.string.cloud_disclosure_intro)
        gateContainer.isVisible = true
        gateHintView.setText(R.string.cloud_disclosure_gate_hint)
        gateSpacer.isVisible = false
        scrollChip.isVisible = false
        agreementContent.setText(R.string.cloud_disclosure_content)
        footerHintView.setText(R.string.cloud_disclosure_footer)
        cancelButton.isVisible = true
        cancelButton.applyPressMotion(pressedScale = 0.988f)
        actionButton.applyPressMotion(pressedScale = 0.988f)

        var remainingSeconds = CLOUD_DISCLOSURE_READ_SECONDS
        fun updateCountdownUi() {
            val complete = remainingSeconds <= 0
            timerChip.setText(
                if (complete) R.string.cloud_disclosure_timer_done
                else R.string.cloud_disclosure_timer_remaining
            )
            if (!complete) {
                timerChip.text = getString(
                    R.string.cloud_disclosure_timer_remaining,
                    remainingSeconds
                )
            }
            timerChip.setBackgroundResource(
                if (complete) R.drawable.bg_agreement_gate_chip_active
                else R.drawable.bg_agreement_gate_chip
            )
            timerChip.setTextColor(
                ContextCompat.getColor(
                    requireContext(),
                    if (complete) R.color.ta_success else R.color.ta_text_secondary
                )
            )
            actionButton.isEnabled = complete
            actionButton.alpha = if (complete) 1f else 0.72f
            actionButton.text = if (complete) {
                getString(R.string.cloud_disclosure_action_enable)
            } else {
                getString(R.string.cloud_disclosure_action_wait, remainingSeconds)
            }
            progressView.scaleX = (
                (CLOUD_DISCLOSURE_READ_SECONDS - remainingSeconds).toFloat() /
                    CLOUD_DISCLOSURE_READ_SECONDS.toFloat()
                ).coerceIn(0f, 1f)
        }
        updateCountdownUi()

        cancelButton.setOnClickListener { dialog.dismiss() }
        actionButton.setOnClickListener {
            if (remainingSeconds > 0) return@setOnClickListener
            CloudDisclosure.markAccepted(requireContext())
            viewModel.setCloudAttestationEnabled(requireContext(), true)
            dialog.dismiss()
        }
        dialog.setOnDismissListener {
            cloudDisclosureCountdownJob?.cancel()
            cloudDisclosureCountdownJob = null
            if (cloudDisclosureDialog === dialog) cloudDisclosureDialog = null
        }

        dialog.show()
        val dialogWidth = (resources.displayMetrics.widthPixels * 0.92f).toInt()
        val dialogHeight = (resources.displayMetrics.heightPixels * 0.88f).toInt()
        dialog.window?.setLayout(dialogWidth, dialogHeight)
        cloudDisclosureDialog = dialog
        progressView.post { progressView.pivotX = 0f }

        dialogCard.alpha = 0f
        dialogCard.translationY = binding.root.dp(18f)
        dialogCard.scaleX = 0.972f
        dialogCard.scaleY = 0.972f
        dialogCard.animate()
            .alpha(1f)
            .translationY(0f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(300)
            .start()

        cloudDisclosureCountdownJob = viewLifecycleOwner.lifecycleScope.launch {
            while (remainingSeconds > 0 && dialog.isShowing) {
                if (viewLifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                    delay(1_000L)
                    if (dialog.isShowing &&
                        viewLifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
                    ) {
                        remainingSeconds--
                        updateCountdownUi()
                    }
                } else {
                    delay(250L)
                }
            }
        }
    }

    private fun launchReportExport() {
        val timestamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        pendingReportJson = ForensicReportCodec.encode(requireContext(), viewModel.uiState.value)
        exportReportLauncher.launch("TrustAttestor-forensic-$timestamp.json")
    }

    private fun formatStepDuration(durationMillis: Long): String {
        return if (durationMillis < 1000L) {
            "${durationMillis.coerceAtLeast(0L)}ms"
        } else {
            String.format(java.util.Locale.US, "%.1fs", durationMillis / 1000.0)
        }
    }

    private fun localizedFindings(item: StepUi) = item.findings.map { finding ->
        FindingTextCatalog.localize(requireContext(), finding)
    }

    private fun localizedStepSubtitle(item: StepUi): String {
        val textRes = if (item.index == MainViewModel.CLOUD_LAYER) {
            when (item.cloudState) {
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
        } else {
            val unavailableOnly = item.findings.any { it.status == FindingStatus.UNAVAILABLE } &&
                item.findings.none { it.status == FindingStatus.DETECTED }
            if (unavailableOnly) {
                R.string.step_probe_unavailable
            } else when (item.state) {
                ScanState.RUNNING -> when (item.index) {
                    MainViewModel.DEVICE_LAYER -> R.string.step_device_running
                    MainViewModel.SYSTEM_LAYER -> R.string.step_system_running
                    else -> R.string.step_hardware_running
                }
                ScanState.PASS -> when (item.index) {
                    MainViewModel.DEVICE_LAYER -> R.string.step_device_pass
                    MainViewModel.SYSTEM_LAYER -> R.string.step_system_pass
                    else -> R.string.step_hardware_pass
                }
                ScanState.FAIL -> when (item.index) {
                    MainViewModel.DEVICE_LAYER -> R.string.step_device_fail
                    MainViewModel.SYSTEM_LAYER -> R.string.step_system_fail
                    else -> R.string.step_hardware_fail
                }
                ScanState.IDLE -> R.string.home_summary_idle
            }
        }
        return buildString {
            append(getString(textRes))
            val activelyRunning = item.state == ScanState.RUNNING ||
                item.cloudState == CloudAttestationState.VERIFYING
            if (!activelyRunning && item.durationMillis > 0L) {
                append(" · ")
                append(formatStepDuration(item.durationMillis))
            }
        }
    }

    private fun renderEvidenceRows(itemBinding: ItemStepBinding, item: StepUi) {
        itemBinding.hardwareEvidence.isVisible = false
        itemBinding.evidenceList.isVisible = true
        itemBinding.evidenceList.removeAllViews()
        if (item.index == MainViewModel.HARDWARE_LAYER) {
            itemBinding.evidenceList.isVisible = false
            itemBinding.hardwareEvidence.isVisible = true
            renderHardwareEvidence(itemBinding, item)
            return
        }
        val activelyRunning = item.state == ScanState.RUNNING &&
            item.index != MainViewModel.CLOUD_LAYER
        val parsedRows = if (activelyRunning) {
            emptyList()
        } else if (item.findings.isNotEmpty()) {
            EvidenceStatusParser.parseFindings(localizedFindings(item))
        } else {
            EvidenceStatusParser.parseRows(item.detail, item.state)
        }
        val rows = if (activelyRunning) {
            listOf(EvidenceRow(localizedStepSubtitle(item), EvidenceStatus.ACTIVE))
        } else when (item.index) {
            MainViewModel.CLOUD_LAYER -> when (item.cloudState) {
                CloudAttestationState.DISABLED -> listOf(EvidenceRow(
                    getString(R.string.step_cloud_disabled),
                    EvidenceStatus.PENDING
                ))
                CloudAttestationState.WAITING -> listOf(EvidenceRow(
                    getString(R.string.step_cloud_waiting),
                    EvidenceStatus.PENDING
                ))
                CloudAttestationState.SKIPPED -> listOf(EvidenceRow(
                    getString(R.string.step_cloud_skipped),
                    EvidenceStatus.PENDING
                ))
                CloudAttestationState.VERIFYING -> listOf(EvidenceRow(
                    getString(R.string.step_cloud_verifying),
                    EvidenceStatus.ACTIVE
                ))
                CloudAttestationState.PASSED -> if (item.findings.any { finding ->
                    finding.serverTitleZh.isNotBlank() || finding.serverTitleEn.isNotBlank()
                }) {
                    parsedRows.filter {
                        it.status == EvidenceStatus.VERIFIED ||
                            it.status == EvidenceStatus.UNAVAILABLE
                    }
                        .ifEmpty { listOf(EvidenceRow(
                            FindingTextCatalog.cleanSummary(
                                requireContext(),
                                MainViewModel.CLOUD_LAYER
                            ),
                            EvidenceStatus.VERIFIED
                        )) }
                } else {
                    listOf(EvidenceRow(
                        FindingTextCatalog.cleanSummary(requireContext(), MainViewModel.CLOUD_LAYER),
                        EvidenceStatus.VERIFIED
                    ))
                }
                CloudAttestationState.BREACH -> parsedRows
                    .filter {
                        it.status == EvidenceStatus.DETECTED ||
                            it.status == EvidenceStatus.UNAVAILABLE
                    }
                    .ifEmpty { listOf(EvidenceRow(getString(R.string.step_cloud_fail), EvidenceStatus.DETECTED)) }
                CloudAttestationState.WARNING -> parsedRows
                    .filter {
                        it.status == EvidenceStatus.WARNING ||
                            it.status == EvidenceStatus.UNAVAILABLE
                    }
                    .ifEmpty { listOf(EvidenceRow(getString(R.string.step_cloud_fail), EvidenceStatus.WARNING)) }
                CloudAttestationState.UNAVAILABLE -> parsedRows
                    .filter { it.status == EvidenceStatus.UNAVAILABLE }
                    .ifEmpty { listOf(EvidenceRow(getString(R.string.step_cloud_fail), EvidenceStatus.UNAVAILABLE)) }
                null -> parsedRows
            }
            else -> parsedRows
        }
        rows.forEach { row ->
            val rowBinding = ItemEvidenceBinding.inflate(layoutInflater, itemBinding.evidenceList, false)
            bindEvidenceRow(rowBinding, row)
            itemBinding.evidenceList.addView(rowBinding.root)
        }
    }

    private fun hardwareDetectionRows(
        item: StepUi,
        parsedRows: List<EvidenceRow>
    ): List<EvidenceRow> {
        val rows = runCatching {
            val detailLines = item.detail.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toList()
            val structuredDetections = parsedRows
                .filter { isVisibleHardwareOutcome(it.status) }
                .map(::withHardwareProbeIdentity)
            val structuredProbeIds = structuredDetections.mapNotNull(EvidenceRow::probeId).toSet()
            val detailedDetections = if (BuildConfig.DEBUG) {
                extractHardwareProbeRows(detailLines, item.state, structuredProbeIds)
                    .filter { isVisibleHardwareOutcome(it.status) }
            } else {
                emptyList()
            }
            val fallbackDetections = extractHardwareFindings(detailLines, item.state)
                .map { withHardwareProbeIdentity(EvidenceRow(it, EvidenceStatus.DETECTED)) }
            mergeHardwareDetections(
                structuredDetections + detailedDetections +
                    if (structuredDetections.isEmpty()) fallbackDetections else emptyList()
            )
        }.getOrElse { error ->
            android.util.Log.e("TrustAttestor", "hardware evidence merge failed", error)
            parsedRows
                .filter { isVisibleHardwareOutcome(it.status) }
                .distinctBy { it.probeId ?: it.label }
        }
        return rows.ifEmpty {
            listOf(EvidenceRow(
                FindingTextCatalog.cleanSummary(requireContext(), MainViewModel.HARDWARE_LAYER),
                EvidenceStatus.VERIFIED
            ))
        }
    }

    private fun isVisibleHardwareOutcome(status: EvidenceStatus): Boolean =
        status == EvidenceStatus.DETECTED ||
            status == EvidenceStatus.WARNING ||
            status == EvidenceStatus.UNAVAILABLE

    private fun bindEvidenceRow(rowBinding: ItemEvidenceBinding, row: EvidenceRow) {
        rowBinding.tvEvidenceLabel.text = evidenceText(row)
        rowBinding.tvEvidenceBadge.isVisible = false
        val accent = ContextCompat.getColor(requireContext(), when (row.status) {
            EvidenceStatus.DETECTED -> R.color.ta_error
            EvidenceStatus.VERIFIED -> R.color.ta_success
            EvidenceStatus.ACTIVE -> R.color.ta_running
            EvidenceStatus.WARNING, EvidenceStatus.UNAVAILABLE -> R.color.ta_warning
            else -> R.color.ta_idle
        })
        val textColor = ContextCompat.getColor(requireContext(), when (row.status) {
            EvidenceStatus.DETECTED -> R.color.ta_error
            EvidenceStatus.WARNING, EvidenceStatus.UNAVAILABLE -> R.color.ta_warning
            else -> R.color.ta_text_secondary
        })
        rowBinding.tvEvidenceBullet.setTextColor(accent)
        rowBinding.tvEvidenceLabel.setTextColor(textColor)
    }

    private fun bindHardwareEvidenceRow(
        rowBinding: ItemEvidenceBinding,
        row: EvidenceRow,
        badgeOverride: String? = null
    ) {
        bindEvidenceRow(rowBinding, row)
        val accent = ContextCompat.getColor(requireContext(), when (row.status) {
            EvidenceStatus.DETECTED -> R.color.ta_error
            EvidenceStatus.VERIFIED -> R.color.ta_success
            EvidenceStatus.ACTIVE -> R.color.ta_running
            EvidenceStatus.WARNING, EvidenceStatus.UNAVAILABLE -> R.color.ta_warning
            else -> R.color.ta_idle
        })
        val surface = ContextCompat.getColor(requireContext(), R.color.ta_surface)
        rowBinding.tvEvidenceBadge.apply {
            isVisible = true
            text = "[${badgeOverride ?: when (row.status) {
                EvidenceStatus.DETECTED -> "DETECTED"
                EvidenceStatus.VERIFIED -> "VERIFIED"
                EvidenceStatus.ACTIVE -> "VERIFYING"
                EvidenceStatus.WARNING -> "WARNING"
                EvidenceStatus.UNAVAILABLE -> "UNAVAILABLE"
                EvidenceStatus.PENDING -> "PENDING"
                EvidenceStatus.INFO -> "INFO"
            }}]"
            setTextColor(accent)
            (background.mutate() as? GradientDrawable)?.apply {
                setColor(MaterialColors.layer(surface, accent, 0.08f))
                setStroke(1, MaterialColors.compositeARGBWithAlpha(accent, 150))
            }
        }
    }

    private fun evidenceText(row: EvidenceRow): String = buildString {
        append(row.label)
        if (BuildConfig.DEBUG && row.evidence.isNotBlank() && row.evidence != row.label) {
            append('\n')
            append(getString(R.string.evidence_prefix, row.evidence))
        }
    }

    private fun renderHardwareEvidence(itemBinding: ItemStepBinding, item: StepUi) {
        val detail = item.detail
        val state = item.state
        val lines = detail.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toList()
        val findingLines = lines
            .dropWhile { it != "HARDWARE FINDINGS" }
            .drop(1)
        val mismatch = if (item.findings.isNotEmpty()) {
            item.findings.any { finding ->
                finding.status == FindingStatus.DETECTED && (
                    finding.title.contains("RootOfTrust", ignoreCase = true) ||
                    finding.title.contains("Verified Boot", ignoreCase = true) ||
                    finding.title.contains("VBMeta", ignoreCase = true) ||
                    finding.title.contains("\u4e0d\u4e00\u81f4")
                )
            }
        } else findingLines.any { line ->
            val mentionsMismatch = line.contains("\u4e0d\u4e00\u81f4") ||
                line.contains("mismatch", ignoreCase = true) ||
                line.contains("discrepancy", ignoreCase = true)
            mentionsMismatch && EvidenceStatusParser.isFinding(line, state, findingSection = true)
        }
        val rootLines = lines.filter { line ->
            line.contains("RootOfTrust", ignoreCase = true) ||
                line.contains("ro.boot", ignoreCase = true) ||
                line.contains("deviceLocked", ignoreCase = true) ||
                line.contains("verifiedBoot", ignoreCase = true) ||
                line.contains("device_state", ignoreCase = true)
        }
        val rootStatus = getString(when {
            mismatch -> R.string.hardware_root_review
            state == ScanState.RUNNING -> R.string.hardware_root_verifying
            state == ScanState.FAIL -> R.string.hardware_root_review
            rootLines.isNotEmpty() -> R.string.hardware_root_verified
            else -> R.string.hardware_root_pending
        })
        val rootAccent = when {
            mismatch -> R.color.ta_error
            state == ScanState.PASS -> R.color.ta_success
            else -> R.color.ta_idle
        }
        val summaryLines = lines
            .takeWhile { line ->
                line != "证书链：" &&
                    !line.startsWith("#") &&
                    line != "HARDWARE FINDINGS" &&
                    line != "主动探针证据"
            }
            .filterNot { it.startsWith("综合结论：") || it.startsWith("证明安全等级：") }
        val rootText = when {
            BuildConfig.DEBUG && summaryLines.isNotEmpty() -> summaryLines.take(9)
                .joinToString("\n", transform = ::localizedHardwareLine)
            summaryLines.isNotEmpty() -> summaryLines.take(3)
                .joinToString("\n", transform = ::localizedHardwareLine)
            rootLines.isNotEmpty() -> rootLines.take(if (BuildConfig.DEBUG) 6 else 3)
                .joinToString("\n", transform = ::localizedHardwareLine)
            else -> getString(R.string.hardware_root_waiting)
        }
        itemBinding.tvHardwareRootHeading.setText(R.string.hardware_root_heading)
        itemBinding.tvHardwareRootStatus.text = rootStatus
        itemBinding.tvHardwareRootComparison.text = rootText
        itemBinding.tvHardwareRootStatus.setTextColor(
            ContextCompat.getColor(
                requireContext(),
                rootAccent
            )
        )
        itemBinding.hardwareRootPanel.setBackgroundResource(
            when {
                mismatch -> R.drawable.bg_hardware_root_alert
                state == ScanState.PASS -> R.drawable.bg_hardware_root_ok
                else -> R.drawable.bg_chain_detail
            }
        )

        val parsedRows = if (item.findings.isNotEmpty()) {
            EvidenceStatusParser.parseFindings(localizedFindings(item))
        } else {
            EvidenceStatusParser.parseRows(item.detail, item.state)
        }
        val hardwareRows = when (state) {
            ScanState.IDLE -> listOf(EvidenceRow(getString(R.string.home_summary_idle), EvidenceStatus.PENDING))
            ScanState.RUNNING -> listOf(EvidenceRow(getString(R.string.step_hardware_running), EvidenceStatus.ACTIVE))
            else -> hardwareDetectionRows(item, parsedRows)
        }
        itemBinding.hardwareFindingsSection.isVisible = true
        itemBinding.tvHardwareFindingsTitle.setText(R.string.hardware_findings_heading)
        itemBinding.tvHardwareFindingsTitle.setTextColor(
            ContextCompat.getColor(
                requireContext(),
                when {
                    hardwareRows.any { it.status == EvidenceStatus.DETECTED } -> R.color.ta_error
                    hardwareRows.any {
                        it.status == EvidenceStatus.WARNING ||
                            it.status == EvidenceStatus.UNAVAILABLE
                    } -> R.color.ta_warning
                    hardwareRows.any { it.status == EvidenceStatus.ACTIVE } -> R.color.ta_running
                    hardwareRows.any { it.status == EvidenceStatus.VERIFIED } -> R.color.ta_success
                    else -> R.color.ta_text
                }
            )
        )
        itemBinding.hardwareFindingsList.removeAllViews()
        hardwareRows.forEach { finding ->
            val rowBinding = ItemEvidenceBinding.inflate(layoutInflater, itemBinding.hardwareFindingsList, false)
            bindHardwareEvidenceRow(rowBinding, finding)
            itemBinding.hardwareFindingsList.addView(rowBinding.root)
        }

        val certificateBlocks = splitCertificateBlocks(lines)
        val declaredCount = lines.firstOrNull { line ->
            line.contains("\u603b\u6570") || line.contains("count", ignoreCase = true)
        }?.let { Regex("\\d+").find(it)?.value?.toIntOrNull() } ?: 0
        val certificateCount = maxOf(declaredCount, certificateBlocks.size)
        itemBinding.tvHardwareChainTitle.text = getString(R.string.hardware_chain_heading, certificateCount)
        itemBinding.hardwareChainList.removeAllViews()

        certificateBlocks.forEachIndexed { index, block ->
            val heading = block.firstOrNull().orEmpty()
            val title = localizedCertificateTitle(
                heading.substringAfter(' ', heading).trim(),
                index
            ).ifBlank {
                getString(R.string.hardware_certificate_number, index + 1)
            }
            val invalid = block.any { line ->
                line.contains("revoked", ignoreCase = true) ||
                    line.contains("expired", ignoreCase = true) ||
                    line.contains("\u540a\u9500") || line.contains("\u8fc7\u671f")
            }
            val rowBinding = ItemEvidenceBinding.inflate(layoutInflater, itemBinding.hardwareChainList, false)
            bindHardwareEvidenceRow(
                rowBinding,
                EvidenceRow(
                    label = "#${index + 1} $title",
                    status = if (invalid) EvidenceStatus.DETECTED else EvidenceStatus.VERIFIED
                ),
                badgeOverride = if (invalid) "REVOKED" else "VALID"
            )
            itemBinding.hardwareChainList.addView(rowBinding.root)
        }

        val hasDetails = certificateBlocks.isNotEmpty()
        itemBinding.btnHardwareChainDetails.isVisible = hasDetails
        itemBinding.tvHardwareChainDetails.isVisible = hasDetails && itemBinding.tvHardwareChainDetails.isVisible
        itemBinding.tvHardwareChainDetails.text = certificateBlocks.joinToString("\n\n") { it.joinToString("\n") }
        itemBinding.btnHardwareChainDetails.text = if (itemBinding.tvHardwareChainDetails.isVisible) {
            getString(R.string.hardware_chain_hide)
        } else {
            getString(R.string.hardware_chain_show)
        }
        itemBinding.btnHardwareChainDetails.setOnClickListener {
            val expanded = !itemBinding.tvHardwareChainDetails.isVisible
            itemBinding.tvHardwareChainDetails.isVisible = expanded
            itemBinding.btnHardwareChainDetails.text = if (expanded) {
                getString(R.string.hardware_chain_hide)
            } else {
                getString(R.string.hardware_chain_show)
            }
        }
    }

    private fun localizedHardwareLine(source: String): String {
        if (resources.configuration.locales[0].language != "en") return source
        return source
            .replace("证书链与 Attestation 信息", "Certificate chain and Attestation")
            .replace("证书总数：", "Certificates: ")
            .replace("根证书来源：", "Root source: ")
            .replace("设备锁定：", "Device locked: ")
            .replace("验证启动状态：", "Verified boot state: ")
    }

    private fun localizedCertificateTitle(source: String, index: Int): String {
        if (resources.configuration.locales[0].language != "en") return source
        return when {
            source.contains("根证书") -> "Root certificate"
            source.contains("中间证书") -> "Intermediate certificate"
            source.contains("叶子证书") -> "Leaf certificate"
            source.isBlank() -> getString(R.string.hardware_certificate_number, index + 1)
            else -> source
        }
    }

    private fun splitCertificateBlocks(lines: List<String>): List<List<String>> {
        val blocks = mutableListOf<List<String>>()
        var current = mutableListOf<String>()
        var finished = false
        lines.forEach { line ->
            if (line == "HARDWARE FINDINGS" ||
                line.contains("\u7efc\u5408\u7ed3\u8bba") ||
                line.contains("\u8bc1\u660e\u5b89\u5168\u7b49\u7ea7") ||
                line.contains("Key Attestation", ignoreCase = true) &&
                    line.contains("failed", ignoreCase = true)
            ) {
                if (current.isNotEmpty()) blocks += current
                current = mutableListOf()
                finished = true
            }
            if (finished) return@forEach
            if (line.startsWith("#") && current.isNotEmpty()) {
                blocks += current
                current = mutableListOf()
            }
            if (line.startsWith("#") || current.isNotEmpty()) current += line
        }
        if (current.isNotEmpty()) blocks += current
        return blocks
    }

    private fun extractHardwareFindings(lines: List<String>, state: ScanState): List<String> {
        val findings = linkedSetOf<String>()
        val markerIndex = lines.indexOfFirst { it == "HARDWARE FINDINGS" }
        if (markerIndex >= 0) {
            lines.drop(markerIndex + 1)
                .filter { line ->
                    EvidenceStatusParser.isFinding(
                        line,
                        state,
                        findingSection = true
                    )
                }
                .map(::normalizeHardwareFinding)
                .filter { it.isNotBlank() }
                .forEach(findings::add)
        }

        val conclusionLine = lines.firstOrNull { line ->
            line.contains("\u7efc\u5408\u7ed3\u8bba") ||
                line.contains("Key Attestation", ignoreCase = true) &&
                (line.contains("\u5931\u8d25") || line.contains("failed", ignoreCase = true))
        }
        val flagHex = conclusionLine?.let {
            Regex("0x([0-9A-Fa-f]+)").find(it)?.groupValues?.getOrNull(1)
        }
        val flags = flagHex?.let {
            runCatching { java.lang.Long.parseUnsignedLong(it, 16) }.getOrNull()
        } ?: 0L
        HARDWARE_FLAG_LABELS.forEach { (flag, label) ->
            if (flags and flag != 0L) findings += label
        }
        return findings.toList()
    }

    private fun extractHardwareProbeRows(
        lines: List<String>,
        state: ScanState,
        structuredProbeIds: Set<String>
    ): List<EvidenceRow> {
        val markerIndex = lines.indexOfFirst { it == "主动探针证据" }
        if (markerIndex < 0) return emptyList()
        val probeLines = lines.drop(markerIndex + 1)
            .takeWhile { it != "HARDWARE FINDINGS" }
        if (probeLines.isEmpty()) return emptyList()
        val flagMarker = Regex("^\\{flag=(0x[0-9A-Fa-f]+)\\}\\s*")
        val entryStart = Regex(
            "^\\s*\\[\\s*(?:DETECTED|VERIFIED|WARNING|UNAVAILABLE)\\s*]",
            RegexOption.IGNORE_CASE
        )
        val entries = mutableListOf<MutableList<String>>()
        probeLines.forEach { line ->
            if (entryStart.containsMatchIn(line)) {
                entries += mutableListOf(line)
            } else {
                entries.lastOrNull()?.add(line)
            }
        }
        return entries.mapNotNull { entry ->
            val row = EvidenceStatusParser.parseRows(entry.first(), state).firstOrNull()
                ?: return@mapNotNull null
            if (row.label == "暂无原始证据") return@mapNotNull null
            val marker = flagMarker.find(row.label)
            if (marker == null) {
                withHardwareProbeIdentity(row, structuredProbeIds)
            } else {
                val flag = runCatching {
                    java.lang.Long.parseUnsignedLong(
                        marker.groupValues[1].removePrefix("0x"),
                        16
                    )
                }.getOrNull() ?: return@mapNotNull withHardwareProbeIdentity(
                    row,
                    structuredProbeIds
                )
                val label = row.label.removeRange(marker.range).trim()
                val evidence = buildList {
                    if (label.isNotBlank()) add(label)
                    entry.drop(1).map(String::trim).filter(String::isNotBlank).forEach(::add)
                }.joinToString("\n")
                HardwareProbePresentation.identifyFlag(
                    row.copy(label = label, evidence = evidence),
                    flag,
                    structuredProbeIds
                )
            }
        }
    }

    private fun withHardwareProbeIdentity(
        row: EvidenceRow,
        structuredProbeIds: Set<String> = emptySet()
    ): EvidenceRow = HardwareProbePresentation.identify(row, structuredProbeIds)

    private fun mergeHardwareDetections(rows: List<EvidenceRow>): List<EvidenceRow> =
        HardwareProbePresentation.merge(rows)

    private fun normalizeHardwareFinding(source: String): String {
        return source
            .trim()
            .trimStart('\u2022', '\u203a', '*', '-', ' ', '\t')
            .replace(Regex("^\\[(?:DETECTED|BREACH|FAILED)]\\s*", RegexOption.IGNORE_CASE), "")
            .replace(Regex("^\\{flag=0x[0-9A-Fa-f]+\\}\\s*"), "")
            .removePrefix("\u53d1\u73b0")
            .removePrefix("\u68c0\u6d4b\u5230")
            .replace(Regex("\\s*\\[(?:DETECTED|BREACH|FAILED)\\]\\s*$", RegexOption.IGNORE_CASE), "")
            .replace(Regex("\\s+(?:DETECTED|BREACH|FAILED)\\s*$", RegexOption.IGNORE_CASE), "")
            .trim()
    }

    private fun animateExpansion(itemBinding: ItemStepBinding, expand: Boolean) {
        itemBinding.detailContainer.animate().cancel()
        itemBinding.ivArrow.animate().cancel()
        if (expand) {
            itemBinding.detailContainer.alpha = 0f
            itemBinding.detailContainer.translationY = binding.root.dp(6f)
            itemBinding.detailContainer.visibility = View.VISIBLE
            itemBinding.detailContainer.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(150)
                .start()
            itemBinding.ivArrow.animate()
                .rotation(180f)
                .setDuration(160)
                .setInterpolator(interpolator)
                .start()
        } else {
            itemBinding.detailContainer.animate()
                .alpha(0f)
                .translationY(binding.root.dp(4f))
                .setDuration(110)
                .withEndAction {
                    itemBinding.detailContainer.visibility = View.GONE
                    itemBinding.detailContainer.alpha = 1f
                    itemBinding.detailContainer.translationY = 0f
                }
                .start()
            itemBinding.ivArrow.animate()
                .rotation(0f)
                .setDuration(140)
                .setInterpolator(interpolator)
                .start()
        }
    }

    override fun onDestroyView() {
        _binding?.root?.removeCallbacks(uiRenderRunnable)
        cloudDisclosureCountdownJob?.cancel()
        cloudDisclosureCountdownJob = null
        cloudDisclosureDialog?.dismiss()
        cloudDisclosureDialog = null
        stepBindings.forEach { itemBinding ->
            (itemBinding.nodeDot.getTag(R.id.tag_step_icon_anim) as? Animator)?.cancel()
            (itemBinding.tvChip.getTag(R.id.tag_step_icon_anim) as? Animator)?.cancel()
            itemBinding.root.animate().cancel()
            itemBinding.detailContainer.animate().cancel()
            itemBinding.ivArrow.animate().cancel()
        }
        pendingUiState = null
        uiRenderScheduled = false
        renderedEvidenceKeys.clear()
        stepBindings.clear()
        topologyRailSyncPosted = false
        lastRenderedState = null
        lastHeroIndicatorTarget = Float.NaN
        stepPalette = null
        super.onDestroyView()
        _binding = null
    }

    companion object {
        private const val MIN_UI_RENDER_INTERVAL_MILLIS = 100L
        private const val CLOUD_DISCLOSURE_READ_SECONDS = 3
        private val HARDWARE_FLAG_LABELS = HardwareProbePresentation.fallbackLabels
    }

    private data class StepPalette(
        val surface: Int,
        val success: Int,
        val error: Int,
        val running: Int,
        val cloud: Int,
        val warning: Int,
        val idle: Int,
        val detailSurface: Int
    )
}

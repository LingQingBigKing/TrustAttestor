package com.lingqing.trustattestor

import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.doOnPreDraw
import androidx.core.view.updatePadding
import androidx.core.widget.NestedScrollView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.RecyclerView
import androidx.viewpager2.adapter.FragmentStateAdapter
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.button.MaterialButton
import com.google.android.material.navigation.NavigationBarView
import com.lingqing.trustattestor.databinding.ActivityMainBinding
import com.lingqing.trustattestor.ui.AboutFragment
import com.lingqing.trustattestor.ui.HomeFragment
import com.lingqing.trustattestor.ui.UserAgreement
import com.lingqing.trustattestor.ui.applyPressMotion
import com.lingqing.trustattestor.ui.dp
import com.lingqing.trustattestor.ui.playPop
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: MainViewModel by viewModels()
    private var detectionStartScheduled = false

    private var firstUseAgreementAccepted = false
    private var firstUseAgreementDialog: Dialog? = null
    private var firstUseCountdownJob: Job? = null
    private var firstUseTimerFinished = false
    private var firstUseReachedBottom = false
    private var firstUseRemainingSeconds = REQUIRED_READ_SECONDS
    private var firstUseScrollProgress = 0f

    private var agreementScrollView: NestedScrollView? = null
    private var agreementTimerChipView: TextView? = null
    private var agreementScrollChipView: TextView? = null
    private var agreementFooterHintView: TextView? = null
    private var agreementProgressView: View? = null
    private var agreementActionButton: MaterialButton? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        // Replace the lightweight launch-window theme before AppCompat inflates
        // content; the launch window itself already uses the same screen color.
        setTheme(R.style.Theme_TrustAttestor)
        AppLanguage.applySaved(this)
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        val versionName = runCatching {
            packageManager.getPackageInfo(packageName, 0).versionName
        }.getOrNull().orEmpty().ifBlank { "--" }
        binding.tvBuildMeta.text = versionName

        val topBarPaddingTop = binding.topBar.paddingTop
        val bottomNavPaddingBottom = binding.bottomNavHolder.paddingBottom
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { _, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            binding.topBar.updatePadding(top = topBarPaddingTop + systemBars.top)
            binding.bottomNavHolder.updatePadding(bottom = bottomNavPaddingBottom + systemBars.bottom)
            insets
        }

        binding.viewPager.adapter = object : FragmentStateAdapter(this) {
            override fun getItemCount(): Int = 2
            override fun createFragment(position: Int): Fragment {
                return if (position == 0) HomeFragment() else AboutFragment()
            }
        }
        binding.viewPager.isUserInputEnabled = true
        (binding.viewPager.getChildAt(0) as? RecyclerView)?.apply {
            overScrollMode = View.OVER_SCROLL_NEVER
            layoutManager?.isItemPrefetchEnabled = false
        }
        binding.bottomNav.setOnItemSelectedListener(NavigationBarView.OnItemSelectedListener {
            binding.viewPager.currentItem = when (it.itemId) {
                R.id.nav_about -> 1
                else -> 0
            }
            true
        })
        binding.viewPager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                binding.bottomNav.selectedItemId = if (position == 0) R.id.nav_home else R.id.nav_about
            }
        })

        firstUseAgreementAccepted = UserAgreement.hasAccepted(this)
        if (firstUseAgreementAccepted) {
            startDetectionAfterFirstHomeFrame()
        } else {
            binding.root.post { showFirstUseAgreementGateIfNeeded() }
        }
    }

    override fun onResume() {
        super.onResume()
        if (firstUseAgreementAccepted || UserAgreement.hasAccepted(this)) return
        if (firstUseAgreementDialog?.isShowing == true) {
            startFirstUseAgreementCountdown()
        } else if (::binding.isInitialized) {
            binding.root.post { showFirstUseAgreementGateIfNeeded() }
        }
    }

    override fun onStop() {
        super.onStop()
        if (!firstUseAgreementAccepted && firstUseAgreementDialog?.isShowing == true) {
            resetFirstUseAgreementGateState(resetScroll = true, showInterruptedHint = true)
        }
    }

    override fun onDestroy() {
        firstUseCountdownJob?.cancel()
        firstUseAgreementDialog?.dismiss()
        super.onDestroy()
    }

    private fun showFirstUseAgreementGateIfNeeded() {
        if (isFinishing || isDestroyed || firstUseAgreementAccepted || UserAgreement.hasAccepted(this)) return
        if (firstUseAgreementDialog?.isShowing == true) return

        val dialog = Dialog(this)
        val dialogView = layoutInflater.inflate(R.layout.dialog_user_agreement, null)
        dialog.setContentView(dialogView)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
        dialog.window?.setDimAmount(0.34f)
        dialog.setCancelable(false)
        dialog.setCanceledOnTouchOutside(false)

        val dialogCard = dialogView.findViewById<View>(R.id.agreementCard)
        val titleView = dialogView.findViewById<TextView>(R.id.tvAgreementTitle)
        val subtitleView = dialogView.findViewById<TextView>(R.id.tvAgreementSubtitle)
        val updatedAtView = dialogView.findViewById<TextView>(R.id.tvAgreementUpdatedAt)
        val introView = dialogView.findViewById<TextView>(R.id.tvAgreementIntro)
        val gateContainer = dialogView.findViewById<View>(R.id.agreementGateContainer)
        val timerChip = dialogView.findViewById<TextView>(R.id.tvAgreementTimerChip)
        val scrollChip = dialogView.findViewById<TextView>(R.id.tvAgreementScrollChip)
        val agreementScroll = dialogView.findViewById<NestedScrollView>(R.id.agreementScroll)
        val agreementContent = dialogView.findViewById<TextView>(R.id.tvAgreementContent)
        val footerHintView = dialogView.findViewById<TextView>(R.id.tvAgreementFooterHint)
        val progressView = dialogView.findViewById<View>(R.id.vAgreementReadProgress)
        val actionButton = dialogView.findViewById<MaterialButton>(R.id.btnAgreementAction)

        titleView.setText(R.string.agreement_first_title)
        subtitleView.setText(R.string.agreement_first_subtitle)
        updatedAtView.text = UserAgreement.updatedAt(this)
        introView.setText(R.string.agreement_first_intro)
        agreementContent.text = UserAgreement.buildContent(this)
        gateContainer.visibility = View.VISIBLE
        footerHintView.setText(R.string.agreement_gate_requirements)
        actionButton.setText(R.string.agreement_action_read)
        actionButton.isEnabled = false
        actionButton.alpha = 0.78f
        actionButton.applyPressMotion(pressedScale = 0.988f)


        agreementScroll.setOnScrollChangeListener { _, _, scrollY, _, _ ->
            val child = agreementScroll.getChildAt(0) ?: return@setOnScrollChangeListener
            val range = (child.height - agreementScroll.height).coerceAtLeast(0)
            firstUseScrollProgress = if (range == 0) 1f else (scrollY.toFloat() / range.toFloat()).coerceIn(0f, 1f)
            val reachedBottom = scrollY + agreementScroll.height >= child.height - agreementScroll.dp(12f).toInt()
            if (reachedBottom && !firstUseReachedBottom) {
                firstUseReachedBottom = true
                updateFirstUseAgreementGateUi()
            } else if (!reachedBottom) {
                updateFirstUseAgreementProgressOnly()
            }
        }

        actionButton.setOnClickListener {
            if (!firstUseTimerFinished || !firstUseReachedBottom) return@setOnClickListener
            firstUseAgreementAccepted = true
            UserAgreement.markAccepted(this)
            firstUseCountdownJob?.cancel()
            actionButton.playPop(scaleTo = 1.018f, duration = 190)
            actionButton.postDelayed({
                if (dialog.isShowing) dialog.dismiss()
                firstUseAgreementDialog = null
                startDetectionAfterFirstHomeFrame()
            }, 120L)
        }

        dialog.show()
        val dialogWidth = (resources.displayMetrics.widthPixels * 0.92f).toInt()
        val dialogHeight = (resources.displayMetrics.heightPixels * 0.88f).toInt()
        dialog.window?.setLayout(dialogWidth, dialogHeight)

        firstUseAgreementDialog = dialog
        agreementScrollView = agreementScroll
        agreementTimerChipView = timerChip
        agreementScrollChipView = scrollChip
        agreementFooterHintView = footerHintView
        agreementProgressView = progressView
        agreementActionButton = actionButton

        dialogCard.alpha = 0f
        dialogCard.translationY = binding.root.dp(18f)
        dialogCard.scaleX = 0.972f
        dialogCard.scaleY = 0.972f
        dialogCard.animate()
            .alpha(1f)
            .translationY(0f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(320)
            .start()

        resetFirstUseAgreementGateState(resetScroll = true, showInterruptedHint = false)
        startFirstUseAgreementCountdown()
    }

    private fun resetFirstUseAgreementGateState(resetScroll: Boolean, showInterruptedHint: Boolean) {
        firstUseCountdownJob?.cancel()
        firstUseTimerFinished = false
        firstUseReachedBottom = false
        firstUseRemainingSeconds = REQUIRED_READ_SECONDS
        firstUseScrollProgress = 0f
        if (resetScroll) {
            agreementScrollView?.post { agreementScrollView?.scrollTo(0, 0) }
        }
        agreementFooterHintView?.text = if (showInterruptedHint) {
            getString(R.string.agreement_interrupted)
        } else {
            getString(R.string.agreement_gate_requirements)
        }
        updateFirstUseAgreementGateUi()
    }

    private fun startFirstUseAgreementCountdown() {
        if (firstUseAgreementAccepted || firstUseAgreementDialog?.isShowing != true) return
        firstUseCountdownJob?.cancel()
        firstUseCountdownJob = lifecycleScope.launch {
            var remaining = firstUseRemainingSeconds.coerceAtLeast(1)
            while (!firstUseAgreementAccepted && firstUseAgreementDialog?.isShowing == true && remaining > 0) {
                firstUseRemainingSeconds = remaining
                updateFirstUseAgreementGateUi()
                delay(1000L)
                remaining -= 1
            }
            if (!firstUseAgreementAccepted && firstUseAgreementDialog?.isShowing == true) {
                firstUseRemainingSeconds = 0
                firstUseTimerFinished = true
                updateFirstUseAgreementGateUi()
            }
        }
    }

    private fun updateFirstUseAgreementGateUi() {
        val timerChip = agreementTimerChipView ?: return
        val scrollChip = agreementScrollChipView ?: return
        val actionButton = agreementActionButton ?: return

        val timerComplete = firstUseTimerFinished
        val scrollComplete = firstUseReachedBottom
        val primaryTextColor = ContextCompat.getColor(this, R.color.ta_primary)
        val secondaryTextColor = ContextCompat.getColor(this, R.color.ta_text_secondary)

        timerChip.text = if (timerComplete) {
            getString(R.string.agreement_timer_done)
        } else {
            getString(R.string.agreement_timer_remaining, firstUseRemainingSeconds)
        }
        timerChip.setBackgroundResource(if (timerComplete) R.drawable.bg_agreement_gate_chip_active else R.drawable.bg_agreement_gate_chip)
        timerChip.setTextColor(if (timerComplete) primaryTextColor else secondaryTextColor)

        scrollChip.setText(
            if (scrollComplete) R.string.agreement_scroll_done
            else R.string.agreement_scroll_required
        )
        scrollChip.setBackgroundResource(if (scrollComplete) R.drawable.bg_agreement_gate_chip_active else R.drawable.bg_agreement_gate_chip)
        scrollChip.setTextColor(if (scrollComplete) primaryTextColor else secondaryTextColor)

        val ready = timerComplete && scrollComplete
        actionButton.isEnabled = ready
        actionButton.alpha = if (ready) 1f else 0.78f
        actionButton.text = when {
            ready -> getString(R.string.agreement_action_accept)
            !timerComplete && !scrollComplete -> getString(R.string.agreement_action_read)
            !timerComplete -> getString(R.string.agreement_action_wait, firstUseRemainingSeconds)
            else -> getString(R.string.agreement_action_scroll)
        }

        agreementFooterHintView?.text = when {
            ready -> getString(R.string.agreement_ready)
            timerComplete -> getString(R.string.agreement_timer_then_scroll)
            scrollComplete -> getString(R.string.agreement_scroll_then_wait)
            else -> agreementFooterHintView?.text
        }

        updateFirstUseAgreementProgressOnly()
    }

    private fun updateFirstUseAgreementProgressOnly() {
        val progressView = agreementProgressView ?: return
        val timeProgress = if (firstUseTimerFinished) 1f else ((REQUIRED_READ_SECONDS - firstUseRemainingSeconds).toFloat() / REQUIRED_READ_SECONDS.toFloat()).coerceIn(0f, 1f)
        val combinedProgress = ((timeProgress + firstUseScrollProgress.coerceIn(0f, 1f)) / 2f).coerceIn(0f, 1f)
        progressView.pivotX = 0f
        progressView.scaleX = combinedProgress
        progressView.alpha = 0.58f + (combinedProgress * 0.42f)
    }

    private fun startDetectionAfterFirstHomeFrame() {
        if (detectionStartScheduled || viewModel.uiState.value.scanning) return
        detectionStartScheduled = true
        binding.viewPager.doOnPreDraw {
            // Two frame callbacks guarantee that ViewPager has presented the
            // HomeFragment skeleton before native initialization starts.
            binding.viewPager.postOnAnimation {
                binding.viewPager.postOnAnimation {
                    detectionStartScheduled = false
                    if (!isFinishing && !isDestroyed && UserAgreement.hasAccepted(this)) {
                        viewModel.startIfNeeded(applicationContext)
                    }
                }
            }
        }
    }

    companion object {
        private const val REQUIRED_READ_SECONDS = 5
    }
}

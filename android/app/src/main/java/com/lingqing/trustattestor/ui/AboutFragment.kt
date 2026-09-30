package com.lingqing.trustattestor.ui

import android.app.Dialog
import android.content.Intent
import android.content.res.Configuration
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.lingqing.trustattestor.AppLanguage
import com.lingqing.trustattestor.MainViewModel
import com.lingqing.trustattestor.R
import com.lingqing.trustattestor.databinding.DialogAcknowledgementsBinding
import com.lingqing.trustattestor.databinding.FragmentAboutBinding
import androidx.core.widget.NestedScrollView
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlin.math.min

class AboutFragment : Fragment() {

    private var _binding: FragmentAboutBinding? = null
    private val binding get() = _binding!!
    private val viewModel: MainViewModel by activityViewModels()
    private var hasPlayedEntry = false
    private var wasFetching = false
    private var acknowledgementsDialog: Dialog? = null

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentAboutBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        binding.btnFetchRevocationList.applyPressMotion(pressedScale = 0.988f)
        binding.btnAcknowledgements.applyPressMotion(pressedScale = 0.988f)
        binding.btnUserAgreement.applyPressMotion(pressedScale = 0.988f)
        binding.rowLanguage.applyPressMotion(pressedScale = 0.992f)

        binding.rowRepo.setOnClickListener {
            openExternal("https://github.com/LingQingBigKing/TrustAttestor")
        }
        binding.rowContact.setOnClickListener {
            openExternal("mailto:ling_qing_lq@163.com")
        }
        binding.tvLanguageValue.setText(AppLanguage.displayNameRes(AppLanguage.selectedTag(requireContext())))
        binding.rowLanguage.setOnClickListener { showLanguageDialog() }

        binding.btnFetchRevocationList.setOnClickListener {
            binding.btnFetchRevocationList.playPop(scaleTo = 1.02f, duration = 220)
            viewModel.fetchRevocationList(requireContext())
        }
        binding.btnUserAgreement.setOnClickListener {
            showUserAgreementDialog()
        }
        binding.btnAcknowledgements.setOnClickListener {
            binding.btnAcknowledgements.playPop(scaleTo = 1.012f, duration = 180)
            showAcknowledgementsDialog()
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                viewModel.uiState
                    .map { state ->
                        AboutUiSnapshot(
                            revocationListText = state.revocationListText,
                            revocationCountText = state.revocationCountText,
                            fetchingRevocationList = state.fetchingRevocationList,
                            lastToast = state.lastToast
                        )
                    }
                    .distinctUntilChanged()
                    .collect { state ->
                        val updated = extractFieldValue(state.revocationListText)
                        val count = extractFieldValue(state.revocationCountText)
                        binding.tvRevocationStatus.text = when {
                            state.fetchingRevocationList -> getString(R.string.about_revocation_syncing)
                            updated != "--" -> getString(R.string.about_revocation_synced)
                            else -> getString(R.string.about_revocation_ready)
                        }
                        binding.tvRevocationStatus.setTextColor(
                            if (state.fetchingRevocationList) {
                                requireContext().getColor(R.color.ta_running)
                            } else {
                                requireContext().getColor(R.color.ta_success)
                            }
                        )
                        binding.tvRevocationListTime.text = getString(R.string.about_revocation_updated, updated)
                        binding.tvRevocationCount.text = getString(R.string.about_revocation_count, count)
                        binding.progressFetch.visibility =
                            if (state.fetchingRevocationList) View.VISIBLE else View.GONE
                        binding.btnFetchRevocationList.isEnabled = !state.fetchingRevocationList
                        animateFetchState(state.fetchingRevocationList)
                        playEntryIfNeeded()
                        state.lastToast?.let {
                            Toast.makeText(requireContext(), it, Toast.LENGTH_SHORT).show()
                            viewModel.consumeToast()
                        }
                    }
            }
        }
    }

    private fun playEntryIfNeeded() {
        if (hasPlayedEntry) return
        hasPlayedEntry = true
        binding.root.post {
            if (!isAdded || _binding == null) return@post
            binding.aboutHeroCard.playEntrance(delay = 30, distance = 20f, duration = 620)
            binding.languageCard.playEntrance(delay = 90, distance = 18f, duration = 590)
            binding.revocationCard.playEntrance(delay = 145, distance = 18f, duration = 570)
            binding.thanksCard.playEntrance(delay = 195, distance = 18f, duration = 550)
            binding.btnUserAgreement.playEntrance(delay = 245, distance = 14f, duration = 500, fromScale = 0.992f)
        }
    }

    private fun showLanguageDialog() {
        val tags = AppLanguage.supportedTags
        val labels = tags.map { getString(AppLanguage.displayNameRes(it)) }.toTypedArray()
        val selected = tags.indexOf(AppLanguage.selectedTag(requireContext())).coerceAtLeast(0)
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.language_dialog_title)
            .setSingleChoiceItems(labels, selected) { dialog, which ->
                dialog.dismiss()
                AppLanguage.select(requireContext(), tags[which])
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun showUserAgreementDialog() {
        val dialog = Dialog(requireContext())
        val dialogView = layoutInflater.inflate(R.layout.dialog_user_agreement, null)
        dialog.setContentView(dialogView)
        dialog.window?.setBackgroundDrawable(ColorDrawable(android.graphics.Color.TRANSPARENT))
        dialog.window?.setDimAmount(0.28f)
        dialog.setCanceledOnTouchOutside(true)

        val dialogCard = dialogView.findViewById<View>(R.id.agreementCard)
        val agreementScroll = dialogView.findViewById<NestedScrollView>(R.id.agreementScroll)
        val agreementContent = dialogView.findViewById<TextView>(R.id.tvAgreementContent)
        val updatedAtView = dialogView.findViewById<TextView>(R.id.tvAgreementUpdatedAt)
        val footerHintView = dialogView.findViewById<TextView>(R.id.tvAgreementFooterHint)
        val gateContainer = dialogView.findViewById<View>(R.id.agreementGateContainer)
        val actionButton = dialogView.findViewById<MaterialButton>(R.id.btnAgreementAction)

        updatedAtView.text = UserAgreement.updatedAt(requireContext())
        agreementContent.text = UserAgreement.buildContent(requireContext())
        gateContainer.visibility = View.GONE
        footerHintView.setText(R.string.agreement_result_notice)
        actionButton.setText(R.string.agreement_acknowledge)
        actionButton.applyPressMotion(pressedScale = 0.988f)
        actionButton.setOnClickListener {
            actionButton.playPop(scaleTo = 1.018f, duration = 180)
            actionButton.postDelayed({ dialog.dismiss() }, 110L)
        }


        dialog.show()
        val dialogWidth = (resources.displayMetrics.widthPixels * 0.92f).toInt()
        val dialogHeight = (resources.displayMetrics.heightPixels * 0.88f).toInt()
        dialog.window?.setLayout(dialogWidth, dialogHeight)

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
    }

    private fun showAcknowledgementsDialog() {
        acknowledgementsDialog?.dismiss()

        val dialog = Dialog(requireContext())
        val dialogBinding = DialogAcknowledgementsBinding.inflate(layoutInflater)
        val entries = listOf(
            AcknowledgementEntry(
                R.drawable.ack_avatar_vvb2060,
                R.string.acknowledgement_name_vvb2060,
                R.string.acknowledgement_message_vvb2060
            ),
            AcknowledgementEntry(
                R.drawable.ack_avatar_lsposed,
                R.string.acknowledgement_name_lsposed,
                R.string.acknowledgement_message_lsposed
            ),
            AcknowledgementEntry(
                R.drawable.ack_avatar_liankong,
                R.string.acknowledgement_name_liankong,
                R.string.acknowledgement_message_liankong
            ),
            AcknowledgementEntry(
                R.drawable.ack_avatar_flandre_pudding,
                R.string.acknowledgement_name_flandre_pudding,
                R.string.acknowledgement_message_flandre_pudding
            ),
            AcknowledgementEntry(
                R.drawable.ack_avatar_wuying,
                R.string.acknowledgement_name_wuying,
                R.string.acknowledgement_message_wuying
            )
        )

        dialog.setContentView(dialogBinding.root)
        dialog.window?.setBackgroundDrawable(ColorDrawable(android.graphics.Color.TRANSPARENT))
        dialog.window?.setDimAmount(0.28f)
        dialog.setCanceledOnTouchOutside(true)

        val pager = dialogBinding.acknowledgementsPager
        pager.adapter = AcknowledgementsAdapter(entries)
        pager.setPageTransformer { page, position ->
            val distance = abs(position).coerceAtMost(1f)
            val scale = 1f - (distance * 0.025f)
            page.alpha = 1f - (distance * 0.16f)
            page.scaleX = scale
            page.scaleY = scale
        }

        fun updateCounter(position: Int) {
            dialogBinding.tvAcknowledgementsCounter.text = getString(
                R.string.acknowledgements_counter,
                position + 1,
                entries.size
            )
        }

        val pageCallback = object : ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                updateCounter(position)
            }
        }
        pager.registerOnPageChangeCallback(pageCallback)
        updateCounter(0)

        fun movePage(offset: Int) {
            val target = (pager.currentItem + offset + entries.size) % entries.size
            pager.setCurrentItem(target, true)
        }

        dialogBinding.btnAcknowledgementsPrevious.applyPressMotion(pressedScale = 0.94f)
        dialogBinding.btnAcknowledgementsNext.applyPressMotion(pressedScale = 0.94f)
        dialogBinding.btnAcknowledgementsClose.applyPressMotion(pressedScale = 0.94f)
        dialogBinding.btnAcknowledgementsPrevious.setOnClickListener {
            movePage(-1)
        }
        dialogBinding.btnAcknowledgementsNext.setOnClickListener {
            movePage(1)
        }
        dialogBinding.btnAcknowledgementsClose.setOnClickListener {
            dialogBinding.btnAcknowledgementsClose.playPop(scaleTo = 1.04f, duration = 150)
            dialogBinding.btnAcknowledgementsClose.postDelayed({ dialog.dismiss() }, 80L)
        }

        dialog.setOnDismissListener {
            pager.unregisterOnPageChangeCallback(pageCallback)
            pager.adapter = null
            if (acknowledgementsDialog === dialog) acknowledgementsDialog = null
        }

        acknowledgementsDialog = dialog
        dialog.show()

        val displayMetrics = resources.displayMetrics
        val landscape = resources.configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
        val desiredWidth = (displayMetrics.widthPixels * if (landscape) 0.72f else 0.92f).toInt()
        val desiredHeight = (displayMetrics.heightPixels * if (landscape) 0.92f else 0.84f).toInt()
        val maxWidth = binding.root.dp(560f).toInt()
        val maxHeight = binding.root.dp(if (landscape) 560f else 680f).toInt()
        dialog.window?.setLayout(min(desiredWidth, maxWidth), min(desiredHeight, maxHeight))

        dialogBinding.acknowledgementsCard.alpha = 0f
        dialogBinding.acknowledgementsCard.translationY = binding.root.dp(18f)
        dialogBinding.acknowledgementsCard.scaleX = 0.972f
        dialogBinding.acknowledgementsCard.scaleY = 0.972f
        dialogBinding.acknowledgementsCard.animate()
            .alpha(1f)
            .translationY(0f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(300)
            .start()
    }

    private fun animateFetchState(fetching: Boolean) {
        if (wasFetching == fetching) return
        if (fetching) {
            binding.revocationCard.playPop(scaleTo = 1.012f, duration = 240)
            binding.btnFetchRevocationList.animate()
                .alpha(0.92f)
                .scaleX(0.992f)
                .scaleY(0.992f)
                .setDuration(160)
                .start()
            binding.progressFetch.alpha = 0f
            binding.progressFetch.scaleX = 0.88f
            binding.progressFetch.scaleY = 0.88f
            binding.progressFetch.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(220).start()
        } else if (wasFetching) {
            binding.btnFetchRevocationList.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .setDuration(220)
                .start()
            binding.btnFetchRevocationList.playPop(scaleTo = 1.015f, duration = 220)
        }
        wasFetching = fetching
    }

    private fun extractFieldValue(raw: String): String {
        val timestamp = Regex("\\d{4}-\\d{2}-\\d{2}(?:[ T]\\d{2}:\\d{2}:\\d{2})?")
            .find(raw)
            ?.value
        if (timestamp != null) return timestamp
        val separator = raw.lastIndexOf('\uFF1A')
        val value = if (separator >= 0) raw.substring(separator + 1).trim() else raw.trim()
        return if (value.isBlank() || value.contains("\u672A\u83B7\u53D6")) "--" else value
    }

    private data class AboutUiSnapshot(
        val revocationListText: String,
        val revocationCountText: String,
        val fetchingRevocationList: Boolean,
        val lastToast: String?
    )

    private fun openExternal(target: String) {
        runCatching {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(target)))
        }.onFailure {
            Toast.makeText(requireContext(), R.string.external_link_failed, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onDestroyView() {
        acknowledgementsDialog?.dismiss()
        acknowledgementsDialog = null
        super.onDestroyView()
        _binding = null
    }
}

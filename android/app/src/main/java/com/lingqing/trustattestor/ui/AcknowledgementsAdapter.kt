package com.lingqing.trustattestor.ui

import android.content.res.Resources
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.recyclerview.widget.RecyclerView
import com.lingqing.trustattestor.R
import com.lingqing.trustattestor.databinding.ItemAcknowledgementBinding

internal data class AcknowledgementEntry(
    @DrawableRes val avatarRes: Int,
    @StringRes val nameRes: Int,
    @StringRes val messageRes: Int
)

internal class AcknowledgementsAdapter(
    private val entries: List<AcknowledgementEntry>
) : RecyclerView.Adapter<AcknowledgementsAdapter.AcknowledgementViewHolder>() {

    private val avatarCache = object : LruCache<Int, Bitmap>(AVATAR_CACHE_BYTES) {
        override fun sizeOf(key: Int, value: Bitmap): Int = value.allocationByteCount
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AcknowledgementViewHolder {
        val binding = ItemAcknowledgementBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return AcknowledgementViewHolder(binding)
    }

    override fun onBindViewHolder(holder: AcknowledgementViewHolder, position: Int) {
        holder.bind(entries[position], ::loadAvatar)
    }

    override fun getItemCount(): Int = entries.size

    private fun loadAvatar(resources: Resources, avatarRes: Int): Bitmap? {
        avatarCache.get(avatarRes)?.let { return it }
        val targetPixels = (AVATAR_SIZE_DP * resources.displayMetrics.density)
            .toInt()
            .coerceIn(1, MAX_AVATAR_PIXELS)
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeResource(resources, avatarRes, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

        var sampleSize = 1
        while (bounds.outWidth / (sampleSize * 2) >= targetPixels &&
            bounds.outHeight / (sampleSize * 2) >= targetPixels
        ) {
            sampleSize *= 2
        }
        val bitmap = BitmapFactory.decodeResource(
            resources,
            avatarRes,
            BitmapFactory.Options().apply {
                inSampleSize = sampleSize
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
        ) ?: return null
        avatarCache.put(avatarRes, bitmap)
        return bitmap
    }

    internal class AcknowledgementViewHolder(
        private val binding: ItemAcknowledgementBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(
            entry: AcknowledgementEntry,
            loadAvatar: (Resources, Int) -> Bitmap?
        ) {
            val context = binding.root.context
            val name = context.getString(entry.nameRes)
            val bitmap = loadAvatar(context.resources, entry.avatarRes)
            if (bitmap != null) {
                binding.ivAcknowledgementAvatar.setImageBitmap(bitmap)
            } else {
                binding.ivAcknowledgementAvatar.setImageResource(entry.avatarRes)
            }
            binding.ivAcknowledgementAvatar.contentDescription = context.getString(
                R.string.acknowledgements_avatar_description,
                name
            )
            binding.tvAcknowledgementName.text = name
            binding.tvAcknowledgementMessage.setText(entry.messageRes)
        }
    }

    private companion object {
        const val AVATAR_SIZE_DP = 168
        const val MAX_AVATAR_PIXELS = 640
        const val AVATAR_CACHE_BYTES = 12 * 1024 * 1024
    }
}

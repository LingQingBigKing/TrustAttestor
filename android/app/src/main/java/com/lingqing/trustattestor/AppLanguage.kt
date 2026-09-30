package com.lingqing.trustattestor

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat

object AppLanguage {
    const val SYSTEM = ""
    const val SIMPLIFIED_CHINESE = "zh-CN"
    const val ENGLISH = "en"

    private const val PREFS_NAME = "trustattestor_language"
    private const val KEY_LANGUAGE_TAG = "language_tag"

    val supportedTags = listOf(SYSTEM, SIMPLIFIED_CHINESE, ENGLISH)

    fun applySaved(context: Context) {
        val tag = selectedTag(context)
        if (tag == SYSTEM) return
        val requested = LocaleListCompat.forLanguageTags(tag)
        if (AppCompatDelegate.getApplicationLocales() != requested) {
            AppCompatDelegate.setApplicationLocales(requested)
        }
    }

    fun selectedTag(context: Context): String = context
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getString(KEY_LANGUAGE_TAG, SYSTEM)
        .orEmpty()
        .takeIf(supportedTags::contains)
        ?: SYSTEM

    fun select(context: Context, tag: String) {
        val normalized = tag.takeIf(supportedTags::contains) ?: SYSTEM
        if (selectedTag(context) == normalized) return
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_LANGUAGE_TAG, normalized)
            .apply()
        val locales = if (normalized == SYSTEM) {
            LocaleListCompat.getEmptyLocaleList()
        } else {
            LocaleListCompat.forLanguageTags(normalized)
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }

    fun displayNameRes(tag: String): Int = when (tag) {
        SIMPLIFIED_CHINESE -> R.string.language_simplified_chinese
        ENGLISH -> R.string.language_english
        else -> R.string.language_follow_system
    }
}

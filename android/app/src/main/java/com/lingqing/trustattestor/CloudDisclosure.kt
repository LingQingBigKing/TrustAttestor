package com.lingqing.trustattestor

import android.content.Context

/** Versioned consent recorded after the first cloud-attestation disclosure. */
object CloudDisclosure {
    private const val PREF_NAME = "trust_attestor_shared_data"
    private const val PREF_KEY_ACCEPTED = "cloud_disclosure_accepted_v1"

    fun hasAccepted(context: Context): Boolean = context.applicationContext
        .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        .getBoolean(PREF_KEY_ACCEPTED, false)

    fun markAccepted(context: Context) {
        context.applicationContext
            .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_KEY_ACCEPTED, true)
            .apply()
    }
}

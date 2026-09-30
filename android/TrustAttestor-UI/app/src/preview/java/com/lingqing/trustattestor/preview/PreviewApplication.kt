package com.lingqing.trustattestor.preview

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.os.Bundle
import android.widget.TextView
import com.lingqing.trustattestor.MainActivity
import com.lingqing.trustattestor.R

class PreviewApplication : Application(), Application.ActivityLifecycleCallbacks {
    override fun onCreate() {
        super.onCreate()
        registerActivityLifecycleCallbacks(this)
    }

    override fun onActivityResumed(activity: Activity) {
        if (activity !is MainActivity) return
        activity.findViewById<TextView>(R.id.tvBuildMeta)?.apply {
            contentDescription = "UI Preview · 返回场景选择 / Choose preview scenario"
            setOnClickListener {
                activity.startActivity(Intent(activity, PreviewLauncherActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
            }
        }
    }

    override fun onActivityCreated(activity: Activity, state: Bundle?) = Unit
    override fun onActivityStarted(activity: Activity) = Unit
    override fun onActivityPaused(activity: Activity) = Unit
    override fun onActivityStopped(activity: Activity) = Unit
    override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit
    override fun onActivityDestroyed(activity: Activity) = Unit
}

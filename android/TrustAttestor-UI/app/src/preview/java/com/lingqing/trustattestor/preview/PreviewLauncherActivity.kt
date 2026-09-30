package com.lingqing.trustattestor.preview

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import com.lingqing.trustattestor.AppLanguage
import com.lingqing.trustattestor.BuildConfig
import com.lingqing.trustattestor.MainActivity
import com.lingqing.trustattestor.R
import com.lingqing.trustattestor.ui.UserAgreement

/** Preview controls live outside shared sources and never sync into TA. */
class PreviewLauncherActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        AppLanguage.applySaved(this)
        super.onCreate(savedInstanceState)
        val padding = (20 * resources.displayMetrics.density).toInt()
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, padding)
        }
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            addView(content)
        }
        ViewCompat.setOnApplyWindowInsetsListener(scroll) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            content.setPadding(padding + bars.left, padding + bars.top,
                padding + bars.right, padding + bars.bottom)
            insets
        }
        setContentView(scroll)
        content.addView(TextView(this).apply {
            text = "TA UI Preview"
            textSize = 28f
            setTextColor(getColor(R.color.ta_text))
        })
        content.addView(TextView(this).apply {
            text = "选择要预览的界面状态。所有检测与云端结果均为模拟数据。\n" +
                "Choose a sample state. No scan or network request is performed.\n\n" +
                "点击首页右上角 UI Preview 版本号可返回这里。\n" +
                "Tap the UI Preview version label to return.\n\n" +
                if (BuildConfig.DEBUG) "DEBUG：展示详细证据 / Detailed evidence" else
                    "RELEASE：使用正式版文案展示规则 / Release presentation"
            textSize = 14f
            setPadding(0, padding / 2, 0, padding)
            setTextColor(getColor(R.color.ta_text_secondary))
        })
        val prefs = getSharedPreferences("ui_preview", Context.MODE_PRIVATE)
        val agreement = MaterialCheckBox(this).apply {
            text = "预览首次使用协议 / Show first-use agreement"
            isChecked = prefs.getBoolean("show_agreement", false)
        }
        content.addView(agreement)
        PreviewScenario.entries.forEach { scenario ->
            content.addView(MaterialButton(this).apply {
                text = scenario.label
                isAllCaps = false
                setOnClickListener {
                    prefs.edit().putString("scenario", scenario.name)
                        .putBoolean("show_agreement", agreement.isChecked).apply()
                    // This is the separate preview application's own preference file.
                    getSharedPreferences("trust_attestor_shared_data", Context.MODE_PRIVATE)
                        .edit().clear().apply()
                    if (!agreement.isChecked) UserAgreement.markAccepted(this@PreviewLauncherActivity)
                    startActivity(Intent(this@PreviewLauncherActivity, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
                }
            }, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT))
        }
    }
}

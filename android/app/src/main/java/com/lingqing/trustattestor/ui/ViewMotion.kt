package com.lingqing.trustattestor.ui

import android.view.MotionEvent
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator

fun View.dp(value: Float): Float = value * resources.displayMetrics.density

fun View.playEntrance(
    delay: Long = 0L,
    distance: Float = 24f,
    duration: Long = 560L,
    fromScale: Float = 0.985f
) {
    alpha = 0f
    translationY = dp(distance)
    scaleX = fromScale
    scaleY = fromScale
    animate()
        .alpha(1f)
        .translationY(0f)
        .scaleX(1f)
        .scaleY(1f)
        .setStartDelay(delay)
        .setDuration(duration)
        .setInterpolator(DecelerateInterpolator(1.8f))
        .start()
}

fun View.playPop(scaleTo: Float = 1.035f, duration: Long = 260L) {
    animate().cancel()
    animate()
        .scaleX(scaleTo)
        .scaleY(scaleTo)
        .setDuration((duration * 0.45f).toLong())
        .setInterpolator(DecelerateInterpolator())
        .withEndAction {
            animate()
                .scaleX(1f)
                .scaleY(1f)
                .setDuration((duration * 0.55f).toLong())
                .setInterpolator(OvershootInterpolator(1.05f))
                .start()
        }
        .start()
}

fun View.applyPressMotion(target: View = this, pressedScale: Float = 0.984f) {
    setOnTouchListener { _, event ->
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                target.animate().scaleX(pressedScale).scaleY(pressedScale).setDuration(110).start()
            }
            MotionEvent.ACTION_UP,
            MotionEvent.ACTION_CANCEL -> {
                target.animate().scaleX(1f).scaleY(1f).setDuration(180)
                    .setInterpolator(OvershootInterpolator(0.8f)).start()
            }
        }
        false
    }
}

package com.lingqing.trustattestor.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.DashPathEffect
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import com.lingqing.trustattestor.R

class TopologyRailView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    private val density = resources.displayMetrics.density
    private val railPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        strokeWidth = density.coerceAtLeast(1f)
        strokeCap = Paint.Cap.ROUND
    }
    private val idleColor = ContextCompat.getColor(context, R.color.ta_stroke_strong)
    private val successColor = ContextCompat.getColor(context, R.color.ta_success)
    private val activeColor = ContextCompat.getColor(context, R.color.ta_running)
    private val breachColor = ColorUtils.setAlphaComponent(
        ContextCompat.getColor(context, R.color.ta_error),
        112
    )
    private val dottedEffect = DashPathEffect(floatArrayOf(2f * density, 3f * density), 0f)
    private var nodeStates: List<NodeState> = emptyList()
    private var nodeCenters: List<Float> = emptyList()

    enum class NodeState {
        SUCCESS,
        MUTED,
        ACTIVE,
        ALERT
    }

    fun setNodeStates(states: List<NodeState>) {
        if (nodeStates == states) return
        nodeStates = states.toList()
        invalidate()
    }

    fun setNodeCenters(centers: List<Float>) {
        if (nodeCenters == centers) return
        nodeCenters = centers.toList()
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val segmentCount = minOf(nodeStates.size, nodeCenters.size) - 1
        if (segmentCount <= 0) return
        val x = width / 2f
        repeat(segmentCount) { index ->
            val startState = nodeStates[index]
            val endState = nodeStates[index + 1]
            val touchesMutedNode = startState == NodeState.MUTED || endState == NodeState.MUTED
            when {
                touchesMutedNode -> {
                    railPaint.color = idleColor
                    railPaint.pathEffect = dottedEffect
                }
                startState == NodeState.SUCCESS && endState == NodeState.SUCCESS -> {
                    railPaint.color = successColor
                    railPaint.pathEffect = null
                }
                startState == NodeState.ALERT || endState == NodeState.ALERT -> {
                    railPaint.color = breachColor
                    railPaint.pathEffect = null
                }
                else -> {
                    railPaint.color = activeColor
                    railPaint.pathEffect = null
                }
            }
            val startY = nodeCenters[index].coerceIn(0f, height.toFloat())
            val endY = nodeCenters[index + 1].coerceIn(0f, height.toFloat())
            if (endY > startY) canvas.drawLine(x, startY, x, endY, railPaint)
        }
    }
}

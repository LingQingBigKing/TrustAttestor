import com.lingqing.trustattestor.*
import com.lingqing.trustattestor.preview.*

fun main() {
    var assertions = 0
    fun verify(condition: Boolean, message: String) {
        check(condition) { message }
        assertions++
    }
    PreviewScenario.entries.forEach { scenario ->
        val state = PreviewFixtures.state(scenario)
        verify(state.steps.map { it.index } == listOf(0, 1, 2, 3), "$scenario: layer order")
        val detected = state.steps.flatMap { it.findings }
            .filter { it.status == FindingStatus.DETECTED }.distinctBy { it.probeId }.size
        verify(state.abnormalCount == detected, "$scenario: only detected findings count")
        verify(state.deviceInfo.first().value.contains("SYNTHETIC"), "$scenario: sample marker")
        verify(state.overallProgressPermille in 0..1000, "$scenario: progress bounds")
    }
    val unavailable = PreviewFixtures.state(PreviewScenario.UNAVAILABLE)
    verify(unavailable.abnormalCount == 0 && unavailable.summaryStatus == ScanState.FAIL,
        "Unavailable must be incomplete with zero anomalies")
    val normal = PreviewFixtures.state(PreviewScenario.PASS)
    verify(normal.summaryStatus == ScanState.PASS && normal.abnormalCount == 0, "Normal outcome")
    verify(normal.steps[2].detail.lineSequence().count { it.startsWith("#") } == 3, "Three sample certificates")
    verify(PreviewFixtures.state(PreviewScenario.DETECTED).abnormalCount == 2, "Two sample anomalies")
    verify(PreviewFixtures.state(PreviewScenario.LONG_TEXT).steps[0].findings.size == 12, "Long evidence set")
    verify(PreviewFixtures.state(PreviewScenario.IDLE).steps.all { it.state == ScanState.IDLE }, "Idle state")
    for (progress in 0..990 step 10) {
        val state = PreviewFixtures.running(progress)
        verify(state.scanning && state.summaryStatus == ScanState.RUNNING, "Replay remains scanning")
        verify(state.overallProgressPermille == progress, "Replay monotonic progress")
        verify(state.steps.count { it.state == ScanState.RUNNING } == 1, "One active layer")
    }
    CloudAttestationState.entries.forEach { cloud ->
        val state = PreviewFixtures.withCloud(normal, cloud)
        verify(state.steps[3].cloudState == cloud, "Cloud state preserved: $cloud")
        verify(state.cloudAttestationEnabled == (cloud != CloudAttestationState.DISABLED), "Cloud toggle: $cloud")
        verify(state.abnormalCount == if (cloud == CloudAttestationState.BREACH) 1 else 0,
            "Cloud warning/unavailable must not become anomalies")
        verify(state.scanning == (cloud == CloudAttestationState.VERIFYING), "Cloud summary activity: $cloud")
        if (cloud == CloudAttestationState.WARNING || cloud == CloudAttestationState.UNAVAILABLE) {
            verify(state.summaryStatus == ScanState.PASS, "Cloud-only unavailability preserves local pass")
        }
    }
    val breached = PreviewFixtures.withCloud(normal, CloudAttestationState.BREACH)
    val disabled = PreviewFixtures.withCloud(breached, CloudAttestationState.DISABLED)
    verify(disabled.abnormalCount == 0 && disabled.steps[3].findings.isEmpty(), "Disable clears demo cloud findings")
    val scanning = PreviewFixtures.withCloud(PreviewFixtures.running(400), CloudAttestationState.VERIFYING)
    verify(scanning.scanning && scanning.summaryStatus == ScanState.RUNNING, "Cloud toggle preserves active scan")
    val cloudFinished = PreviewFixtures.withCloud(
        PreviewFixtures.withCloud(normal, CloudAttestationState.VERIFYING), CloudAttestationState.PASSED)
    verify(!cloudFinished.scanning && cloudFinished.summaryStatus == ScanState.PASS, "Cloud completion stops progress")
    val interaction = PreviewFixtures.running(100).copy(fetchingRevocationList = true,
        revocationListText = "sample timestamp", revocationCountText = "sample count", lastToast = "sample toast")
        .updateStep(2) { it.copy(expanded = true) }
    for (frame in listOf(PreviewFixtures.running(200), normal)) {
        val preserved = PreviewFixtures.preserveUserState(frame, interaction)
        verify(preserved.steps[2].expanded, "Keep user expansion across replay frames")
        verify(preserved.fetchingRevocationList, "Keep mock request loading across replay frames")
        verify(preserved.revocationListText == "sample timestamp" && preserved.revocationCountText == "sample count",
            "Keep about screen data across replay frames")
        verify(preserved.lastToast == "sample toast", "Keep pending toast across replay frames")
    }
    println("PASS: $assertions fixture assertions across ${PreviewScenario.entries.size} scenarios")
}

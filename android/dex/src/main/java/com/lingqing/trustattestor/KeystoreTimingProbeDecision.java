package com.lingqing.trustattestor;

/** Keeps the Java/native timing-probe status contract independent from statistical confidence. */
final class KeystoreTimingProbeDecision {
    static final int COMPLETED = 0;
    static final int DETECTED = 1;
    static final int UNAVAILABLE = 2;

    private KeystoreTimingProbeDecision() { }

    static int status(boolean interfaceHealthy, boolean samplesUsable,
                      boolean anomalyDetected, boolean interrupted) {
        if (!interfaceHealthy || interrupted) return UNAVAILABLE;
        // A bounded sampling budget or a scheduler/clock-window gap can make the statistical
        // sample inconclusive even though AndroidKeyStore itself worked. That is a completed
        // neutral observation, not an unavailable interface. A positive verdict still requires
        // the full usable sample set.
        return samplesUsable && anomalyDetected ? DETECTED : COMPLETED;
    }
}

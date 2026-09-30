package com.lingqing.trustattestor;

/** Run main on the host JDK; no Android runtime or JUnit dependency is required. */
public final class KeystoreTimingProbeDecisionTest {
    private static int assertions;

    public static void main(String[] args) {
        check(KeystoreTimingProbeDecision.status(true, true, false, false)
                        == KeystoreTimingProbeDecision.COMPLETED,
                "complete noisy samples stay completed");
        check(KeystoreTimingProbeDecision.status(true, true, false, false)
                        == KeystoreTimingProbeDecision.COMPLETED,
                "complete normal samples are completed");
        check(KeystoreTimingProbeDecision.status(true, true, true, false)
                        == KeystoreTimingProbeDecision.DETECTED,
                "stable anomaly is detected");
        check(KeystoreTimingProbeDecision.status(true, false, false, false)
                        == KeystoreTimingProbeDecision.COMPLETED,
                "bounded inconclusive sampling is completed and neutral");
        check(KeystoreTimingProbeDecision.status(false, false, false, false)
                        == KeystoreTimingProbeDecision.UNAVAILABLE,
                "an unhealthy keystore interface remains unavailable");
        check(KeystoreTimingProbeDecision.status(true, true, false, true)
                        == KeystoreTimingProbeDecision.UNAVAILABLE,
                "an interrupted scan remains unavailable");
        System.out.println("KeystoreTimingProbeDecisionTest: " + assertions
                + " assertions passed");
    }

    private static void check(boolean value, String description) {
        assertions++;
        if (!value) throw new AssertionError(description);
    }
}

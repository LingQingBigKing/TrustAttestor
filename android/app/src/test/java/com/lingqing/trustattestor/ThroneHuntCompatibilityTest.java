package com.lingqing.trustattestor;

import java.util.HashSet;
import java.util.Set;

/** Host-side checks for API gates and the PackageManager MIME-group stimulus. */
public final class ThroneHuntCompatibilityTest {
    private static int assertions;

    public static void main(String[] args) {
        apiGatesMatchPlatformCapabilities();
        passiveWaitIsBounded();
        markersDoNotChangeEffectiveIntentFilters();
        markerStateAlternatesWithoutDestroyingOtherEntries();
        System.out.println("ThroneHuntCompatibilityTest: " + assertions + " assertions passed");
    }

    private static void passiveWaitIsBounded() {
        check(ThroneHuntCarrierManager.maximumPassiveWaitMillis() == 15_500L,
                "carrier bind plus observation covers the delayed settings write");
        check(ThroneHuntStimulus.SETTINGS_WRITE_WINDOW_MS
                        > ThroneHuntStimulus.SETTINGS_WRITE_DELAY_MS,
                "observation includes a post-write manager-search allowance");
    }

    private static void apiGatesMatchPlatformCapabilities() {
        check(!ThroneHuntCarrierManager.supportsRetainedPreloadDescriptors(30),
                "Android 11 does not run the retained-descriptor probe");
        check(ThroneHuntCarrierManager.supportsRetainedPreloadDescriptors(31),
                "Android 12 enables the retained-descriptor probe");
        check(!ThroneHuntStimulus.supportsMimeGroups(29),
                "MIME-group API is unavailable before Android 11");
        check(ThroneHuntStimulus.supportsMimeGroups(30),
                "MIME-group API is available on Android 11+");
    }

    private static void markersDoNotChangeEffectiveIntentFilters() {
        check(!ThroneHuntStimulus.isFrameworkValidMime(ThroneHuntStimulus.MARK_A),
                "marker A is deliberately malformed");
        check(!ThroneHuntStimulus.isFrameworkValidMime(ThroneHuntStimulus.MARK_B),
                "marker B is deliberately malformed");
        check(ThroneHuntStimulus.isFrameworkValidMime("image/png"),
                "ordinary MIME values remain framework-valid");
    }

    private static void markerStateAlternatesWithoutDestroyingOtherEntries() {
        Set<String> initial = new HashSet<>();
        initial.add("image/png");
        initial.add("application/x-trustattestor-throne-a");
        initial.add(ThroneHuntStimulus.MARK_A);

        Set<String> first = ThroneHuntStimulus.nextMimeTypes(initial);
        check(first.contains("image/png"), "unrelated MIME entries are preserved");
        check(first.contains(ThroneHuntStimulus.MARK_B)
                        && !first.contains(ThroneHuntStimulus.MARK_A),
                "marker A toggles to marker B");
        check(!first.contains("application/x-trustattestor-throne-a"),
                "legacy effective markers are removed");
        check(initial.contains(ThroneHuntStimulus.MARK_A),
                "the caller's MIME set is not mutated");

        Set<String> second = ThroneHuntStimulus.nextMimeTypes(first);
        check(second.contains(ThroneHuntStimulus.MARK_A)
                        && !second.contains(ThroneHuntStimulus.MARK_B),
                "marker B toggles back to marker A");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

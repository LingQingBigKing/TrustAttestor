package com.lingqing.trustattestor;

/** Run main on the host JDK; no Android runtime or JUnit dependency is required. */
public final class ThroneHuntWatchSnapshotTest {
    private static int assertions;

    public static void main(String[] args) {
        setupPayloadDoesNotNeedEventCounts();
        drainPayloadCarriesCounts();
        namedChildEventsAreNoise();
        partialDrainsAccumulate();
        supportAndFailureDiagnosticsAreDecoded();
        invalidWatchStatesAreNotUsable();
        System.out.println("ThroneHuntWatchSnapshotTest: " + assertions + " assertions passed");
    }

    private static void setupPayloadDoesNotNeedEventCounts() {
        ThroneHuntWatchSnapshot snapshot = ThroneHuntWatchSnapshot.parse(
                "WATCH_INSTALLED=1\nWATCH_DESCRIPTOR=4\nWATCH_PACKAGE_DIR=/data/app/pkg\n");
        check(snapshot.usable(), "installed watch without event payload is usable");
        check(snapshot.directoryOpen == 0 && snapshot.directoryAccess == 0,
                "setup response has no event counts");
    }

    private static void drainPayloadCarriesCounts() {
        ThroneHuntWatchSnapshot snapshot = ThroneHuntWatchSnapshot.parse(
                "WATCH_INSTALLED=1\nWATCH_DESCRIPTOR=4\n"
                        + "EVENT_DIRECTORY_OPEN=2\nEVENT_DIRECTORY_ACCESS=3\n"
                        + "EVENT_RAW=7\nEVENT_INVALID=0\n");
        check(snapshot.usable(), "valid drain is usable");
        check(snapshot.directoryOpen == 2 && snapshot.directoryAccess == 3,
                "directory open/access counts are decoded");
        check(snapshot.raw == 7 && snapshot.invalidEvents == 0,
                "raw and invalid counts are decoded");
    }

    private static void namedChildEventsAreNoise() {
        ThroneHuntWatchSnapshot snapshot = ThroneHuntWatchSnapshot.parse(
                "WATCH_SUPPORTED=1\nWATCH_INSTALLED=1\nWATCH_DESCRIPTOR=4\n"
                        + "WATCH_STAGE=drain\nEVENT_RAW=3\nEVENT_INVALID=0\n"
                        + "EVENT_NAMED_NOISE=3\n");
        check(snapshot.usable(), "ordinary named child events do not invalidate the watch");
        check(snapshot.namedNoise == 3 && "drain".equals(snapshot.stage),
                "named noise and native stage are decoded");
        check(snapshot.encode("FINAL_").contains("FINAL_NAMED_NOISE=3\n"),
                "named noise is forwarded in the round payload");
    }

    private static void partialDrainsAccumulate() {
        ThroneHuntWatchSnapshot total = new ThroneHuntWatchSnapshot();
        ThroneHuntWatchSnapshot first = ThroneHuntWatchSnapshot.parse(
                "EVENT_DIRECTORY_OPEN=1\nEVENT_RAW=2\nEVENT_NAMED_NOISE=1\n");
        ThroneHuntWatchSnapshot second = ThroneHuntWatchSnapshot.parse(
                "EVENT_DIRECTORY_ACCESS=1\nEVENT_RAW=3\nEVENT_NAMED_NOISE=2\n");
        total.addEventCountsFrom(first);
        check(total.signalObserved(), "an OPEN-only directory traversal is a positive signal");
        total.addEventCountsFrom(second);
        check(total.signalObserved(), "open and access events can arrive in separate drains");
        check(total.raw == 5 && total.namedNoise == 3,
                "polling drain counts are accumulated");
    }

    private static void supportAndFailureDiagnosticsAreDecoded() {
        ThroneHuntWatchSnapshot unsupported = ThroneHuntWatchSnapshot.parse(
                "WATCH_SUPPORTED=0\nWATCH_STAGE=path\nWATCH_ERRNO=22\n"
                        + "WATCH_DETAIL=sourceDir is not an installed path\n");
        check(!unsupported.usable(), "explicitly unsupported watch is not usable");
        check(unsupported.problem().contains("stage=path")
                        && unsupported.problem().contains("errno=22"),
                "watch stage and errno are retained in diagnostics");
        ThroneHuntWatchSnapshot gone = ThroneHuntWatchSnapshot.parse(
                "WATCH_INSTALLED=1\nWATCH_DESCRIPTOR=2\nWATCH_GONE=1\n");
        check(!gone.usable() && gone.problem().contains("disappeared"),
                "a removed package directory has a distinct diagnostic");
    }

    private static void invalidWatchStatesAreNotUsable() {
        check(!ThroneHuntWatchSnapshot.parse("WATCH_INSTALLED=0\n").usable(),
                "missing watch is unavailable");
        check(!ThroneHuntWatchSnapshot.parse(
                "WATCH_INSTALLED=1\nWATCH_DESCRIPTOR=-1\n").usable(),
                "invalid descriptor is unavailable");
        check(!ThroneHuntWatchSnapshot.parse(
                "WATCH_INSTALLED=1\nWATCH_DESCRIPTOR=2\nWATCH_OVERFLOW=1\n").usable(),
                "queue overflow is unavailable");
        check(!ThroneHuntWatchSnapshot.parse(
                "WATCH_INSTALLED=1\nWATCH_DESCRIPTOR=2\nEVENT_INVALID=1\n").usable(),
                "malformed events invalidate a drain");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
}

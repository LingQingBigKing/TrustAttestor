package com.lingqing.trustattestor;

/** Small line-oriented payload returned by the native inotify carrier. */
final class ThroneHuntWatchSnapshot {
    boolean supported = true;
    boolean installed;
    boolean addDenied;
    boolean invalid;
    boolean overflow;
    boolean gone;
    int descriptor = -1;
    int errno;
    String packageDirectory = "";
    String stage = "";
    String detail = "";
    int directoryOpen;
    int directoryAccess;
    int raw;
    int invalidEvents;
    int namedNoise;

    static ThroneHuntWatchSnapshot parse(String payload) {
        ThroneHuntWatchSnapshot snapshot = new ThroneHuntWatchSnapshot();
        if (payload == null) return snapshot;
        for (String line : payload.split("\\n")) {
            int separator = line.indexOf('=');
            if (separator <= 0) continue;
            String key = line.substring(0, separator);
            String value = line.substring(separator + 1);
            switch (key) {
                case "WATCH_SUPPORTED" -> snapshot.supported = bool(value);
                case "WATCH_INSTALLED" -> snapshot.installed = bool(value);
                case "WATCH_ADD_DENIED" -> snapshot.addDenied = bool(value);
                case "WATCH_INVALID" -> snapshot.invalid = bool(value);
                case "WATCH_OVERFLOW" -> snapshot.overflow = bool(value);
                case "WATCH_GONE" -> snapshot.gone = bool(value);
                case "WATCH_DESCRIPTOR" -> snapshot.descriptor = integer(value, -1);
                case "WATCH_ERRNO" -> snapshot.errno = integer(value, 0);
                case "WATCH_PACKAGE_DIR" -> snapshot.packageDirectory = value;
                case "WATCH_STAGE" -> snapshot.stage = value;
                case "WATCH_DETAIL" -> snapshot.detail = value;
                case "EVENT_DIRECTORY_OPEN" -> snapshot.directoryOpen = integer(value, 0);
                case "EVENT_DIRECTORY_ACCESS" -> snapshot.directoryAccess = integer(value, 0);
                case "EVENT_RAW" -> snapshot.raw = integer(value, 0);
                case "EVENT_INVALID" -> snapshot.invalidEvents = integer(value, 0);
                case "EVENT_NAMED_NOISE" -> snapshot.namedNoise = integer(value, 0);
                default -> { }
            }
        }
        return snapshot;
    }

    String encode(String prefix) {
        String safePrefix = prefix == null ? "" : prefix;
        return safePrefix + "OPEN=" + directoryOpen + "\n"
                + safePrefix + "ACCESS=" + directoryAccess + "\n"
                + safePrefix + "RAW=" + raw + "\n"
                + safePrefix + "INVALID=" + invalidEvents + "\n"
                + safePrefix + "NAMED_NOISE=" + namedNoise + "\n";
    }

    boolean usable() {
        return supported && installed && descriptor >= 0 && !addDenied && !invalid
                && !overflow && !gone && invalidEvents == 0;
    }

    boolean signalObserved() {
        // Kernel/filesystem combinations do not promise both bits for a directory traversal.
        // Either unnamed self event is the positive signal used by KernelSU's recovery walk.
        return directoryOpen > 0 || directoryAccess > 0;
    }

    void addEventCountsFrom(ThroneHuntWatchSnapshot other) {
        if (other == null) return;
        directoryOpen = saturatedAdd(directoryOpen, other.directoryOpen);
        directoryAccess = saturatedAdd(directoryAccess, other.directoryAccess);
        raw = saturatedAdd(raw, other.raw);
        invalidEvents = saturatedAdd(invalidEvents, other.invalidEvents);
        namedNoise = saturatedAdd(namedNoise, other.namedNoise);
    }

    String problem() {
        String reason;
        if (!supported) reason = "watch is not supported on this platform or install path";
        else if (addDenied) reason = "inotify_add_watch was denied";
        else if (gone) reason = "watched package directory disappeared";
        else if (!installed) reason = "watch was not installed";
        else if (descriptor < 0) reason = "watch descriptor is invalid";
        else if (overflow) reason = "inotify queue overflowed";
        else if (invalid) reason = "watch entered an invalid state";
        else if (invalidEvents != 0) reason = "invalid inotify events=" + invalidEvents;
        else reason = "watch snapshot is unavailable";
        if (stage != null && !stage.isEmpty()) reason += " (stage=" + stage + ")";
        if (errno != 0) reason += " (errno=" + errno + ")";
        if (detail != null && !detail.isEmpty()) reason += ": " + detail;
        return reason;
    }

    private static boolean bool(String value) {
        return "1".equals(value) || "true".equalsIgnoreCase(value);
    }

    private static int integer(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private static int saturatedAdd(int left, int right) {
        long result = (long) left + right;
        if (result > Integer.MAX_VALUE) return Integer.MAX_VALUE;
        if (result < Integer.MIN_VALUE) return Integer.MIN_VALUE;
        return (int) result;
    }
}


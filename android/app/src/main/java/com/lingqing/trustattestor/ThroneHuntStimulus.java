package com.lingqing.trustattestor;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import java.util.HashSet;
import java.util.Set;

/** Causes PackageManagerService to rewrite packages.list without installing a package. */
final class ThroneHuntStimulus {
    static final String MIME_GROUP = "trustattestor-throne-hunt";
    static final String MARK_A = "trustattestor-throne-a";
    static final String MARK_B = "trustattestor-throne-b";
    private static final String LEGACY_MARK_A = "application/x-trustattestor-throne-a";
    private static final String LEGACY_MARK_B = "application/x-trustattestor-throne-b";
    static final long SETTINGS_WRITE_DELAY_MS = 10_000L;
    static final long SEARCH_MANAGER_ALLOWANCE_MS = 3_000L;
    static final long SETTINGS_WRITE_WINDOW_MS =
            SETTINGS_WRITE_DELAY_MS + SEARCH_MANAGER_ALLOWANCE_MS;

    private ThroneHuntStimulus() { }

    @TargetApi(Build.VERSION_CODES.R)
    static Result run(Context context) {
        if (!supportsMimeGroups(Build.VERSION.SDK_INT) || context == null) {
            return new Result(false, false, "PackageManager MIME groups require Android 11+");
        }
        PackageManager packageManager = context.getPackageManager();
        if (packageManager == null) {
            return new Result(false, false, "getPackageManager returned null");
        }

        final Set<String> current;
        try {
            current = copyMimeGroup(packageManager.getMimeGroup(MIME_GROUP), "initial read");
        } catch (Throwable failure) {
            return failure("getMimeGroup(initial)", false, failure);
        }

        Set<String> next = nextMimeTypes(current);
        String mark = next.contains(MARK_B) ? MARK_B : MARK_A;
        try {
            packageManager.setMimeGroup(MIME_GROUP, next);
        } catch (Throwable failure) {
            return failure("setMimeGroup", false, failure);
        }

        final Set<String> readback;
        try {
            readback = copyMimeGroup(packageManager.getMimeGroup(MIME_GROUP), "readback");
        } catch (Throwable failure) {
            return failure("getMimeGroup(readback)", true, failure);
        }
        boolean matches = readback.equals(next) && readback.contains(mark);
        return new Result(true, matches, matches
                ? "PackageManager MIME group changed and read back: " + mark
                : "PackageManager MIME group readback mismatch");
    }

    static boolean supportsMimeGroups(int sdkInt) {
        return sdkInt >= Build.VERSION_CODES.R;
    }

    static Set<String> nextMimeTypes(Set<String> current) {
        Set<String> next = new HashSet<>();
        if (current != null) {
            for (String value : current) {
                if (isFrameworkValidMime(value)
                        && !LEGACY_MARK_A.equals(value)
                        && !LEGACY_MARK_B.equals(value)) {
                    next.add(value);
                }
            }
        }
        boolean useB = current != null && current.contains(MARK_A)
                && !current.contains(MARK_B);
        next.add(useB ? MARK_B : MARK_A);
        return next;
    }

    /**
     * PackageManager persists malformed dynamic-group entries but ComponentResolver cannot add
     * them to an effective intent filter. Alternating such an entry schedules packages.list while
     * avoiding a PACKAGE_CHANGED broadcast and the package-directory noise it would create.
     */
    static boolean isFrameworkValidMime(String value) {
        if (value == null) return false;
        int slash = value.indexOf('/');
        return slash > 0 && slash < value.length() - 1;
    }

    private static Set<String> copyMimeGroup(Set<String> value, String phase) {
        if (value == null) throw new IllegalStateException(phase + " returned null");
        Set<String> result = new HashSet<>();
        for (String mime : value) {
            if (mime == null || mime.isEmpty()) {
                throw new IllegalStateException(phase + " returned an empty MIME type");
            }
            result.add(mime);
        }
        return result;
    }

    private static Result failure(String phase, boolean applied, Throwable failure) {
        StringBuilder detail = new StringBuilder(phase).append(" failed: ")
                .append(failure.getClass().getSimpleName());
        if (failure.getMessage() != null && !failure.getMessage().isEmpty()) {
            detail.append(": ").append(failure.getMessage());
        }
        Throwable cause = failure.getCause();
        if (cause != null && cause != failure) {
            detail.append(" <- ").append(cause.getClass().getSimpleName());
            if (cause.getMessage() != null && !cause.getMessage().isEmpty()) {
                detail.append(": ").append(cause.getMessage());
            }
        }
        return new Result(applied, false, detail.toString());
    }

    static final class Result {
        final boolean applied;
        final boolean readback;
        final String detail;

        Result(boolean applied, boolean readback, String detail) {
            this.applied = applied;
            this.readback = readback;
            this.detail = detail == null ? "" : detail;
        }
    }
}


package com.lingqing.trustattestor;

import android.annotation.TargetApi;
import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Process;

@TargetApi(Build.VERSION_CODES.Q)
public class TrustAttestorZygotePreload implements ZygotePreload {
    private static final int SEPOLICY_PROBE_ERROR = 1 << 6;
    private static final int RESULT_UNAVAILABLE = 1 << 5;

    public native int check();
    public static native String installThroneHuntWatch(String sourceDir);
    public static native String throneHuntWatchState();
    public static native String throneHuntWatchDrain();
    public static native String throneHuntWatchReset();

    static {
        System.loadLibrary("TrustAttestor");
    }

    // Never let a missing or interrupted preload look like a clean result.
    public static volatile int success = RESULT_UNAVAILABLE;

    @Override
    public void doPreload(ApplicationInfo app) {
        success = RESULT_UNAVAILABLE;
        // DirtySepolicy treats a UID mismatch as a fake App Zygote
        // environment. Keep check() argument-free so its JNI ABI stays ()I.
        if (app == null || Process.myUid() != app.uid) {
            success = SEPOLICY_PROBE_ERROR;
            return;
        }
        // Android 11 does not preserve descriptors opened by an app-zygote
        // preload across the service fork. Do not create a watch that cannot be
        // consumed; the main probe also treats this capability as not applicable.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            installThroneHuntWatch(app.sourceDir);
        }
        success = check();
    }
}

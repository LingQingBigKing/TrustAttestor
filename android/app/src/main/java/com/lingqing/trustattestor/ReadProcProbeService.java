package com.lingqing.trustattestor;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;

/** Runs outside the App Zygote so it can retain the platform Zygote READPROC group. */
public final class ReadProcProbeService extends Service {
    private static final int TRANSACTION_CHECK = 1;

    static {
        System.loadLibrary("TrustAttestor");
    }

    private volatile int result;
    private volatile boolean checked;

    private native int check();

    private int getResult() {
        if (!checked) {
            synchronized (this) {
                if (!checked) {
                    result = isCurrentProcessIsolated() ? check() : 1;
                    checked = true;
                }
            }
        }
        return result;
    }

    @Override
    public IBinder onBind(Intent intent) {
        if (!isCurrentProcessIsolated()) return null;
        return new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                if (code != TRANSACTION_CHECK || reply == null) return false;
                reply.writeInt(getResult());
                return true;
            }
        };
    }

    private static boolean isCurrentProcessIsolated() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return Process.isIsolated();
        }
        // Android assigns pre-P isolated processes from this per-user app-id range.
        int appId = Process.myUid() % 100000;
        return appId >= 99000 && appId <= 99999;
    }
}

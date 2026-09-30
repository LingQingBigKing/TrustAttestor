package com.lingqing.trustattestor;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Matches the fixed getDeviceId reply forged by TEESimulator-RS. */
public final class SoterRsProbe {
    private static final String TAG = "TrustAttestorLog";
    private static final String SOTER_PACKAGE = "com.tencent.soter.soterserver";
    private static final String SOTER_DESCRIPTOR =
            "com.tencent.soter.soterserver.ISoterService";
    private static final int TRANSACTION_GET_DEVICE_ID = 11;
    private static final byte[] TEESIM_DEVICE_ID =
            "TEESIM-SOTER-0001".getBytes(StandardCharsets.UTF_8);
    private static final long TIMEOUT_SECONDS = 3;

    private SoterRsProbe() {}

    public static boolean probe(Context context) {
        if (context == null) return false;
        return new Session(context.getApplicationContext()).run();
    }

    private static final class Session {
        private final Context context;
        private final CountDownLatch completed = new CountDownLatch(1);
        private final AtomicBoolean bound = new AtomicBoolean(false);
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final AtomicBoolean transactionStarted = new AtomicBoolean(false);
        private volatile boolean matched;

        private final ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                if (closed.get() || service == null ||
                        !transactionStarted.compareAndSet(false, true)) {
                    return;
                }
                Thread transaction = new Thread(() -> complete(probeBinder(service)),
                        "TrustAttestor-SoterProbe");
                transaction.start();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                complete(false);
            }

            @Override
            public void onNullBinding(ComponentName name) {
                complete(false);
            }

            @Override
            public void onBindingDied(ComponentName name) {
                complete(false);
            }
        };

        private Session(Context context) {
            this.context = context;
        }

        private boolean run() {
            try {
                Intent intent = new Intent(SOTER_DESCRIPTOR).setPackage(SOTER_PACKAGE);
                boolean didBind = context.bindService(intent, connection, Context.BIND_AUTO_CREATE);
                bound.set(didBind);
                if (!didBind) return false;
                if (!completed.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    Log.d(TAG, "TEESimulator-RS SOTER probe timed out");
                    return false;
                }
                return matched;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            } catch (Throwable t) {
                Log.d(TAG, "TEESimulator-RS SOTER service unavailable", t);
                return false;
            } finally {
                closed.set(true);
                unbind();
            }
        }

        private void complete(boolean hit) {
            if (closed.get()) return;
            if (hit) matched = true;
            completed.countDown();
        }

        private void unbind() {
            if (!bound.compareAndSet(true, false)) return;
            try {
                context.unbindService(connection);
            } catch (Throwable t) {
                Log.d(TAG, "TEESimulator-RS SOTER unbind ignored", t);
            }
        }
    }

    private static boolean probeBinder(IBinder service) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(SOTER_DESCRIPTOR);
            if (!service.transact(TRANSACTION_GET_DEVICE_ID, data, reply, 0)) return false;
            reply.readException();
            if (reply.readInt() == 0) return false;
            int resultCode = reply.readInt();
            byte[] exportData = reply.createByteArray();
            int exportDataLength = reply.readInt();
            return resultCode == 0 && exportData != null &&
                    exportDataLength == exportData.length &&
                    Arrays.equals(exportData, TEESIM_DEVICE_ID);
        } catch (Throwable t) {
            Log.d(TAG, "TEESimulator-RS SOTER transaction unavailable", t);
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
}

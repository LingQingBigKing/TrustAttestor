package com.lingqing.trustattestor;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Starts the App Zygote probe early so its cold start overlaps local checks. */
public final class AppZygoteProbe {
    private static final String TAG = "TrustAttestorLog";
    private static final int RESULT_UNAVAILABLE = 1 << 5;
    private static final Object SESSION_LOCK = new Object();

    private static Session currentSession;

    private AppZygoteProbe() {}

    public static void prepare(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || context == null) return;

        Session previous;
        Session next = new Session(context.getApplicationContext());
        synchronized (SESSION_LOCK) {
            previous = currentSession;
            currentSession = next;
        }
        if (previous != null) previous.close();
        next.start();
    }

    public static int awaitResult(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return RESULT_UNAVAILABLE;

        Session session;
        synchronized (SESSION_LOCK) {
            session = currentSession;
        }
        if (session == null) {
            prepare(context);
            synchronized (SESSION_LOCK) {
                session = currentSession;
            }
        }
        return session == null ? RESULT_UNAVAILABLE : session.awaitResult();
    }

    public static void release() {
        Session session;
        synchronized (SESSION_LOCK) {
            session = currentSession;
            currentSession = null;
        }
        if (session != null) session.close();
    }

    private static final class Session {
        private final Context context;
        private final CountDownLatch completed = new CountDownLatch(1);
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final AtomicBoolean bound = new AtomicBoolean(false);
        private volatile int result = RESULT_UNAVAILABLE;

        private final ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    if (service.transact(1, data, reply, 0)) {
                        result = reply.readInt();
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "App Zygote transaction failed", t);
                } finally {
                    data.recycle();
                    reply.recycle();
                    complete();
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                complete();
            }

            @Override
            public void onNullBinding(ComponentName name) {
                complete();
            }

            @Override
            public void onBindingDied(ComponentName name) {
                complete();
            }
        };

        private Session(Context context) {
            this.context = context;
        }

        @SuppressLint("NewApi")
        private void start() {
            try {
                String instanceName = "ta" + Long.toHexString(System.nanoTime())
                        + Integer.toHexString(System.identityHashCode(this));
                boolean didBind = context.bindIsolatedService(
                        new Intent().setComponent(new ComponentName(
                                context.getPackageName(), TrustAttestorService.class.getName())),
                        Context.BIND_AUTO_CREATE,
                        instanceName,
                        context.getMainExecutor(),
                        connection);
                bound.set(didBind);
                if (!didBind) complete();
                if (completed.getCount() == 0) unbind();
            } catch (Throwable t) {
                Log.e(TAG, "App Zygote bind failed", t);
                complete();
            }
        }

        private int awaitResult() {
            try {
                completed.await(8, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                close();
            }
            return result;
        }

        private void complete() {
            completed.countDown();
            unbind();
        }

        private void close() {
            if (closed.compareAndSet(false, true)) {
                completed.countDown();
                unbind();
            }
        }

        private void unbind() {
            if (!bound.compareAndSet(true, false)) return;
            try {
                context.unbindService(connection);
            } catch (Throwable t) {
                Log.d(TAG, "App Zygote unbind ignored", t);
            }
        }
    }
}

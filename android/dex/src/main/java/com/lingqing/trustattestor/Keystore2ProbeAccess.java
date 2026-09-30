package com.lingqing.trustattestor;

import android.os.IBinder;

/**
 * Gives active probes the real Keystore2 Binder captured before the in-process
 * certificate-observation proxy is installed.
 *
 * <p>Using {@link ServiceManager#getService(String)} after the hook is installed would return
 * TrustAttestor's own local dynamic proxy. That would invalidate Binder-locality observations and
 * add certificate parsing work to timing probes.</p>
 */
final class Keystore2ProbeAccess {
    private static volatile IBinder rawBinder;

    private Keystore2ProbeAccess() { }

    static void clear() {
        rawBinder = null;
    }

    static void publishRawBinder(IBinder binder) {
        if (binder != null) rawBinder = binder;
    }

    static IBinder binder() {
        // Never fall back to ServiceManager here. Once TrustAttestor has installed its observation
        // hook, that cache can contain our own local proxy and would invalidate locality/timing.
        return rawBinder;
    }
}

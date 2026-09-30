package com.lingqing.trustattestor;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;

public class TrustAttestorService extends Service {
    private IsolatedAttestationResponder attestationResponder;

    @Override
    public IBinder onBind(Intent intent) {
        if (intent != null && IsolatedAttestationResponder.ACTION.equals(intent.getAction())) {
            if (attestationResponder == null) attestationResponder = new IsolatedAttestationResponder(this);
            return attestationResponder.binder();
        }
        return new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                if (reply != null) {
                    if (code == 1) {
                        reply.writeInt(TrustAttestorZygotePreload.success);
                    } else if (code == 2) {
                        reply.writeString(TrustAttestorZygotePreload.throneHuntWatchState());
                    } else if (code == 3) {
                        reply.writeString(TrustAttestorZygotePreload.throneHuntWatchDrain());
                    } else if (code == 4) {
                        reply.writeString(TrustAttestorZygotePreload.throneHuntWatchReset());
                    } else {
                        reply.writeInt(0);
                    }
                }
                return true;
            }
        };
    }

    @Override public void onDestroy() {
        if (attestationResponder != null) attestationResponder.close();
        super.onDestroy();
    }
}

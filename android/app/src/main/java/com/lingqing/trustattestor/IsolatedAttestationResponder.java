package com.lingqing.trustattestor;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.RemoteException;

/** Runs only in the bound service after App Zygote has forked and specialized it. */
final class IsolatedAttestationResponder implements AutoCloseable {
    static final String ACTION = "com.lingqing.trustattestor.ISOLATED_ATTESTATION_V1";
    static final int HELLO = 1;
    static final int READ = 2;
    private final Context context;
    private final HandlerThread thread = new HandlerThread("ta-chain-reader");
    private final Messenger receiver;
    private String token;
    private IBinder peer;
    private boolean readStarted;

    IsolatedAttestationResponder(Context context) {
        this.context = context;
        thread.start();
        receiver = new Messenger(new Handler(thread.getLooper(), this::handle));
    }

    IBinder binder() { return receiver.getBinder(); }

    private boolean handle(Message request) {
        if (request.replyTo == null || request.sendingUid != context.getApplicationInfo().uid) return true;
        Bundle input = request.getData();
        String requestToken = input.getString("token");
        if (requestToken == null || requestToken.length() != 36) return true;
        if (request.what == HELLO && token == null) {
            token = requestToken;
            peer = request.replyTo.getBinder();
        } else if (!requestToken.equals(token) || !request.replyTo.getBinder().equals(peer)) {
            return true;
        }
        Bundle output = new Bundle();
        output.putString("token", token);
        output.putInt("uid", Process.myUid());
        output.putInt("status", IsolatedAttestationProbe.TRANSPORT_UNAVAILABLE);
        try {
            if (request.what == HELLO) {
                new PublicKeyGrantApi(context);
                output.putInt("status", IsolatedAttestationProbe.CLEAN);
            } else if (request.what == READ && !readStarted && input.containsKey("grant")) {
                readStarted = true;
                byte[][] chain = new PublicKeyGrantApi(context).read(input.getLong("grant"));
                output.putInt("count", chain.length);
                for (int i = 0; i < chain.length; i++) output.putByteArray("cert" + i, chain[i]);
                output.putInt("status", IsolatedAttestationProbe.CLEAN);
            }
        } catch (UnsupportedOperationException | ReflectiveOperationException unavailable) {
            output.putInt("status",
                    IsolatedAttestationCapabilityPolicy.optionalSharingFailureStatus());
        } catch (Exception | LinkageError unavailable) {
            // A grant may be issued by the owner while the vendor Keystore provider still does
            // not support resolving it from an isolated UID. Treat that documented provider/API
            // limitation as not applicable. Only a successfully returned chain is evidence that
            // can be compared by the detector.
            output.putInt("status", IsolatedAttestationProbe.API_UNAVAILABLE);
        }
        Message response = Message.obtain(null, request.what);
        response.setData(output);
        try { request.replyTo.send(response); } catch (RemoteException ignored) { }
        return true;
    }

    @Override public void close() { thread.quitSafely(); }
}

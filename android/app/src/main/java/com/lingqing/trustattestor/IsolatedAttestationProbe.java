package com.lingqing.trustattestor;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Silent, public-SDK sharing of one app-owned disposable attestation key. */
public final class IsolatedAttestationProbe {
    public static final int CLEAN = 0;
    public static final int ANOMALY = 1;
    public static final int API_UNAVAILABLE = 2;
    public static final int ACCESS_UNAVAILABLE = 3;
    public static final int TRANSPORT_UNAVAILABLE = 4;
    public static final int EVIDENCE_UNAVAILABLE = 5;
    public static final int CLEANUP_INCOMPLETE = 6;
    public static final int NOT_RUN = 7;
    private static final long BUDGET_MS = 15000;
    private static final AtomicBoolean running = new AtomicBoolean();
    private static final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "ta-chain-owner");
        thread.setDaemon(true);
        return thread;
    });

    private IsolatedAttestationProbe() { }

    /** Kept by R8: called from the separately loaded attestation DEX. */
    public static int run(Context context) {
        if (context == null) return NOT_RUN;
        if (Build.VERSION.SDK_INT < 36) return API_UNAVAILABLE;
        if (!running.compareAndSet(false, true)) return TRANSPORT_UNAVAILABLE;
        Session session = new Session(context.getApplicationContext());
        Future<Integer> future;
        try {
            future = worker.submit(() -> {
                try { return session.inspect(); }
                finally { running.set(false); }
            });
        } catch (RuntimeException unavailable) {
            running.set(false);
            return TRANSPORT_UNAVAILABLE;
        }
        try {
            return future.get(BUDGET_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            session.cancelled.set(true);
            Thread.currentThread().interrupt();
            return session.establishedOutcome == ANOMALY ? ANOMALY : TRANSPORT_UNAVAILABLE;
        } catch (Exception unavailable) {
            // Do not start more work while a slow platform call finishes and cleans up.
            session.cancelled.set(true);
            return session.establishedOutcome == ANOMALY ? ANOMALY : TRANSPORT_UNAVAILABLE;
        }
    }

    private static final class Response {
        final int uid;
        final int what;
        final Bundle data;
        Response(Message message) {
            uid = message.sendingUid;
            what = message.what;
            data = new Bundle(message.getData());
        }
    }

    @android.annotation.TargetApi(29)
    private static final class Session {
        final Context context;
        final AtomicBoolean cancelled = new AtomicBoolean();
        final long deadline = SystemClock.elapsedRealtime() + BUDGET_MS;
        final String token = UUID.randomUUID().toString();
        final String alias = "TrustAttestor_isolated_" + UUID.randomUUID();
        final CountDownLatch connected = new CountDownLatch(1);
        final ArrayBlockingQueue<Response> responses = new ArrayBlockingQueue<>(2);
        final HandlerThread callbacks = new HandlerThread("ta-chain-callback");
        volatile Messenger remote;
        volatile boolean disconnected;
        volatile int establishedOutcome = NOT_RUN;
        Messenger receiver;
        boolean bound;
        boolean bindingAttempted;
        int granteeUid = -1;

        Session(Context context) { this.context = context; }

        final ServiceConnection connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder binder) {
                if (!cancelled.get()) remote = new Messenger(binder);
                connected.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name) { disconnect(); }
            @Override public void onBindingDied(ComponentName name) { disconnect(); }
            @Override public void onNullBinding(ComponentName name) { disconnect(); }
            private void disconnect() { disconnected = true; connected.countDown(); }
        };

        int inspect() {
            int outcome = ACCESS_UNAVAILABLE;
            PublicKeyGrantApi api = null;
            KeyStore store = null;
            boolean ownAlias = false;
            boolean grantIssued = false;
            try {
              inspection: {
                api = new PublicKeyGrantApi(context);
                callbacks.start();
                Handler handler = new Handler(callbacks.getLooper());
                receiver = new Messenger(new Handler(callbacks.getLooper(), message -> {
                    if (!cancelled.get() && token.equals(message.getData().getString("token"))) {
                        responses.offer(new Response(message));
                    }
                    return true;
                }));
                Intent intent = new Intent(context, TrustAttestorService.class)
                        .setAction(IsolatedAttestationResponder.ACTION);
                bindingAttempted = true;
                bound = context.bindIsolatedService(intent, Context.BIND_AUTO_CREATE,
                        "chain_" + token.replace("-", ""), command -> handler.post(command), connection);
                if (!bound || !connected.await(remaining(5000), TimeUnit.MILLISECONDS)
                        || remote == null || disconnected) throw new TimeoutException();

                Response hello = exchange(IsolatedAttestationResponder.HELLO, new Bundle());
                // sendingUid is supplied by Messenger/Binder, not by the response body.
                if (hello.uid <= 0 || hello.uid == Process.myUid()
                        || hello.uid != hello.data.getInt("uid", -1)) {
                    outcome = EVIDENCE_UNAVAILABLE;
                    break inspection;
                }
                granteeUid = hello.uid;
                int helloStatus = hello.data.getInt("status", TRANSPORT_UNAVAILABLE);
                if (helloStatus != CLEAN) { outcome = unavailableStatus(helloStatus); break inspection; }

                checkActive();
                store = KeyStore.getInstance("AndroidKeyStore");
                store.load(null);
                if (store.containsAlias(alias)) { outcome = EVIDENCE_UNAVAILABLE; break inspection; }
                ownAlias = true;
                byte[] challenge = new byte[32];
                new SecureRandom().nextBytes(challenge);
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(false)
                        .setAttestationChallenge(challenge).build());
                KeyPair pair = generator.generateKeyPair();
                checkActive();
                Certificate[] certificates = store.getCertificateChain(alias);
                byte[][] before = PublicKeyGrantApi.encode(certificates);
                if (!(certificates[0] instanceof X509Certificate leaf)
                        || leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") == null
                        || !Arrays.equals(leaf.getPublicKey().getEncoded(), pair.getPublic().getEncoded())) {
                    outcome = EVIDENCE_UNAVAILABLE;
                    break inspection;
                }
                // Bind the owner snapshot to the generated key by an actual fresh signature.
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(pair.getPrivate());
                signer.update(challenge);
                byte[] signature = signer.sign();
                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(leaf.getPublicKey());
                verifier.update(challenge);
                if (!verifier.verify(signature)) { outcome = EVIDENCE_UNAVAILABLE; break inspection; }

                checkActive();
                final long grantId;
                try {
                    grantId = api.grant(alias, granteeUid);
                    grantIssued = true;
                } catch (Exception | LinkageError unsupportedByProvider) {
                    // API 36 exposes key grants publicly, but the framework documentation also
                    // allows the provider to reject a grant with KeyStoreException.  Several
                    // otherwise stock devices do so for an isolated UID.  That is a capability
                    // limitation, not evidence that the certificate chain was substituted.
                    outcome = IsolatedAttestationCapabilityPolicy.optionalSharingFailureStatus();
                    break inspection;
                }
                checkActive();
                Bundle request = new Bundle();
                request.putLong("grant", grantId);
                Response read = exchange(IsolatedAttestationResponder.READ, request);
                if (read.uid != granteeUid || read.data.getInt("uid", -1) != granteeUid) {
                    outcome = EVIDENCE_UNAVAILABLE;
                    break inspection;
                }
                int readStatus = read.data.getInt("status", TRANSPORT_UNAVAILABLE);
                if (readStatus != CLEAN) { outcome = unavailableStatus(readStatus); break inspection; }
                byte[][] granted = decode(read.data);
                byte[][] after = PublicKeyGrantApi.encode(store.getCertificateChain(alias));
                checkActive();
                int evidence = IsolatedAttestationEvidence.compare(before, granted, after);
                outcome = evidence == IsolatedAttestationEvidence.ANOMALY ? ANOMALY
                        : evidence == IsolatedAttestationEvidence.CLEAN ? CLEAN : EVIDENCE_UNAVAILABLE;
                establishedOutcome = outcome;
              }
            } catch (UnsupportedOperationException | ReflectiveOperationException unavailable) {
                outcome = API_UNAVAILABLE;
            } catch (TimeoutException unavailable) {
                outcome = TRANSPORT_UNAVAILABLE;
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                outcome = TRANSPORT_UNAVAILABLE;
            } catch (Exception | LinkageError unavailable) {
                // This entire cross-UID exercise is optional. Provider rejection while creating,
                // reading, signing with, granting, or resolving its disposable key does not by
                // itself prove a chain mismatch. Reserve positive evidence for a completed
                // three-snapshot comparison.
                outcome = IsolatedAttestationCapabilityPolicy.optionalSharingFailureStatus();
            } finally {
                boolean cleanupComplete = true;
                cancelled.set(true);
                if (bindingAttempted) {
                    try { context.unbindService(connection); }
                    catch (IllegalArgumentException notRegistered) { /* Bind may not have registered. */ }
                    catch (RuntimeException failure) { cleanupComplete = false; }
                }
                callbacks.quitSafely();
                if (IsolatedAttestationCapabilityPolicy.shouldRevoke(grantIssued) && api != null) {
                    try { api.revoke(alias, granteeUid); }
                    catch (Exception | LinkageError failure) { cleanupComplete = false; }
                }
                if (ownAlias && store != null) {
                    try {
                        store.deleteEntry(alias);
                        if (store.containsAlias(alias)) cleanupComplete = false;
                    }
                    catch (Exception | LinkageError failure) { cleanupComplete = false; }
                }
                // A cleanup failure can never erase a completed positive comparison.
                if (!cleanupComplete && outcome != ANOMALY) outcome = CLEANUP_INCOMPLETE;
            }
            return outcome;
        }

        Response exchange(int what, Bundle data) throws Exception {
            checkActive();
            data.putString("token", token);
            Message message = Message.obtain(null, what);
            message.replyTo = receiver;
            message.setData(data);
            remote.send(message);
            Response response = responses.poll(remaining(5000), TimeUnit.MILLISECONDS);
            checkActive();
            if (response == null || response.what != what || disconnected) throw new TimeoutException();
            return response;
        }

        long remaining(long maximum) throws TimeoutException {
            checkActive();
            return Math.max(1, Math.min(maximum, deadline - SystemClock.elapsedRealtime()));
        }

        void checkActive() throws TimeoutException {
            if (cancelled.get() || disconnected || SystemClock.elapsedRealtime() >= deadline) {
                throw new TimeoutException();
            }
        }
    }

    private static int unavailableStatus(int status) {
        int normalized = IsolatedAttestationCapabilityPolicy.normalizeRemoteStatus(status);
        return switch (normalized) {
            case API_UNAVAILABLE, TRANSPORT_UNAVAILABLE,
                    EVIDENCE_UNAVAILABLE, CLEANUP_INCOMPLETE -> normalized;
            default -> ACCESS_UNAVAILABLE;
        };
    }

    private static byte[][] decode(Bundle bundle) throws Exception {
        int count = bundle.getInt("count", 0);
        if (count <= 0 || count > 16) throw new IllegalArgumentException("Incomplete response");
        byte[][] chain = new byte[count][];
        int total = 0;
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < count; i++) {
            chain[i] = bundle.getByteArray("cert" + i);
            if (chain[i] == null || chain[i].length == 0 || chain[i].length > 32768) {
                throw new IllegalArgumentException("Invalid certificate size");
            }
            total += chain[i].length;
            if (total > 131072) throw new IllegalArgumentException("Invalid chain size");
            ByteArrayInputStream input = new ByteArrayInputStream(chain[i]);
            if (!(factory.generateCertificate(input) instanceof X509Certificate) || input.available() != 0) {
                throw new IllegalArgumentException("Invalid X509 response");
            }
        }
        return chain;
    }
}

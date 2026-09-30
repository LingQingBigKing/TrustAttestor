package com.lingqing.trustattestor;

import android.content.Context;
import android.os.Build;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/** Runtime adapter for the public API 36 SDK, while the project compiles with SDK 35. */
final class PublicKeyGrantApi {
    private final Object manager;
    private final Method grant;
    private final Method revoke;
    private final Method read;

    PublicKeyGrantApi(Context context) throws Exception {
        if (Build.VERSION.SDK_INT < 36) throw new UnsupportedOperationException("API 36 required");
        Class<?> type = Class.forName("android.security.keystore.KeyStoreManager");
        manager = context.getSystemService(type);
        if (manager == null) throw new UnsupportedOperationException("Public key sharing unavailable");
        // These are public SDK methods. No hidden API access or private Binder fallback.
        grant = type.getMethod("grantKeyAccess", String.class, int.class);
        revoke = type.getMethod("revokeKeyAccess", String.class, int.class);
        read = type.getMethod("getGrantedCertificateChainFromId", long.class);
    }

    long grant(String alias, int uid) throws Exception {
        return (Long) invoke(grant, alias, uid);
    }

    void revoke(String alias, int uid) throws Exception {
        invoke(revoke, alias, uid);
    }

    byte[][] read(long id) throws Exception {
        Object value = invoke(read, id);
        if (!(value instanceof List<?> chain) || chain.isEmpty() || chain.size() > 16) {
            throw new IllegalArgumentException("Incomplete granted chain");
        }
        Certificate[] certificates = new Certificate[chain.size()];
        for (int i = 0; i < chain.size(); i++) {
            if (!(chain.get(i) instanceof X509Certificate certificate)) {
                throw new IllegalArgumentException("Non-X509 granted chain");
            }
            certificates[i] = certificate;
        }
        return encode(certificates);
    }

    static byte[][] encode(Certificate[] chain) throws Exception {
        if (chain == null || chain.length == 0 || chain.length > 16) {
            throw new IllegalArgumentException("Incomplete chain");
        }
        byte[][] encoded = new byte[chain.length][];
        int total = 0;
        for (int i = 0; i < chain.length; i++) {
            if (!(chain[i] instanceof X509Certificate)) throw new IllegalArgumentException("Non-X509 chain");
            encoded[i] = chain[i].getEncoded().clone();
            if (encoded[i].length == 0 || encoded[i].length > 32768) {
                throw new IllegalArgumentException("Certificate size outside bounds");
            }
            total += encoded[i].length;
            if (total > 131072) throw new IllegalArgumentException("Chain size outside bounds");
        }
        return encoded;
    }

    private Object invoke(Method method, Object... arguments) throws Exception {
        try {
            return method.invoke(manager, arguments);
        } catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception exception) throw exception;
            if (cause instanceof Error error) throw error;
            throw failure;
        }
    }
}

package com.lingqing.trustattestor;

import java.util.Arrays;

/** Bounded byte-level chain comparison; does not parse certificates or establish trust. */
public final class IsolatedAttestationEvidence {
    public static final int CLEAN = 0;
    public static final int ANOMALY = 1;
    public static final int UNAVAILABLE = 2;

    private static final int MAX_CERTIFICATES = 16;
    private static final int MAX_CERTIFICATE_BYTES = 32768;
    private static final int MAX_CHAIN_BYTES = 131072;

    private IsolatedAttestationEvidence() { }

    /**
     * Compares three complete, caller-owned snapshots of the same shared key's chain.
     * Invalid shapes or an owner chain that changed during observation are unavailable.
     * A bounded grantee chain differing from a stable owner chain is an anomaly.
     * CLEAN means byte-for-byte consistency only, not certificate validity or trust.
     * Inputs are not modified and must not be concurrently modified by the caller.
     */
    public static int compare(byte[][] ownerBefore, byte[][] grantee, byte[][] ownerAfter) {
        if (!isBoundedChain(ownerBefore) || !isBoundedChain(grantee)
                || !isBoundedChain(ownerAfter)) {
            return UNAVAILABLE;
        }
        if (!sameChain(ownerBefore, ownerAfter)) {
            return UNAVAILABLE;
        }
        return sameChain(ownerBefore, grantee) ? CLEAN : ANOMALY;
    }

    private static boolean isBoundedChain(byte[][] chain) {
        if (chain == null || chain.length == 0 || chain.length > MAX_CERTIFICATES) {
            return false;
        }
        int total = 0;
        for (byte[] certificate : chain) {
            if (certificate == null || certificate.length == 0
                    || certificate.length > MAX_CERTIFICATE_BYTES) {
                return false;
            }
            if (certificate.length > MAX_CHAIN_BYTES - total) {
                return false;
            }
            total += certificate.length;
        }
        return true;
    }

    private static boolean sameChain(byte[][] first, byte[][] second) {
        if (first.length != second.length) {
            return false;
        }
        for (int i = 0; i < first.length; i++) {
            if (!Arrays.equals(first[i], second[i])) {
                return false;
            }
        }
        return true;
    }
}

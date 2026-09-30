package com.lingqing.trustattestor;

import android.util.Log;

import com.android.apksig.ApkVerifier;

import java.io.File;

public class Verifier {
    public static boolean run(String path) {
        ApkVerifier verifier = new ApkVerifier.Builder(new File(path))
                .setMinCheckedPlatformVersion(27)
                .build();
        try {
            ApkVerifier.Result result = verifier.verify();
            return result.isVerified();
        } catch (Throwable t) {
            Log.e("TrustAttestor", "verify: ", t);
            return false;
        }
    }
}

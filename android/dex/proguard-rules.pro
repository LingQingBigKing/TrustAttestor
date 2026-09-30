-keep class com.lingqing.trustattestor.KeyAttestation {
    public static int run(...);
    public static long getLastProbeFlags();
    public static java.lang.String[] getLastUnavailableProbeIds();
    public static int getLastIsolatedChainStatus();
    public static int getLastCertificateRecordStatus();
    public static int getLastTimingProbeStatus();
}

-keep class com.lingqing.trustattestor.Verifier {
    public static boolean run(...);
}

# Registered by the host library in the embedded DEX class loader.
-keep class com.lingqing.trustattestor.KeystoreTimingClock {
    private static native long nativeClockNanos();
    private static native long nativeClockResolutionNanos();
}

# ApkVerifier reflects over these runtime annotations while decoding the
# signing certificate's ASN.1 structures. R8 may otherwise remove the
# annotations from the embedded release DEX, making an intact APK fail its own
# signature-structure check.
-keepattributes RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,AnnotationDefault
-keep @interface com.android.apksig.internal.asn1.Asn1Class
-keep @interface com.android.apksig.internal.asn1.Asn1Field
-keep @com.android.apksig.internal.asn1.Asn1Class class * { *; }

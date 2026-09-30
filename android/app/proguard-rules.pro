-repackageclasses
-allowaccessmodification
-keepclasseswithmembernames class * {
    native <methods>;
}

-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

-dontwarn android.support.annotation.Nullable
-dontwarn android.support.annotation.VisibleForTesting

-keep class com.lingqing.trustattestor.TrustAttestorNativeBridge { *; }
-keep class com.lingqing.trustattestor.AppZygoteProbe { *; }
-keep class com.lingqing.trustattestor.ThroneHuntCarrierManager { *; }
-keep class com.lingqing.trustattestor.ThroneHuntStimulus { *; }
-keep class com.lingqing.trustattestor.ThroneHuntWatchSnapshot { *; }
-keep class com.lingqing.trustattestor.IsolatedAttestationProbe {
    public static int run(android.content.Context);
}
-keep class com.lingqing.trustattestor.ReadProcProbe { *; }
-keep class com.lingqing.trustattestor.ReadProcProbeService { *; }
-keep class com.lingqing.trustattestor.SoterRsProbe { *; }
-keep class com.lingqing.trustattestor.NativeScanCallback { *; }
-keep interface com.lingqing.trustattestor.NativeScanCallback { *; }

-keepclassmembers class com.lingqing.trustattestor.** {
    native <methods>;
}

-keepclassmembers class * {
    void onNativeEvent(int, int, int, java.lang.String);
}

-keep class androidx.concurrent.futures.AbstractResolvableFuture { *; }
-keep class androidx.concurrent.futures.AbstractResolvableFuture$* { *; }

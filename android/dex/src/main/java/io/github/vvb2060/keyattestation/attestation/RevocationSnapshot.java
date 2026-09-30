package io.github.vvb2060.keyattestation.attestation;

import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Immutable scan snapshot. A cache timestamp is not evidence of a current online lookup. */
public final class RevocationSnapshot {
    public enum Source { CACHED, EMBEDDED, UNAVAILABLE }
    public enum Freshness { CACHED_NOT_REVALIDATED, EMBEDDED_DATE_UNKNOWN, UNAVAILABLE }

    public record Metadata(Source source, String retrievedAt, Freshness freshness,
                           int entryCount, boolean available, String detail) {}

    public record Entry(String status, String reason) {
        public boolean isRevokedOrSuspended() {
            return "REVOKED".equals(status) || "SUSPENDED".equals(status);
        }
        public boolean isKnownStatus() { return isRevokedOrSuspended(); }
    }

    private final Map<String, Entry> entries;
    private final Metadata metadata;

    public RevocationSnapshot(Map<String, Entry> entries, Source source,
                              String retrievedAt, String detail) {
        this.entries = Collections.unmodifiableMap(new LinkedHashMap<>(entries));
        this.metadata = new Metadata(source, retrievedAt,
                source == Source.CACHED ? Freshness.CACHED_NOT_REVALIDATED
                        : source == Source.EMBEDDED ? Freshness.EMBEDDED_DATE_UNKNOWN
                        : Freshness.UNAVAILABLE,
                entries.size(), source != Source.UNAVAILABLE, detail);
    }

    public static RevocationSnapshot unavailable(String detail) {
        return new RevocationSnapshot(Collections.emptyMap(), Source.UNAVAILABLE, null, detail);
    }

    public Metadata metadata() { return metadata; }

    public Entry get(BigInteger serial) {
        if (serial == null || serial.signum() < 0) return null;
        // Google status-feed keys are hexadecimal. Do not also try decimal aliases.
        return entries.get(serial.toString(16));
    }

    public boolean canCheck(BigInteger serial) {
        if (!metadata.available() || serial == null || serial.signum() < 0) return false;
        Entry entry = get(serial);
        return entry == null || entry.isKnownStatus();
    }
}

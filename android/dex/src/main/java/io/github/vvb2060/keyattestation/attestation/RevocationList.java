package io.github.vvb2060.keyattestation.attestation;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedHashMap;

import com.lingqing.trustattestor.KeyAttestation;

public record RevocationList(String status, String reason) {
    private static volatile RevocationSnapshot snapshot =
            RevocationSnapshot.unavailable("Revocation snapshot has not been loaded.");

    static RevocationSnapshot parseStatusText(String text, RevocationSnapshot.Source source,
                                              String retrievedAt, String detail) throws IOException {
        try {
            JSONObject entries = new JSONObject(text).getJSONObject("entries");
            var parsed = new LinkedHashMap<String, RevocationSnapshot.Entry>();
            var keys = entries.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                // The official feed is a lowercase, unpadded hexadecimal-keyed map.
                if (!key.matches("[a-f1-9][a-f0-9]*")) {
                    throw new IOException("Invalid certificate serial encoding in revocation feed");
                }
                JSONObject value = entries.optJSONObject(key);
                Object rawStatus = value == null ? null : value.opt("status");
                Object rawReason = value == null ? null : value.opt("reason");
                String status = rawStatus instanceof String ? (String) rawStatus : null;
                String reason = rawReason instanceof String ? (String) rawReason : null;
                // Missing/unknown status is retained as unavailable for this serial. Reason is optional.
                parsed.put(key, new RevocationSnapshot.Entry(status, reason));
            }
            return new RevocationSnapshot(parsed, source, retrievedAt, detail);
        } catch (JSONException | NullPointerException e) {
            throw new IOException("Failed to parse certificate revocation status", e);
        }
    }

    /** Read only app-owned cache and the bundled snapshot; this never starts a network request. */
    public static synchronized RevocationSnapshot refreshSnapshot() {
        String cached = null;
        String retrievedAt = null;
        String fallbackDetail = "Using the bundled revocation snapshot; publication date is unknown.";
        try {
            cached = KeyAttestation.getSharedData("revocation_list_data");
            retrievedAt = KeyAttestation.getSharedData("revocation_list_time");
        } catch (Throwable ignored) {
            fallbackDetail = "App cache was unavailable; using the bundled revocation snapshot.";
        }
        if (cached != null && !cached.isBlank()) {
            try {
                snapshot = parseStatusText(cached, RevocationSnapshot.Source.CACHED, retrievedAt,
                        "Saved official feed; no online revalidation was performed during this scan.");
                return snapshot;
            } catch (IOException ignored) {
                fallbackDetail = "Saved feed could not be parsed; using the bundled revocation snapshot.";
            }
        }
        try {
            snapshot = parseStatusText(RevocationListData.get(), RevocationSnapshot.Source.EMBEDDED,
                    null, fallbackDetail);
        } catch (IOException | RuntimeException e) {
            snapshot = RevocationSnapshot.unavailable("Both saved and bundled revocation data were unavailable.");
        }
        return snapshot;
    }

    public static RevocationSnapshot.Metadata getSnapshotMetadata() { return snapshot.metadata(); }

    public static RevocationList get(BigInteger serialNumber) {
        RevocationSnapshot current = snapshot;
        if (!current.metadata().available()) current = refreshSnapshot();
        return get(current, serialNumber);
    }

    static RevocationList get(RevocationSnapshot current, BigInteger serialNumber) {
        var entry = current.get(serialNumber);
        return entry != null && entry.isRevokedOrSuspended()
                ? new RevocationList(entry.status(), entry.reason()) : null;
    }

    @Override
    public String toString() {
        return "status is " + status + (reason == null || reason.isBlank() ? "" : ", reason is " + reason);
    }
}

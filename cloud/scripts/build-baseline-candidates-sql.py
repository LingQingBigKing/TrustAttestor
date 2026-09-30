#!/usr/bin/env python3
"""Validate evidence-bound baseline candidates and build idempotent D1 SQL."""

import argparse
import hashlib
import json
import re
import sqlite3
import unicodedata
from pathlib import Path

SCHEMA = "trustattestor.baseline-candidates/v1"
SCHEMA_V2 = "trustattestor.baseline-candidates/v2"
PAYLOAD_SCHEMA = "trustattestor.baseline-candidate/v1"
PAYLOAD_SCHEMA_V2 = "trustattestor.baseline-candidate/v2"
POLICY = "CANDIDATE_ONLY"
MAX_STATEMENT_BYTES = 80_000
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
KERNEL_FAMILY_PATTERN = re.compile(r"^\d+\.\d+$")
ANDROID_RELEASE_PATTERN = re.compile(r"^\d{1,2}$")
SOURCE_AUTHORITIES = {
    "BENCHMARK_DATABASE",
    "COMMUNITY_FINGERPRINT",
    "FIRMWARE_DUMP",
    "GOOGLE_PLAY_CATALOG",
    "HARDWARE_SPEC",
    "OEM_PRODUCT_PAGE",
    "OEM_OPEN_SOURCE",
    "OEM_SECURITY_BULLETIN",
    "REFERENCE_CATALOG",
    "LOCAL_VERIFIED_REPORT",
}
VALUE_FIELDS = (
    "oem",
    "marketingName",
    "device",
    "model",
    "product",
    "sku",
    "brand",
    "manufacturer",
    "boardPlatform",
    "socAlias",
    "launchAndroidRelease",
    "kernelAndroidGeneration",
    "kernelFamily",
)
VALUE_FIELDS_V2 = VALUE_FIELDS + (
    "fingerprint",
    "securityPatch",
    "supportedAbis",
)
PROMOTION_FIELDS = (
    "device",
    "model",
    "product",
    "brand",
    "manufacturer",
    "boardPlatform",
    "socAlias",
    "launchAndroidRelease",
    "kernelFamily",
)
PROMOTION_FIELDS_V2 = PROMOTION_FIELDS + ("fingerprint", "supportedAbis")
SOURCE_KINDS = {
    "FIRMWARE_PROPS",
    "GOOGLE_PLAY_CSV",
    "HARDWARE_SPEC_CSV",
    "PIF_JSON",
    "REFERENCE_CATALOG",
}
SOC_FIELDS = ("VENDOR", "NAME", "FAB", "CPU", "MEMORY", "BANDWIDTH", "CHANNELS")


class CandidateError(ValueError):
    pass


def normalize(value: object) -> str:
    text = unicodedata.normalize("NFKC", "" if value is None else str(value)).strip().lower()
    return re.sub(r"\s+", " ", text)


def compact(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize(value))


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sql(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_fields(values: tuple[str, ...]) -> str:
    return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()[:32]


def require_text(value: object, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CandidateError(f"{field} is required")
    cleaned = value.strip()
    if len(cleaned) > maximum:
        raise CandidateError(f"{field} exceeds {maximum} characters")
    return cleaned


def require_identifier(value: object, field: str) -> str:
    cleaned = normalize(require_text(value, field, 128))
    if IDENTIFIER_PATTERN.fullmatch(cleaned) is None:
        raise CandidateError(f"{field} must match {IDENTIFIER_PATTERN.pattern}")
    return cleaned


def read_device_pairs(path: Path) -> set[tuple[str, str]]:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
        if not {"device", "model"}.issubset(columns):
            raise CandidateError(f"{path}: devices(device, model) table is missing")
        return {
            (normalize(device), normalize(model))
            for device, model in connection.execute(
                "SELECT COALESCE(device, ''), COALESCE(model, '') FROM devices"
            )
            if normalize(device) and normalize(model)
        }
    finally:
        connection.close()


def read_soc_aliases(path: Path) -> dict[str, set[str]]:
    with path.open("r", encoding="utf-8-sig") as stream:
        source = json.load(stream)
    if not isinstance(source, dict):
        raise CandidateError(f"{path}: top-level SoC catalog must be an object")
    aliases: dict[str, set[str]] = {}
    for query_key, raw_record in source.items():
        if not isinstance(raw_record, dict):
            raise CandidateError(f"{path}: SoC record {query_key!r} must be an object")
        fields = tuple(str(raw_record.get(field, "") or "").strip() for field in SOC_FIELDS)
        if not fields[0] or not fields[1]:
            # The source dictionary contains a few broad/incomplete query keys.
            # They cannot form a stable identity, but must not make valid aliases unusable.
            continue
        identity_id = hash_fields(tuple(normalize(value) for value in fields[:2]))
        for key in {normalize(query_key), compact(query_key)}:
            if key:
                aliases.setdefault(key, set()).add(identity_id)
    return aliases


def resolve_soc(alias: str, aliases: dict[str, set[str]], candidate_id: str) -> str:
    matches: set[str] = set()
    for key in {normalize(alias), compact(alias)}:
        matches.update(aliases.get(key, set()))
    if not matches:
        raise CandidateError(f"{candidate_id}: socAlias={alias!r} is not present in socs.json")
    if len(matches) != 1:
        raise CandidateError(f"{candidate_id}: socAlias={alias!r} resolves ambiguously")
    return next(iter(matches))


def read_manifest(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8-sig") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict):
        raise CandidateError(f"{path}: top-level value must be an object")
    return manifest


def validate_catalog_digest(
    catalogs: object, key: str, path: Path, field: str
) -> str:
    if not isinstance(catalogs, dict):
        raise CandidateError("catalogs must be an object")
    declared = normalize(catalogs.get(key, ""))
    if SHA256_PATTERN.fullmatch(declared) is None:
        raise CandidateError(f"catalogs.{key} must be a lowercase SHA-256")
    actual = digest_file(path)
    if declared != actual:
        raise CandidateError(f"catalogs.{key} does not match {field}")
    return actual


def validate_sources(raw_sources: object) -> dict[str, dict[str, str]]:
    if not isinstance(raw_sources, list) or not raw_sources:
        raise CandidateError("sources must be a non-empty array")
    sources: dict[str, dict[str, str]] = {}
    for index, raw_source in enumerate(raw_sources):
        if not isinstance(raw_source, dict):
            raise CandidateError(f"sources[{index}] must be an object")
        source_id = require_identifier(raw_source.get("sourceId"), f"sources[{index}].sourceId")
        if source_id in sources:
            raise CandidateError(f"duplicate sourceId={source_id}")
        authority = require_text(raw_source.get("authority"), f"sources[{index}].authority").upper()
        if authority not in SOURCE_AUTHORITIES:
            raise CandidateError(f"sources[{index}].authority is unsupported")
        uri = require_text(raw_source.get("uri"), f"sources[{index}].uri", 2048)
        if authority == "REFERENCE_CATALOG":
            if not uri.startswith("catalog://"):
                raise CandidateError(f"sources[{index}].uri must use catalog://")
        elif not uri.startswith("https://"):
            raise CandidateError(f"sources[{index}].uri must use HTTPS")
        sources[source_id] = {
            "sourceId": source_id,
            "authority": authority,
            "uri": uri,
            "title": require_text(raw_source.get("title"), f"sources[{index}].title"),
        }
    return sources


def validate_values(
    raw_values: object, candidate_id: str, value_fields: tuple[str, ...]
) -> dict[str, str]:
    if not isinstance(raw_values, dict):
        raise CandidateError(f"{candidate_id}: values must be an object")
    extra = sorted(set(raw_values) - set(value_fields))
    missing = sorted(set(value_fields) - set(raw_values))
    if extra or missing:
        raise CandidateError(
            f"{candidate_id}: values fields mismatch; missing={missing or 'none'}, extra={extra or 'none'}"
        )
    values: dict[str, str] = {}
    for field in value_fields:
        value = raw_values[field]
        if not isinstance(value, str):
            raise CandidateError(f"{candidate_id}: values.{field} must be a string")
        values[field] = value.strip()
        if len(values[field]) > 512:
            raise CandidateError(f"{candidate_id}: values.{field} exceeds 512 characters")
    for required in ("oem", "marketingName", "model"):
        if not values[required]:
            raise CandidateError(f"{candidate_id}: values.{required} is required")
    if values["kernelFamily"] and KERNEL_FAMILY_PATTERN.fullmatch(values["kernelFamily"]) is None:
        raise CandidateError(f"{candidate_id}: values.kernelFamily must look like 6.1 or 6.6")
    if values["launchAndroidRelease"] and ANDROID_RELEASE_PATTERN.fullmatch(
        values["launchAndroidRelease"]
    ) is None:
        raise CandidateError(f"{candidate_id}: values.launchAndroidRelease must be numeric")
    return values


def validate_evidence(
    raw_evidence: object,
    values: dict[str, str],
    sources: dict[str, dict[str, str]],
    candidate_id: str,
    value_fields: tuple[str, ...],
) -> dict[str, list[str]]:
    if not isinstance(raw_evidence, dict):
        raise CandidateError(f"{candidate_id}: evidence must be an object")
    unknown_fields = sorted(set(raw_evidence) - set(value_fields))
    if unknown_fields:
        raise CandidateError(f"{candidate_id}: evidence has unknown fields {unknown_fields}")
    evidence: dict[str, list[str]] = {}
    for field in value_fields:
        raw_ids = raw_evidence.get(field, [])
        if not isinstance(raw_ids, list) or any(not isinstance(item, str) for item in raw_ids):
            raise CandidateError(f"{candidate_id}: evidence.{field} must be a string array")
        source_ids = sorted(set(normalize(item) for item in raw_ids if normalize(item)))
        unknown_ids = [source_id for source_id in source_ids if source_id not in sources]
        if unknown_ids:
            raise CandidateError(f"{candidate_id}: evidence.{field} has unknown sources {unknown_ids}")
        if values[field] and not source_ids:
            raise CandidateError(f"{candidate_id}: non-empty values.{field} has no evidence")
        if not values[field] and source_ids:
            raise CandidateError(f"{candidate_id}: empty values.{field} must not claim evidence")
        if source_ids:
            evidence[field] = source_ids
    if not evidence:
        raise CandidateError(f"{candidate_id}: at least one evidenced field is required")
    return evidence


def validate_aggregation(
    raw_aggregation: object,
    sources: dict[str, dict[str, str]],
    candidate_id: str,
    value_fields: tuple[str, ...],
) -> dict[str, object]:
    if not isinstance(raw_aggregation, dict):
        raise CandidateError(f"{candidate_id}: aggregation must be an object")
    expected = {"factIds", "sourceSnapshotIds", "sourceKinds", "fieldConflicts"}
    extra = sorted(set(raw_aggregation) - expected)
    missing = sorted(expected - set(raw_aggregation))
    if extra or missing:
        raise CandidateError(
            f"{candidate_id}: aggregation fields mismatch; "
            f"missing={missing or 'none'}, extra={extra or 'none'}"
        )

    def validate_hashes(field: str) -> list[str]:
        raw_values = raw_aggregation[field]
        if not isinstance(raw_values, list) or len(raw_values) > 512:
            raise CandidateError(f"{candidate_id}: aggregation.{field} must be an array")
        if any(not isinstance(value, str) for value in raw_values):
            raise CandidateError(
                f"{candidate_id}: aggregation.{field} must contain strings"
            )
        values = sorted(set(raw_values))
        if any(SHA256_PATTERN.fullmatch(value) is None for value in values):
            raise CandidateError(
                f"{candidate_id}: aggregation.{field} must contain lowercase SHA-256 values"
            )
        return values

    fact_ids = validate_hashes("factIds")
    snapshot_ids = validate_hashes("sourceSnapshotIds")
    raw_source_kinds = raw_aggregation["sourceKinds"]
    if not isinstance(raw_source_kinds, list) or len(raw_source_kinds) > len(SOURCE_KINDS):
        raise CandidateError(f"{candidate_id}: aggregation.sourceKinds must be an array")
    if any(not isinstance(kind, str) for kind in raw_source_kinds):
        raise CandidateError(f"{candidate_id}: aggregation.sourceKinds must contain strings")
    source_kinds = sorted(set(raw_source_kinds))
    if any(not isinstance(kind, str) or kind not in SOURCE_KINDS for kind in source_kinds):
        raise CandidateError(f"{candidate_id}: aggregation.sourceKinds is unsupported")

    raw_conflicts = raw_aggregation["fieldConflicts"]
    if not isinstance(raw_conflicts, dict):
        raise CandidateError(f"{candidate_id}: aggregation.fieldConflicts must be an object")
    unknown_fields = sorted(set(raw_conflicts) - set(value_fields))
    if unknown_fields:
        raise CandidateError(
            f"{candidate_id}: aggregation.fieldConflicts has unknown fields {unknown_fields}"
        )
    conflicts: dict[str, list[dict[str, object]]] = {}
    for field in sorted(raw_conflicts):
        raw_variants = raw_conflicts[field]
        if not isinstance(raw_variants, list) or not raw_variants or len(raw_variants) > 32:
            raise CandidateError(
                f"{candidate_id}: aggregation.fieldConflicts.{field} must be a non-empty array"
            )
        variants: list[dict[str, object]] = []
        for variant in raw_variants:
            if not isinstance(variant, dict) or set(variant) != {"value", "sourceIds"}:
                raise CandidateError(
                    f"{candidate_id}: conflict variants require value and sourceIds"
                )
            value = require_text(variant.get("value"), f"{candidate_id}.conflict.{field}")
            raw_source_ids = variant.get("sourceIds")
            if not isinstance(raw_source_ids, list) or not raw_source_ids:
                raise CandidateError(
                    f"{candidate_id}: conflict sourceIds must be a non-empty array"
                )
            source_ids = sorted(set(normalize(item) for item in raw_source_ids if normalize(item)))
            if any(source_id not in sources for source_id in source_ids):
                raise CandidateError(f"{candidate_id}: conflict has an unknown sourceId")
            variants.append({"value": value, "sourceIds": source_ids})
        conflicts[field] = variants
    return {
        "factIds": fact_ids,
        "sourceSnapshotIds": snapshot_ids,
        "sourceKinds": source_kinds,
        "fieldConflicts": conflicts,
    }


def validate_records(
    manifest: dict[str, object],
    sources: dict[str, dict[str, str]],
    device_pairs: set[tuple[str, str]],
    soc_aliases: dict[str, set[str]],
) -> list[tuple[str, str, str, int]]:
    manifest_schema = manifest.get("schema")
    is_v2 = manifest_schema == SCHEMA_V2
    value_fields = VALUE_FIELDS_V2 if is_v2 else VALUE_FIELDS
    promotion_fields = PROMOTION_FIELDS_V2 if is_v2 else PROMOTION_FIELDS
    payload_schema = PAYLOAD_SCHEMA_V2 if is_v2 else PAYLOAD_SCHEMA
    raw_records = manifest.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        raise CandidateError("records must be a non-empty array")
    dataset_id = require_identifier(manifest.get("datasetId"), "datasetId")
    region = require_text(manifest.get("region"), "region", 32).upper()
    collected_at = require_text(manifest.get("collectedAt"), "collectedAt", 32)
    candidates: list[tuple[str, str, str, int]] = []
    candidate_ids: set[str] = set()
    for index, raw_record in enumerate(raw_records):
        if not isinstance(raw_record, dict):
            raise CandidateError(f"records[{index}] must be an object")
        candidate_id = require_identifier(
            raw_record.get("candidateId"), f"records[{index}].candidateId"
        )
        if candidate_id in candidate_ids:
            raise CandidateError(f"duplicate candidateId={candidate_id}")
        if raw_record.get("candidateKind") != "DEVICE_VARIANT":
            raise CandidateError(f"{candidate_id}: candidateKind must be DEVICE_VARIANT")
        if require_text(raw_record.get("market"), f"{candidate_id}.market", 32).upper() != region:
            raise CandidateError(f"{candidate_id}: market must match manifest region")
        values = validate_values(raw_record.get("values"), candidate_id, value_fields)
        evidence = validate_evidence(
            raw_record.get("evidence"), values, sources, candidate_id, value_fields
        )
        device = normalize(values["device"])
        model = normalize(values["model"])
        if device:
            if (device, model) not in device_pairs:
                raise CandidateError(
                    f"{candidate_id}: device/model pair {values['device']!r}/{values['model']!r} "
                    "is not present in devices.db"
                )
            if not any(
                sources[source_id]["authority"] == "REFERENCE_CATALOG"
                for source_id in evidence.get("device", []) + evidence.get("model", [])
            ):
                raise CandidateError(
                    f"{candidate_id}: device/model pair requires REFERENCE_CATALOG evidence"
                )
        soc_identity_id = ""
        if values["socAlias"]:
            soc_identity_id = resolve_soc(values["socAlias"], soc_aliases, candidate_id)
        missing_fields = [field for field in promotion_fields if not values[field]]
        used_source_ids = sorted({source_id for ids in evidence.values() for source_id in ids})
        payload = {
            "schema": payload_schema,
            "datasetId": dataset_id,
            "region": region,
            "collectedAt": collected_at,
            "promotionState": POLICY,
            "values": values,
            "evidence": evidence,
            "sources": [sources[source_id] for source_id in used_source_ids],
            "resolvedSocIdentityId": soc_identity_id,
            "missingPromotionFields": missing_fields,
        }
        if is_v2:
            payload["aggregation"] = validate_aggregation(
                raw_record.get("aggregation"), sources, candidate_id, value_fields
            )
        payload_json = canonical_json(payload)
        evidence_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        candidates.append((candidate_id, payload_json, evidence_sha256, len(used_source_ids)))
        candidate_ids.add(candidate_id)
    return candidates


def build_sql(candidates: list[tuple[str, str, str, int]]) -> str:
    statements: list[str] = []
    for candidate_id, payload_json, evidence_sha256, source_count in candidates:
        statement = (
            "INSERT INTO baseline_candidates "
            "(candidate_id,candidate_kind,payload_json,evidence_sha256,observation_count,"
            "distinct_source_count,state) VALUES "
            f"({sql(candidate_id)},'DEVICE_VARIANT',{sql(payload_json)},{sql(evidence_sha256)},"
            f"1,{source_count},'PENDING') "
            "ON CONFLICT(candidate_id) DO UPDATE SET "
            "payload_json=excluded.payload_json,evidence_sha256=excluded.evidence_sha256,"
            "distinct_source_count=CASE WHEN excluded.distinct_source_count > "
            "baseline_candidates.distinct_source_count THEN excluded.distinct_source_count "
            "ELSE baseline_candidates.distinct_source_count END,last_seen_at=CURRENT_TIMESTAMP "
            "WHERE baseline_candidates.state='PENDING';"
        )
        if len(statement.encode("utf-8")) > MAX_STATEMENT_BYTES:
            raise CandidateError(f"{candidate_id}: generated SQL statement exceeds 80 KB")
        statements.append(statement)
    return "\n".join(statements) + "\n"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate evidence-bound candidate baselines and build D1 SQL"
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--socs", required=True, type=Path)
    parser.add_argument("--devices", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    if not arguments.check_only and arguments.output is None:
        raise CandidateError("--output is required unless --check-only is used")
    if arguments.output is not None and arguments.output.exists():
        raise FileExistsError(f"Refusing to overwrite {arguments.output}")
    manifest = read_manifest(arguments.input)
    if manifest.get("schema") not in {SCHEMA, SCHEMA_V2}:
        raise CandidateError(f"schema must be {SCHEMA} or {SCHEMA_V2}")
    if manifest.get("policy") != POLICY:
        raise CandidateError(f"policy must be {POLICY}")
    validate_catalog_digest(
        manifest.get("catalogs"), "devicesDbSha256", arguments.devices, "devices.db"
    )
    validate_catalog_digest(
        manifest.get("catalogs"), "socsJsonSha256", arguments.socs, "socs.json"
    )
    sources = validate_sources(manifest.get("sources"))
    candidates = validate_records(
        manifest,
        sources,
        read_device_pairs(arguments.devices),
        read_soc_aliases(arguments.socs),
    )
    output_sql = build_sql(candidates)
    if not arguments.check_only:
        assert arguments.output is not None
        arguments.output.write_text(output_sql, encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": "validated" if arguments.check_only else "generated",
        "datasetId": normalize(manifest["datasetId"]),
        "region": str(manifest["region"]).upper(),
        "candidateRows": len(candidates),
        "policy": POLICY,
        **({} if arguments.output is None else {"output": str(arguments.output)}),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

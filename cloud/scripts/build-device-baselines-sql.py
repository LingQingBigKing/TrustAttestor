#!/usr/bin/env python3
"""Validate reviewed device baselines and build an immutable D1 import batch."""

import argparse
import csv
import hashlib
import json
import re
import sqlite3
import unicodedata
from datetime import date
from pathlib import Path

SOC_FIELDS = ("VENDOR", "NAME", "FAB", "CPU", "MEMORY", "BANDWIDTH", "CHANNELS")
CONFIDENCE_VALUES = {"OFFICIAL", "VERIFIED", "COMMUNITY"}
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PATCH_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
KERNEL_FAMILY_PATTERN = re.compile(r"^\d+\.\d+$")
MAX_STATEMENT_BYTES = 80_000

HARDWARE_COLUMNS = (
    "variant_id", "device", "model", "product", "sku", "brand", "manufacturer",
    "board_platform", "source", "confidence",
)
SOC_COLUMNS = ("variant_id", "soc_alias", "source", "confidence")
KERNEL_COLUMNS = (
    "baseline_id", "variant_id", "sdk_min", "sdk_max", "os_release",
    "build_id_prefix", "fingerprint_prefix", "security_patch_min", "security_patch_max",
    "kernel_family", "kernel_release_prefix", "build_version_contains", "machine",
    "source", "confidence",
)


class BaselineError(ValueError):
    pass


def normalize(value: object) -> str:
    text = unicodedata.normalize("NFKC", "" if value is None else str(value)).strip().lower()
    return re.sub(r"\s+", " ", text)


def compact(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize(value))


def sql(value: object) -> str:
    return "'" + ("" if value is None else str(value)).replace("'", "''") + "'"


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_fields(values: tuple[str, ...]) -> str:
    return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()[:32]


def require_identifier(value: str, field: str, line: int) -> str:
    normalized = normalize(value)
    if IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise BaselineError(f"line {line}: {field} must match {IDENTIFIER_PATTERN.pattern}")
    return normalized


def require_text(value: str, field: str, line: int) -> str:
    cleaned = str(value).strip()
    if not cleaned:
        raise BaselineError(f"line {line}: {field} is required")
    if len(cleaned) > 512:
        raise BaselineError(f"line {line}: {field} exceeds 512 characters")
    return cleaned


def parse_confidence(value: str, line: int) -> str:
    confidence = str(value).strip().upper()
    if confidence not in CONFIDENCE_VALUES:
        raise BaselineError(f"line {line}: confidence must be one of {sorted(CONFIDENCE_VALUES)}")
    return confidence


def parse_integer(value: str, field: str, line: int) -> int:
    try:
        parsed = int(str(value).strip())
    except ValueError as error:
        raise BaselineError(f"line {line}: {field} must be an integer") from error
    if not 1 <= parsed <= 100:
        raise BaselineError(f"line {line}: {field} must be between 1 and 100")
    return parsed


def parse_patch(value: str, field: str, line: int) -> str:
    cleaned = str(value).strip()
    if not cleaned:
        return ""
    if PATCH_PATTERN.fullmatch(cleaned) is None:
        raise BaselineError(f"line {line}: {field} must use YYYY-MM-DD")
    try:
        date.fromisoformat(cleaned)
    except ValueError as error:
        raise BaselineError(f"line {line}: {field} is not a valid date") from error
    return cleaned


def read_csv(path: Path, expected_columns: tuple[str, ...]) -> list[tuple[int, dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        actual = tuple(reader.fieldnames or ())
        missing = [column for column in expected_columns if column not in actual]
        extra = [column for column in actual if column not in expected_columns]
        if missing or extra:
            raise BaselineError(
                f"{path}: invalid columns; missing={missing or 'none'}, extra={extra or 'none'}"
            )
        return [(line, {column: str(row.get(column, "")) for column in expected_columns})
                for line, row in enumerate(reader, start=2)]


def read_device_pairs(path: Path) -> set[tuple[str, str]]:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
        if not {"device", "model"}.issubset(columns):
            raise BaselineError(f"{path}: devices(device, model) table is missing")
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
        raise BaselineError(f"{path}: top-level SoC catalog must be an object")
    aliases: dict[str, set[str]] = {}
    for query_key, raw_record in source.items():
        if not isinstance(raw_record, dict):
            raise BaselineError(f"{path}: SoC record {query_key!r} must be an object")
        fields = tuple(str(raw_record.get(field, "") or "").strip() for field in SOC_FIELDS)
        if not fields[0] or not fields[1]:
            # Incomplete catch-all query keys cannot form a stable identity.
            # Ignore them while preserving every resolvable SoC alias.
            continue
        identity_id = hash_fields(tuple(normalize(value) for value in fields[:2]))
        for key in {normalize(query_key), compact(query_key)}:
            if key:
                aliases.setdefault(key, set()).add(identity_id)
    return aliases


def resolve_soc_identity(alias: str, aliases: dict[str, set[str]], line: int) -> str:
    matches = set()
    for key in {normalize(alias), compact(alias)}:
        matches.update(aliases.get(key, set()))
    if not matches:
        raise BaselineError(f"line {line}: soc_alias={alias!r} is not present in socs.json")
    if len(matches) != 1:
        raise BaselineError(f"line {line}: soc_alias={alias!r} resolves to multiple SoC identities")
    return next(iter(matches))


def read_hardware_rows(
    path: Path,
    device_pairs: set[tuple[str, str]],
) -> tuple[list[tuple[object, ...]], set[str]]:
    result: list[tuple[object, ...]] = []
    variant_ids: set[str] = set()
    for line, row in read_csv(path, HARDWARE_COLUMNS):
        variant_id = require_identifier(row["variant_id"], "variant_id", line)
        if variant_id in variant_ids:
            raise BaselineError(f"line {line}: duplicate variant_id={variant_id}")
        device = require_text(row["device"], "device", line)
        model = require_text(row["model"], "model", line)
        device_norm = normalize(device)
        model_norm = normalize(model)
        if (device_norm, model_norm) not in device_pairs:
            raise BaselineError(
                f"line {line}: device/model pair {device!r}/{model!r} is not present in devices.db"
            )
        product_norm = normalize(require_text(row["product"], "product", line))
        brand_norm = normalize(require_text(row["brand"], "brand", line))
        manufacturer_norm = normalize(require_text(row["manufacturer"], "manufacturer", line))
        board_platform_norm = normalize(require_text(row["board_platform"], "board_platform", line))
        source = require_text(row["source"], "source", line)
        confidence = parse_confidence(row["confidence"], line)
        fingerprint_prefix = f"{brand_norm}/{product_norm}/{device_norm}:"
        result.append((
            variant_id, device_norm, model_norm, product_norm, normalize(row["sku"]), brand_norm,
            manufacturer_norm, board_platform_norm, fingerprint_prefix, source, confidence, 1,
        ))
        variant_ids.add(variant_id)
    if not result:
        raise BaselineError(f"{path}: at least one reviewed device variant is required")
    return result, variant_ids


def read_soc_rows(
    path: Path | None,
    variant_ids: set[str],
    soc_aliases: dict[str, set[str]],
) -> list[tuple[object, ...]]:
    if path is None:
        return []
    result: list[tuple[object, ...]] = []
    seen: set[tuple[str, str]] = set()
    for line, row in read_csv(path, SOC_COLUMNS):
        variant_id = require_identifier(row["variant_id"], "variant_id", line)
        if variant_id not in variant_ids:
            raise BaselineError(f"line {line}: variant_id={variant_id} is not defined by hardware CSV")
        soc_identity_id = resolve_soc_identity(
            require_text(row["soc_alias"], "soc_alias", line), soc_aliases, line
        )
        key = (variant_id, soc_identity_id)
        if key in seen:
            raise BaselineError(
                f"line {line}: duplicate SoC identity for variant_id={variant_id}"
            )
        result.append((
            variant_id, soc_identity_id, require_text(row["source"], "source", line),
            parse_confidence(row["confidence"], line), 1,
        ))
        seen.add(key)
    return result


def build_legacy_hardware_rows(
    hardware_rows: list[tuple[object, ...]],
    soc_rows: list[tuple[object, ...]],
) -> tuple[list[tuple[object, ...]], set[str]]:
    """Keep the retired combined table usable for offline legacy kernel imports."""
    identities: dict[str, list[str]] = {}
    for variant_id, soc_identity_id, *_ in soc_rows:
        identities.setdefault(str(variant_id), []).append(str(soc_identity_id))
    result: list[tuple[object, ...]] = []
    legacy_variants: set[str] = set()
    for row in hardware_rows:
        variant_id = str(row[0])
        mapped = identities.get(variant_id, [])
        if len(mapped) != 1:
            continue
        result.append((*row[:9], mapped[0], *row[9:]))
        legacy_variants.add(variant_id)
    return result, legacy_variants


def read_kernel_rows(path: Path, variant_ids: set[str]) -> list[tuple[object, ...]]:
    result: list[tuple[object, ...]] = []
    baseline_ids: set[str] = set()
    for line, row in read_csv(path, KERNEL_COLUMNS):
        baseline_id = require_identifier(row["baseline_id"], "baseline_id", line)
        variant_id = require_identifier(row["variant_id"], "variant_id", line)
        if baseline_id in baseline_ids:
            raise BaselineError(f"line {line}: duplicate baseline_id={baseline_id}")
        if variant_id not in variant_ids:
            raise BaselineError(f"line {line}: variant_id={variant_id} is not defined by hardware CSV")
        sdk_min = parse_integer(row["sdk_min"], "sdk_min", line)
        sdk_max = parse_integer(row["sdk_max"], "sdk_max", line)
        if sdk_min > sdk_max:
            raise BaselineError(f"line {line}: sdk_min must not exceed sdk_max")
        os_release_norm = normalize(require_text(row["os_release"], "os_release", line))
        patch_min = parse_patch(row["security_patch_min"], "security_patch_min", line)
        patch_max = parse_patch(row["security_patch_max"], "security_patch_max", line)
        if patch_min and patch_max and patch_min > patch_max:
            raise BaselineError(f"line {line}: security_patch_min must not exceed security_patch_max")
        kernel_family = normalize(row["kernel_family"])
        if kernel_family and KERNEL_FAMILY_PATTERN.fullmatch(kernel_family) is None:
            raise BaselineError(f"line {line}: kernel_family must look like 5.15 or 6.1")
        kernel_release_prefix = normalize(row["kernel_release_prefix"])
        build_version_contains = normalize(row["build_version_contains"])
        machine = normalize(row["machine"])
        if not any((kernel_family, kernel_release_prefix, build_version_contains, machine)):
            raise BaselineError(f"line {line}: at least one kernel constraint is required")
        result.append((
            baseline_id, variant_id, sdk_min, sdk_max, os_release_norm,
            normalize(row["build_id_prefix"]), normalize(row["fingerprint_prefix"]),
            patch_min, patch_max, kernel_family, kernel_release_prefix,
            build_version_contains, machine,
            require_text(row["source"], "source", line), parse_confidence(row["confidence"], line), 1,
        ))
        baseline_ids.add(baseline_id)
    return result


def values_statements(
    table: str,
    columns: tuple[str, ...],
    rows: list[tuple[object, ...]],
    batch_id: str,
) -> list[str]:
    prefix = f"INSERT INTO {table} (batch_id,{','.join(columns)}) VALUES\n"
    statements: list[str] = []
    encoded_rows: list[str] = []
    for row in rows:
        encoded = "(" + ",".join(sql(value) for value in (batch_id, *row)) + ")"
        candidate = prefix + ",\n".join((*encoded_rows, encoded)) + ";"
        if len(candidate.encode("utf-8")) > MAX_STATEMENT_BYTES:
            if not encoded_rows:
                raise BaselineError(f"one {table} row exceeds the SQL statement limit")
            statements.append(prefix + ",\n".join(encoded_rows) + ";")
            encoded_rows = [encoded]
        else:
            encoded_rows.append(encoded)
    if encoded_rows:
        statements.append(prefix + ",\n".join(encoded_rows) + ";")
    return statements


def build_sql(
    batch_id: str,
    version: str,
    manifest_json: str,
    manifest_sha256: str,
    source_summary: str,
    hardware_rows: list[tuple[object, ...]],
    soc_rows: list[tuple[object, ...]],
    legacy_hardware_rows: list[tuple[object, ...]],
    kernel_rows: list[tuple[object, ...]],
) -> str:
    statements = [
        "INSERT INTO baseline_import_batches "
        "(batch_id,dataset_version,manifest_json,manifest_sha256,hardware_rows,soc_rows,firmware_rows,source_summary,status) VALUES "
        f"({sql(batch_id)},{sql(version)},{sql(manifest_json)},{sql(manifest_sha256)},{len(hardware_rows)},{len(soc_rows)},{len(kernel_rows)},{sql(source_summary)},'STAGING');"
    ]
    statements.extend(values_statements(
        "device_hardware_variant_baselines",
        (
            "variant_id", "device_norm", "model_norm", "product_norm", "sku_norm", "brand_norm",
            "manufacturer_norm", "board_platform_norm", "fingerprint_prefix_norm", "source",
            "confidence", "active",
        ),
        hardware_rows,
        batch_id,
    ))
    statements.extend(values_statements(
        "device_soc_baselines",
        ("variant_id", "soc_identity_id", "source", "confidence", "active"),
        soc_rows,
        batch_id,
    ))
    statements.extend(values_statements(
        "device_variant_baselines",
        (
            "variant_id", "device_norm", "model_norm", "product_norm", "sku_norm", "brand_norm",
            "manufacturer_norm", "board_platform_norm", "fingerprint_prefix_norm", "soc_identity_id",
            "source", "confidence", "active",
        ),
        legacy_hardware_rows,
        batch_id,
    ))
    statements.extend(values_statements(
        "firmware_kernel_baselines",
        (
            "baseline_id", "variant_id", "sdk_min", "sdk_max", "os_release_norm",
            "build_id_prefix_norm", "fingerprint_prefix_norm", "security_patch_min_norm",
            "security_patch_max_norm", "kernel_family_norm", "kernel_release_prefix_norm",
            "build_version_contains_norm", "machine_norm", "source", "confidence", "active",
        ),
        kernel_rows,
        batch_id,
    ))
    statements.extend([
        "UPDATE baseline_import_batches SET status = 'PUBLISHED', published_at = CURRENT_TIMESTAMP "
        f"WHERE batch_id = {sql(batch_id)};",
        "INSERT INTO baseline_metadata (key,value,updated_at) "
        f"VALUES ('active_batch_id',{sql(batch_id)},CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP;",
    ])
    for statement in statements:
        if len(statement.encode("utf-8")) > MAX_STATEMENT_BYTES:
            raise BaselineError("generated SQL statement exceeds 80 KB safety limit")
    return "\n".join(statements) + "\n"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate reviewed model/SoC/kernel baselines and build a D1 SQL batch"
    )
    parser.add_argument("--hardware", required=True, type=Path)
    parser.add_argument("--soc", type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--socs", required=True, type=Path)
    parser.add_argument("--devices", required=True, type=Path)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    batch_id = require_identifier(arguments.batch_id, "batch_id", 0)
    version = require_text(arguments.version, "version", 0)
    if not arguments.check_only and arguments.output is None:
        raise BaselineError("--output is required unless --check-only is used")
    if arguments.output is not None and arguments.output.exists():
        raise FileExistsError(f"Refusing to overwrite {arguments.output}")

    device_pairs = read_device_pairs(arguments.devices)
    soc_aliases = read_soc_aliases(arguments.socs)
    hardware_rows, variant_ids = read_hardware_rows(arguments.hardware, device_pairs)
    soc_rows = read_soc_rows(arguments.soc, variant_ids, soc_aliases)
    legacy_hardware_rows, legacy_variant_ids = build_legacy_hardware_rows(
        hardware_rows, soc_rows
    )
    kernel_rows = read_kernel_rows(arguments.kernel, legacy_variant_ids)
    input_digests = {
        "devices": digest_file(arguments.devices),
        "hardware": digest_file(arguments.hardware),
        "kernel": digest_file(arguments.kernel),
        "socs": digest_file(arguments.socs),
        **({} if arguments.soc is None else {"soc": digest_file(arguments.soc)}),
    }
    manifest_source = json.dumps(
        {"batchId": batch_id, "version": version, "inputs": input_digests},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    manifest_sha256 = hashlib.sha256(manifest_source.encode("utf-8")).hexdigest()
    source_summary = (
        f"hardware={arguments.hardware.name};"
        f"soc={arguments.soc.name if arguments.soc is not None else 'none'};"
        f"kernel={arguments.kernel.name}"
    )
    output_sql = build_sql(
        batch_id, version, manifest_source, manifest_sha256, source_summary,
        hardware_rows, soc_rows, legacy_hardware_rows, kernel_rows
    )
    if not arguments.check_only:
        assert arguments.output is not None
        arguments.output.write_text(output_sql, encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": "validated" if arguments.check_only else "generated",
        "batchId": batch_id,
        "datasetVersion": version,
        "manifestSha256": manifest_sha256,
        "hardwareRows": len(hardware_rows),
        "socRows": len(soc_rows),
        "firmwareRows": len(kernel_rows),
        **({} if arguments.output is None else {"output": str(arguments.output)}),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

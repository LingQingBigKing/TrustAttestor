#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import sqlite3
import unicodedata
from pathlib import Path

SOC_FIELDS = ("VENDOR", "NAME", "FAB", "CPU", "MEMORY", "BANDWIDTH", "CHANNELS")
BATCH_SIZE = 100


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


def values_statements(table: str, columns: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[str]:
    statements = []
    for offset in range(0, len(rows), BATCH_SIZE):
        batch = rows[offset : offset + BATCH_SIZE]
        encoded = ",\n".join("(" + ",".join(sql(value) for value in row) + ")" for row in batch)
        statements.append(f"INSERT INTO {table} ({','.join(columns)}) VALUES\n{encoded};")
    return statements


def read_devices(path: Path) -> tuple[int, list[tuple[str, ...]]]:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        source_rows = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        pairs: dict[tuple[str, str], tuple[str, str, str]] = {}
        for name, device, model in connection.execute(
            "SELECT COALESCE(name, ''), COALESCE(device, ''), COALESCE(model, '') FROM devices"
        ):
            device_norm = normalize(device)
            model_norm = normalize(model)
            if not device_norm or not model_norm:
                continue
            key = (device_norm, model_norm)
            current = pairs.get(key)
            candidate = (str(name).strip(), str(device).strip(), str(model).strip())
            if current is None or (not current[0] and candidate[0]):
                pairs[key] = candidate
        rows = [
            (device_norm, model_norm, name, device, model)
            for (device_norm, model_norm), (name, device, model) in sorted(pairs.items())
        ]
        return source_rows, rows
    finally:
        connection.close()


def read_socs(path: Path) -> list[tuple[str, ...]]:
    with path.open("r", encoding="utf-8-sig") as stream:
        source = json.load(stream)
    rows = []
    for query_key, raw_record in sorted(source.items(), key=lambda item: (normalize(item[0]), item[0])):
        fields = tuple(str(raw_record.get(field, "") or "").strip() for field in SOC_FIELDS)
        normalized_fields = tuple(normalize(value) for value in fields)
        identity_id = hash_fields(normalized_fields[:2])
        canonical_id = hash_fields(normalized_fields)
        rows.append((
            str(query_key), normalize(query_key), compact(query_key), identity_id, canonical_id,
            fields[0], normalize(fields[0]), *fields[1:]
        ))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a deterministic D1 import for TrustAttestor device catalogs")
    parser.add_argument("--socs", required=True, type=Path)
    parser.add_argument("--devices", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", default="1")
    arguments = parser.parse_args()
    if arguments.output.exists():
        raise FileExistsError(f"Refusing to overwrite {arguments.output}")

    device_source_rows, device_rows = read_devices(arguments.devices)
    soc_rows = read_socs(arguments.socs)
    metadata = {
        "catalog_status": "ready",
        "catalog_version": arguments.version,
        "devices_source_sha256": digest_file(arguments.devices),
        "devices_source_rows": str(device_source_rows),
        "devices_catalog_pairs": str(len(device_rows)),
        "socs_source_sha256": digest_file(arguments.socs),
        "socs_query_keys": str(len(soc_rows)),
    }
    statements = [
        "DELETE FROM catalog_metadata;",
        "DELETE FROM device_catalog;",
        "DELETE FROM soc_catalog;",
    ]
    statements.extend(values_statements(
        "device_catalog",
        ("device_norm", "model_norm", "name", "device", "model"),
        device_rows,
    ))
    statements.extend(values_statements(
        "soc_catalog",
        (
            "query_key", "query_key_norm", "query_key_compact", "identity_id", "canonical_id",
            "vendor", "vendor_norm", "name", "fab", "cpu", "memory", "bandwidth", "channels",
        ),
        soc_rows,
    ))
    metadata_rows = [(key, value) for key, value in sorted(metadata.items())]
    statements.extend(values_statements("catalog_metadata", ("key", "value"), metadata_rows))
    arguments.output.write_text("\n".join(statements) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "output": str(arguments.output),
        "deviceSourceRows": device_source_rows,
        "deviceCatalogPairs": len(device_rows),
        "socQueryKeys": len(soc_rows),
        "metadata": metadata,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

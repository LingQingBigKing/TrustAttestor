#!/usr/bin/env python3
"""Aggregate pinned public device snapshots into auditable candidate evidence.

This tool never publishes verdict baselines. It emits normalized source facts and
a v2 CANDIDATE_ONLY manifest for the existing review/promotion workflow.
"""

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import sqlite3
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Callable, Iterable

SCHEMA = "trustattestor.source-aggregation/v1"
CANDIDATE_SCHEMA = "trustattestor.baseline-candidates/v2"
POLICY = "CANDIDATE_ONLY"
PARSER_VERSION = "trustattestor-public-sources/1"
SOURCE_KINDS = {
    "GOOGLE_PLAY_CSV",
    "FIRMWARE_PROPS",
    "PIF_JSON",
    "HARDWARE_SPEC_CSV",
}
DEFAULT_AUTHORITIES = {
    "GOOGLE_PLAY_CSV": "GOOGLE_PLAY_CATALOG",
    "FIRMWARE_PROPS": "FIRMWARE_DUMP",
    "PIF_JSON": "COMMUNITY_FINGERPRINT",
    "HARDWARE_SPEC_CSV": "HARDWARE_SPEC",
}
ALLOWED_AUTHORITIES = {
    "GOOGLE_PLAY_CSV": {"GOOGLE_PLAY_CATALOG"},
    "FIRMWARE_PROPS": {"FIRMWARE_DUMP"},
    "PIF_JSON": {"COMMUNITY_FINGERPRINT"},
    "HARDWARE_SPEC_CSV": {
        "BENCHMARK_DATABASE",
        "HARDWARE_SPEC",
        "OEM_PRODUCT_PAGE",
    },
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
    "fingerprint",
    "securityPatch",
    "supportedAbis",
)
FACT_FIELDS = (
    "marketingName",
    "device",
    "model",
    "product",
    "sku",
    "brand",
    "manufacturer",
    "boardPlatform",
    "socAlias",
    "fingerprint",
    "securityPatch",
    "supportedAbis",
)
SQL_COLUMNS = {
    "marketingName": "marketing_name_norm",
    "device": "device_norm",
    "model": "model_norm",
    "product": "product_norm",
    "sku": "sku_norm",
    "brand": "brand_norm",
    "manufacturer": "manufacturer_norm",
    "boardPlatform": "board_platform_norm",
    "socAlias": "soc_alias_norm",
    "fingerprint": "fingerprint_norm",
    "securityPatch": "security_patch_norm",
    "supportedAbis": "supported_abis_norm",
}
FIELD_RANKS = {
    "marketingName": {
        "GOOGLE_PLAY_CATALOG": 100,
        "OEM_PRODUCT_PAGE": 100,
        "REFERENCE_CATALOG": 95,
        "HARDWARE_SPEC": 80,
        "BENCHMARK_DATABASE": 60,
    },
    "product": {
        "FIRMWARE_DUMP": 100,
        "COMMUNITY_FINGERPRINT": 65,
        "GOOGLE_PLAY_CATALOG": 50,
    },
    "sku": {"FIRMWARE_DUMP": 100, "OEM_PRODUCT_PAGE": 90, "HARDWARE_SPEC": 80},
    "brand": {
        "GOOGLE_PLAY_CATALOG": 100,
        "FIRMWARE_DUMP": 95,
        "COMMUNITY_FINGERPRINT": 65,
        "OEM_PRODUCT_PAGE": 90,
    },
    "manufacturer": {
        "GOOGLE_PLAY_CATALOG": 100,
        "FIRMWARE_DUMP": 95,
        "COMMUNITY_FINGERPRINT": 65,
        "OEM_PRODUCT_PAGE": 90,
    },
    "boardPlatform": {
        "FIRMWARE_DUMP": 100,
        "OEM_PRODUCT_PAGE": 95,
        "HARDWARE_SPEC": 90,
        "BENCHMARK_DATABASE": 75,
    },
    "socAlias": {
        "FIRMWARE_DUMP": 100,
        "OEM_PRODUCT_PAGE": 100,
        "HARDWARE_SPEC": 90,
        "BENCHMARK_DATABASE": 75,
        "GOOGLE_PLAY_CATALOG": 80,
    },
    "fingerprint": {
        "FIRMWARE_DUMP": 100,
        "COMMUNITY_FINGERPRINT": 65,
    },
    "securityPatch": {
        "FIRMWARE_DUMP": 100,
        "COMMUNITY_FINGERPRINT": 65,
    },
    "supportedAbis": {
        "FIRMWARE_DUMP": 100,
        "GOOGLE_PLAY_CATALOG": 90,
        "HARDWARE_SPEC": 80,
        "BENCHMARK_DATABASE": 70,
    },
}


class AggregationError(ValueError):
    pass


def normalize(value: object) -> str:
    text = unicodedata.normalize("NFKC", "" if value is None else str(value)).strip().lower()
    return re.sub(r"\s+", " ", text)


def compact(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize(value))


def clean(value: object, maximum: int = 512) -> str:
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    result = unicodedata.normalize("NFKC", str(value)).strip()
    return re.sub(r"\s+", " ", result)[:maximum]


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_path(path: Path) -> str:
    if path.is_file():
        return digest_file(path)
    digest = hashlib.sha256()
    files = sorted(item for item in path.rglob("*") if item.is_file())
    if not files:
        raise AggregationError(f"{path}: source directory has no files")
    for item in files:
        relative = item.relative_to(path).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        with item.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        digest.update(b"\0")
    return digest.hexdigest()


def sql(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def require_text(value: object, field: str, maximum: int = 2048) -> str:
    result = clean(value, maximum)
    if not result:
        raise AggregationError(f"{field} is required")
    return result


def header_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize(value))


def row_value(row: dict[str, object], *aliases: str) -> str:
    normalized = {header_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = clean(normalized.get(header_key(alias), ""))
        if value:
            return value
    return ""


def normalize_abis(value: object) -> str:
    parts = [clean(item) for item in re.split(r"[,;|\s]+", clean(value))]
    return ",".join(dict.fromkeys(item for item in parts if item))


def read_csv_rows(path: Path) -> Iterable[tuple[str, dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise AggregationError(f"{path}: CSV header is missing")
        for line, row in enumerate(reader, start=2):
            yield f"{path.name}:{line}", {str(key): clean(value) for key, value in row.items()}


def parse_google_play(path: Path) -> list[tuple[str, dict[str, str], object]]:
    records = []
    for record_ref, row in read_csv_rows(path):
        values = {
            "marketingName": row_value(row, "Marketing Name", "Model name", "MarketingName"),
            "device": row_value(row, "Device", "Device code"),
            "model": row_value(row, "Model", "Model code", "ModelCode"),
            "product": row_value(row, "Product", "Product name"),
            "brand": row_value(row, "Retail Branding", "Brand"),
            "manufacturer": row_value(row, "Manufacturer"),
            "socAlias": row_value(row, "System on chip", "SoC", "SoC Model"),
            "supportedAbis": normalize_abis(row_value(row, "ABIs", "Supported ABIs")),
        }
        if not values["model"] and values["marketingName"]:
            values["model"] = values["marketingName"]
        records.append((record_ref, values, row))
    return records


PROP_KEYS = {
    "device": (
        "ro.product.device",
        "ro.product.vendor.device",
        "ro.product.system.device",
        "ro.product.odm.device",
    ),
    "model": (
        "ro.product.model",
        "ro.product.vendor.model",
        "ro.product.system.model",
        "ro.product.odm.model",
    ),
    "product": ("ro.product.name", "ro.build.product", "ro.product.vendor.name"),
    "sku": (
        "ro.boot.product.hardware.sku",
        "ro.boot.hardware.sku",
        "ro.product.vendor.sku",
        "ro.boot.product.vendor.sku",
    ),
    "brand": ("ro.product.brand", "ro.product.vendor.brand", "ro.product.system.brand"),
    "manufacturer": (
        "ro.product.manufacturer",
        "ro.product.vendor.manufacturer",
        "ro.product.system.manufacturer",
    ),
    "boardPlatform": (
        "ro.board.platform",
        "ro.vendor.board.platform",
        "ro.boot.hardware.platform",
        "ro.mediatek.platform",
    ),
    "socAlias": ("ro.soc.model", "ro.vendor.soc.model", "ro.hardware"),
    "fingerprint": (
        "ro.build.fingerprint",
        "ro.system.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.odm.build.fingerprint",
    ),
    "securityPatch": (
        "ro.build.version.security_patch",
        "ro.vendor.build.security_patch",
        "ro.product.build.version.security_patch",
    ),
    "supportedAbis": (
        "ro.product.cpu.abilist",
        "ro.vendor.product.cpu.abilist",
        "ro.product.cpu.abi",
    ),
}


def parse_prop_file(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError as error:
        raise AggregationError(f"cannot read {path}: {error}") from error
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and key not in props:
            props[key] = clean(value)
    return props


def parse_firmware_props(path: Path) -> list[tuple[str, dict[str, str], object]]:
    if path.is_file():
        files = [path]
        root = path.parent
    else:
        files = sorted(
            item
            for item in path.rglob("*")
            if item.is_file()
            and (item.name in {"build.prop", "default.prop", "prop.default"} or item.suffix == ".prop")
        )
        root = path
    if not files:
        raise AggregationError(f"{path}: no Android property files found")
    merged: dict[str, str] = {}
    for item in files:
        for key, value in parse_prop_file(item).items():
            if value and key not in merged:
                merged[key] = value
    values: dict[str, str] = {}
    for field, keys in PROP_KEYS.items():
        values[field] = next((clean(merged.get(key)) for key in keys if clean(merged.get(key))), "")
    values["supportedAbis"] = normalize_abis(values.get("supportedAbis"))
    refs = [item.relative_to(root).as_posix() for item in files[:64]]
    record_ref = f"{path.name}#props={','.join(refs)}"
    raw = {key: merged[key] for key in sorted(merged) if key.startswith("ro.")}
    return [(record_ref, values, raw)]


PIF_ALIASES = {
    "device": ("DEVICE", "ro.product.device"),
    "model": ("MODEL", "ro.product.model"),
    "product": ("PRODUCT", "ro.product.name"),
    "brand": ("BRAND", "ro.product.brand"),
    "manufacturer": ("MANUFACTURER", "ro.product.manufacturer"),
    "fingerprint": ("FINGERPRINT", "ro.build.fingerprint"),
    "securityPatch": ("SECURITY_PATCH", "ro.build.version.security_patch"),
}


def values_from_mapping(mapping: dict[str, object]) -> dict[str, str]:
    normalized = {header_key(key): value for key, value in mapping.items()}
    values: dict[str, str] = {}
    for field, aliases in PIF_ALIASES.items():
        values[field] = next(
            (clean(normalized.get(header_key(alias))) for alias in aliases if clean(normalized.get(header_key(alias)))),
            "",
        )
    return values


def walk_json_records(value: object, path: str = "$") -> Iterable[tuple[str, dict[str, object]]]:
    if isinstance(value, dict):
        values = values_from_mapping(value)
        if sum(bool(item) for item in values.values()) >= 2:
            yield path, value
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield from walk_json_records(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_json_records(child, f"{path}[{index}]")


def parse_pif_json(path: Path) -> list[tuple[str, dict[str, str], object]]:
    files = [path] if path.is_file() else sorted(path.rglob("*.json"))
    if not files:
        raise AggregationError(f"{path}: no JSON files found")
    records = []
    for item in files:
        with item.open("r", encoding="utf-8-sig") as stream:
            payload = json.load(stream)
        for json_path, mapping in walk_json_records(payload):
            values = values_from_mapping(mapping)
            records.append((f"{item.name}#{json_path}", values, mapping))
    return records


def parse_hardware_spec(path: Path) -> list[tuple[str, dict[str, str], object]]:
    records = []
    for record_ref, row in read_csv_rows(path):
        values = {
            "marketingName": row_value(row, "marketingName", "marketing name", "name"),
            "device": row_value(row, "device", "device code"),
            "model": row_value(row, "model", "model code"),
            "product": row_value(row, "product"),
            "sku": row_value(row, "sku", "hardware sku"),
            "brand": row_value(row, "brand"),
            "manufacturer": row_value(row, "manufacturer", "oem"),
            "boardPlatform": row_value(row, "boardPlatform", "board platform", "motherboard", "platform"),
            "socAlias": row_value(row, "socAlias", "soc", "soc model", "chipset"),
            "fingerprint": row_value(row, "fingerprint", "build fingerprint"),
            "securityPatch": row_value(row, "securityPatch", "security patch"),
            "supportedAbis": normalize_abis(row_value(row, "supportedAbis", "abis", "architecture")),
        }
        records.append((record_ref, values, row))
    return records


PARSERS: dict[str, Callable[[Path], list[tuple[str, dict[str, str], object]]]] = {
    "GOOGLE_PLAY_CSV": parse_google_play,
    "FIRMWARE_PROPS": parse_firmware_props,
    "PIF_JSON": parse_pif_json,
    "HARDWARE_SPEC_CSV": parse_hardware_spec,
}


def load_devices(
    path: Path,
) -> tuple[
    dict[tuple[str, str], str],
    dict[str, set[tuple[str, str]]],
    dict[str, set[tuple[str, str]]],
]:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
        if not {"device", "model"}.issubset(columns):
            raise AggregationError(f"{path}: devices(device, model) table is missing")
        name_expression = "COALESCE(name, '')" if "name" in columns else "''"
        rows = connection.execute(
            f"SELECT {name_expression}, COALESCE(device, ''), COALESCE(model, '') FROM devices"
        )
        pairs: dict[tuple[str, str], str] = {}
        by_model: dict[str, set[tuple[str, str]]] = defaultdict(set)
        by_device: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for name, device, model in rows:
            pair = (normalize(device), normalize(model))
            if not all(pair):
                continue
            pairs.setdefault(pair, clean(name) or clean(model))
            by_model[pair[1]].add(pair)
            by_device[pair[0]].add(pair)
        return pairs, by_model, by_device
    finally:
        connection.close()


def load_soc_aliases(path: Path) -> set[str]:
    with path.open("r", encoding="utf-8-sig") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise AggregationError(f"{path}: SoC catalog must be an object")
    aliases: set[str] = set()
    for query, record in payload.items():
        if not isinstance(record, dict) or not clean(record.get("VENDOR")) or not clean(record.get("NAME")):
            continue
        aliases.update({normalize(query), compact(query)})
    return aliases


def make_fact(source: dict[str, object], record_ref: str, values: dict[str, str], raw: object) -> dict[str, object] | None:
    cleaned = {field: clean(values.get(field, "")) for field in FACT_FIELDS}
    cleaned["supportedAbis"] = normalize_abis(cleaned["supportedAbis"])
    if not any(cleaned.get(field) for field in ("device", "model", "fingerprint", "boardPlatform", "socAlias")):
        return None
    raw_json = canonical_json(raw)
    identity = "\x1f".join(normalize(cleaned.get(field)) for field in ("device", "model", "product", "sku", "fingerprint"))
    fact_material = canonical_json({
        "snapshotId": source["snapshotId"],
        "recordRef": record_ref,
        "values": cleaned,
        "rawSha256": sha256_text(raw_json),
    })
    return {
        "sourceId": source["sourceId"],
        "sourceKind": source["kind"],
        "authority": source["authority"],
        "snapshotId": source["snapshotId"],
        "factId": sha256_text(fact_material),
        "entityKey": sha256_text(identity),
        "recordRef": clean(record_ref, 2048),
        "values": cleaned,
        "rawSha256": sha256_text(raw_json),
    }


def resolve_pair(
    values: dict[str, str],
    pairs: dict[tuple[str, str], str],
    by_model: dict[str, set[tuple[str, str]]],
    by_device: dict[str, set[tuple[str, str]]],
) -> tuple[str, str] | None:
    device = normalize(values.get("device"))
    model = normalize(values.get("model"))
    if device and model:
        return (device, model) if (device, model) in pairs else None
    candidates = by_model.get(model, set()) if model else by_device.get(device, set())
    return next(iter(candidates)) if len(candidates) == 1 else None


def field_rank(field: str, authority: str) -> int:
    return FIELD_RANKS.get(field, {}).get(authority, 10)


def choose_field(field: str, facts: list[dict[str, object]]) -> tuple[str, list[str], list[dict[str, object]]]:
    variants: dict[str, dict[str, object]] = {}
    for fact in facts:
        values = fact["values"]
        assert isinstance(values, dict)
        value = clean(values.get(field))
        if not value:
            continue
        key = normalize(value)
        variant = variants.setdefault(key, {"value": value, "rank": 0, "sourceIds": set()})
        variant["rank"] = max(int(variant["rank"]), field_rank(field, str(fact["authority"])))
        source_ids = variant["sourceIds"]
        assert isinstance(source_ids, set)
        source_ids.add(str(fact["sourceId"]))
    if not variants:
        return "", [], []
    maximum = max(int(variant["rank"]) for variant in variants.values())
    winners = [variant for variant in variants.values() if int(variant["rank"]) == maximum]
    if len(winners) > 1:
        conflict = [
            {"value": str(variant["value"]), "sourceIds": sorted(variant["sourceIds"])}
            for variant in sorted(winners, key=lambda item: normalize(item["value"]))
        ]
        return "", [], conflict
    winner = winners[0]
    return str(winner["value"]), sorted(winner["sourceIds"]), []


def compatible_facts(facts: list[dict[str, object]], sku: str, product: str) -> list[dict[str, object]]:
    selected = []
    for fact in facts:
        values = fact["values"]
        assert isinstance(values, dict)
        fact_sku = normalize(values.get("sku"))
        fact_product = normalize(values.get("product"))
        if fact_sku and sku and fact_sku != sku:
            continue
        if fact_product and product and fact_product != product:
            continue
        selected.append(fact)
    return selected


def candidate_identifier(region: str, device: str, model: str, sku: str, product: str) -> str:
    readable = re.sub(r"[^a-z0-9]+", "-", f"{region}-{device}-{model}".lower()).strip("-")[:88]
    suffix = sha256_text("\x1f".join((device, model, sku, product)))[:12]
    return f"{readable}-{suffix}"


def build_candidates(
    manifest: dict[str, object],
    sources: list[dict[str, object]],
    facts: list[dict[str, object]],
    devices_path: Path,
    socs_path: Path,
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]], list[str]]:
    pairs, by_model, by_device = load_devices(devices_path)
    soc_aliases = load_soc_aliases(socs_path)
    grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    unresolved: list[dict[str, object]] = []
    for fact in facts:
        values = fact["values"]
        assert isinstance(values, dict)
        pair = resolve_pair(values, pairs, by_model, by_device)
        if pair is None:
            unresolved.append({"factId": fact["factId"], "recordRef": fact["recordRef"], "reason": "DEVICE_MODEL_NOT_IN_REFERENCE_CATALOG"})
        else:
            grouped[pair].append(fact)

    region = require_text(manifest.get("region"), "region", 32).upper()
    records = []
    conflicts: list[dict[str, object]] = []
    unknown_soc_aliases: list[str] = []
    for (device, model), group_facts in sorted(grouped.items()):
        skus = {
            normalize(fact["values"].get("sku"))
            for fact in group_facts
            if isinstance(fact["values"], dict) and normalize(fact["values"].get("sku"))
        }
        if skus:
            signatures: set[tuple[str, str]] = set()
            for sku_value in skus:
                products = {
                    normalize(fact["values"].get("product"))
                    for fact in group_facts
                    if isinstance(fact["values"], dict)
                    and normalize(fact["values"].get("sku")) == sku_value
                    and normalize(fact["values"].get("product"))
                }
                signatures.update((sku_value, product_value) for product_value in products or {""})
        else:
            products = {
                normalize(fact["values"].get("product"))
                for fact in group_facts
                if isinstance(fact["values"], dict) and normalize(fact["values"].get("product"))
            }
            signatures = {("", product_value) for product_value in products} or {("", "")}
        for sku, product in sorted(signatures):
            selected_facts = compatible_facts(group_facts, sku, product)
            values = {field: "" for field in VALUE_FIELDS}
            evidence: dict[str, list[str]] = {}
            field_conflicts: dict[str, list[dict[str, object]]] = {}
            values["device"] = next(
                (clean(fact["values"].get("device")) for fact in selected_facts if normalize(fact["values"].get("device")) == device),
                device,
            )
            values["model"] = next(
                (clean(fact["values"].get("model")) for fact in selected_facts if normalize(fact["values"].get("model")) == model),
                model,
            )
            values["marketingName"] = pairs[(device, model)] or values["model"]
            evidence["device"] = ["device-catalog"]
            evidence["model"] = ["device-catalog"]
            evidence["marketingName"] = ["device-catalog"]
            for field in FACT_FIELDS:
                if field in {"device", "model", "marketingName"}:
                    continue
                value, source_ids, conflict = choose_field(field, selected_facts)
                if conflict:
                    field_conflicts[field] = conflict
                    conflicts.append({"device": device, "model": model, "field": field, "variants": conflict})
                elif value:
                    values[field] = value
                    evidence[field] = source_ids
            for identity_field in ("device", "model", "marketingName"):
                supporting = sorted({
                    str(fact["sourceId"])
                    for fact in selected_facts
                    if normalize(fact["values"].get(identity_field)) == normalize(values[identity_field])
                })
                evidence[identity_field] = sorted(set(evidence[identity_field] + supporting))
            oem_value, oem_sources, oem_conflict = choose_field("manufacturer", selected_facts)
            if not oem_value:
                oem_value, oem_sources, brand_conflict = choose_field("brand", selected_facts)
                oem_conflict = oem_conflict or brand_conflict
            if not oem_value:
                unresolved.append({
                    "device": device,
                    "model": model,
                    "reason": "OEM_IDENTITY_MISSING_OR_CONFLICTING",
                    **({"variants": oem_conflict} if oem_conflict else {}),
                })
                continue
            values["oem"] = oem_value
            evidence["oem"] = oem_sources
            if values["socAlias"] and normalize(values["socAlias"]) not in soc_aliases and compact(values["socAlias"]) not in soc_aliases:
                unknown_soc_aliases.append(values["socAlias"])
                values["socAlias"] = ""
                evidence.pop("socAlias", None)
            candidate_id = candidate_identifier(region, device, model, sku, product)
            records.append({
                "candidateId": candidate_id,
                "candidateKind": "DEVICE_VARIANT",
                "market": region,
                "values": values,
                "evidence": evidence,
                "aggregation": {
                    "factIds": sorted(str(fact["factId"]) for fact in selected_facts),
                    "sourceSnapshotIds": sorted({str(fact["snapshotId"]) for fact in selected_facts}),
                    "sourceKinds": sorted({str(fact["sourceKind"]) for fact in selected_facts} | {"REFERENCE_CATALOG"}),
                    "fieldConflicts": field_conflicts,
                },
            })

    source_entries = [{
        "sourceId": "device-catalog",
        "authority": "REFERENCE_CATALOG",
        "uri": f"catalog://devices.db#sha256={digest_file(devices_path)}",
        "title": "Google Play supported device reference catalog",
    }]
    source_entries.extend({
        "sourceId": source["sourceId"],
        "authority": source["authority"],
        "uri": source["uri"],
        "title": source["title"],
    } for source in sources)
    candidate_manifest = {
        "schema": CANDIDATE_SCHEMA,
        "datasetId": require_text(manifest.get("datasetId"), "datasetId", 128).lower(),
        "region": region,
        "collectedAt": require_text(manifest.get("collectedAt"), "collectedAt", 32),
        "policy": POLICY,
        "catalogs": {
            "devicesDbSha256": digest_file(devices_path),
            "socsJsonSha256": digest_file(socs_path),
        },
        "sources": source_entries,
        "records": records,
    }
    return candidate_manifest, unresolved, conflicts, sorted(set(unknown_soc_aliases))


def build_evidence_sql(
    sources: list[dict[str, object]],
    facts: list[dict[str, object]],
    receipt: dict[str, object],
    candidate_manifest_sha256: str,
) -> str:
    statements = ["BEGIN TRANSACTION;"]
    for source in sources:
        metadata_json = canonical_json(source.get("metadata", {}))
        statements.append(
            "INSERT INTO catalog_source_snapshots "
            "(snapshot_id,source_id,source_kind,authority,source_uri,title,content_sha256,"
            "collected_at,parser_version,record_count,metadata_json,status) VALUES "
            f"({sql(source['snapshotId'])},{sql(source['sourceId'])},{sql(source['kind'])},"
            f"{sql(source['authority'])},{sql(source['uri'])},{sql(source['title'])},"
            f"{sql(source['contentSha256'])},{sql(source['collectedAt'])},{sql(PARSER_VERSION)},"
            f"{source['recordCount']},{sql(metadata_json)},'IMPORTED') "
            "ON CONFLICT(snapshot_id) DO UPDATE SET record_count=excluded.record_count,"
            "metadata_json=excluded.metadata_json,status='IMPORTED',updated_at=CURRENT_TIMESTAMP "
            "WHERE catalog_source_snapshots.status<>'RETIRED';"
        )
    columns = [SQL_COLUMNS[field] for field in FACT_FIELDS]
    for fact in facts:
        values = fact["values"]
        assert isinstance(values, dict)
        normalized_values = [normalize(values.get(field)) for field in FACT_FIELDS]
        values_json = canonical_json(values)
        statements.append(
            "INSERT OR IGNORE INTO catalog_source_facts "
            "(snapshot_id,fact_id,entity_key,record_ref,oem_norm,"
            + ",".join(columns)
            + ",values_json,raw_sha256) VALUES "
            f"({sql(fact['snapshotId'])},{sql(fact['factId'])},{sql(fact['entityKey'])},"
            f"{sql(fact['recordRef'])},{sql(normalize(values.get('manufacturer') or values.get('brand'))) },"
            + ",".join(sql(value) for value in normalized_values)
            + f",{sql(values_json)},{sql(fact['rawSha256'])});"
        )
    run_id = str(receipt["runId"])
    receipt_json = canonical_json(receipt)
    statements.append(
        "INSERT OR IGNORE INTO catalog_aggregation_runs "
        "(run_id,dataset_id,candidate_manifest_sha256,source_snapshot_count,fact_count,"
        "candidate_count,unresolved_fact_count,conflict_count,policy,receipt_json) VALUES "
        f"({sql(run_id)},{sql(receipt['datasetId'])},{sql(candidate_manifest_sha256)},"
        f"{receipt['sourceSnapshotCount']},{receipt['factCount']},{receipt['candidateCount']},"
        f"{receipt['unresolvedFactCount']},{receipt['conflictCount']},'{POLICY}',"
        f"{sql(receipt_json)});"
    )
    statements.append("COMMIT;")
    return "\n".join(statements) + "\n"


def build_candidate_sql(candidate_manifest: dict[str, object], devices_path: Path, socs_path: Path) -> str:
    builder_path = Path(__file__).with_name("build-baseline-candidates-sql.py")
    spec = importlib.util.spec_from_file_location("trustattestor_candidate_builder", builder_path)
    if spec is None or spec.loader is None:
        raise AggregationError(f"cannot load candidate validator: {builder_path}")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    sources = builder.validate_sources(candidate_manifest["sources"])
    candidates = builder.validate_records(
        candidate_manifest,
        sources,
        builder.read_device_pairs(devices_path),
        builder.read_soc_aliases(socs_path),
    )
    return builder.build_sql(candidates)


def read_sources(manifest: dict[str, object], manifest_path: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise AggregationError("sources must be a non-empty array")
    sources = []
    facts = []
    seen_ids: set[str] = set()
    for index, raw_source in enumerate(raw_sources):
        if not isinstance(raw_source, dict):
            raise AggregationError(f"sources[{index}] must be an object")
        source_id = normalize(require_text(raw_source.get("sourceId"), f"sources[{index}].sourceId", 128))
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", source_id):
            raise AggregationError(f"sources[{index}].sourceId is invalid")
        if source_id in seen_ids or source_id == "device-catalog":
            raise AggregationError(f"duplicate or reserved sourceId={source_id}")
        seen_ids.add(source_id)
        kind = require_text(raw_source.get("kind"), f"sources[{index}].kind", 64).upper()
        if kind not in SOURCE_KINDS:
            raise AggregationError(f"sources[{index}].kind is unsupported")
        authority = clean(raw_source.get("authority") or DEFAULT_AUTHORITIES[kind], 64).upper()
        if authority not in ALLOWED_AUTHORITIES[kind]:
            raise AggregationError(f"sources[{index}].authority is invalid for {kind}")
        uri = require_text(raw_source.get("uri"), f"sources[{index}].uri")
        if not uri.startswith("https://"):
            raise AggregationError(f"sources[{index}].uri must use HTTPS")
        metadata = raw_source.get("metadata", {})
        if not isinstance(metadata, dict) or len(canonical_json(metadata).encode("utf-8")) > 8192:
            raise AggregationError(f"sources[{index}].metadata must be a bounded object")
        raw_path = Path(require_text(raw_source.get("path"), f"sources[{index}].path"))
        path = raw_path if raw_path.is_absolute() else manifest_path.parent / raw_path
        path = path.resolve()
        if not path.exists():
            raise AggregationError(f"sources[{index}].path does not exist: {path}")
        content_sha256 = digest_path(path)
        snapshot_id = sha256_text("\x1f".join((source_id, kind, content_sha256)))
        parsed = PARSERS[kind](path)
        source = {
            "sourceId": source_id,
            "kind": kind,
            "authority": authority,
            "uri": uri,
            "title": require_text(raw_source.get("title"), f"sources[{index}].title", 512),
            "collectedAt": require_text(raw_source.get("collectedAt") or manifest.get("collectedAt"), f"sources[{index}].collectedAt", 32),
            "contentSha256": content_sha256,
            "snapshotId": snapshot_id,
            "recordCount": 0,
            "metadata": metadata,
        }
        for record_ref, values, raw in parsed:
            fact = make_fact(source, record_ref, values, raw)
            if fact is not None:
                facts.append(fact)
                source["recordCount"] = int(source["recordCount"]) + 1
        sources.append(source)
    return sources, facts


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aggregate pinned public device data into review-only candidates")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--devices", required=True, type=Path)
    parser.add_argument("--socs", required=True, type=Path)
    parser.add_argument("--output-candidates", required=True, type=Path)
    parser.add_argument(
        "--output-candidate-sql",
        "--output-sql",
        dest="output_candidate_sql",
        required=True,
        type=Path,
    )
    parser.add_argument("--output-evidence-sql", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    for output in (
        arguments.output_candidates,
        arguments.output_candidate_sql,
        arguments.output_evidence_sql,
        arguments.receipt,
    ):
        if output.exists():
            raise FileExistsError(f"Refusing to overwrite {output}")
    with arguments.manifest.open("r", encoding="utf-8-sig") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise AggregationError(f"schema must be {SCHEMA}")
    if manifest.get("policy") != POLICY:
        raise AggregationError(f"policy must be {POLICY}")
    sources, facts = read_sources(manifest, arguments.manifest.resolve())
    candidates, unresolved, conflicts, unknown_socs = build_candidates(
        manifest, sources, facts, arguments.devices, arguments.socs
    )
    candidate_text = json.dumps(candidates, ensure_ascii=False, indent=2) + "\n"
    candidate_sql = build_candidate_sql(candidates, arguments.devices, arguments.socs)
    candidate_sha256 = sha256_text(candidate_text)
    run_id = sha256_text(canonical_json({
        "datasetId": candidates["datasetId"],
        "candidateManifestSha256": candidate_sha256,
        "snapshotIds": sorted(source["snapshotId"] for source in sources),
    }))
    receipt = {
        "schema": "trustattestor.source-aggregation-receipt/v1",
        "runId": run_id,
        "datasetId": candidates["datasetId"],
        "policy": POLICY,
        "sourceSnapshotCount": len(sources),
        "factCount": len(facts),
        "candidateCount": len(candidates["records"]),
        "unresolvedFactCount": len(unresolved),
        "conflictCount": len(conflicts),
        "candidateManifestSha256": candidate_sha256,
        "unknownSocAliases": unknown_socs,
        "unresolved": unresolved,
        "conflicts": conflicts,
    }
    evidence_sql = build_evidence_sql(sources, facts, receipt, candidate_sha256)
    arguments.output_candidates.parent.mkdir(parents=True, exist_ok=True)
    arguments.output_candidate_sql.parent.mkdir(parents=True, exist_ok=True)
    arguments.output_evidence_sql.parent.mkdir(parents=True, exist_ok=True)
    arguments.receipt.parent.mkdir(parents=True, exist_ok=True)
    arguments.output_candidates.write_text(candidate_text, encoding="utf-8", newline="\n")
    arguments.output_candidate_sql.write_text(candidate_sql, encoding="utf-8", newline="\n")
    arguments.output_evidence_sql.write_text(evidence_sql, encoding="utf-8", newline="\n")
    arguments.receipt.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": "generated",
        "policy": POLICY,
        "candidateRows": len(candidates["records"]),
        "sourceFacts": len(facts),
        "unresolvedFacts": len(unresolved),
        "conflicts": len(conflicts),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

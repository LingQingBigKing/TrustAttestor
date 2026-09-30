#!/usr/bin/env python3
"""Classify every supported domestic-OEM device pair into the D1 candidate queue."""

import argparse
import collections
import hashlib
import importlib.util
import json
import re
import sqlite3
import unicodedata
from pathlib import Path

RULE_SCHEMA = "trustattestor.domestic-oem-rules/v1"
REPORT_SCHEMA = "trustattestor.domestic-oem-coverage/v1"
PAYLOAD_SCHEMA = "trustattestor.baseline-candidate/v1"
POLICY = "CANDIDATE_ONLY"
CONFIDENCE_VALUES = {"BRAND_NAME", "MODEL_PREFIX", "SERIES_AND_MODEL"}
FIELDS = {"name", "device", "model"}
OPERATORS = {"PREFIX", "REGEX"}
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
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

_candidate_script = Path(__file__).with_name("build-baseline-candidates-sql.py")
_candidate_spec = importlib.util.spec_from_file_location("candidate_sql_support", _candidate_script)
assert _candidate_spec is not None and _candidate_spec.loader is not None
candidate_support = importlib.util.module_from_spec(_candidate_spec)
_candidate_spec.loader.exec_module(candidate_support)


class DomesticCatalogError(ValueError):
    pass


def normalize(value: object) -> str:
    text = unicodedata.normalize("NFKC", "" if value is None else str(value)).strip().lower()
    return re.sub(r"\s+", " ", text)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_text(value: object, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomesticCatalogError(f"{field} is required")
    cleaned = value.strip()
    if len(cleaned) > maximum:
        raise DomesticCatalogError(f"{field} exceeds {maximum} characters")
    return cleaned


def require_identifier(value: object, field: str) -> str:
    cleaned = normalize(require_text(value, field, 128))
    if IDENTIFIER_PATTERN.fullmatch(cleaned) is None:
        raise DomesticCatalogError(f"{field} must match {IDENTIFIER_PATTERN.pattern}")
    return cleaned


def prefix_matches(text: str, raw_prefix: str) -> bool:
    prefix = normalize(raw_prefix)
    return text == prefix or any(
        text.startswith(prefix + separator) for separator in (" ", "_", "-")
    )


def validate_condition(raw: object, rule_id: str, index: int) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise DomesticCatalogError(f"{rule_id}: conditions[{index}] must be an object")
    field = require_text(raw.get("field"), f"{rule_id}.conditions[{index}].field").lower()
    operator = require_text(
        raw.get("operator"), f"{rule_id}.conditions[{index}].operator"
    ).upper()
    values = raw.get("values")
    if field not in FIELDS:
        raise DomesticCatalogError(f"{rule_id}: unsupported condition field={field}")
    if operator not in OPERATORS:
        raise DomesticCatalogError(f"{rule_id}: unsupported condition operator={operator}")
    if not isinstance(values, list) or not values:
        raise DomesticCatalogError(f"{rule_id}: condition values must be a non-empty array")
    cleaned_values = [require_text(value, f"{rule_id}.condition value", 256) for value in values]
    compiled = []
    if operator == "REGEX":
        for value in cleaned_values:
            try:
                compiled.append(re.compile(value, re.IGNORECASE))
            except re.error as error:
                raise DomesticCatalogError(f"{rule_id}: invalid regex {value!r}") from error
    return {
        "field": field,
        "operator": operator,
        "values": cleaned_values,
        "compiled": compiled,
    }


def load_rules(path: Path, devices_path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    with path.open("r", encoding="utf-8-sig") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict):
        raise DomesticCatalogError(f"{path}: top-level value must be an object")
    if manifest.get("schema") != RULE_SCHEMA:
        raise DomesticCatalogError(f"schema must be {RULE_SCHEMA}")
    if manifest.get("policy") != POLICY:
        raise DomesticCatalogError(f"policy must be {POLICY}")
    require_identifier(manifest.get("datasetId"), "datasetId")
    if require_text(manifest.get("region"), "region", 32).upper() != "MULTI_REGION":
        raise DomesticCatalogError("region must be MULTI_REGION")
    require_text(manifest.get("collectedAt"), "collectedAt", 32)
    declared_digest = normalize(manifest.get("devicesDbSha256", ""))
    if SHA256_PATTERN.fullmatch(declared_digest) is None:
        raise DomesticCatalogError("devicesDbSha256 must be a lowercase SHA-256")
    if declared_digest != digest_file(devices_path):
        raise DomesticCatalogError("devicesDbSha256 does not match devices.db")
    raw_rules = manifest.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise DomesticCatalogError("rules must be a non-empty array")
    rules: list[dict[str, object]] = []
    rule_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise DomesticCatalogError(f"rules[{index}] must be an object")
        rule_id = require_identifier(raw_rule.get("ruleId"), f"rules[{index}].ruleId")
        if rule_id in rule_ids:
            raise DomesticCatalogError(f"duplicate ruleId={rule_id}")
        oem = require_text(raw_rule.get("oem"), f"{rule_id}.oem", 128)
        group = require_text(
            raw_rule.get("manufacturerGroup"), f"{rule_id}.manufacturerGroup", 128
        )
        confidence = require_text(raw_rule.get("confidence"), f"{rule_id}.confidence").upper()
        if confidence not in CONFIDENCE_VALUES:
            raise DomesticCatalogError(f"{rule_id}: unsupported confidence={confidence}")
        try:
            priority = int(raw_rule.get("priority"))
        except (TypeError, ValueError) as error:
            raise DomesticCatalogError(f"{rule_id}: priority must be an integer") from error
        if not 1 <= priority <= 10_000:
            raise DomesticCatalogError(f"{rule_id}: priority must be between 1 and 10000")
        raw_conditions = raw_rule.get("conditions")
        if not isinstance(raw_conditions, list) or not raw_conditions:
            raise DomesticCatalogError(f"{rule_id}: conditions must be a non-empty array")
        conditions = [
            validate_condition(condition, rule_id, condition_index)
            for condition_index, condition in enumerate(raw_conditions)
        ]
        prefix_map: dict[str, str] = {}
        raw_prefix_map = raw_rule.get("prefixOemMap", {})
        if raw_prefix_map:
            if oem != "__FROM_PREFIX__" or not isinstance(raw_prefix_map, dict):
                raise DomesticCatalogError(f"{rule_id}: prefixOemMap requires __FROM_PREFIX__")
            prefix_map = {
                normalize(require_text(prefix, f"{rule_id}.prefixOemMap key")):
                require_text(mapped_oem, f"{rule_id}.prefixOemMap value", 128)
                for prefix, mapped_oem in raw_prefix_map.items()
            }
        elif oem == "__FROM_PREFIX__":
            raise DomesticCatalogError(f"{rule_id}: __FROM_PREFIX__ requires prefixOemMap")
        rules.append({
            "ruleId": rule_id,
            "oem": oem,
            "manufacturerGroup": group,
            "confidence": confidence,
            "priority": priority,
            "conditions": conditions,
            "prefixOemMap": prefix_map,
        })
        rule_ids.add(rule_id)
    rules.sort(key=lambda rule: (int(rule["priority"]), str(rule["ruleId"])))
    return manifest, rules


def condition_matches(condition: dict[str, object], values: dict[str, str]) -> bool:
    text = values[str(condition["field"])]
    if condition["operator"] == "PREFIX":
        return any(prefix_matches(text, value) for value in condition["values"])
    return any(pattern.search(text) is not None for pattern in condition["compiled"])


def match_rule(rule: dict[str, object], values: dict[str, str]) -> str | None:
    if not all(condition_matches(condition, values) for condition in rule["conditions"]):
        return None
    oem = str(rule["oem"])
    if oem != "__FROM_PREFIX__":
        return oem
    for condition in rule["conditions"]:
        if condition["operator"] != "PREFIX":
            continue
        field_value = values[str(condition["field"])]
        for prefix, mapped_oem in rule["prefixOemMap"].items():
            if prefix_matches(field_value, prefix):
                return mapped_oem
    raise DomesticCatalogError(f"{rule['ruleId']}: matched but prefixOemMap could not resolve OEM")


def read_rows(path: Path) -> tuple[int, list[tuple[str, str, str]]]:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
        if not {"name", "device", "model"}.issubset(columns):
            raise DomesticCatalogError(f"{path}: devices(name, device, model) table is missing")
        source_rows = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        rows = [
            (str(name).strip(), str(device).strip(), str(model).strip())
            for name, device, model in connection.execute(
                "SELECT COALESCE(name, ''), COALESCE(device, ''), COALESCE(model, '') FROM devices"
            )
            if normalize(device) and normalize(model)
        ]
        return source_rows, rows
    finally:
        connection.close()


def read_exclusions(paths: list[Path]) -> tuple[set[tuple[str, str]], set[str]]:
    pairs: set[tuple[str, str]] = set()
    model_only: set[str] = set()
    for path in paths:
        with path.open("r", encoding="utf-8-sig") as stream:
            manifest = json.load(stream)
        records = manifest.get("records") if isinstance(manifest, dict) else None
        if not isinstance(records, list):
            raise DomesticCatalogError(f"{path}: records must be an array")
        for record in records:
            values = record.get("values") if isinstance(record, dict) else None
            if not isinstance(values, dict):
                raise DomesticCatalogError(f"{path}: record values must be an object")
            device = normalize(values.get("device", ""))
            model = normalize(values.get("model", ""))
            if device and model:
                pairs.add((device, model))
            elif model:
                model_only.add(model)
    return pairs, model_only


def safe_marketing_name(name: str, model: str) -> str:
    cleaned = name.strip()
    if not cleaned or "\ufffd" in cleaned or any(ord(character) < 32 for character in cleaned):
        return model.strip()
    return cleaned


def candidate_id(device_norm: str, model_norm: str) -> str:
    digest = hashlib.sha256(f"{device_norm}\x1f{model_norm}".encode("utf-8")).hexdigest()[:24]
    return f"cn-catalog-{digest}"


def classify(
    rows: list[tuple[str, str, str]],
    rules: list[dict[str, object]],
    excluded_pairs: set[tuple[str, str]],
    excluded_models: set[str],
    dataset_id: str,
    region: str,
    collected_at: str,
    devices_digest: str,
    rules_digest: str,
) -> tuple[list[tuple[str, str, str, int]], dict[str, object]]:
    all_pairs: set[tuple[str, str]] = set()
    choices: dict[tuple[str, str], dict[str, object]] = {}
    unclassified_tokens: collections.Counter[str] = collections.Counter()
    for name, device, model in rows:
        normalized_values = {
            "name": normalize(name),
            "device": normalize(device),
            "model": normalize(model),
        }
        pair = (normalized_values["device"], normalized_values["model"])
        all_pairs.add(pair)
        selected_rule = None
        selected_oem = None
        for rule in rules:
            selected_oem = match_rule(rule, normalized_values)
            if selected_oem is not None:
                selected_rule = rule
                break
        if selected_rule is None:
            token_match = re.search(r"[a-z0-9]+", normalized_values["name"])
            if token_match:
                unclassified_tokens[token_match.group(0)] += 1
            continue
        choice = {
            "name": safe_marketing_name(name, model),
            "device": device,
            "model": model,
            "oem": selected_oem,
            "rule": selected_rule,
        }
        current = choices.get(pair)
        choice_score = (
            int(selected_rule["priority"]),
            "\ufffd" in name,
            -len(choice["name"]),
            normalize(choice["name"]),
        )
        if current is None:
            choices[pair] = choice
        else:
            current_rule = current["rule"]
            current_score = (
                int(current_rule["priority"]),
                "\ufffd" in str(current["name"]),
                -len(str(current["name"])),
                normalize(current["name"]),
            )
            if choice_score < current_score:
                choices[pair] = choice

    classified_before_exclusions = len(choices)
    excluded_count = 0
    for pair in list(choices):
        if pair in excluded_pairs or pair[1] in excluded_models:
            del choices[pair]
            excluded_count += 1

    device_source = {
        "sourceId": "device-catalog",
        "authority": "REFERENCE_CATALOG",
        "uri": f"catalog://devices.db#sha256={devices_digest}",
        "title": "设备识别字典 devices.db",
    }
    taxonomy_source = {
        "sourceId": "domestic-oem-taxonomy",
        "authority": "REFERENCE_CATALOG",
        "uri": f"catalog://domestic-oem-rules.json#sha256={rules_digest}",
        "title": "TrustAttestor 国内厂商品牌与系列归类规则",
    }
    candidates: list[tuple[str, str, str, int]] = []
    oem_counts: collections.Counter[str] = collections.Counter()
    group_counts: collections.Counter[str] = collections.Counter()
    confidence_counts: collections.Counter[str] = collections.Counter()
    rule_counts: collections.Counter[str] = collections.Counter()
    ids: set[str] = set()
    for pair, choice in sorted(choices.items()):
        rule = choice["rule"]
        values = {field: "" for field in VALUE_FIELDS}
        values.update({
            "oem": choice["oem"],
            "marketingName": choice["name"],
            "device": choice["device"],
            "model": choice["model"],
        })
        payload = {
            "schema": PAYLOAD_SCHEMA,
            "datasetId": dataset_id,
            "region": region,
            "collectedAt": collected_at,
            "promotionState": POLICY,
            "values": values,
            "evidence": {
                "oem": ["domestic-oem-taxonomy"],
                "marketingName": ["device-catalog"],
                "device": ["device-catalog"],
                "model": ["device-catalog"],
            },
            "sources": [device_source, taxonomy_source],
            "classification": {
                "ruleId": rule["ruleId"],
                "confidence": rule["confidence"],
                "manufacturerGroup": rule["manufacturerGroup"],
            },
            "resolvedSocIdentityId": "",
            "missingPromotionFields": [field for field in PROMOTION_FIELDS if not values[field]],
        }
        payload_json = canonical_json(payload)
        evidence_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        generated_id = candidate_id(*pair)
        if generated_id in ids:
            raise DomesticCatalogError(f"candidate ID collision for {pair}")
        candidates.append((generated_id, payload_json, evidence_sha256, 2))
        ids.add(generated_id)
        oem_counts[str(choice["oem"])] += 1
        group_counts[str(rule["manufacturerGroup"])] += 1
        confidence_counts[str(rule["confidence"])] += 1
        rule_counts[str(rule["ruleId"])] += 1

    coverage = 0.0 if not all_pairs else classified_before_exclusions * 100.0 / len(all_pairs)
    report = {
        "schema": REPORT_SCHEMA,
        "datasetId": dataset_id,
        "region": region,
        "policy": POLICY,
        "devicesDbSha256": devices_digest,
        "rulesSha256": rules_digest,
        "validDeviceModelPairs": len(all_pairs),
        "classifiedPairsBeforeCuratedExclusions": classified_before_exclusions,
        "excludedCuratedPairs": excluded_count,
        "candidateRows": len(candidates),
        "catalogCoveragePercent": round(coverage, 3),
        "byOem": dict(sorted(oem_counts.items())),
        "byManufacturerGroup": dict(sorted(group_counts.items())),
        "byConfidence": dict(sorted(confidence_counts.items())),
        "byRule": dict(sorted(rule_counts.items())),
        "topUnclassifiedNameTokens": [
            {"token": token, "rows": count}
            for token, count in unclassified_tokens.most_common(50)
        ],
    }
    return candidates, report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build all domestic-OEM device/model candidates from devices.db"
    )
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--devices", required=True, type=Path)
    parser.add_argument("--exclude-manifest", action="append", default=[], type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--check-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    if not arguments.check_only and arguments.output is None:
        raise DomesticCatalogError("--output is required unless --check-only is used")
    for path in (arguments.output, arguments.report):
        if path is not None and path.exists():
            raise FileExistsError(f"Refusing to overwrite {path}")
    manifest, rules = load_rules(arguments.rules, arguments.devices)
    source_rows, rows = read_rows(arguments.devices)
    exclusions = read_exclusions(arguments.exclude_manifest)
    candidates, report = classify(
        rows,
        rules,
        *exclusions,
        require_identifier(manifest["datasetId"], "datasetId"),
        require_text(manifest["region"], "region", 32).upper(),
        require_text(manifest["collectedAt"], "collectedAt", 32),
        digest_file(arguments.devices),
        digest_file(arguments.rules),
    )
    report["sourceRows"] = source_rows
    report_json = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if not arguments.check_only:
        assert arguments.output is not None
        arguments.output.write_text(candidate_support.build_sql(candidates), encoding="utf-8", newline="\n")
    if arguments.report is not None:
        arguments.report.write_text(report_json, encoding="utf-8", newline="\n")
    print(report_json, end="")


if __name__ == "__main__":
    main()

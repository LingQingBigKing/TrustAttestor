import copy
import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "build-baseline-candidates-sql.py"
SPEC = importlib.util.spec_from_file_location("candidate_builder", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class CandidateBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.devices = self.directory / "devices.db"
        connection = sqlite3.connect(self.devices)
        connection.execute("CREATE TABLE devices(name TEXT, device TEXT, model TEXT)")
        connection.execute(
            "INSERT INTO devices(name, device, model) VALUES (?, ?, ?)",
            ("Example Phone", "example_device", "EX100"),
        )
        connection.commit()
        connection.close()
        self.socs = self.directory / "socs.json"
        self.socs.write_text(json.dumps({
            "GENERIC": {
                "VENDOR": "Example",
                "NAME": "",
                "FAB": "",
                "CPU": "",
                "MEMORY": "",
                "BANDWIDTH": "",
                "CHANNELS": "",
            },
            "SM9999": {
                "VENDOR": "Example",
                "NAME": "Example SoC",
                "FAB": "4 nm",
                "CPU": "",
                "MEMORY": "",
                "BANDWIDTH": "",
                "CHANNELS": "",
            }
        }), encoding="utf-8")
        self.manifest = {
            "schema": builder.SCHEMA,
            "datasetId": "domestic-test-1",
            "region": "CN",
            "collectedAt": "2026-08-23",
            "policy": builder.POLICY,
            "catalogs": {
                "devicesDbSha256": builder.digest_file(self.devices),
                "socsJsonSha256": builder.digest_file(self.socs),
            },
            "sources": [
                {
                    "sourceId": "device-catalog",
                    "authority": "REFERENCE_CATALOG",
                    "uri": "catalog://devices.db",
                    "title": "test catalog",
                },
                {
                    "sourceId": "oem-source",
                    "authority": "OEM_OPEN_SOURCE",
                    "uri": "https://example.test/oem/kernel",
                    "title": "test OEM source",
                },
            ],
            "records": [self.record()],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def record() -> dict:
        return {
            "candidateId": "cn-example-ex100",
            "candidateKind": "DEVICE_VARIANT",
            "market": "CN",
            "values": {
                "oem": "Example",
                "marketingName": "Example Phone",
                "device": "example_device",
                "model": "EX100",
                "product": "",
                "sku": "",
                "brand": "",
                "manufacturer": "",
                "boardPlatform": "",
                "socAlias": "SM9999",
                "launchAndroidRelease": "15",
                "kernelAndroidGeneration": "V",
                "kernelFamily": "6.6",
            },
            "evidence": {
                "oem": ["oem-source"],
                "marketingName": ["oem-source"],
                "device": ["device-catalog"],
                "model": ["device-catalog"],
                "socAlias": ["oem-source"],
                "launchAndroidRelease": ["oem-source"],
                "kernelAndroidGeneration": ["oem-source"],
                "kernelFamily": ["oem-source"],
            },
        }

    def validated_candidates(self, manifest: dict | None = None):
        selected = self.manifest if manifest is None else manifest
        sources = builder.validate_sources(selected["sources"])
        return builder.validate_records(
            selected,
            sources,
            builder.read_device_pairs(self.devices),
            builder.read_soc_aliases(self.socs),
        )

    def test_valid_candidate_builds_and_applies_pending_sql(self) -> None:
        candidates = self.validated_candidates()
        self.assertEqual(1, len(candidates))
        payload = json.loads(candidates[0][1])
        self.assertEqual("CANDIDATE_ONLY", payload["promotionState"])
        self.assertIn("product", payload["missingPromotionFields"])
        self.assertEqual(32, len(payload["resolvedSocIdentityId"]))

        connection = sqlite3.connect(":memory:")
        connection.executescript(
            (ROOT / "catalog-migrations" / "0003_device_baseline_batches.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.executescript(builder.build_sql(candidates))
        row = connection.execute(
            "SELECT candidate_kind, state, distinct_source_count FROM baseline_candidates"
        ).fetchone()
        self.assertEqual(("DEVICE_VARIANT", "PENDING", 2), row)
        connection.close()

    def test_approved_candidate_is_immutable_on_reimport(self) -> None:
        candidates = self.validated_candidates()
        connection = sqlite3.connect(":memory:")
        connection.executescript(
            (ROOT / "catalog-migrations" / "0003_device_baseline_batches.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.executescript(builder.build_sql(candidates))
        connection.execute(
            "UPDATE baseline_candidates SET state='APPROVED', review_note='reviewed'"
        )
        original = connection.execute(
            "SELECT payload_json, evidence_sha256 FROM baseline_candidates"
        ).fetchone()
        changed_payload = json.dumps({"changed": True}, separators=(",", ":"))
        changed = [(
            candidates[0][0],
            changed_payload,
            hashlib.sha256(changed_payload.encode()).hexdigest(),
            3,
        )]
        connection.executescript(builder.build_sql(changed))
        current = connection.execute(
            "SELECT payload_json, evidence_sha256, state, review_note FROM baseline_candidates"
        ).fetchone()
        self.assertEqual((*original, "APPROVED", "reviewed"), current)
        connection.close()

    def test_non_empty_field_without_evidence_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["records"][0]["values"]["product"] = "example_product"
        with self.assertRaisesRegex(builder.CandidateError, "values.product has no evidence"):
            self.validated_candidates(manifest)

    def test_unknown_device_model_pair_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["records"][0]["values"]["model"] = "UNKNOWN"
        with self.assertRaisesRegex(builder.CandidateError, "not present in devices.db"):
            self.validated_candidates(manifest)

    def test_unknown_soc_alias_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["records"][0]["values"]["socAlias"] = "UNKNOWN-SOC"
        with self.assertRaisesRegex(builder.CandidateError, "not present in socs.json"):
            self.validated_candidates(manifest)

    def test_incomplete_catch_all_soc_key_does_not_block_valid_aliases(self) -> None:
        aliases = builder.read_soc_aliases(self.socs)
        self.assertNotIn("generic", aliases)
        self.assertIn("sm9999", aliases)

    def test_declared_catalog_digest_must_match(self) -> None:
        with self.assertRaisesRegex(builder.CandidateError, "does not match devices.db"):
            builder.validate_catalog_digest(
                {"devicesDbSha256": "0" * 64},
                "devicesDbSha256",
                self.devices,
                "devices.db",
            )


if __name__ == "__main__":
    unittest.main()

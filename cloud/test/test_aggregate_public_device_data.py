import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGGREGATOR_PATH = ROOT / "scripts" / "aggregate-public-device-data.py"
CANDIDATE_PATH = ROOT / "scripts" / "build-baseline-candidates-sql.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


aggregator = load_module("public_source_aggregator", AGGREGATOR_PATH)
candidate_builder = load_module("candidate_builder_v2", CANDIDATE_PATH)


class PublicSourceAggregatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.devices = self.directory / "devices.db"
        connection = sqlite3.connect(self.devices)
        connection.execute("CREATE TABLE devices(name TEXT, device TEXT, model TEXT)")
        connection.executemany(
            "INSERT INTO devices(name, device, model) VALUES (?, ?, ?)",
            [
                ("Example Phone", "example_device", "EX100"),
                ("Other Phone", "other_device", "OT200"),
            ],
        )
        connection.commit()
        connection.close()
        self.socs = self.directory / "socs.json"
        self.socs.write_text(
            json.dumps({
                "SM9999": {
                    "VENDOR": "Example",
                    "NAME": "Example SoC",
                    "FAB": "4 nm",
                    "CPU": "armv9",
                    "MEMORY": "",
                    "BANDWIDTH": "",
                    "CHANNELS": "",
                }
            }),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_standard_sources(self) -> Path:
        (self.directory / "play.csv").write_text(
            "Retail Branding,Marketing Name,Device,Model\n"
            "Example,Example Phone,example_device,EX100\n",
            encoding="utf-8",
        )
        firmware = self.directory / "firmware"
        firmware.mkdir()
        (firmware / "build.prop").write_text(
            "\n".join([
                "ro.product.device=example_device",
                "ro.product.model=EX100",
                "ro.product.name=example_global",
                "ro.product.brand=Example",
                "ro.product.manufacturer=Example Corp",
                "ro.boot.product.hardware.sku=EX100-CN",
                "ro.board.platform=sm9999",
                "ro.soc.model=SM9999",
                "ro.build.fingerprint=Example/example_global/example_device:15/AP4A/1:user/release-keys",
                "ro.build.version.security_patch=2026-08-05",
                "ro.product.cpu.abilist=arm64-v8a,armeabi-v7a",
            ])
            + "\n",
            encoding="utf-8",
        )
        (self.directory / "pif.json").write_text(
            json.dumps({
                "BRAND": "Example",
                "PRODUCT": "example_global",
                "DEVICE": "example_device",
                "MODEL": "EX100",
                "MANUFACTURER": "Example Corp",
                "FINGERPRINT": "community/older/fingerprint:user/release-keys",
                "SECURITY_PATCH": "2026-07-05",
            }),
            encoding="utf-8",
        )
        (self.directory / "spec.csv").write_text(
            "manufacturer,model,device,boardPlatform,socAlias,supportedAbis\n"
            "Example Corp,EX100,example_device,sm9999,SM9999,arm64-v8a\n",
            encoding="utf-8",
        )
        manifest = {
            "schema": aggregator.SCHEMA,
            "datasetId": "public-test-1",
            "region": "GLOBAL",
            "collectedAt": "2026-08-29",
            "policy": aggregator.POLICY,
            "sources": [
                {
                    "sourceId": "google-play",
                    "kind": "GOOGLE_PLAY_CSV",
                    "path": "play.csv",
                    "uri": "https://example.test/play.csv",
                    "title": "Google Play snapshot",
                },
                {
                    "sourceId": "firmware-example",
                    "kind": "FIRMWARE_PROPS",
                    "path": "firmware",
                    "uri": "https://example.test/firmware",
                    "title": "Firmware dump",
                },
                {
                    "sourceId": "pif-community",
                    "kind": "PIF_JSON",
                    "path": "pif.json",
                    "uri": "https://example.test/pif.json",
                    "title": "Community PIF",
                },
                {
                    "sourceId": "hardware-spec",
                    "kind": "HARDWARE_SPEC_CSV",
                    "path": "spec.csv",
                    "uri": "https://example.test/spec.csv",
                    "title": "Hardware specification",
                },
            ],
        }
        path = self.directory / "sources.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_aggregates_sources_with_field_level_precedence(self) -> None:
        manifest_path = self.write_standard_sources()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sources, facts = aggregator.read_sources(manifest, manifest_path)
        candidates, unresolved, conflicts, unknown_socs = aggregator.build_candidates(
            manifest, sources, facts, self.devices, self.socs
        )
        self.assertEqual(4, len(sources))
        self.assertEqual(4, len(facts))
        self.assertEqual([], unresolved)
        self.assertEqual([], conflicts)
        self.assertEqual([], unknown_socs)
        self.assertEqual(1, len(candidates["records"]))
        record = candidates["records"][0]
        self.assertEqual("sm9999", record["values"]["boardPlatform"])
        self.assertEqual("SM9999", record["values"]["socAlias"])
        self.assertTrue(record["values"]["fingerprint"].startswith("Example/"))
        self.assertEqual(["firmware-example"], record["evidence"]["fingerprint"])
        self.assertIn("pif-community", {source["sourceId"] for source in candidates["sources"]})

        validated = candidate_builder.validate_records(
            candidates,
            candidate_builder.validate_sources(candidates["sources"]),
            candidate_builder.read_device_pairs(self.devices),
            candidate_builder.read_soc_aliases(self.socs),
        )
        self.assertEqual(1, len(validated))
        payload = json.loads(validated[0][1])
        self.assertEqual(candidate_builder.PAYLOAD_SCHEMA_V2, payload["schema"])
        self.assertEqual(4, len(payload["aggregation"]["factIds"]))
        candidate_sql = aggregator.build_candidate_sql(candidates, self.devices, self.socs)
        self.assertIn("INSERT INTO baseline_candidates", candidate_sql)
        self.assertIn("'PENDING'", candidate_sql)

    def test_equal_authority_conflict_is_recorded_and_not_selected(self) -> None:
        first = self.directory / "first.csv"
        second = self.directory / "second.csv"
        header = "manufacturer,model,device,boardPlatform\n"
        first.write_text(header + "Example,EX100,example_device,board-a\n", encoding="utf-8")
        second.write_text(header + "Example,EX100,example_device,board-b\n", encoding="utf-8")
        manifest = {
            "schema": aggregator.SCHEMA,
            "datasetId": "conflict-test",
            "region": "GLOBAL",
            "collectedAt": "2026-08-29",
            "policy": aggregator.POLICY,
            "sources": [
                {
                    "sourceId": name,
                    "kind": "HARDWARE_SPEC_CSV",
                    "path": path.name,
                    "uri": f"https://example.test/{path.name}",
                    "title": name,
                }
                for name, path in (("first", first), ("second", second))
            ],
        }
        manifest_path = self.directory / "conflict.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        sources, facts = aggregator.read_sources(manifest, manifest_path)
        candidates, _, conflicts, _ = aggregator.build_candidates(
            manifest, sources, facts, self.devices, self.socs
        )
        self.assertEqual("", candidates["records"][0]["values"]["boardPlatform"])
        self.assertNotIn("boardPlatform", candidates["records"][0]["evidence"])
        self.assertEqual("boardPlatform", conflicts[0]["field"])
        self.assertEqual(2, len(conflicts[0]["variants"]))

    def test_unknown_device_is_retained_as_fact_but_not_candidate(self) -> None:
        pif = self.directory / "unknown.json"
        pif.write_text(
            json.dumps({
                "BRAND": "Unknown",
                "DEVICE": "unknown_device",
                "MODEL": "UNKNOWN100",
                "FINGERPRINT": "Unknown/product/device:15/id/1:user/release-keys",
            }),
            encoding="utf-8",
        )
        manifest = {
            "schema": aggregator.SCHEMA,
            "datasetId": "unknown-test",
            "region": "GLOBAL",
            "collectedAt": "2026-08-29",
            "policy": aggregator.POLICY,
            "sources": [{
                "sourceId": "unknown-pif",
                "kind": "PIF_JSON",
                "path": pif.name,
                "uri": "https://example.test/unknown.json",
                "title": "Unknown PIF",
            }],
        }
        manifest_path = self.directory / "unknown-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        sources, facts = aggregator.read_sources(manifest, manifest_path)
        candidates, unresolved, conflicts, unknown_socs = aggregator.build_candidates(
            manifest, sources, facts, self.devices, self.socs
        )
        self.assertEqual(1, len(facts))
        self.assertEqual([], candidates["records"])
        self.assertEqual("DEVICE_MODEL_NOT_IN_REFERENCE_CATALOG", unresolved[0]["reason"])
        self.assertEqual([], conflicts)
        self.assertEqual([], unknown_socs)

    def test_generated_evidence_sql_applies_to_catalog_schema(self) -> None:
        manifest_path = self.write_standard_sources()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sources, facts = aggregator.read_sources(manifest, manifest_path)
        candidates, unresolved, conflicts, _ = aggregator.build_candidates(
            manifest, sources, facts, self.devices, self.socs
        )
        receipt = {
            "runId": "a" * 64,
            "datasetId": candidates["datasetId"],
            "sourceSnapshotCount": len(sources),
            "factCount": len(facts),
            "candidateCount": len(candidates["records"]),
            "unresolvedFactCount": len(unresolved),
            "conflictCount": len(conflicts),
        }
        generated = aggregator.build_evidence_sql(sources, facts, receipt, "b" * 64)
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(
            (ROOT / "catalog-migrations" / "0006_catalog_source_evidence.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.executescript(generated)
        self.assertEqual(4, connection.execute("SELECT COUNT(*) FROM catalog_source_snapshots").fetchone()[0])
        self.assertEqual(4, connection.execute("SELECT COUNT(*) FROM catalog_source_facts").fetchone()[0])
        self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM catalog_aggregation_runs").fetchone()[0])
        connection.close()


if __name__ == "__main__":
    unittest.main()

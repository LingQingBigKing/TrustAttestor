import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "build-domestic-device-candidates-sql.py"
RULES_PATH = ROOT / "data" / "candidates" / "domestic-oem-rules-2026-08.json"
SPEC = importlib.util.spec_from_file_location("domestic_candidate_builder", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class DomesticDeviceCandidateBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.devices = self.directory / "devices.db"
        connection = sqlite3.connect(self.devices)
        connection.execute("CREATE TABLE devices(name TEXT, device TEXT, model TEXT)")
        connection.executemany(
            "INSERT INTO devices(name, device, model) VALUES (?, ?, ?)",
            [
                ("Xiaomi 15", "dada", "24129PN74C"),
                ("Find N6", "OP61A9L1", "PLP110"),
                ("Unknown OPlus device", "OP68F7L1", "PYS110"),
                ("S20", "PD2429", "V2429A"),
                ("Mate 10", "HWBLA", "BLA-AL00"),
                ("MATE ONE", "MO_Pro", "MO_Series"),
                ("Micromax Spark", "Q409", "Micromax Q409"),
                ("DINOSAUR", "x5623_h6013_cubot", "CUBOT DINOSAUR"),
                ("Zenfone 11", "AI2401", "ASUS_AI2401"),
                ("WIKO CINK PEAX", "s9091", "CINK PEAX"),
                ("Galaxy S25", "pa3q", "SM-S931B"),
            ],
        )
        connection.commit()
        connection.close()

        manifest = json.loads(RULES_PATH.read_text(encoding="utf-8"))
        manifest["devicesDbSha256"] = builder.digest_file(self.devices)
        self.rules = self.directory / "rules.json"
        self.rules.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def classify(self, excluded_pairs=None):
        manifest, rules = builder.load_rules(self.rules, self.devices)
        _, rows = builder.read_rows(self.devices)
        return builder.classify(
            rows,
            rules,
            excluded_pairs or set(),
            set(),
            manifest["datasetId"],
            manifest["region"],
            manifest["collectedAt"],
            builder.digest_file(self.devices),
            builder.digest_file(self.rules),
        )

    def test_production_rules_classify_strong_domestic_identifiers_only(self) -> None:
        candidates, report = self.classify()
        payloads = [json.loads(candidate[1]) for candidate in candidates]
        by_model = {payload["values"]["model"]: payload for payload in payloads}

        self.assertEqual(7, len(candidates))
        self.assertEqual("Xiaomi", by_model["24129PN74C"]["values"]["oem"])
        self.assertEqual("OPPO", by_model["PLP110"]["values"]["oem"])
        self.assertEqual("OPlus", by_model["PYS110"]["values"]["oem"])
        self.assertEqual("vivo", by_model["V2429A"]["values"]["oem"])
        self.assertEqual("Huawei", by_model["BLA-AL00"]["values"]["oem"])
        self.assertEqual("CUBOT", by_model["CUBOT DINOSAUR"]["values"]["oem"])
        self.assertEqual("ASUS", by_model["ASUS_AI2401"]["values"]["oem"])
        self.assertNotIn("MO_Series", by_model)
        self.assertNotIn("Micromax Q409", by_model)
        self.assertNotIn("CINK PEAX", by_model)
        self.assertNotIn("SM-S931B", by_model)
        self.assertEqual(7, report["classifiedPairsBeforeCuratedExclusions"])
        self.assertEqual("MULTI_REGION", report["region"])

    def test_generated_payload_cannot_be_promoted_without_hardware_evidence(self) -> None:
        candidates, _ = self.classify()
        payload = json.loads(candidates[0][1])
        self.assertEqual("CANDIDATE_ONLY", payload["promotionState"])
        self.assertEqual("", payload["values"]["socAlias"])
        self.assertEqual("", payload["values"]["boardPlatform"])
        self.assertEqual("", payload["values"]["launchAndroidRelease"])
        self.assertIn("socAlias", payload["missingPromotionFields"])
        self.assertEqual(2, candidates[0][3])

    def test_curated_pair_is_excluded_and_id_is_stable(self) -> None:
        pair = (builder.normalize("dada"), builder.normalize("24129PN74C"))
        candidates, report = self.classify({pair})
        self.assertEqual(6, len(candidates))
        self.assertEqual(1, report["excludedCuratedPairs"])
        expected = builder.candidate_id(*pair)
        candidates_without_exclusion, _ = self.classify()
        matching = [
            candidate[0]
            for candidate in candidates_without_exclusion
            if json.loads(candidate[1])["values"]["model"] == "24129PN74C"
        ]
        self.assertEqual([expected], matching)

    def test_generated_sql_applies_to_candidate_queue(self) -> None:
        candidates, _ = self.classify()
        connection = sqlite3.connect(":memory:")
        connection.executescript(
            (ROOT / "catalog-migrations" / "0003_device_baseline_batches.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.executescript(builder.candidate_support.build_sql(candidates))
        count, states = connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT state) FROM baseline_candidates"
        ).fetchone()
        state = connection.execute(
            "SELECT state FROM baseline_candidates LIMIT 1"
        ).fetchone()[0]
        connection.close()
        self.assertEqual((7, 1), (count, states))
        self.assertEqual("PENDING", state)

    def test_rules_are_pinned_to_exact_devices_database(self) -> None:
        manifest = json.loads(self.rules.read_text(encoding="utf-8"))
        manifest["devicesDbSha256"] = "0" * 64
        self.rules.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(builder.DomesticCatalogError, "does not match devices.db"):
            builder.load_rules(self.rules, self.devices)


if __name__ == "__main__":
    unittest.main()

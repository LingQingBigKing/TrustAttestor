import csv
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build-device-baselines-sql.py"
SPEC = importlib.util.spec_from_file_location("device_baseline_builder", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class DeviceBaselineBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.devices = self.root / "devices.db"
        connection = sqlite3.connect(self.devices)
        connection.execute("CREATE TABLE devices(name TEXT, device TEXT, model TEXT)")
        connection.execute(
            "INSERT INTO devices VALUES (?, ?, ?)",
            ("Test Phone", "test_device", "Test Model"),
        )
        connection.commit()
        connection.close()
        self.socs = self.root / "socs.json"
        self.socs.write_text(json.dumps({
            "GENERIC": {
                "VENDOR": "Qualcomm",
                "NAME": "",
            },
            "SMTEST": {
                "VENDOR": "Qualcomm",
                "NAME": "Test SoC",
                "FAB": "4 nm",
                "CPU": "test",
                "MEMORY": "LPDDR5",
                "BANDWIDTH": "",
                "CHANNELS": "4",
            }
        }), encoding="utf-8")
        self.hardware = self.root / "hardware.csv"
        self.soc = self.root / "soc.csv"
        self.kernel = self.root / "kernel.csv"
        self.write_csv(self.hardware, BUILDER.HARDWARE_COLUMNS, [{
            "variant_id": "test-global",
            "device": "test_device",
            "model": "Test Model",
            "product": "test_product",
            "sku": "global",
            "brand": "TestBrand",
            "manufacturer": "TestVendor",
            "board_platform": "test_platform",
            "source": "official fixture",
            "confidence": "OFFICIAL",
        }])
        self.write_csv(self.soc, BUILDER.SOC_COLUMNS, [{
            "variant_id": "test-global",
            "soc_alias": "smtest",
            "source": "official fixture",
            "confidence": "OFFICIAL",
        }])
        self.write_csv(self.kernel, BUILDER.KERNEL_COLUMNS, [{
            "baseline_id": "test-android15",
            "variant_id": "test-global",
            "sdk_min": "35",
            "sdk_max": "35",
            "os_release": "15",
            "build_id_prefix": "AP4A.",
            "fingerprint_prefix": "testbrand/test_product/test_device:",
            "security_patch_min": "2025-01-01",
            "security_patch_max": "2025-12-31",
            "kernel_family": "6.1",
            "kernel_release_prefix": "6.1.",
            "build_version_contains": "",
            "machine": "aarch64",
            "source": "official fixture",
            "confidence": "OFFICIAL",
        }])

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def write_csv(path: Path, columns: tuple[str, ...], rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)

    def load(self):
        pairs = BUILDER.read_device_pairs(self.devices)
        aliases = BUILDER.read_soc_aliases(self.socs)
        hardware, variants = BUILDER.read_hardware_rows(self.hardware, pairs)
        soc = BUILDER.read_soc_rows(self.soc, variants, aliases)
        legacy, legacy_variants = BUILDER.build_legacy_hardware_rows(hardware, soc)
        kernel = BUILDER.read_kernel_rows(self.kernel, legacy_variants)
        return hardware, soc, legacy, kernel

    def test_builds_migration_compatible_batch_with_pointer_last(self) -> None:
        hardware, soc, legacy, kernel = self.load()
        generated = BUILDER.build_sql(
            "batch-2025-01", "2025.01", "{}", "a" * 64, "fixture",
            hardware, soc, legacy, kernel
        )
        self.assertLessEqual(
            max(len(statement.encode("utf-8")) for statement in generated.split(";\n") if statement),
            BUILDER.MAX_STATEMENT_BYTES,
        )
        self.assertTrue(generated.rstrip().endswith(
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP;"
        ))
        connection = sqlite3.connect(":memory:")
        migration_root = Path(__file__).parents[1] / "catalog-migrations"
        connection.executescript(
            (migration_root / "0002_cloud_consistency_rules.sql").read_text(encoding="utf-8")
        )
        connection.executescript(
            (migration_root / "0003_device_baseline_batches.sql").read_text(encoding="utf-8")
        )
        split_migration = (Path(__file__).parents[1] / "catalog-migrations" /
                           "0005_split_device_soc_baselines.sql").read_text(encoding="utf-8")
        connection.executescript(split_migration)
        connection.executescript(generated)
        self.assertEqual(
            connection.execute(
                "SELECT value FROM baseline_metadata WHERE key='active_batch_id'"
            ).fetchone()[0],
            "batch-2025-01",
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM device_hardware_variant_baselines").fetchone()[0], 1
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM device_soc_baselines").fetchone()[0], 1
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM firmware_kernel_baselines").fetchone()[0], 1
        )

    def test_rejects_unknown_device_model_pair(self) -> None:
        self.write_csv(self.hardware, BUILDER.HARDWARE_COLUMNS, [{
            "variant_id": "unknown",
            "device": "missing",
            "model": "Missing",
            "product": "missing",
            "sku": "",
            "brand": "brand",
            "manufacturer": "vendor",
            "board_platform": "platform",
            "source": "fixture",
            "confidence": "VERIFIED",
        }])
        with self.assertRaisesRegex(BUILDER.BaselineError, "not present in devices.db"):
            self.load()

    def test_rejects_ambiguous_soc_alias(self) -> None:
        self.socs.write_text(json.dumps({
            "SM-TEST": {"VENDOR": "Vendor A", "NAME": "Chip A"},
            "SM TEST": {"VENDOR": "Vendor B", "NAME": "Chip B"},
        }), encoding="utf-8")
        with self.assertRaisesRegex(BUILDER.BaselineError, "multiple SoC identities"):
            self.load()

    def test_ignores_incomplete_catch_all_soc_alias(self) -> None:
        aliases = BUILDER.read_soc_aliases(self.socs)
        self.assertNotIn("generic", aliases)
        self.assertIn("smtest", aliases)

    def test_publishes_hardware_without_a_soc_binding(self) -> None:
        self.write_csv(self.soc, BUILDER.SOC_COLUMNS, [])
        self.write_csv(self.kernel, BUILDER.KERNEL_COLUMNS, [])
        hardware, soc, legacy, kernel = self.load()
        generated = BUILDER.build_sql(
            "hardware-only", "2025.02", "{}", "b" * 64, "fixture",
            hardware, soc, legacy, kernel
        )
        connection = sqlite3.connect(":memory:")
        for migration_name in (
            "0002_cloud_consistency_rules.sql",
            "0003_device_baseline_batches.sql",
            "0005_split_device_soc_baselines.sql",
        ):
            migration = (Path(__file__).parents[1] / "catalog-migrations" /
                         migration_name).read_text(encoding="utf-8")
            connection.executescript(migration)
        connection.executescript(generated)
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM device_hardware_variant_baselines").fetchone()[0], 1
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM device_soc_baselines").fetchone()[0], 0
        )

    def test_split_migration_backfills_existing_combined_baselines(self) -> None:
        connection = sqlite3.connect(":memory:")
        migration_root = Path(__file__).parents[1] / "catalog-migrations"
        connection.executescript(
            (migration_root / "0002_cloud_consistency_rules.sql").read_text(encoding="utf-8")
        )
        connection.executescript(
            (migration_root / "0003_device_baseline_batches.sql").read_text(encoding="utf-8")
        )
        connection.execute(
            "INSERT INTO baseline_import_batches "
            "(batch_id,dataset_version,manifest_json,manifest_sha256,hardware_rows,"
            "firmware_rows,source_summary,status) VALUES (?,?,?,?,?,?,?,?)",
            ("legacy", "1", "{}", "c" * 64, 1, 0, "fixture", "PUBLISHED"),
        )
        connection.execute(
            "INSERT INTO device_variant_baselines "
            "(batch_id,variant_id,device_norm,model_norm,product_norm,sku_norm,"
            "brand_norm,manufacturer_norm,board_platform_norm,fingerprint_prefix_norm,"
            "soc_identity_id,source,confidence,active) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "legacy", "legacy-variant", "device", "model", "product", "", "brand",
                "manufacturer", "platform", "brand/product/device:", "d" * 32,
                "fixture", "VERIFIED", 1,
            ),
        )
        connection.executescript(
            (migration_root / "0005_split_device_soc_baselines.sql").read_text(encoding="utf-8")
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM device_hardware_variant_baselines").fetchone()[0], 1
        )
        self.assertEqual(
            connection.execute("SELECT COUNT(*) FROM device_soc_baselines").fetchone()[0], 1
        )
        self.assertEqual(
            connection.execute("SELECT soc_rows FROM baseline_import_batches").fetchone()[0], 1
        )

    def test_splits_large_imports_below_the_d1_safety_limit(self) -> None:
        statements = BUILDER.values_statements(
            "fixture_table",
            ("value",),
            [("x" * 1_000,) for _ in range(200)],
            "fixture-batch",
        )
        self.assertGreater(len(statements), 1)
        self.assertTrue(all(
            len(statement.encode("utf-8")) <= BUILDER.MAX_STATEMENT_BYTES
            for statement in statements
        ))


if __name__ == "__main__":
    unittest.main()

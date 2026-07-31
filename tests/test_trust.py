from __future__ import annotations

import csv
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from regulated_data_ops.cli import main
from regulated_data_ops.contract import (
    PAYMENT_CONTRACT_V1,
    PAYMENT_CONTRACT_V2,
    payment_contract_for_policy,
)
from regulated_data_ops.pipeline import IngestionPipeline
from regulated_data_ops.schema import assess_schema
from regulated_data_ops.store import DataStore
from regulated_data_ops.trust import DEFAULT_TRUST_POLICY, TrustPolicy

KEY = "test-key-with-at-least-32-characters"
V1_HEADERS = (
    "event_id",
    "customer_email",
    "amount",
    "currency",
    "event_time",
    "country",
    "lawful_basis",
)


class TrustPolicyTests(unittest.TestCase):
    def test_committed_policy_matches_safe_default(self) -> None:
        root = Path(__file__).resolve().parents[1]
        loaded = TrustPolicy.load(root / "config" / "trust-policy.json")
        self.assertEqual(loaded, DEFAULT_TRUST_POLICY)
        self.assertEqual(loaded.fingerprint, DEFAULT_TRUST_POLICY.fingerprint)

    def test_policy_round_trip_is_canonical(self) -> None:
        rebuilt = TrustPolicy.from_mapping(DEFAULT_TRUST_POLICY.as_dict())
        self.assertEqual(rebuilt.fingerprint, DEFAULT_TRUST_POLICY.fingerprint)

    def test_policy_rejects_unknown_keys(self) -> None:
        payload = DEFAULT_TRUST_POLICY.as_dict() | {"unreviewed": True}
        with self.assertRaisesRegex(ValueError, "policy keys mismatch"):
            TrustPolicy.from_mapping(payload)

    def test_policy_rejects_impossible_rate(self) -> None:
        payload = DEFAULT_TRUST_POLICY.as_dict()
        payload["slo"]["minimum_valid_rate"] = 1.1
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            TrustPolicy.from_mapping(payload)

    def test_policy_rejects_unknown_nested_key(self) -> None:
        payload = DEFAULT_TRUST_POLICY.as_dict()
        payload["rules"]["unreviewed"] = "value"
        with self.assertRaisesRegex(ValueError, "rules keys mismatch"):
            TrustPolicy.from_mapping(payload)

    def test_policy_file_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"policy_version":"2.0.0","policy_version":"shadow"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate policy key"):
                TrustPolicy.load(path)


class SchemaEvolutionTests(unittest.TestCase):
    def test_v1_headers_remain_compatible_with_v2(self) -> None:
        result = assess_schema(PAYMENT_CONTRACT_V2, V1_HEADERS)
        self.assertTrue(result.compatible)
        self.assertEqual(result.mode, "backward-compatible")
        self.assertEqual(result.missing_optional, ("source_system",))

    def test_v2_native_headers_are_recognized(self) -> None:
        result = assess_schema(
            PAYMENT_CONTRACT_V2, V1_HEADERS + ("source_system",)
        )
        self.assertTrue(result.compatible)
        self.assertEqual(result.mode, "native")

    def test_unknown_header_still_fails_closed(self) -> None:
        result = assess_schema(PAYMENT_CONTRACT_V2, V1_HEADERS + ("raw_pan",))
        self.assertFalse(result.compatible)
        with self.assertRaisesRegex(ValueError, "unexpected=.*raw_pan"):
            result.require_compatible()

    def test_duplicate_header_fails_closed(self) -> None:
        result = assess_schema(
            PAYMENT_CONTRACT_V2, V1_HEADERS + ("customer_email",)
        )
        self.assertFalse(result.compatible)
        self.assertEqual(result.duplicates, ("customer_email",))

    def test_v1_fingerprint_is_preserved(self) -> None:
        self.assertEqual(
            PAYMENT_CONTRACT_V1.fingerprint,
            "2d1c4194d51f7c8386fb98ad6c281ee2503e9f08f3aa8fc74d5d659066b62299",
        )


class TrustPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = self.root / "trust.db"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _row(self) -> dict[str, str]:
        return {
            "event_id": "af455f9c-b931-4f77-82da-1b726a25e5f4",
            "customer_email": "synthetic.trust@example.test",
            "amount": "35.20",
            "currency": "EUR",
            "event_time": "2026-07-21T14:00:00+00:00",
            "country": "ES",
            "lawful_basis": "contract",
        }

    def _csv(self, row: dict[str, str], name: str) -> Path:
        path = self.root / name
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=tuple(row))
            writer.writeheader()
            writer.writerow(row)
        return path

    def test_clean_v1_input_passes_with_legacy_default(self) -> None:
        pipeline = IngestionPipeline(self.database, KEY)
        try:
            report = pipeline.ingest(self._csv(self._row(), "v1.csv"))
            stored = pipeline.lineage(self._row()["event_id"])
        finally:
            pipeline.close()
        self.assertEqual(report.schema_mode, "backward-compatible")
        self.assertEqual(report.trust_status, "passing")
        self.assertEqual(stored["source_system"], "legacy")

    def test_clean_v2_input_passes_as_native(self) -> None:
        row = self._row() | {"source_system": "core-banking"}
        pipeline = IngestionPipeline(self.database, KEY)
        try:
            report = pipeline.ingest(self._csv(row, "v2.csv"))
            stored = pipeline.lineage(row["event_id"])
        finally:
            pipeline.close()
        self.assertEqual(report.schema_mode, "native")
        self.assertEqual(report.trust_status, "passing")
        self.assertEqual(stored["source_system"], "core-banking")

    def test_missing_optional_value_uses_legacy_default(self) -> None:
        path = self.root / "optional-empty.csv"
        values = [self._row()[name] for name in V1_HEADERS]
        path.write_text(
            ",".join(V1_HEADERS + ("source_system",))
            + "\n"
            + ",".join(values)
            + "\n",
            encoding="utf-8",
        )
        pipeline = IngestionPipeline(self.database, KEY)
        try:
            report = pipeline.ingest(path)
            stored = pipeline.lineage(self._row()["event_id"])
        finally:
            pipeline.close()
        self.assertEqual(report.schema_mode, "native")
        self.assertEqual(stored["source_system"], "legacy")

    def test_extra_row_value_fails_closed(self) -> None:
        path = self.root / "overflow.csv"
        values = [self._row()[name] for name in V1_HEADERS]
        path.write_text(
            ",".join(V1_HEADERS) + "\n" + ",".join(values + ["secret"]) + "\n",
            encoding="utf-8",
        )
        pipeline = IngestionPipeline(self.database, KEY)
        try:
            with self.assertRaisesRegex(ValueError, "row shape mismatch"):
                pipeline.ingest(path)
            status = pipeline.latest_status()
        finally:
            pipeline.close()
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["trust_status"], "breached")

    def test_configured_rule_quarantines_disallowed_currency(self) -> None:
        payload = DEFAULT_TRUST_POLICY.as_dict()
        payload["policy_version"] = "2.0.0-eur-only"
        payload["rules"]["allowed_currencies"] = ["EUR"]
        policy = TrustPolicy.from_mapping(payload)
        row = self._row() | {"currency": "USD"}
        pipeline = IngestionPipeline(
            self.database,
            KEY,
            contract=payment_contract_for_policy(policy),
            policy=policy,
        )
        try:
            report = pipeline.ingest(self._csv(row, "usd.csv"))
            trust_report = pipeline.trust_report()
        finally:
            pipeline.close()
        self.assertEqual(report.quarantined_rows, 1)
        self.assertEqual(report.trust_status, "breached")
        self.assertIn("minimum_valid_rate", report.slo_breaches)
        self.assertEqual(trust_report["overall_status"], "breached")

    def test_trust_report_can_fail_an_automation(self) -> None:
        row = self._row() | {"amount": "-1.00"}
        pipeline = IngestionPipeline(self.database, KEY)
        try:
            pipeline.ingest(self._csv(row, "bad.csv"))
        finally:
            pipeline.close()
        with redirect_stdout(io.StringIO()):
            exit_code = main(
                [
                    "--database",
                    str(self.database),
                    "trust-report",
                    "--fail-on-breach",
                ]
            )
        self.assertEqual(exit_code, 2)

    def test_empty_report_is_not_reported_as_passing(self) -> None:
        store = DataStore(self.database)
        try:
            report = store.trust_report()
        finally:
            store.close()
        self.assertEqual(report["overall_status"], "no_data")

    def test_v1_database_is_migrated_without_losing_rows(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            CREATE TABLE ingestion_runs (
                run_id TEXT PRIMARY KEY,
                source_uri TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                contract_version TEXT NOT NULL,
                contract_fingerprint TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                total_rows INTEGER NOT NULL DEFAULT 0,
                accepted_rows INTEGER NOT NULL DEFAULT 0,
                quarantined_rows INTEGER NOT NULL DEFAULT 0,
                duplicate_rows INTEGER NOT NULL DEFAULT 0,
                error_message TEXT
            );
            CREATE TABLE accepted_payment_events (
                event_id TEXT PRIMARY KEY,
                subject_token TEXT NOT NULL,
                amount_minor INTEGER NOT NULL,
                currency TEXT NOT NULL,
                event_time TEXT NOT NULL,
                country TEXT NOT NULL,
                lawful_basis TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                source_row_number INTEGER NOT NULL
            );
            INSERT INTO ingestion_runs (
                run_id, source_uri, source_sha256, contract_version,
                contract_fingerprint, started_at, status
            ) VALUES ('legacy-run', 'legacy.csv', 'sha', '1.0.0', 'fp', 'now', 'succeeded');
            INSERT INTO accepted_payment_events VALUES (
                'legacy-event', 'token', 100, 'EUR', 'now', 'ES',
                'contract', 'legacy-run', 2
            );
            """
        )
        connection.commit()
        connection.close()

        store = DataStore(self.database)
        try:
            row = store.connection.execute(
                "SELECT source_system FROM accepted_payment_events "
                "WHERE event_id = 'legacy-event'"
            ).fetchone()
            status = store.schema_status()
        finally:
            store.close()
        self.assertEqual(row["source_system"], "legacy")
        self.assertEqual(status["schema_version"], "2.0.0")


if __name__ == "__main__":
    unittest.main()

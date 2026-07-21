from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from regulated_data_ops.pipeline import IngestionPipeline

HEADERS = (
    "event_id",
    "customer_email",
    "amount",
    "currency",
    "event_time",
    "country",
    "lawful_basis",
)
KEY = "test-key-with-at-least-16-characters"


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = self.root / "data.db"
        self.pipeline = IngestionPipeline(self.database, KEY)

    def tearDown(self) -> None:
        self.pipeline.close()
        self.tempdir.cleanup()

    def _csv(self, rows: list[dict[str, str]], headers=HEADERS) -> Path:
        index = len(list(self.root.glob("input-*")))
        path = self.root / f"input-{index}.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _valid_row(self) -> dict[str, str]:
        return {
            "event_id": "9f4ec919-2ff5-4cd1-9017-8ff0a99daf2d",
            "customer_email": "synthetic.person@example.test",
            "amount": "125.40",
            "currency": "EUR",
            "event_time": "2026-07-20T10:15:00+00:00",
            "country": "ES",
            "lawful_basis": "contract",
        }

    def test_ingests_valid_event_and_exposes_lineage(self) -> None:
        row = self._valid_row()
        report = self.pipeline.ingest(self._csv([row]))
        lineage = self.pipeline.lineage(row["event_id"])

        self.assertEqual(report.accepted_rows, 1)
        self.assertEqual(report.quarantined_rows, 0)
        self.assertEqual(lineage["source_sha256"], report.source_sha256)
        self.assertEqual(lineage["source_row_number"], 2)
        self.assertEqual(lineage["amount_minor"], 12540)

    def test_never_persists_plain_email(self) -> None:
        row = self._valid_row()
        self.pipeline.ingest(self._csv([row]))
        self.pipeline.close()
        self.assertNotIn(row["customer_email"].encode(), self.database.read_bytes())
        self.pipeline = IngestionPipeline(self.database, KEY)

    def test_quarantines_invalid_amount_without_plain_pii(self) -> None:
        row = self._valid_row() | {"amount": "-1.00"}
        report = self.pipeline.ingest(self._csv([row]))
        quarantine = self.pipeline.store.connection.execute(
            "SELECT * FROM quarantine_events"
        ).fetchone()

        self.assertEqual(report.quarantined_rows, 1)
        self.assertEqual(quarantine["primary_reason"], "invalid_amount")
        self.assertNotIn("customer_email", quarantine.keys())
        self.assertNotIn(row["customer_email"], tuple(quarantine))

    def test_reingestion_is_idempotent(self) -> None:
        source = self._csv([self._valid_row()])
        first = self.pipeline.ingest(source)
        second = self.pipeline.ingest(source)
        count = self.pipeline.store.connection.execute(
            "SELECT COUNT(*) FROM accepted_payment_events"
        ).fetchone()[0]

        self.assertEqual(first.accepted_rows, 1)
        self.assertEqual(second.accepted_rows, 0)
        self.assertEqual(second.duplicate_rows, 1)
        self.assertEqual(count, 1)

    def test_schema_drift_fails_closed_and_records_failure(self) -> None:
        headers = tuple(header for header in HEADERS if header != "lawful_basis")
        row = {key: value for key, value in self._valid_row().items() if key in headers}

        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            self.pipeline.ingest(self._csv([row], headers=headers))

        status = self.pipeline.latest_status()
        self.assertEqual(status["status"], "failed")
        self.assertIn("schema mismatch", status["error_message"])

    def test_header_order_does_not_create_false_schema_drift(self) -> None:
        headers = tuple(reversed(HEADERS))
        report = self.pipeline.ingest(self._csv([self._valid_row()], headers=headers))
        self.assertEqual(report.accepted_rows, 1)

    def test_conflicting_replay_fails_closed(self) -> None:
        original = self._valid_row()
        self.pipeline.ingest(self._csv([original]))
        conflict = original | {"amount": "999.00"}

        with self.assertRaisesRegex(ValueError, "idempotency conflict"):
            self.pipeline.ingest(self._csv([conflict]))

        stored = self.pipeline.lineage(original["event_id"])
        status = self.pipeline.latest_status()
        self.assertEqual(stored["amount_minor"], 12540)
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["accepted_rows"], 0)

    def test_transaction_rolls_back_partial_batch_on_internal_failure(self) -> None:
        valid = self._valid_row()
        second = valid | {"event_id": "1cfaa082-cfc7-467e-b06f-a9f75d42f03a"}
        source = self._csv([valid, second])
        original = self.pipeline.store.insert_payment
        calls = 0

        def fail_second(payment, run_id, row_number):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("simulated warehouse failure")
            return original(payment, run_id, row_number)

        self.pipeline.store.insert_payment = fail_second
        with self.assertRaisesRegex(RuntimeError, "simulated warehouse failure"):
            self.pipeline.ingest(source)

        count = self.pipeline.store.connection.execute(
            "SELECT COUNT(*) FROM accepted_payment_events"
        ).fetchone()[0]
        self.assertEqual(count, 0)
        self.assertEqual(self.pipeline.latest_status()["accepted_rows"], 0)

    def test_rejects_weak_hmac_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 32"):
            IngestionPipeline(self.root / "weak.db", "too-short")


if __name__ == "__main__":
    unittest.main()

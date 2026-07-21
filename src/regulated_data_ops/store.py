"""Transactional SQLite data plane and operational evidence ledger."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Mapping


class DataStore:
    def __init__(self, database: str | Path) -> None:
        self.connection = sqlite3.connect(str(database))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ingestion_runs (
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

            CREATE TABLE IF NOT EXISTS accepted_payment_events (
                event_id TEXT PRIMARY KEY,
                subject_token TEXT NOT NULL,
                amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
                currency TEXT NOT NULL,
                event_time TEXT NOT NULL,
                country TEXT NOT NULL,
                lawful_basis TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                source_row_number INTEGER NOT NULL,
                FOREIGN KEY(source_run_id) REFERENCES ingestion_runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS quarantine_events (
                quarantine_id TEXT PRIMARY KEY,
                event_ref TEXT,
                subject_token TEXT,
                primary_reason TEXT NOT NULL,
                all_reasons_json TEXT NOT NULL,
                row_fingerprint TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                source_row_number INTEGER NOT NULL,
                FOREIGN KEY(source_run_id) REFERENCES ingestion_runs(run_id)
            );

            CREATE INDEX IF NOT EXISTS idx_quarantine_run
            ON quarantine_events(source_run_id, primary_reason);
            """
        )
        self.connection.commit()

    def start_run(self, values: Mapping[str, object]) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ingestion_runs (
                    run_id, source_uri, source_sha256, contract_version,
                    contract_fingerprint, started_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, 'running')
                """,
                (
                    values["run_id"],
                    values["source_uri"],
                    values["source_sha256"],
                    values["contract_version"],
                    values["contract_fingerprint"],
                    values["started_at"],
                ),
            )

    def insert_payment(
        self, payment: Mapping[str, object], run_id: str, row_number: int
    ) -> str:
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO accepted_payment_events (
                event_id, subject_token, amount_minor, currency, event_time,
                country, lawful_basis, source_run_id, source_row_number
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payment["event_id"],
                payment["subject_token"],
                payment["amount_minor"],
                payment["currency"],
                payment["event_time"],
                payment["country"],
                payment["lawful_basis"],
                run_id,
                row_number,
            ),
        )
        if cursor.rowcount == 1:
            return "inserted"

        existing = self.connection.execute(
            """
            SELECT subject_token, amount_minor, currency, event_time, country,
                   lawful_basis
            FROM accepted_payment_events
            WHERE event_id = ?
            """,
            (payment["event_id"],),
        ).fetchone()
        candidate = (
            payment["subject_token"],
            payment["amount_minor"],
            payment["currency"],
            payment["event_time"],
            payment["country"],
            payment["lawful_basis"],
        )
        if existing is not None and tuple(existing) == candidate:
            return "duplicate"
        raise ValueError(
            f"idempotency conflict: event_id {payment['event_id']} has different content"
        )

    def quarantine(
        self,
        *,
        quarantine_id: str,
        event_ref: str | None,
        subject_token: str | None,
        reasons: tuple[str, ...],
        fingerprint: str,
        run_id: str,
        row_number: int,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO quarantine_events (
                quarantine_id, event_ref, subject_token, primary_reason,
                all_reasons_json, row_fingerprint, source_run_id, source_row_number
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quarantine_id,
                event_ref,
                subject_token,
                reasons[0],
                json.dumps(reasons),
                fingerprint,
                run_id,
                row_number,
            ),
        )

    def finish_run(self, run_id: str, report: Mapping[str, object]) -> None:
        with self.connection:
            self.connection.execute(
                """
                UPDATE ingestion_runs
                SET finished_at = ?, status = ?, total_rows = ?,
                    accepted_rows = ?, quarantined_rows = ?, duplicate_rows = ?,
                    error_message = ?
                WHERE run_id = ?
                """,
                (
                    report["finished_at"],
                    report["status"],
                    report["total_rows"],
                    report["accepted_rows"],
                    report["quarantined_rows"],
                    report["duplicate_rows"],
                    report.get("error_message"),
                    run_id,
                ),
            )

    def latest_run(self) -> dict[str, object] | None:
        row = self.connection.execute(
            "SELECT * FROM ingestion_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def lineage(self, event_id: str) -> dict[str, object] | None:
        row = self.connection.execute(
            """
            SELECT e.*, r.source_uri, r.source_sha256, r.contract_version,
                   r.contract_fingerprint, r.started_at AS ingested_at
            FROM accepted_payment_events e
            JOIN ingestion_runs r ON r.run_id = e.source_run_id
            WHERE e.event_id = ?
            """,
            (event_id,),
        ).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self.connection.close()

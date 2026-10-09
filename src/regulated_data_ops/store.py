"""Transactional SQLite data plane and operational evidence ledger."""

from __future__ import annotations

import json
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from regulated_data_ops.crypto import FieldCipher


class DataStore:
    def __init__(
        self, database: str | Path, field_cipher: FieldCipher | None = None
    ) -> None:
        self.field_cipher = field_cipher
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
                policy_version TEXT NOT NULL DEFAULT '1.0.0',
                policy_fingerprint TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                total_rows INTEGER NOT NULL DEFAULT 0,
                accepted_rows INTEGER NOT NULL DEFAULT 0,
                quarantined_rows INTEGER NOT NULL DEFAULT 0,
                duplicate_rows INTEGER NOT NULL DEFAULT 0,
                schema_mode TEXT NOT NULL DEFAULT 'v1-strict',
                duration_ms INTEGER NOT NULL DEFAULT 0,
                valid_rate REAL NOT NULL DEFAULT 0,
                quarantine_rate REAL NOT NULL DEFAULT 0,
                trust_status TEXT NOT NULL DEFAULT 'not_evaluated',
                slo_breaches_json TEXT NOT NULL DEFAULT '[]',
                error_message TEXT,
                source_name TEXT NOT NULL DEFAULT '',
                source_uri_ciphertext TEXT,
                error_message_ciphertext TEXT
            );

            CREATE TABLE IF NOT EXISTS accepted_payment_events (
                event_id TEXT PRIMARY KEY,
                subject_token TEXT NOT NULL,
                amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
                currency TEXT NOT NULL,
                event_time TEXT NOT NULL,
                country TEXT NOT NULL,
                lawful_basis TEXT NOT NULL,
                source_system TEXT NOT NULL DEFAULT 'legacy',
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
                created_at TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(source_run_id) REFERENCES ingestion_runs(run_id)
            );

            CREATE INDEX IF NOT EXISTS idx_quarantine_run
            ON quarantine_events(source_run_id, primary_reason);

            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id TEXT NOT NULL UNIQUE,
                occurred_at TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                outcome TEXT NOT NULL,
                request_id TEXT NOT NULL,
                detail_ciphertext TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );

            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END;
            """
        )
        self._migrate_legacy_database()
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            ("2.0.0", datetime.now(timezone.utc).isoformat()),
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            ("4.0.0", datetime.now(timezone.utc).isoformat()),
        )
        self.connection.commit()

    def _migrate_legacy_database(self) -> None:
        run_columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(ingestion_runs)")
        }
        additions = {
            "policy_version": "TEXT NOT NULL DEFAULT '1.0.0'",
            "policy_fingerprint": "TEXT NOT NULL DEFAULT ''",
            "schema_mode": "TEXT NOT NULL DEFAULT 'v1-strict'",
            "duration_ms": "INTEGER NOT NULL DEFAULT 0",
            "valid_rate": "REAL NOT NULL DEFAULT 0",
            "quarantine_rate": "REAL NOT NULL DEFAULT 0",
            "trust_status": "TEXT NOT NULL DEFAULT 'not_evaluated'",
            "slo_breaches_json": "TEXT NOT NULL DEFAULT '[]'",
            "source_name": "TEXT NOT NULL DEFAULT ''",
            "source_uri_ciphertext": "TEXT",
            "error_message_ciphertext": "TEXT",
        }
        for name, definition in additions.items():
            if name not in run_columns:
                self.connection.execute(
                    f"ALTER TABLE ingestion_runs ADD COLUMN {name} {definition}"
                )
        payment_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(accepted_payment_events)"
            )
        }
        if "source_system" not in payment_columns:
            self.connection.execute(
                "ALTER TABLE accepted_payment_events "
                "ADD COLUMN source_system TEXT NOT NULL DEFAULT 'legacy'"
            )
        quarantine_columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(quarantine_events)")
        }
        if "created_at" not in quarantine_columns:
            self.connection.execute(
                "ALTER TABLE quarantine_events "
                "ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
            )
        self.connection.execute(
            """
            UPDATE quarantine_events
            SET created_at = COALESCE(
                (SELECT started_at FROM ingestion_runs
                 WHERE run_id = quarantine_events.source_run_id),
                ''
            )
            WHERE created_at = ''
            """
        )

    def start_run(self, values: Mapping[str, object]) -> None:
        source_uri = str(values["source_uri"])
        source_name = Path(source_uri).name
        source_uri_ciphertext: str | None = None
        stored_source_uri = source_uri
        if self.field_cipher is not None:
            source_uri_ciphertext = self.field_cipher.encrypt(
                source_uri,
                associated_data=f"run:{values['run_id']}:source_uri",
            )
            stored_source_uri = "<encrypted>"
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ingestion_runs (
                    run_id, source_uri, source_sha256, contract_version,
                    contract_fingerprint, policy_version, policy_fingerprint,
                    started_at, status, source_name, source_uri_ciphertext
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    values["run_id"],
                    stored_source_uri,
                    values["source_sha256"],
                    values["contract_version"],
                    values["contract_fingerprint"],
                    values["policy_version"],
                    values["policy_fingerprint"],
                    values["started_at"],
                    source_name,
                    source_uri_ciphertext,
                ),
            )

    def insert_payment(
        self, payment: Mapping[str, object], run_id: str, row_number: int
    ) -> str:
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO accepted_payment_events (
                event_id, subject_token, amount_minor, currency, event_time,
                country, lawful_basis, source_system, source_run_id,
                source_row_number
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payment["event_id"],
                payment["subject_token"],
                payment["amount_minor"],
                payment["currency"],
                payment["event_time"],
                payment["country"],
                payment["lawful_basis"],
                payment["source_system"],
                run_id,
                row_number,
            ),
        )
        if cursor.rowcount == 1:
            return "inserted"

        existing = self.connection.execute(
            """
            SELECT subject_token, amount_minor, currency, event_time, country,
                   lawful_basis, source_system
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
            payment["source_system"],
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
                all_reasons_json, row_fingerprint, source_run_id, source_row_number,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def finish_run(self, run_id: str, report: Mapping[str, object]) -> None:
        error_message = report.get("error_message")
        error_ciphertext: str | None = None
        stored_error = error_message
        if self.field_cipher is not None and isinstance(error_message, str):
            error_ciphertext = self.field_cipher.encrypt(
                error_message,
                associated_data=f"run:{run_id}:error_message",
            )
            stored_error = "<encrypted>"
        with self.connection:
            self.connection.execute(
                """
                UPDATE ingestion_runs
                SET finished_at = ?, status = ?, total_rows = ?,
                    accepted_rows = ?, quarantined_rows = ?, duplicate_rows = ?,
                    schema_mode = ?, duration_ms = ?, valid_rate = ?,
                    quarantine_rate = ?, trust_status = ?, slo_breaches_json = ?,
                    error_message = ?, error_message_ciphertext = ?
                WHERE run_id = ?
                """,
                (
                    report["finished_at"],
                    report["status"],
                    report["total_rows"],
                    report["accepted_rows"],
                    report["quarantined_rows"],
                    report["duplicate_rows"],
                    report["schema_mode"],
                    report["duration_ms"],
                    report["valid_rate"],
                    report["quarantine_rate"],
                    report["trust_status"],
                    json.dumps(report["slo_breaches"]),
                    stored_error,
                    error_ciphertext,
                    run_id,
                ),
            )

    def latest_run(self) -> dict[str, object] | None:
        row = self.connection.execute(
            "SELECT * FROM ingestion_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return self._run_dict(row) if row else None

    def trust_report(self, limit: int = 20) -> dict[str, object]:
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        rows = self.connection.execute(
            "SELECT * FROM ingestion_runs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        runs = [self._run_dict(row) for row in rows]
        total_rows = sum(int(run["total_rows"]) for run in runs)
        valid_rows = sum(
            int(run["accepted_rows"]) + int(run["duplicate_rows"])
            for run in runs
        )
        quarantined = sum(int(run["quarantined_rows"]) for run in runs)
        breached = sum(run["trust_status"] == "breached" for run in runs)
        unassessed = sum(
            run["trust_status"] not in {"passing", "breached"} for run in runs
        )
        overall_status = (
            "no_data"
            if not runs
            else "breached"
            if breached
            else "insufficient_evidence"
            if unassessed
            else "passing"
        )
        return {
            "overall_status": overall_status,
            "window_runs": len(runs),
            "passing_runs": sum(
                run["trust_status"] == "passing" for run in runs
            ),
            "breached_runs": breached,
            "unassessed_runs": unassessed,
            "failed_runs": sum(run["status"] == "failed" for run in runs),
            "valid_rate": round(valid_rows / total_rows, 6) if total_rows else 0.0,
            "quarantine_rate": (
                round(quarantined / total_rows, 6) if total_rows else 0.0
            ),
            "runs": runs,
        }

    def schema_status(self) -> dict[str, object]:
        migrations = self.connection.execute(
            "SELECT version, applied_at FROM schema_migrations ORDER BY version"
        ).fetchall()
        return {
            "schema_version": migrations[-1]["version"] if migrations else None,
            "migrations": [dict(row) for row in migrations],
        }

    @staticmethod
    def _decode_json(value: object) -> object:
        return json.loads(str(value))

    def _run_dict(self, row: sqlite3.Row) -> dict[str, object]:
        result = dict(row)
        result["slo_breaches"] = self._decode_json(
            result.pop("slo_breaches_json")
        )
        if not result.get("source_name") and isinstance(result.get("source_uri"), str):
            result["source_name"] = Path(str(result["source_uri"])).name
        if self.field_cipher is not None:
            if result.get("source_uri_ciphertext"):
                result["source_uri"] = self.field_cipher.decrypt(
                    str(result["source_uri_ciphertext"]),
                    associated_data=f"run:{result['run_id']}:source_uri",
                )
            if result.get("error_message_ciphertext"):
                result["error_message"] = self.field_cipher.decrypt(
                    str(result["error_message_ciphertext"]),
                    associated_data=f"run:{result['run_id']}:error_message",
                )
        return result

    def lineage(self, event_id: str) -> dict[str, object] | None:
        row = self.connection.execute(
            """
            SELECT e.*, r.source_uri, r.source_name, r.source_sha256, r.contract_version,
                   r.contract_fingerprint, r.started_at AS ingested_at
            FROM accepted_payment_events e
            JOIN ingestion_runs r ON r.run_id = e.source_run_id
            WHERE e.event_id = ?
            """,
            (event_id,),
        ).fetchone()
        return dict(row) if row else None

    def append_audit(self, values: Mapping[str, object]) -> dict[str, object]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            event = self._append_audit_uncommitted(values)
            self.connection.commit()
            return event
        except Exception:
            self.connection.rollback()
            raise

    def _append_audit_uncommitted(
        self, values: Mapping[str, object]
    ) -> dict[str, object]:
        if self.field_cipher is None:
            raise ValueError("field encryption is required for audit evidence")
        audit_id = str(values["audit_id"])
        detail = json.dumps(
            values.get("detail", {}), sort_keys=True, separators=(",", ":")
        )
        detail_ciphertext = self.field_cipher.encrypt(
            detail, associated_data=f"audit:{audit_id}:detail"
        )
        previous = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous["event_hash"]) if previous else "0" * 64
        fields = {
            "audit_id": audit_id,
            "occurred_at": str(values["occurred_at"]),
            "actor_id": str(values["actor_id"]),
            "actor_role": str(values["actor_role"]),
            "action": str(values["action"]),
            "resource_type": str(values["resource_type"]),
            "resource_id": (
                str(values["resource_id"])
                if values.get("resource_id") is not None
                else None
            ),
            "outcome": str(values["outcome"]),
            "request_id": str(values["request_id"]),
            "detail_ciphertext": detail_ciphertext,
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.connection.execute(
            """
            INSERT INTO audit_events (
                audit_id, occurred_at, actor_id, actor_role, action,
                resource_type, resource_id, outcome, request_id,
                detail_ciphertext, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fields["audit_id"],
                fields["occurred_at"],
                fields["actor_id"],
                fields["actor_role"],
                fields["action"],
                fields["resource_type"],
                fields["resource_id"],
                fields["outcome"],
                fields["request_id"],
                fields["detail_ciphertext"],
                fields["previous_hash"],
                event_hash,
            ),
        )
        return fields | {"event_hash": event_hash}

    def audit_events(self, limit: int = 50) -> list[dict[str, object]]:
        if limit < 1 or limit > 200:
            raise ValueError("limit must be between 1 and 200")
        rows = self.connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,)
        ).fetchall()
        events: list[dict[str, object]] = []
        for row in rows:
            event = dict(row)
            ciphertext = str(event.pop("detail_ciphertext"))
            if self.field_cipher is not None:
                plaintext = self.field_cipher.decrypt(
                    ciphertext,
                    associated_data=f"audit:{event['audit_id']}:detail",
                )
                event["detail"] = json.loads(plaintext)
            events.append(event)
        return events

    def verify_audit_chain(self) -> dict[str, object]:
        rows = self.connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence"
        ).fetchall()
        previous_hash = "0" * 64
        for row in rows:
            fields = {
                "audit_id": row["audit_id"],
                "occurred_at": row["occurred_at"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "outcome": row["outcome"],
                "request_id": row["request_id"],
                "detail_ciphertext": row["detail_ciphertext"],
                "previous_hash": row["previous_hash"],
            }
            canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return {
                    "status": "invalid",
                    "events_checked": int(row["sequence"]) - 1,
                    "failed_sequence": row["sequence"],
                }
            previous_hash = str(row["event_hash"])
        return {
            "status": "valid",
            "events_checked": len(rows),
            "head_hash": previous_hash,
        }

    def retention_preview(
        self, *, accepted_before: str, quarantine_before: str
    ) -> dict[str, int]:
        accepted = self.connection.execute(
            "SELECT COUNT(*) FROM accepted_payment_events "
            "WHERE julianday(event_time) < julianday(?)",
            (accepted_before,),
        ).fetchone()[0]
        quarantine = self.connection.execute(
            "SELECT COUNT(*) FROM quarantine_events "
            "WHERE julianday(created_at) < julianday(?)",
            (quarantine_before,),
        ).fetchone()[0]
        return {
            "accepted_payment_events": int(accepted),
            "quarantine_events": int(quarantine),
        }

    def apply_retention(
        self,
        *,
        accepted_before: str,
        quarantine_before: str,
        audit_values: Mapping[str, object],
    ) -> dict[str, int]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            preview = self.retention_preview(
                accepted_before=accepted_before,
                quarantine_before=quarantine_before,
            )
            self.connection.execute(
                "DELETE FROM accepted_payment_events "
                "WHERE julianday(event_time) < julianday(?)",
                (accepted_before,),
            )
            self.connection.execute(
                "DELETE FROM quarantine_events "
                "WHERE julianday(created_at) < julianday(?)",
                (quarantine_before,),
            )
            values = dict(audit_values)
            values["detail"] = dict(values.get("detail", {})) | {
                "deleted": preview,
                "accepted_before": accepted_before,
                "quarantine_before": quarantine_before,
            }
            self._append_audit_uncommitted(values)
            self.connection.commit()
            return preview
        except Exception:
            self.connection.rollback()
            raise

    def close(self) -> None:
        self.connection.close()

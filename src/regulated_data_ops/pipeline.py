"""Contract-driven CSV ingestion with idempotency, quarantine and lineage."""

from __future__ import annotations

import csv
import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from regulated_data_ops.contract import DataContract, PAYMENT_CONTRACT
from regulated_data_ops.store import DataStore
from regulated_data_ops.validation import (
    normalized_payment,
    row_fingerprint,
    subject_token,
    validate_row,
)


@dataclass(frozen=True, slots=True)
class RunReport:
    run_id: str
    status: str
    total_rows: int
    accepted_rows: int
    quarantined_rows: int
    duplicate_rows: int
    source_sha256: str
    contract_fingerprint: str
    error_message: str | None = None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class IngestionPipeline:
    def __init__(
        self,
        database: str | Path,
        hmac_key: str,
        contract: DataContract = PAYMENT_CONTRACT,
    ) -> None:
        if len(hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 characters")
        self.key = hmac_key.encode("utf-8")
        self.contract = contract
        self.store = DataStore(database)

    def ingest(self, source: str | Path) -> RunReport:
        source_path = Path(source)
        source_sha = hashlib.sha256(source_path.read_bytes()).hexdigest()
        run_id = str(uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        self.store.start_run(
            {
                "run_id": run_id,
                "source_uri": str(source_path.resolve()),
                "source_sha256": source_sha,
                "contract_version": self.contract.version,
                "contract_fingerprint": self.contract.fingerprint,
                "started_at": started_at,
            }
        )

        counters = {"total": 0, "accepted": 0, "quarantined": 0, "duplicate": 0}
        try:
            with source_path.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                actual = tuple(reader.fieldnames or ())
                expected = self.contract.required_headers
                missing = tuple(name for name in expected if name not in actual)
                unexpected = tuple(name for name in actual if name not in expected)
                if missing or unexpected:
                    raise ValueError(
                        f"schema mismatch: missing={missing!r}, unexpected={unexpected!r}"
                    )

                with self.store.connection:
                    for row_number, row in enumerate(reader, start=2):
                        counters["total"] += 1
                        failures = validate_row(self.contract, row)
                        if failures:
                            email = row.get("customer_email", "")
                            self.store.quarantine(
                                quarantine_id=str(uuid4()),
                                event_ref=_valid_uuid_or_none(row.get("event_id", "")),
                                subject_token=(
                                    subject_token(email, self.key) if "@" in email else None
                                ),
                                reasons=failures,
                                fingerprint=row_fingerprint(row, self.key),
                                run_id=run_id,
                                row_number=row_number,
                            )
                            counters["quarantined"] += 1
                            continue

                        outcome = self.store.insert_payment(
                            normalized_payment(row, self.key), run_id, row_number
                        )
                        counters["accepted" if outcome == "inserted" else "duplicate"] += 1

            return self._finish(run_id, source_sha, counters, "succeeded")
        except Exception as exc:
            rolled_back = counters | {
                "accepted": 0,
                "quarantined": 0,
                "duplicate": 0,
            }
            self._finish(
                run_id,
                source_sha,
                rolled_back,
                "failed",
                error_message=str(exc),
            )
            raise

    def _finish(
        self,
        run_id: str,
        source_sha: str,
        counters: dict[str, int],
        status: str,
        error_message: str | None = None,
    ) -> RunReport:
        report = RunReport(
            run_id=run_id,
            status=status,
            total_rows=counters["total"],
            accepted_rows=counters["accepted"],
            quarantined_rows=counters["quarantined"],
            duplicate_rows=counters["duplicate"],
            source_sha256=source_sha,
            contract_fingerprint=self.contract.fingerprint,
            error_message=error_message,
        )
        payload = report.as_dict() | {
            "finished_at": datetime.now(timezone.utc).isoformat()
        }
        self.store.finish_run(run_id, payload)
        return report

    def latest_status(self) -> dict[str, object] | None:
        return self.store.latest_run()

    def lineage(self, event_id: str) -> dict[str, object] | None:
        return self.store.lineage(event_id)

    def close(self) -> None:
        self.store.close()


def _valid_uuid_or_none(value: str) -> str | None:
    try:
        return str(UUID(value.strip()))
    except (ValueError, AttributeError):
        return None

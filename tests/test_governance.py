from __future__ import annotations

import base64
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from regulated_data_ops.crypto import FieldCipher
from regulated_data_ops.governance import GovernancePolicy
from regulated_data_ops.store import DataStore

ENCRYPTION_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii")


class FieldCipherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cipher = FieldCipher.from_base64(ENCRYPTION_KEY)

    def test_aes_gcm_round_trip_uses_versioned_envelope(self) -> None:
        encrypted = self.cipher.encrypt("regulated", associated_data="record:1")
        self.assertTrue(encrypted.startswith("aesgcm:v1:"))
        self.assertEqual(
            self.cipher.decrypt(encrypted, associated_data="record:1"), "regulated"
        )

    def test_nonce_is_not_reused_for_equal_plaintext(self) -> None:
        first = self.cipher.encrypt("same", associated_data="record:1")
        second = self.cipher.encrypt("same", associated_data="record:1")
        self.assertNotEqual(first, second)

    def test_wrong_associated_data_fails_authentication(self) -> None:
        encrypted = self.cipher.encrypt("secret", associated_data="record:1")
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            self.cipher.decrypt(encrypted, associated_data="record:2")

    def test_key_must_decode_to_256_bits(self) -> None:
        weak = base64.urlsafe_b64encode(b"short").decode("ascii")
        with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
            FieldCipher.from_base64(weak)


class GovernancePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        project = Path(__file__).resolve().parents[1]
        self.policy = GovernancePolicy.load(project / "config/governance-policy.json")

    def test_committed_policy_authenticates_individual_actor(self) -> None:
        principal = self.policy.authenticate(
            "demo-operator-key-000000000000000001"
        )
        self.assertIsNotNone(principal)
        self.assertEqual(principal.actor_id, "demo-operator")
        self.assertEqual(principal.role, "operator")
        self.assertTrue(self.policy.permits(principal, "ingestion:create"))
        self.assertFalse(self.policy.permits(principal, "audit:read"))

    def test_unknown_key_is_rejected(self) -> None:
        self.assertIsNone(self.policy.authenticate("x" * 36))

    def test_public_policy_never_exposes_key_hashes(self) -> None:
        public = json.dumps(self.policy.public_dict())
        self.assertNotIn("key_sha256", public)
        self.assertIn("demo-auditor", public)

    def test_fingerprint_covers_key_rotation_and_retention(self) -> None:
        payload = self.policy.as_dict()
        original = self.policy.fingerprint
        payload["retention"]["quarantine_days"] += 1
        changed = GovernancePolicy.from_mapping(payload)
        self.assertNotEqual(original, changed.fingerprint)

    def test_unknown_permission_fails_closed(self) -> None:
        payload = self.policy.as_dict()
        payload["roles"]["viewer"].append("database:drop")
        with self.assertRaisesRegex(ValueError, "unknown permissions"):
            GovernancePolicy.from_mapping(payload)

    def test_duplicate_principal_key_fails_closed(self) -> None:
        payload = self.policy.as_dict()
        payload["principals"][1]["key_sha256"] = payload["principals"][0][
            "key_sha256"
        ]
        with self.assertRaisesRegex(ValueError, "key_sha256 values must be unique"):
            GovernancePolicy.from_mapping(payload)

    def test_disabled_principal_cannot_authenticate(self) -> None:
        payload = self.policy.as_dict()
        payload["principals"][0]["enabled"] = False
        disabled = GovernancePolicy.from_mapping(payload)
        self.assertIsNone(
            disabled.authenticate("demo-viewer-key-00000000000000000001")
        )


class AuditAndRetentionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Path(self.tempdir.name) / "governance.db"
        self.cipher = FieldCipher.from_base64(ENCRYPTION_KEY)
        self.store = DataStore(self.database, field_cipher=self.cipher)

    def tearDown(self) -> None:
        self.store.close()
        self.tempdir.cleanup()

    def _audit(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "audit_id": str(uuid4()),
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "actor_id": "actor-1",
            "actor_role": "admin",
            "action": "test:write",
            "resource_type": "test",
            "resource_id": "resource-1",
            "outcome": "succeeded",
            "request_id": uuid4().hex,
            "detail": {"private": "encrypted evidence"},
        }
        payload.update(overrides)
        return payload

    def test_audit_details_are_encrypted_and_chain_verifies(self) -> None:
        self.store.append_audit(self._audit())
        self.store.append_audit(self._audit(actor_id="actor-2"))
        self.store.close()
        self.assertNotIn(b"encrypted evidence", self.database.read_bytes())
        self.store = DataStore(self.database, field_cipher=self.cipher)
        self.assertEqual(self.store.verify_audit_chain()["status"], "valid")
        events = self.store.audit_events()
        self.assertEqual(events[0]["detail"]["private"], "encrypted evidence")

    def test_audit_rows_are_append_only(self) -> None:
        event = self.store.append_audit(self._audit())
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.store.connection.execute(
                "UPDATE audit_events SET outcome = 'altered' WHERE audit_id = ?",
                (event["audit_id"],),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.store.connection.execute(
                "DELETE FROM audit_events WHERE audit_id = ?", (event["audit_id"],)
            )

    def test_retention_and_its_audit_commit_atomically(self) -> None:
        self.store.connection.execute(
            """
            INSERT INTO ingestion_runs (
                run_id, source_uri, source_sha256, contract_version,
                contract_fingerprint, started_at, status
            ) VALUES ('run-old', 'old.csv', 'sha', '1', 'fingerprint',
                      '2000-01-01T00:00:00+00:00', 'succeeded')
            """
        )
        self.store.connection.execute(
            """
            INSERT INTO accepted_payment_events (
                event_id, subject_token, amount_minor, currency, event_time,
                country, lawful_basis, source_run_id, source_row_number
            ) VALUES ('event-old', 'token', 1, 'EUR',
                      '2000-01-01T00:00:00+00:00', 'ES', 'contract', 'run-old', 2)
            """
        )
        self.store.connection.commit()
        deleted = self.store.apply_retention(
            accepted_before="2020-01-01T00:00:00+00:00",
            quarantine_before="2020-01-01T00:00:00+00:00",
            audit_values=self._audit(action="retention:execute"),
        )
        self.assertEqual(deleted["accepted_payment_events"], 1)
        self.assertEqual(
            self.store.connection.execute(
                "SELECT COUNT(*) FROM accepted_payment_events"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(self.store.verify_audit_chain()["events_checked"], 1)


if __name__ == "__main__":
    unittest.main()

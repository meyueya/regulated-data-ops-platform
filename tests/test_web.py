from __future__ import annotations

import base64
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from regulated_data_ops.cli import main
from regulated_data_ops.crypto import FieldCipher
from regulated_data_ops.governance import GovernancePolicy
from regulated_data_ops.store import DataStore
from regulated_data_ops.web import API_KEY_HEADER, AppConfig, create_app

VIEWER_KEY = "demo-viewer-key-00000000000000000001"
OPERATOR_KEY = "demo-operator-key-000000000000000001"
AUDITOR_KEY = "demo-auditor-key-0000000000000000001"
ADMIN_KEY = "demo-admin-key-000000000000000000001"
HMAC_KEY = "test-hmac-key-with-at-least-32-characters"
ENCRYPTION_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii")
EVENT_ID = "68518f42-f422-4f98-a83a-f4d779c8a9fb"


class WebGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.project = Path(__file__).resolve().parents[1]
        self.sources = self.root / "sources"
        self.sources.mkdir()
        shutil.copy2(
            self.project / "examples" / "payments-clean-v2.csv",
            self.sources / "clean.csv",
        )
        shutil.copy2(
            self.project / "examples" / "payments.csv",
            self.sources / "mixed.csv",
        )
        (self.sources / "ignore.txt").write_text("not a source", encoding="utf-8")
        nested = self.sources / "nested"
        nested.mkdir()
        shutil.copy2(self.sources / "clean.csv", nested / "hidden.csv")
        self.database = self.root / "operations.db"
        config = AppConfig(
            database=self.database,
            ingestion_root=self.sources,
            policy_path=self.project / "config" / "trust-policy.json",
            governance_path=self.project / "config" / "governance-policy.json",
            hmac_key=HMAC_KEY,
            encryption_key=ENCRYPTION_KEY,
        )
        self.client = TestClient(create_app(config))
        self.viewer = {API_KEY_HEADER: VIEWER_KEY}
        self.operator = {API_KEY_HEADER: OPERATOR_KEY}
        self.auditor = {API_KEY_HEADER: AUDITOR_KEY}
        self.admin = {API_KEY_HEADER: ADMIN_KEY}

    def tearDown(self) -> None:
        self.client.close()
        self.tempdir.cleanup()

    def test_health_is_public_and_hardened(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "version": "4.0.0"})
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(len(response.headers["x-request-id"]), 32)

    def test_personal_key_resolves_actor_role_and_permissions(self) -> None:
        response = self.client.get("/api/v1/me", headers=self.operator)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["actor_id"], "demo-operator")
        self.assertEqual(response.json()["role"], "operator")
        self.assertIn("ingestion:create", response.json()["permissions"])
        self.assertNotIn("audit:read", response.json()["permissions"])

    def test_missing_or_wrong_key_is_rejected_and_audited(self) -> None:
        missing = self.client.get("/api/v1/status")
        wrong = self.client.get(
            "/api/v1/status", headers={API_KEY_HEADER: "x" * 36}
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        events = self.client.get("/api/v1/audit-events", headers=self.auditor).json()[
            "events"
        ]
        denied = [event for event in events if event["action"] == "authentication"]
        self.assertGreaterEqual(len(denied), 2)
        self.assertTrue(all(event["actor_id"] == "anonymous" for event in denied))

    def test_viewer_can_read_health_evidence_but_cannot_ingest(self) -> None:
        self.assertEqual(
            self.client.get("/api/v1/status", headers=self.viewer).status_code, 200
        )
        self.assertEqual(
            self.client.get("/api/v1/trust-report", headers=self.viewer).status_code,
            200,
        )
        denied = self.client.post(
            "/api/v1/ingestions", headers=self.viewer, json={"source": "clean.csv"}
        )
        self.assertEqual(denied.status_code, 403)
        self.assertIn("lacks permission", denied.json()["detail"])

    def test_operator_can_ingest_but_cannot_read_governance(self) -> None:
        created = self.client.post(
            "/api/v1/ingestions", headers=self.operator, json={"source": "clean.csv"}
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["trust_status"], "passing")
        self.assertEqual(
            self.client.get("/api/v1/governance", headers=self.operator).status_code,
            403,
        )

    def test_auditor_sees_governance_without_key_hashes(self) -> None:
        response = self.client.get("/api/v1/governance", headers=self.auditor)
        self.assertEqual(response.status_code, 200)
        body = json.dumps(response.json())
        self.assertNotIn("key_sha256", body)
        self.assertIn("demo-operator", body)
        self.assertEqual(len(response.json()["fingerprint"]), 64)

    def test_audit_chain_records_actor_and_verifies(self) -> None:
        self.client.get("/api/v1/status", headers=self.viewer)
        self.client.post(
            "/api/v1/ingestions", headers=self.operator, json={"source": "clean.csv"}
        )
        integrity = self.client.get(
            "/api/v1/audit-integrity", headers=self.auditor
        ).json()
        self.assertEqual(integrity["status"], "valid")
        self.assertGreaterEqual(integrity["events_checked"], 4)
        events = self.client.get("/api/v1/audit-events", headers=self.auditor).json()[
            "events"
        ]
        self.assertIn("demo-operator", {event["actor_id"] for event in events})

    def test_audit_table_rejects_update_and_delete(self) -> None:
        self.client.get("/api/v1/status", headers=self.viewer)
        connection = sqlite3.connect(self.database)
        try:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute("UPDATE audit_events SET outcome = 'altered'")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute("DELETE FROM audit_events")
        finally:
            connection.close()

    def test_v4_ingestion_encrypts_internal_path_at_rest(self) -> None:
        self.client.post(
            "/api/v1/ingestions", headers=self.operator, json={"source": "clean.csv"}
        )
        raw = self.database.read_bytes()
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertIn(b"aesgcm:v1", raw)
        status = self.client.get("/api/v1/status", headers=self.viewer).json()
        self.assertEqual(status["schema_version"], "4.0.0")
        self.assertEqual(status["latest_run"]["source_name"], "clean.csv")

    def test_sources_remain_flat_and_traversal_is_rejected(self) -> None:
        sources = self.client.get("/api/v1/sources", headers=self.operator).json()
        self.assertEqual(
            [item["name"] for item in sources["sources"]], ["clean.csv", "mixed.csv"]
        )
        traversal = self.client.post(
            "/api/v1/ingestions",
            headers=self.operator,
            json={"source": "../clean.csv"},
        )
        self.assertEqual(traversal.status_code, 400)

    def test_ingestion_rejects_unknown_request_fields(self) -> None:
        response = self.client.post(
            "/api/v1/ingestions",
            headers=self.operator,
            json={"source": "clean.csv", "path": "/tmp/override.csv"},
        )
        self.assertEqual(response.status_code, 422)

    def test_lineage_is_minimized_and_role_protected(self) -> None:
        self.client.post(
            "/api/v1/ingestions", headers=self.operator, json={"source": "clean.csv"}
        )
        response = self.client.get(
            f"/api/v1/lineage/{EVENT_ID}", headers=self.operator
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["source_name"], "clean.csv")
        self.assertNotIn("subject_token", response.json())
        self.assertNotIn("source_uri", response.json())
        self.assertEqual(
            self.client.get(
                f"/api/v1/lineage/{EVENT_ID}", headers=self.viewer
            ).status_code,
            403,
        )

    def test_quality_breach_remains_operational_evidence(self) -> None:
        response = self.client.post(
            "/api/v1/ingestions", headers=self.operator, json={"source": "mixed.csv"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["trust_status"], "breached")

    def test_retention_requires_admin_and_exact_policy_confirmation(self) -> None:
        policy = GovernancePolicy.load(
            self.project / "config" / "governance-policy.json"
        )
        denied = self.client.post(
            "/api/v1/retention-executions",
            headers=self.operator,
            json={"confirm_policy_fingerprint": policy.fingerprint},
        )
        mismatch = self.client.post(
            "/api/v1/retention-executions",
            headers=self.admin,
            json={"confirm_policy_fingerprint": "0" * 64},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(mismatch.status_code, 409)

    def test_retention_preview_and_execution_delete_only_expired_data(self) -> None:
        cipher = FieldCipher.from_base64(ENCRYPTION_KEY)
        store = DataStore(self.database, field_cipher=cipher)
        try:
            store.connection.execute(
                """
                INSERT INTO ingestion_runs (
                    run_id, source_uri, source_sha256, contract_version,
                    contract_fingerprint, started_at, status
                ) VALUES ('old-run', '<fixture>', 'sha', '1', 'fingerprint',
                          '2000-01-01T00:00:00+00:00', 'succeeded')
                """
            )
            store.connection.execute(
                """
                INSERT INTO accepted_payment_events (
                    event_id, subject_token, amount_minor, currency, event_time,
                    country, lawful_basis, source_run_id, source_row_number
                ) VALUES ('old-event', 'token', 1, 'EUR',
                          '2000-01-01T00:00:00+00:00', 'ES', 'contract', 'old-run', 2)
                """
            )
            store.connection.commit()
        finally:
            store.close()
        preview = self.client.get(
            "/api/v1/retention-preview", headers=self.auditor
        ).json()
        self.assertEqual(preview["candidates"]["accepted_payment_events"], 1)
        applied = self.client.post(
            "/api/v1/retention-executions",
            headers=self.admin,
            json={"confirm_policy_fingerprint": preview["policy_fingerprint"]},
        )
        self.assertEqual(applied.status_code, 200)
        self.assertEqual(applied.json()["deleted"]["accepted_payment_events"], 1)

    def test_dashboard_has_no_external_runtime_or_persistent_key_storage(self) -> None:
        page = self.client.get("/")
        script = self.client.get("/assets/dashboard.js")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("http://", page.text)
        self.assertNotIn("https://", page.text)
        self.assertIn("sessionStorage", script.text)
        self.assertNotIn("localStorage", script.text)
        self.assertNotIn("innerHTML", script.text)

    def test_openapi_docs_are_disabled_and_limits_are_bounded(self) -> None:
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)
        self.assertEqual(
            self.client.get(
                "/api/v1/trust-report?limit=101", headers=self.viewer
            ).status_code,
            422,
        )


class WebConfigurationTests(unittest.TestCase):
    def test_invalid_encryption_key_is_rejected_before_startup(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
            AppConfig(
                database=Path("unused.db"),
                ingestion_root=project / "examples",
                policy_path=project / "config" / "trust-policy.json",
                governance_path=project / "config" / "governance-policy.json",
                hmac_key=HMAC_KEY,
                encryption_key=base64.urlsafe_b64encode(b"weak").decode("ascii"),
            )

    def test_cli_requires_explicit_consent_for_network_binding(self) -> None:
        with self.assertRaisesRegex(SystemExit, "--allow-network"):
            main(["serve", "--host", "0.0.0.0"])


if __name__ == "__main__":
    unittest.main()

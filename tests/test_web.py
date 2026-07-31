from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from regulated_data_ops.cli import main
from regulated_data_ops.web import API_KEY_HEADER, AppConfig, create_app

API_KEY = "test-api-key-with-at-least-32-characters"
HMAC_KEY = "test-hmac-key-with-at-least-32-characters"
EVENT_ID = "68518f42-f422-4f98-a83a-f4d779c8a9fb"


class WebOperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        project = Path(__file__).resolve().parents[1]
        self.sources = self.root / "sources"
        self.sources.mkdir()
        shutil.copy2(
            project / "examples" / "payments-clean-v2.csv",
            self.sources / "clean.csv",
        )
        shutil.copy2(
            project / "examples" / "payments.csv",
            self.sources / "mixed.csv",
        )
        (self.sources / "ignore.txt").write_text("not a source", encoding="utf-8")
        nested = self.sources / "nested"
        nested.mkdir()
        shutil.copy2(self.sources / "clean.csv", nested / "hidden.csv")
        config = AppConfig(
            database=self.root / "operations.db",
            ingestion_root=self.sources,
            policy_path=project / "config" / "trust-policy.json",
            api_key=API_KEY,
            hmac_key=HMAC_KEY,
        )
        self.client = TestClient(create_app(config))
        self.headers = {API_KEY_HEADER: API_KEY}

    def tearDown(self) -> None:
        self.client.close()
        self.tempdir.cleanup()

    def test_health_is_public_and_has_security_headers(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "version": "3.0.0"})
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(len(response.headers["x-request-id"]), 32)

    def test_data_endpoints_require_a_valid_api_key(self) -> None:
        missing = self.client.get("/api/v1/status")
        wrong = self.client.get(
            "/api/v1/status", headers={API_KEY_HEADER: "x" * 32}
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(missing.headers["www-authenticate"], "APIKey")
        self.assertEqual(missing.headers["cache-control"], "no-store")
        self.assertNotIn(API_KEY, missing.text)

    def test_openapi_docs_are_disabled_by_default(self) -> None:
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)

    def test_sources_are_flat_csv_files_only(self) -> None:
        response = self.client.get("/api/v1/sources", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        names = [item["name"] for item in response.json()["sources"]]
        self.assertEqual(names, ["clean.csv", "mixed.csv"])
        self.assertNotIn(str(self.sources), response.text)

    def test_ingestion_rejects_traversal_and_non_csv_sources(self) -> None:
        traversal = self.client.post(
            "/api/v1/ingestions",
            headers=self.headers,
            json={"source": "../clean.csv"},
        )
        extension = self.client.post(
            "/api/v1/ingestions",
            headers=self.headers,
            json={"source": "ignore.txt"},
        )
        unknown = self.client.post(
            "/api/v1/ingestions",
            headers=self.headers,
            json={"source": "absent.csv"},
        )
        self.assertEqual(traversal.status_code, 400)
        self.assertEqual(extension.status_code, 400)
        self.assertEqual(unknown.status_code, 404)

    def test_ingestion_rejects_unknown_request_fields(self) -> None:
        response = self.client.post(
            "/api/v1/ingestions",
            headers=self.headers,
            json={"source": "clean.csv", "path": "/tmp/override.csv"},
        )
        self.assertEqual(response.status_code, 422)

    def test_clean_ingestion_is_created_and_passing(self) -> None:
        response = self.client.post(
            "/api/v1/ingestions",
            headers=self.headers,
            json={"source": "clean.csv"},
        )
        result = response.json()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(result["trust_status"], "passing")
        self.assertEqual(result["schema_mode"], "native")
        self.assertEqual(result["accepted_rows"], 2)
        self.assertEqual(result["source_name"], "clean.csv")

    def test_quality_breach_is_operational_evidence_not_http_failure(self) -> None:
        response = self.client.post(
            "/api/v1/ingestions",
            headers=self.headers,
            json={"source": "mixed.csv"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["trust_status"], "breached")
        self.assertEqual(response.json()["quarantined_rows"], 1)

    def test_status_and_report_do_not_expose_internal_paths_or_tokens(self) -> None:
        self.client.post(
            "/api/v1/ingestions", headers=self.headers, json={"source": "clean.csv"}
        )
        status_response = self.client.get("/api/v1/status", headers=self.headers)
        report_response = self.client.get(
            "/api/v1/trust-report?limit=5", headers=self.headers
        )
        combined = json.dumps([status_response.json(), report_response.json()])
        self.assertNotIn("source_uri", combined)
        self.assertNotIn("subject_token", combined)
        self.assertNotIn(str(self.root), combined)
        self.assertEqual(status_response.json()["latest_run"]["source_name"], "clean.csv")

    def test_lineage_is_available_without_pseudonymous_subject(self) -> None:
        self.client.post(
            "/api/v1/ingestions", headers=self.headers, json={"source": "clean.csv"}
        )
        response = self.client.get(
            f"/api/v1/lineage/{EVENT_ID}", headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["source_name"], "clean.csv")
        self.assertNotIn("subject_token", response.json())
        self.assertNotIn("source_uri", response.json())

    def test_invalid_lineage_identifier_fails_validation(self) -> None:
        response = self.client.get("/api/v1/lineage/not-a-uuid", headers=self.headers)
        self.assertEqual(response.status_code, 422)

    def test_policy_endpoint_returns_reviewable_fingerprint(self) -> None:
        response = self.client.get("/api/v1/policy", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["policy_version"], "2.0.0")
        self.assertEqual(len(response.json()["fingerprint"]), 64)

    def test_dashboard_has_no_external_runtime_or_persistent_key_storage(self) -> None:
        page = self.client.get("/")
        script = self.client.get("/assets/dashboard.js")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("http://", page.text)
        self.assertNotIn("https://", page.text)
        self.assertIn("sessionStorage", script.text)
        self.assertNotIn("localStorage", script.text)
        self.assertNotIn("innerHTML", script.text)

    def test_report_limit_is_bounded_at_the_api(self) -> None:
        response = self.client.get(
            "/api/v1/trust-report?limit=101", headers=self.headers
        )
        self.assertEqual(response.status_code, 422)


class WebConfigurationTests(unittest.TestCase):
    def test_weak_api_key_is_rejected_before_startup(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with self.assertRaisesRegex(ValueError, "api_key.*32"):
            AppConfig(
                database=Path("unused.db"),
                ingestion_root=project / "examples",
                policy_path=project / "config" / "trust-policy.json",
                api_key="weak",
                hmac_key=HMAC_KEY,
            )

    def test_cli_requires_explicit_consent_for_network_binding(self) -> None:
        with self.assertRaisesRegex(SystemExit, "--allow-network"):
            main(["serve", "--host", "0.0.0.0"])


if __name__ == "__main__":
    unittest.main()

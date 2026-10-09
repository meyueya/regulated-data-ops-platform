"""Identity-aware V4 operations plane with policy-enforced governance."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Callable
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security, status
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from regulated_data_ops import __version__
from regulated_data_ops.crypto import FieldCipher
from regulated_data_ops.governance import GovernancePolicy, Principal
from regulated_data_ops.pipeline import IngestionPipeline
from regulated_data_ops.store import DataStore
from regulated_data_ops.trust import TrustPolicy

API_KEY_HEADER = "X-API-Key"
_STATIC_ROOT = Path(__file__).with_name("static")
_ingestion_lock = threading.Lock()


@dataclass(frozen=True, slots=True)
class AppConfig:
    database: Path
    ingestion_root: Path
    policy_path: Path
    governance_path: Path
    hmac_key: str
    encryption_key: str
    enable_docs: bool = False

    def __post_init__(self) -> None:
        if len(self.hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 characters")
        FieldCipher.from_base64(self.encryption_key)
        if not self.ingestion_root.is_dir():
            raise ValueError("ingestion_root must be an existing directory")
        if not self.policy_path.is_file():
            raise ValueError("policy_path must be an existing file")
        if not self.governance_path.is_file():
            raise ValueError("governance_path must be an existing file")


class IngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source: str = Field(min_length=5, max_length=128)


class RetentionExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    confirm_policy_fingerprint: str = Field(min_length=64, max_length=64)


def create_app(config: AppConfig) -> FastAPI:
    """Build a fail-closed app from explicit server-side configuration."""

    trust_policy = TrustPolicy.load(config.policy_path)
    governance = GovernancePolicy.load(config.governance_path)
    cipher = FieldCipher.from_base64(config.encryption_key)
    docs_url = "/docs" if config.enable_docs else None
    openapi_url = "/openapi.json" if config.enable_docs else None
    app = FastAPI(
        title="Regulated Data Ops",
        version=__version__,
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )
    app.state.config = config
    app.state.trust_policy = trust_policy
    app.state.governance = governance
    app.state.field_cipher = cipher
    api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)

    def write_audit(
        *,
        request: Request,
        principal: Principal | None,
        action: str,
        outcome: str,
        resource_type: str = "endpoint",
        resource_id: str | None = None,
        detail: dict[str, object] | None = None,
    ) -> None:
        with _store(config.database, cipher) as store:
            store.append_audit(
                {
                    "audit_id": str(uuid4()),
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "actor_id": principal.actor_id if principal else "anonymous",
                    "actor_role": principal.role if principal else "none",
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id or request.url.path,
                    "outcome": outcome,
                    "request_id": request.state.request_id,
                    "detail": detail or {"method": request.method},
                }
            )

    def authenticate(
        request: Request,
        supplied: str | None = Security(api_key_header),
    ) -> Principal:
        principal = governance.authenticate(supplied or "")
        if principal is None:
            write_audit(
                request=request,
                principal=None,
                action="authentication",
                outcome="denied",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or missing API key",
                headers={"WWW-Authenticate": "APIKey"},
            )
        return principal

    def require(permission: str) -> Callable[..., Principal]:
        def authorize(
            request: Request,
            principal: Principal = Depends(authenticate),
        ) -> Principal:
            permitted = governance.permits(principal, permission)
            write_audit(
                request=request,
                principal=principal,
                action=permission,
                outcome="allowed" if permitted else "denied",
            )
            if not permitted:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"role {principal.role!r} lacks permission {permission!r}",
                )
            return principal

        return authorize

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any):
        request.state.request_id = uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(_STATIC_ROOT / "index.html")

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/me")
    def me(
        principal: Principal = Depends(require("status:read")),
    ) -> dict[str, object]:
        return principal.public_dict() | {
            "permissions": list(governance.permissions_for(principal))
        }

    @app.get("/api/v1/status")
    def latest_status(
        _: Principal = Depends(require("status:read")),
    ) -> dict[str, object]:
        with _store(config.database, cipher) as store:
            latest = store.latest_run()
            schema = store.schema_status()
        return {
            "service_version": __version__,
            "schema_version": schema["schema_version"],
            "encryption_key_id": cipher.key_id,
            "latest_run": _safe_run(latest) if latest else None,
        }

    @app.get("/api/v1/trust-report")
    def trust_report(
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        _: Principal = Depends(require("trust:read")),
    ) -> dict[str, object]:
        with _store(config.database, cipher) as store:
            report = store.trust_report(limit)
        report["runs"] = [_safe_run(run) for run in report["runs"]]
        return report

    @app.get("/api/v1/lineage/{event_id}")
    def lineage(
        event_id: UUID,
        _: Principal = Depends(require("lineage:read")),
    ) -> dict[str, object]:
        with _store(config.database, cipher) as store:
            result = store.lineage(str(event_id))
        if result is None:
            raise HTTPException(status_code=404, detail="event not found")
        return _safe_lineage(result)

    @app.get("/api/v1/sources")
    def sources(
        _: Principal = Depends(require("sources:read")),
    ) -> dict[str, list[dict[str, object]]]:
        root = config.ingestion_root.resolve()
        available = []
        for candidate in sorted(root.glob("*.csv")):
            resolved = candidate.resolve()
            if candidate.is_file() and resolved.is_relative_to(root):
                available.append(
                    {"name": candidate.name, "size_bytes": candidate.stat().st_size}
                )
        return {"sources": available}

    @app.get("/api/v1/policy")
    def active_policy(
        _: Principal = Depends(require("policy:read")),
    ) -> dict[str, object]:
        return trust_policy.as_dict() | {"fingerprint": trust_policy.fingerprint}

    @app.get("/api/v1/governance")
    def active_governance(
        _: Principal = Depends(require("governance:read")),
    ) -> dict[str, object]:
        return governance.public_dict() | {"encryption_key_id": cipher.key_id}

    @app.get("/api/v1/audit-events")
    def audit_events(
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        _: Principal = Depends(require("audit:read")),
    ) -> dict[str, object]:
        with _store(config.database, cipher) as store:
            events = store.audit_events(limit)
        return {"events": events}

    @app.get("/api/v1/audit-integrity")
    def audit_integrity(
        _: Principal = Depends(require("audit:read")),
    ) -> dict[str, object]:
        with _store(config.database, cipher) as store:
            return store.verify_audit_chain()

    @app.get("/api/v1/retention-preview")
    def retention_preview(
        _: Principal = Depends(require("retention:preview")),
    ) -> dict[str, object]:
        accepted_before, quarantine_before = _retention_cutoffs(governance)
        with _store(config.database, cipher) as store:
            candidates = store.retention_preview(
                accepted_before=accepted_before,
                quarantine_before=quarantine_before,
            )
        return {
            "policy_fingerprint": governance.fingerprint,
            "accepted_before": accepted_before,
            "quarantine_before": quarantine_before,
            "candidates": candidates,
        }

    @app.post("/api/v1/retention-executions")
    def execute_retention(
        payload: RetentionExecutionRequest,
        request: Request,
        principal: Principal = Depends(require("retention:execute")),
    ) -> dict[str, object]:
        if payload.confirm_policy_fingerprint != governance.fingerprint:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="governance policy fingerprint confirmation does not match",
            )
        accepted_before, quarantine_before = _retention_cutoffs(governance)
        with _store(config.database, cipher) as store:
            deleted = store.apply_retention(
                accepted_before=accepted_before,
                quarantine_before=quarantine_before,
                audit_values={
                    "audit_id": str(uuid4()),
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "actor_id": principal.actor_id,
                    "actor_role": principal.role,
                    "action": "retention:execute",
                    "resource_type": "retention_policy",
                    "resource_id": governance.fingerprint,
                    "outcome": "succeeded",
                    "request_id": request.state.request_id,
                    "detail": {"policy_version": governance.version},
                },
            )
        return {"status": "applied", "deleted": deleted}

    @app.post(
        "/api/v1/ingestions",
        status_code=status.HTTP_201_CREATED,
    )
    def ingest(
        payload: IngestionRequest,
        request: Request,
        principal: Principal = Depends(require("ingestion:create")),
    ) -> dict[str, object]:
        source = _allowed_source(config.ingestion_root, payload.source)
        with _ingestion_lock:
            pipeline = IngestionPipeline(
                config.database,
                config.hmac_key,
                policy=trust_policy,
                field_cipher=cipher,
            )
            try:
                report = pipeline.ingest(source).as_dict()
            except ValueError as exc:
                write_audit(
                    request=request,
                    principal=principal,
                    action="ingestion:create",
                    outcome="failed",
                    resource_type="source",
                    resource_id=source.name,
                    detail={"error_type": type(exc).__name__},
                )
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            finally:
                pipeline.close()
        write_audit(
            request=request,
            principal=principal,
            action="ingestion:create",
            outcome="succeeded",
            resource_type="ingestion_run",
            resource_id=str(report["run_id"]),
            detail={"source_name": source.name, "trust_status": report["trust_status"]},
        )
        return _safe_run(report) | {"source_name": source.name}

    app.mount("/assets", StaticFiles(directory=_STATIC_ROOT), name="assets")
    return app


class _StoreContext:
    def __init__(self, database: Path, cipher: FieldCipher) -> None:
        self.store = DataStore(database, field_cipher=cipher)

    def __enter__(self) -> DataStore:
        return self.store

    def __exit__(self, *_: object) -> None:
        self.store.close()


def _store(database: Path, cipher: FieldCipher) -> _StoreContext:
    return _StoreContext(database, cipher)


def _retention_cutoffs(governance: GovernancePolicy) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    accepted = now - timedelta(days=governance.retention.accepted_payment_days)
    quarantine = now - timedelta(days=governance.retention.quarantine_days)
    return accepted.isoformat(), quarantine.isoformat()


def _allowed_source(root_path: Path, source_name: str) -> Path:
    if source_name != Path(source_name).name or Path(source_name).suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="source must be an allowed CSV name")
    root = root_path.resolve()
    source = (root / source_name).resolve()
    if not source.is_relative_to(root) or not source.is_file():
        raise HTTPException(status_code=404, detail="source not found")
    return source


_SAFE_RUN_FIELDS = (
    "run_id",
    "source_sha256",
    "contract_version",
    "contract_fingerprint",
    "policy_version",
    "policy_fingerprint",
    "started_at",
    "finished_at",
    "status",
    "total_rows",
    "accepted_rows",
    "quarantined_rows",
    "duplicate_rows",
    "schema_mode",
    "duration_ms",
    "valid_rate",
    "quarantine_rate",
    "trust_status",
    "slo_breaches",
)


def _safe_run(run: dict[str, object]) -> dict[str, object]:
    result = {field: run[field] for field in _SAFE_RUN_FIELDS if field in run}
    source_name = run.get("source_name")
    if isinstance(source_name, str) and source_name:
        result["source_name"] = source_name
    elif isinstance(run.get("source_uri"), str):
        result["source_name"] = Path(str(run["source_uri"])).name
    return result


def _safe_lineage(row: dict[str, object]) -> dict[str, object]:
    fields = (
        "event_id",
        "amount_minor",
        "currency",
        "event_time",
        "country",
        "lawful_basis",
        "source_system",
        "source_run_id",
        "source_row_number",
        "source_sha256",
        "contract_version",
        "contract_fingerprint",
        "ingested_at",
        "source_name",
    )
    result = {field: row[field] for field in fields if field in row and row[field]}
    if "source_name" not in result and isinstance(row.get("source_uri"), str):
        result["source_name"] = Path(str(row["source_uri"])).name
    return result

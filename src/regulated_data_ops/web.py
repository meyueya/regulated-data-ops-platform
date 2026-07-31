"""Authenticated HTTP operations plane with a same-origin dashboard."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security, status
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from regulated_data_ops import __version__
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
    api_key: str
    hmac_key: str
    enable_docs: bool = False

    def __post_init__(self) -> None:
        if len(self.api_key) < 32:
            raise ValueError("api_key must contain at least 32 characters")
        if len(self.hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 characters")
        if not self.ingestion_root.is_dir():
            raise ValueError("ingestion_root must be an existing directory")
        if not self.policy_path.is_file():
            raise ValueError("policy_path must be an existing file")


class IngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source: str = Field(min_length=5, max_length=128)


def create_app(config: AppConfig) -> FastAPI:
    """Build a fail-closed app from explicit server-side configuration."""

    policy = TrustPolicy.load(config.policy_path)
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
    app.state.policy = policy
    api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)

    def authenticate(
        supplied: str | None = Security(api_key_header),
    ) -> None:
        if supplied is None or not secrets.compare_digest(supplied, config.api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or missing API key",
                headers={"WWW-Authenticate": "APIKey"},
            )

    auth = Depends(authenticate)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any):
        request_id = uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
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

    @app.get("/api/v1/status", dependencies=[auth])
    def latest_status() -> dict[str, object]:
        with _store(config.database) as store:
            latest = store.latest_run()
            schema = store.schema_status()
        return {
            "service_version": __version__,
            "schema_version": schema["schema_version"],
            "latest_run": _safe_run(latest) if latest else None,
        }

    @app.get("/api/v1/trust-report", dependencies=[auth])
    def trust_report(
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
    ) -> dict[str, object]:
        with _store(config.database) as store:
            report = store.trust_report(limit)
        report["runs"] = [_safe_run(run) for run in report["runs"]]
        return report

    @app.get("/api/v1/lineage/{event_id}", dependencies=[auth])
    def lineage(event_id: UUID) -> dict[str, object]:
        with _store(config.database) as store:
            result = store.lineage(str(event_id))
        if result is None:
            raise HTTPException(status_code=404, detail="event not found")
        return _safe_lineage(result)

    @app.get("/api/v1/sources", dependencies=[auth])
    def sources() -> dict[str, list[dict[str, object]]]:
        root = config.ingestion_root.resolve()
        available = []
        for candidate in sorted(root.glob("*.csv")):
            resolved = candidate.resolve()
            if candidate.is_file() and resolved.is_relative_to(root):
                available.append(
                    {"name": candidate.name, "size_bytes": candidate.stat().st_size}
                )
        return {"sources": available}

    @app.get("/api/v1/policy", dependencies=[auth])
    def active_policy() -> dict[str, object]:
        return policy.as_dict() | {"fingerprint": policy.fingerprint}

    @app.post(
        "/api/v1/ingestions",
        dependencies=[auth],
        status_code=status.HTTP_201_CREATED,
    )
    def ingest(payload: IngestionRequest) -> dict[str, object]:
        source = _allowed_source(config.ingestion_root, payload.source)
        with _ingestion_lock:
            pipeline = IngestionPipeline(
                config.database,
                config.hmac_key,
                policy=policy,
            )
            try:
                report = pipeline.ingest(source).as_dict()
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            finally:
                pipeline.close()
        return _safe_run(report) | {"source_name": source.name}

    app.mount("/assets", StaticFiles(directory=_STATIC_ROOT), name="assets")
    return app


class _StoreContext:
    def __init__(self, database: Path) -> None:
        self.store = DataStore(database)

    def __enter__(self) -> DataStore:
        return self.store

    def __exit__(self, *_: object) -> None:
        self.store.close()


def _store(database: Path) -> _StoreContext:
    return _StoreContext(database)


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
    source_uri = run.get("source_uri")
    if isinstance(source_uri, str):
        result["source_name"] = Path(source_uri).name
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
    )
    result = {field: row[field] for field in fields if field in row}
    if isinstance(row.get("source_uri"), str):
        result["source_name"] = Path(str(row["source_uri"])).name
    return result

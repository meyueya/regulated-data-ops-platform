"""Command-line interface for the regulated data trust boundary."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
from typing import Sequence

from regulated_data_ops.crypto import FieldCipher
from regulated_data_ops.governance import GovernancePolicy
from regulated_data_ops.pipeline import IngestionPipeline
from regulated_data_ops.store import DataStore
from regulated_data_ops.trust import DEFAULT_TRUST_POLICY, TrustPolicy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="regulated-data-ops")
    parser.add_argument("--database", default="regulated-data.db")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="ingest a contractual CSV")
    ingest.add_argument("source")
    ingest.add_argument("--policy", help="path to a versioned trust policy JSON")
    commands.add_parser("status", help="show the latest ingestion run")
    lineage = commands.add_parser("lineage", help="trace one accepted event")
    lineage.add_argument("--event-id", required=True)
    report = commands.add_parser("trust-report", help="evaluate recent run SLOs")
    report.add_argument("--limit", type=int, default=20)
    report.add_argument("--fail-on-breach", action="store_true")
    commands.add_parser("schema-status", help="show applied schema migrations")
    policy = commands.add_parser("policy-check", help="validate and fingerprint policy")
    policy.add_argument("path")
    governance = commands.add_parser(
        "governance-check", help="validate and fingerprint the V4 governance policy"
    )
    governance.add_argument("path")
    serve = commands.add_parser("serve", help="serve the governed V4 operations plane")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--ingestion-root", default="examples")
    serve.add_argument("--policy", default="config/trust-policy.json")
    serve.add_argument("--governance", default="config/governance-policy.json")
    serve.add_argument(
        "--allow-network",
        action="store_true",
        help="explicitly permit binding to a non-loopback interface",
    )
    serve.add_argument(
        "--enable-docs",
        action="store_true",
        help="enable OpenAPI docs for local development",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    exit_code = 0
    if args.command == "serve":
        if not _is_loopback(args.host) and not args.allow_network:
            raise SystemExit(
                "non-loopback binding requires the explicit --allow-network flag"
            )
        hmac_key = os.getenv("REGULATED_DATA_HMAC_KEY")
        if not hmac_key:
            raise SystemExit("REGULATED_DATA_HMAC_KEY is required to serve V4")
        encryption_key = os.getenv("REGULATED_DATA_ENCRYPTION_KEY")
        if not encryption_key:
            raise SystemExit("REGULATED_DATA_ENCRYPTION_KEY is required to serve V4")
        from regulated_data_ops.web import AppConfig, create_app

        try:
            import uvicorn
        except ImportError as exc:  # pragma: no cover - packaging failure guard
            raise SystemExit("uvicorn is required to serve V4") from exc
        app = create_app(
            AppConfig(
                database=Path(args.database),
                ingestion_root=Path(args.ingestion_root),
                policy_path=Path(args.policy),
                governance_path=Path(args.governance),
                hmac_key=hmac_key,
                encryption_key=encryption_key,
                enable_docs=args.enable_docs,
            )
        )
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    if args.command == "ingest":
        key = os.getenv("REGULATED_DATA_HMAC_KEY")
        if not key:
            raise SystemExit("REGULATED_DATA_HMAC_KEY is required for ingestion")
        policy = TrustPolicy.load(args.policy) if args.policy else DEFAULT_TRUST_POLICY
        pipeline = IngestionPipeline(
            args.database,
            key,
            policy=policy,
            field_cipher=_field_cipher_from_env(),
        )
        try:
            result = pipeline.ingest(args.source).as_dict()
        finally:
            pipeline.close()
    elif args.command == "policy-check":
        policy = TrustPolicy.load(args.path)
        result = policy.as_dict() | {"fingerprint": policy.fingerprint}
    elif args.command == "governance-check":
        governance = GovernancePolicy.load(args.path)
        result = governance.public_dict()
    else:
        store = DataStore(args.database, field_cipher=_field_cipher_from_env())
        try:
            if args.command == "status":
                result = store.latest_run()
            elif args.command == "lineage":
                result = store.lineage(args.event_id)
            elif args.command == "schema-status":
                result = store.schema_status()
            else:
                result = store.trust_report(args.limit)
                if args.fail_on_breach and result["overall_status"] != "passing":
                    exit_code = 2
        finally:
            store.close()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return exit_code


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _field_cipher_from_env() -> FieldCipher | None:
    encoded = os.getenv("REGULATED_DATA_ENCRYPTION_KEY")
    return FieldCipher.from_base64(encoded) if encoded else None


if __name__ == "__main__":
    raise SystemExit(main())

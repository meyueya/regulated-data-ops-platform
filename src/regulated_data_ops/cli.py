"""Command-line interface for the regulated data trust boundary."""

from __future__ import annotations

import argparse
import json
import os
from typing import Sequence

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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    exit_code = 0
    if args.command == "ingest":
        key = os.getenv("REGULATED_DATA_HMAC_KEY")
        if not key:
            raise SystemExit("REGULATED_DATA_HMAC_KEY is required for ingestion")
        policy = TrustPolicy.load(args.policy) if args.policy else DEFAULT_TRUST_POLICY
        pipeline = IngestionPipeline(args.database, key, policy=policy)
        try:
            result = pipeline.ingest(args.source).as_dict()
        finally:
            pipeline.close()
    elif args.command == "policy-check":
        policy = TrustPolicy.load(args.path)
        result = policy.as_dict() | {"fingerprint": policy.fingerprint}
    else:
        store = DataStore(args.database)
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


if __name__ == "__main__":
    raise SystemExit(main())

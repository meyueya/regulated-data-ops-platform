"""Command-line interface for the V1 regulated data boundary."""

from __future__ import annotations

import argparse
import json
import os
from typing import Sequence

from regulated_data_ops.pipeline import IngestionPipeline
from regulated_data_ops.store import DataStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="regulated-data-ops")
    parser.add_argument("--database", default="regulated-data.db")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="ingest a contractual CSV")
    ingest.add_argument("source")
    commands.add_parser("status", help="show the latest ingestion run")
    lineage = commands.add_parser("lineage", help="trace one accepted event")
    lineage.add_argument("--event-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "ingest":
        key = os.getenv("REGULATED_DATA_HMAC_KEY")
        if not key:
            raise SystemExit("REGULATED_DATA_HMAC_KEY is required for ingestion")
        pipeline = IngestionPipeline(args.database, key)
        try:
            result = pipeline.ingest(args.source).as_dict()
        finally:
            pipeline.close()
    else:
        store = DataStore(args.database)
        try:
            result = (
                store.latest_run()
                if args.command == "status"
                else store.lineage(args.event_id)
            )
        finally:
            store.close()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

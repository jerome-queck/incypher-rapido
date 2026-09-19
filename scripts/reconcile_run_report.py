#!/usr/bin/env python3
"""Print one sanitized, read-only reconciliation from a finalized Rapido archive."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rapido.reporting import ReconciliationInputs, reconcile_archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.inputs.read_text(encoding="utf-8"))
    report = reconcile_archive(
        args.database,
        args.run_id,
        ReconciliationInputs.from_mapping(source),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

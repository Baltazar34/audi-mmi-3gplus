#!/usr/bin/env python3
"""Select dominant runtime XAC branches for semantic parser implementation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--min-count", type=int, default=100)
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    selected = [
        {"branch": branch, **value}
        for branch, value in report["branches"].items()
        if int(value["count"]) >= args.min_count
    ]
    selected.sort(key=lambda row: (-int(row["count"]), row["branch"]))
    output = {
        "source": str(args.input),
        "min_count": args.min_count,
        "branch_count": len(selected),
        "records": sum(int(row["count"]) for row in selected),
        "branches": selected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"branch_count": len(selected), "records": output["records"]}, sort_keys=True))


if __name__ == "__main__":
    main()

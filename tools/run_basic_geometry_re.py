#!/usr/bin/env python3
"""Run the repeatable Ghidra batch used for Basic geometry reconstruction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


DEFAULT_HEADLESS = Path("/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless")
DEFAULT_PROJECT_DIRECTORY = Path("/private/tmp/ghidra_pf")
DEFAULT_USER_HOME = Path("/private/tmp/ghidra_user")
HELPER_ADDRESSES = (
    "015583c4",  # geometry-handle loader/cache result
    "002e62b4",  # variable geometry extension locator
    "0149d144",  # tagged geometry extension length
    "0154f934",  # raw geometry-cluster accessor
    "01559fe4",  # edge/geometry accessor initializer
    "01553940",  # complete edge topology + geometry record consumer
    "0154fd30",  # geometry-record visitor dispatcher
    "01559540",  # edge geometry bounding-box accessor
    "01559a0c",  # bounding-box visitor constructor
    "01559a60",  # bounding-box visitor per-subrecord coordinate decoder
    "01559a5c",  # bounding-box visitor finalize callback
)
XREF_ADDRESSES = (
    "015583c4",
    "002e62b4",
    "0149d144",
    "01553940",
    "0154fd30",
    "01559540",
    "01559a0c",
    "01559a60",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], environment: dict[str, str], stage: str) -> None:
    print(f"geometry-re stage={stage} status=start", flush=True)
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    assert process.stdout is not None
    for line in process.stdout:
        if any(
            marker in line
            for marker in (
                "HEADLESS: execution starts",
                "Opening existing project",
                "REPORT: Execute script",
                "SCRIPT:",
                "Save succeeded",
                "ERROR",
            )
        ):
            print(f"geometry-re ghidra={line.rstrip()}", flush=True)
    return_code = process.wait()
    if return_code:
        raise RuntimeError(f"Ghidra stage {stage} failed with exit code {return_code}")
    print(f"geometry-re stage={stage} status=complete", flush=True)


def run(args: argparse.Namespace) -> dict[str, object]:
    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    if not args.headless.is_file():
        raise FileNotFoundError(args.headless)
    if not script_directory.is_dir():
        raise FileNotFoundError(script_directory)
    args.output.mkdir(parents=True, exist_ok=True)
    helpers = args.output / "geometry_helpers.c.txt"
    xrefs = args.output / "geometry_xrefs.c.txt"
    environment = os.environ.copy()
    environment["JAVA_TOOL_OPTIONS"] = f"-Duser.home={args.user_home}"
    base = [
        str(args.headless),
        str(args.project_directory),
        args.project_name,
        "-process",
        args.program,
        "-noanalysis",
        "-scriptPath",
        str(script_directory),
    ]
    _run(
        base
        + [
            "-postScript",
            "GhidraCreateDecompile.java",
            str(helpers),
            *HELPER_ADDRESSES,
        ],
        environment,
        "decompile-helpers",
    )
    _run(
        base
        + [
            "-postScript",
            "GhidraAddressXrefs.java",
            str(xrefs),
            *XREF_ADDRESSES,
        ],
        environment,
        "decompile-xrefs",
    )
    artifacts = {
        path.name: {
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in (helpers, xrefs)
    }
    manifest: dict[str, object] = {
        "schema_version": 1,
        "ghidra_headless": str(args.headless),
        "project_directory": str(args.project_directory),
        "project_name": args.project_name,
        "program": args.program,
        "image_base_note": "Ghidra VA = raw ELF VA + 0x10000",
        "helper_addresses": list(HELPER_ADDRESSES),
        "xref_addresses": list(XREF_ADDRESSES),
        "artifacts": artifacts,
    }
    manifest_path = args.output / "manifest.json"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(manifest_path)
    checksums = args.output / "CHECKSUMS.sha256"
    checksums.write_text(
        "".join(
            f"{_sha256(path)}  {path.name}\n"
            for path in (helpers, xrefs, manifest_path)
        ),
        encoding="ascii",
    )
    print(f"geometry-re stage=complete output={args.output}", flush=True)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--headless", type=Path, default=DEFAULT_HEADLESS)
    parser.add_argument(
        "--project-directory", type=Path, default=DEFAULT_PROJECT_DIRECTORY
    )
    parser.add_argument("--project-name", default="Pathfinder")
    parser.add_argument("--program", default="libPathfinderApp.so")
    parser.add_argument("--user-home", type=Path, default=DEFAULT_USER_HOME)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"run_basic_geometry_re: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Reproduce the local firmware proof for the MIB edge Urban flag."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from run_basic_geometry_re import (
    DEFAULT_HEADLESS,
    DEFAULT_PROJECT_DIRECTORY,
    DEFAULT_USER_HOME,
)


HELPER_ADDRESSES = (
    "002f7c74",  # async routing-edge decode request
    "002eec28",  # routing-edge decode dispatcher
    "002f0484",  # full routing-edge translator; writes Urban output
    "002f9c50",  # decode-request constructor/vtable assignment
    "008ce240",  # separate extended-automotive mask API
    "010ecf5c",  # route-edge formatter exposing explicit is-urban flag
    "010e6878",  # formatter caller
    "013c4850",  # edge-object hash lookup
    "013da078",  # temporary edge-map to central-cache transfer
    "013db20c",  # second cache transfer path
    "013e55a4",  # cached edge-object constructor
    "013e5be8",  # Urban Entry/Exit transition consumer
)
XREF_ADDRESSES = (
    "002f0484",
    "002f7c74",
    "010ecf5c",
    "013c4850",
    "013e5be8",
)
STRING_NEEDLES = (
    "is urban:",
    "ManGen_Data: Urban Entry",
    "ManGen_Data: Urban Exit",
    "non_urban",
)
DEEP_STRING_NEEDLES = (
    "UrbanRoad",
    "BuiltUpArea",
    "PedestrianZone",
)
VTABLE_SLOTS = tuple(f"{value:08x}" for value in range(0x016E3FD0, 0x016E4010, 4))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], environment: dict[str, str], stage: str) -> None:
    print(f"urban-semantics-re stage={stage} status=start", flush=True)
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
                "Save succeeded",
                "GhidraRangeDecompileGrep visited",
                "GhidraAddressXrefs wrote",
                "ERROR",
            )
        ):
            print(f"urban-semantics-re ghidra={line.rstrip()}", flush=True)
    return_code = process.wait()
    if return_code:
        raise RuntimeError(f"Ghidra stage {stage} failed with exit code {return_code}")
    print(f"urban-semantics-re stage={stage} status=complete", flush=True)


def run(args: argparse.Namespace) -> dict[str, object]:
    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    if not args.headless.is_file():
        raise FileNotFoundError(args.headless)
    if not script_directory.is_dir():
        raise FileNotFoundError(script_directory)
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output.resolve()
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

    artifacts: list[Path] = []

    def ghidra(stage: str, script: str, filename: str, *script_args: str) -> None:
        path = output / filename
        _run(base + ["-postScript", script, str(path), *script_args], environment, stage)
        artifacts.append(path)

    ghidra(
        "decompile-helpers",
        "GhidraCreateDecompile.java",
        "urban_helpers.c.txt",
        *HELPER_ADDRESSES,
    )
    ghidra(
        "address-xrefs",
        "GhidraAddressXrefs.java",
        "urban_address_xrefs.c.txt",
        *XREF_ADDRESSES,
    )
    ghidra(
        "string-xrefs",
        "GhidraStringXrefs.java",
        "urban_string_xrefs.c.txt",
        *STRING_NEEDLES,
    )
    ghidra(
        "cache-field-scan",
        "GhidraRangeDecompileGrep.java",
        "urban_cache_field_scan.c.txt",
        "01300000",
        "01400000",
        "+ 0x268",
        "+ 0x16c",
    )
    ghidra(
        "decode-request-listing",
        "GhidraFunctionListing.java",
        "urban_decode_request_listing.txt",
        "002f9c50",
        "002faa20",
    )
    ghidra(
        "decode-request-vtable",
        "GhidraPointerTableDecompile.java",
        "urban_decode_request_vtable.c.txt",
        *VTABLE_SLOTS,
    )
    if args.deep:
        ghidra(
            "catalog-string-deep-scan",
            "GhidraStringXrefs.java",
            "urban_catalog_string_deep_scan.c.txt",
            *DEEP_STRING_NEEDLES,
        )
        ghidra(
            "neighbor-flag-deep-scan",
            "GhidraRangeDecompileGrep.java",
            "urban_neighbor_flag_deep_scan.c.txt",
            "00800000",
            "01450000",
            "+ 0x1d4",
            "+ 0x1e9",
        )

    manifest: dict[str, object] = {
        "schema_version": 1,
        "status": "complete",
        "project_directory": str(args.project_directory),
        "project_name": args.project_name,
        "program": args.program,
        "image_base_note": "Ghidra VA = raw ELF VA + 0x10000",
        "deep_scan": args.deep,
        "proven_contract": {
            "mib_source": "OR of geometry-part secondary flag bit 5 (0x20)",
            "decoder": (
                "VA 0x002f0484 writes output+0x168; caller VA 0x002f7c74 "
                "passes edge_object+4, therefore edge_object+0x16c"
            ),
            "consumer": (
                "VA 0x013e5be8 reads edge_object+0x16c for Urban Entry/Exit"
            ),
            "audi_urban_status": "not proven; do not substitute neighboring flags",
        },
        "helper_addresses": list(HELPER_ADDRESSES),
        "xref_addresses": list(XREF_ADDRESSES),
        "string_needles": list(STRING_NEEDLES),
        "deep_string_needles": list(DEEP_STRING_NEEDLES),
        "artifacts": {
            path.name: {"size": path.stat().st_size, "sha256": _sha256(path)}
            for path in artifacts
        },
    }
    manifest_path = output / "manifest.json"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    temporary.replace(manifest_path)
    checksum_paths = [*artifacts, manifest_path]
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
    )
    print(f"urban-semantics-re stage=complete output={output}", flush=True)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--headless", type=Path, default=DEFAULT_HEADLESS)
    parser.add_argument("--project-directory", type=Path, default=DEFAULT_PROJECT_DIRECTORY)
    parser.add_argument("--project-name", default="Pathfinder")
    parser.add_argument("--program", default="libPathfinderApp.so")
    parser.add_argument("--user-home", type=Path, default=DEFAULT_USER_HOME)
    parser.add_argument("--deep", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"run_basic_urban_semantics_re: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

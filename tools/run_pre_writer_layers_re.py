#!/usr/bin/env python3
"""Run the repeatable Ghidra batch for AdvancedRouting and ADAS semantics."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from run_basic_geometry_re import (
    DEFAULT_HEADLESS,
    DEFAULT_PROJECT_DIRECTORY,
    DEFAULT_USER_HOME,
    _run,
    _sha256,
)


HELPER_ADDRESSES = (
    "002b3210",  # complete-edge container load path
    "002b4358",  # base-edge container load path
    "002b5a64",  # paired base/complete container load path
    "002e2758",  # public routing/guidance data request dispatcher
    "002f0484",  # simplified-storage routing/guidance translator
    "009d42dc",  # decoded edge iterator
    "009d6bcc",  # cached base/complete/ADAS edge-container lookup
    "009e6d10",  # ADAS conversion worker
    "009e8310",  # ADAS cluster conversion loop
    "009df8fc",  # ADAS compact profile decoder/emitter
    "009e0ea0",  # ADAS attribute/profile expansion worker
    "009f70d0",  # paired PSF slot cluster loader
    "009f8514",  # Routing/Guidance/ADAS cluster load coordinator
    "01553940",  # complete routing-edge aggregate parser
    "015583c4",  # secondary cluster handle lookup
    "01558594",  # primary cluster handle lookup
    "00263368",  # ADAS sub-record selector
    "014a6878",  # packed ADAS flag accessor
    "014a6930",  # packed ADAS flag accessor
    "014a6e8c",  # packed ADAS flag accessor
)

XREF_ADDRESSES = HELPER_ADDRESSES

STRING_NEEDLES = (
    "Loading of CompleteEdgeContainer failed",
    "Loading of BaseEdgeContainer failed",
    "Loading of AdasEdgeContainer failed",
    "DATA_ACCESS_LOAD_GUIDANCE_DATA",
    "DATA_ACCESS_LOAD_ROUTINGEDGE_ATTRIBUTES",
    "SSA : failed to load routing cluster",
    "SSA : failed to load guidance cluster",
    "ADAS_CLUSTER_CONVERSION",
    "Adas edge ",
    "Routing/Guidance cluster loading failed",
    "ADAS cluster loading failed",
    "process_edge: Attribute (id:",
    "Offset of attribute is bigger than edge length:",
    "MapAccessServiceImpl::load_attributes called for path",
    "MapAccessServiceImpl::load_attributes finished for path",
    "Loading routing cluster",
    "addRestriction: invalid edge found in restriction",
    "StreetRestrictionsChecker: no restricted edges exist",
)


def run(args: argparse.Namespace) -> dict[str, object]:
    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    if not args.headless.is_file():
        raise FileNotFoundError(args.headless)
    args.output.mkdir(parents=True, exist_ok=True)
    helpers = args.output / "pre_writer_helpers.c.txt"
    xrefs = args.output / "pre_writer_xrefs.c.txt"
    string_xrefs = args.output / "pre_writer_string_xrefs.c.txt"
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
        base + ["-postScript", "GhidraCreateDecompile.java", str(helpers), *HELPER_ADDRESSES],
        environment,
        "pre-writer-decompile-helpers",
    )
    _run(
        base + ["-postScript", "GhidraAddressXrefs.java", str(xrefs), *XREF_ADDRESSES],
        environment,
        "pre-writer-decompile-xrefs",
    )
    _run(
        base + ["-postScript", "GhidraStringXrefs.java", str(string_xrefs), *STRING_NEEDLES],
        environment,
        "pre-writer-decompile-string-xrefs",
    )
    artifacts = {
        path.name: {"size": path.stat().st_size, "sha256": _sha256(path)}
        for path in (helpers, xrefs, string_xrefs)
    }
    manifest = {
        "schema_version": 1,
        "ghidra_headless": str(args.headless),
        "project_directory": str(args.project_directory),
        "project_name": args.project_name,
        "program": args.program,
        "image_base_note": "Ghidra VA = raw ELF VA + 0x10000",
        "helper_addresses": list(HELPER_ADDRESSES),
        "xref_addresses": list(XREF_ADDRESSES),
        "string_needles": list(STRING_NEEDLES),
        "artifacts": artifacts,
    }
    manifest_path = args.output / "manifest.json"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(manifest_path)
    paths = (helpers, xrefs, string_xrefs, manifest_path)
    (args.output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in paths),
        encoding="ascii",
    )
    print(f"pre-writer-re stage=complete output={args.output}", flush=True)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--headless", type=Path, default=DEFAULT_HEADLESS)
    parser.add_argument("--project-directory", type=Path, default=DEFAULT_PROJECT_DIRECTORY)
    parser.add_argument("--project-name", default="Pathfinder")
    parser.add_argument("--program", default="libPathfinderApp.so")
    parser.add_argument("--user-home", type=Path, default=DEFAULT_USER_HOME)
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"run_pre_writer_layers_re: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

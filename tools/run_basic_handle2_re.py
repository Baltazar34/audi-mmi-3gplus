#!/usr/bin/env python3
"""Run the repeatable sequential Ghidra batch for Basic handle-2 semantics."""

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


LOADER_ADDRESSES = (
    "01558038",  # adjacent typed cluster loader/accessor
    "01558164",  # candidate handle-2 cluster loader/accessor
    "015583c4",  # confirmed geometry loader for comparison
    "01558594",  # confirmed topology loader for comparison
    "01550730",  # sole direct handle-2 consumer
    "014a4538",  # handle-2 semantic object parser
    "014a25b8",  # semantic result object constructor
    "014a1c98",  # record field accessor
    "014a1d18",  # record field-count accessor
    "014a1db8",  # record field-count accessor
    "014a1e08",  # record field-count accessor
    "014a1e68",  # core record parser
    "014a2514",  # schema route-type priority accessor
    "014a2a98",  # semantic item-count accessor
    "014a3268",  # semantic list accessor
    "014a32b0",  # header-flag-0x02 route-number item decoder
    "014a34e8",  # semantic list accessor
    "014a375c",  # semantic string/property accessor
    "014a37fc",  # semantic property accessor
    "014a3830",  # semantic property accessor
    "014a3ec0",  # preferred route-number selector
    "014a41c0",  # preferred route-number wrapper
    "014a44d8",  # semantic aggregate accessor
    "014a2254",  # property table lookup
    "014a2170",  # selected-property metadata post-processor
    "014a24c8",  # selected route-number punctuation flag resolver
    "014a23cc",  # property kind resolver
    "014a2870",  # property list decoder
    "014a2af0",  # property item count
    "014a2ba4",  # property item decoder
    "014a2c60",  # property identifier accessor
    "014a2e80",  # property text decoder
    "014a35c0",  # alternate property text decoder
    "014a31c8",  # route-number/property classifier
    "014a439c",  # preferred route-number aggregate accessor
    "014a4258",  # preferred route-number fallback accessor
    "014a358c",  # direct-text cache/locale helper
    "014a4a80",  # direct-text cache accessor
    "014a4a84",  # section-text cache accessor
    "014a4850",  # parsed-record cache builder
    "014a4974",  # parsed-record cache helper
    "014a5034",  # parsed-record cache lookup
    "014a51a8",  # record section initializer
    "014abd4c",  # record optional-field offset helper
    "014915e8",  # SDString decoder used by semantic property accessors
    "014911d4",  # locale/phonetic post-processor
    "01490db0",  # locale-dependent SDString normalizer
    "01491d24",  # related SDString cursor helper
    "01491fac",  # alternate SDString decoder used by semantic properties
    "01492b00",  # related name/SDString helper
    "0026b5b4",  # external schema route-config lookup
    "012a97e0",  # consumer language/transliteration selector
    "012a9fb8",  # caller separating route priority from language selection
    "0026b63c",  # schema-specific route-type mapping lookup
    "00f2d8fc",  # worldCountry official-language array loader
    "00f4b764",  # worldCountry official-language membership consumer
)
XREF_ADDRESSES = (
    "01558038",
    "01558164",
    "01550730",
    "014a4538",
    "014a34e8",
    "014a375c",
    "014a3ec0",
    "014a24c8",
    "014a4258",
    "014911d4",
    "01490db0",
    "0026b5b4",
    "012a97e0",
    "012a9fb8",
    "0026b63c",
    "00f2d8fc",
    "00f4b764",
)


def run(args: argparse.Namespace) -> dict[str, object]:
    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    if not args.headless.is_file():
        raise FileNotFoundError(args.headless)
    args.output.mkdir(parents=True, exist_ok=True)
    functions = args.output / "functions_01557000_01559000.txt"
    string_functions = args.output / "functions_01491000_01493000.txt"
    parser_functions = args.output / "functions_014a1800_014a5000.txt"
    helpers = args.output / "handle2_helpers.c.txt"
    xrefs = args.output / "handle2_xrefs.c.txt"
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
            "GhidraListFunctions.java",
            str(functions),
            "01557000",
            "01559000",
        ],
        environment,
        "list-functions",
    )
    _run(
        base
        + [
            "-postScript",
            "GhidraListFunctions.java",
            str(string_functions),
            "01491000",
            "01493000",
        ],
        environment,
        "list-string-functions",
    )
    _run(
        base
        + [
            "-postScript",
            "GhidraListFunctions.java",
            str(parser_functions),
            "014a1800",
            "014a5000",
        ],
        environment,
        "list-parser-functions",
    )
    _run(
        base
        + [
            "-postScript",
            "GhidraCreateDecompile.java",
            str(helpers),
            *LOADER_ADDRESSES,
        ],
        environment,
        "decompile-loaders",
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
        path.name: {"size": path.stat().st_size, "sha256": _sha256(path)}
        for path in (functions, string_functions, parser_functions, helpers, xrefs)
    }
    manifest: dict[str, object] = {
        "schema_version": 1,
        "ghidra_headless": str(args.headless),
        "project_directory": str(args.project_directory),
        "project_name": args.project_name,
        "program": args.program,
        "image_base_note": "Ghidra VA = raw ELF VA + 0x10000",
        "loader_addresses": list(LOADER_ADDRESSES),
        "xref_addresses": list(XREF_ADDRESSES),
        "artifacts": artifacts,
    }
    manifest_path = args.output / "manifest.json"
    temporary = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(manifest_path)
    checksum_paths = (
        functions,
        string_functions,
        parser_functions,
        helpers,
        xrefs,
        manifest_path,
    )
    (args.output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
    )
    print(f"handle2-re stage=complete output={args.output}", flush=True)
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
        print(f"run_basic_handle2_re: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

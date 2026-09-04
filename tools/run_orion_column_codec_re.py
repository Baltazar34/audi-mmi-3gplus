#!/usr/bin/env python3
"""Extract repeatable Orion column-codec evidence from the MMI 3G NavCore project."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from run_basic_geometry_re import DEFAULT_HEADLESS, DEFAULT_USER_HOME, _run, _sha256


DEFAULT_SOURCE_PROJECT = Path(
    os.environ.get("NAVCORE_GHIDRA_PROJECT", str(Path.home() / "mmi3g-atlas" / "ghidra_proj"))
)
DEFAULT_PROJECT_DIRECTORY = Path("/private/tmp/ghidra_navcore")
DEFAULT_PROJECT_NAME = "NavCoreProj"
DEFAULT_PROGRAM = "NavCore"

CORE_FUNCTIONS = (
    "0832c064",  # COrionContainerBase::parseDescriptions
    "0832d65c",  # COrionContainerBase::createTables
    "0832da88",  # COrionContainerBase::loadIndexArray
    "083319e8",  # CDecompression::create
    "08330224",  # compression code 1 type dispatcher
    "08331050",  # compression code 2 type dispatcher
    "08331740",  # compression code 3 composite decoder
    "0832ead8",  # COrionContainerBase::calculateOffsets
)

SCHEMA_HELPER_SLOTS = (
    "0832c830",  # logical type -> serialized part amount
    "0832d008", "0832d00c",  # post-description preparation/allocation
    "0832d33c", "0832d340", "0832d488",  # table/decompressor preparation
)

CODE1_TYPE_FACTORY_SLOTS = (
    "0833038c", "08330390", "08330394", "08330398", "0833039c",
    "083303a0", "083303a4", "083303a8", "083303ac", "083303b0",
    "083303b4", "083303b8", "083303bc", "083303c0", "083303c4",
    "083303c8", "083303cc",
)
CODE2_TYPE_FACTORY_SLOTS = (
    "083311b8", "083311bc", "083311c0", "083311c4", "083311c8",
    "083311cc", "083311d0", "083311d4", "083311d8", "083311dc",
    "083311e0", "083311e4", "083311e8", "083311ec", "083311f0",
    "083311f4", "083311f8",
)
CODE3_CALL_SLOTS = (
    "083319a4", "083319a8", "083319ac", "083319b0", "083319e0",
    "083319e4",
)

# These vtable targets make the source-width difference visible: code 1 reads
# native-width values, code 2 reads the per-column width held at object +8,
# and code 3 builds/uses an indirect placement table.
REPRESENTATIVE_VTABLE_FUNCTIONS = (
    "08334770", "0833469c",  # code 1, 1-bit scalar/range
    "08333800", "08333724",  # code 2, dynamic-width scalar/range
    "0833121c", "0832f8e8", "0832f94c",  # code 3 placement/read path
    "0833599c",  # type code -> storage/alignment width
)

STRING_NEEDLES = (
    "Unknown compression type",
    "CByteBitDecompression",
    "CBytePlainDecompression",
    "CBitBitDecompression",
    "CBitPlainDecompression",
    "offset has brocken bit alignment",
)


def _ensure_project(args: argparse.Namespace) -> None:
    marker = args.project_directory / f"{args.project_name}.gpr"
    repository = args.project_directory / f"{args.project_name}.rep"
    if marker.is_file() and repository.is_dir():
        return
    source_marker = args.source_project / f"{args.project_name}.gpr"
    source_repository = args.source_project / f"{args.project_name}.rep"
    if not source_marker.is_file() or not source_repository.is_dir():
        raise FileNotFoundError(
            f"missing source Ghidra project {source_marker} / {source_repository}"
        )
    args.project_directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_marker, marker)
    shutil.copytree(source_repository, repository, dirs_exist_ok=True)


def run(args: argparse.Namespace) -> dict[str, object]:
    if not args.headless.is_file():
        raise FileNotFoundError(args.headless)
    _ensure_project(args)
    args.output.mkdir(parents=True, exist_ok=True)
    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    environment = os.environ.copy()
    environment["JAVA_TOOL_OPTIONS"] = f"-Duser.home={args.user_home}"
    base = [
        str(args.headless), str(args.project_directory), args.project_name,
        "-process", args.program, "-noanalysis", "-scriptPath", str(script_directory),
    ]

    core_output = args.output / "factory_modes_offsets.c.txt"
    dispatch_output = args.output / "type_factory_dispatch.c.txt"
    code3_output = args.output / "code3_recursive_calls.c.txt"
    vtable_output = args.output / "representative_vtable_reads.c.txt"
    strings_output = args.output / "decompression_strings.c.txt"
    schema_helpers_output = args.output / "schema_helpers.c.txt"
    schema_constants_output = args.output / "schema_constants.hex.txt"

    _run(
        base + ["-postScript", "GhidraCreateDecompile.java", str(core_output),
                *CORE_FUNCTIONS],
        environment, "orion-codec-core",
    )
    _run(
        base + ["-postScript", "GhidraPointerTableDecompile.java",
                str(dispatch_output), *CODE1_TYPE_FACTORY_SLOTS,
                *CODE2_TYPE_FACTORY_SLOTS],
        environment, "orion-codec-type-factories",
    )
    _run(
        base + ["-postScript", "GhidraPointerTableDecompile.java",
                str(code3_output), *CODE3_CALL_SLOTS],
        environment, "orion-codec-code3-recursion",
    )
    _run(
        base + ["-postScript", "GhidraCreateDecompile.java", str(vtable_output),
                *REPRESENTATIVE_VTABLE_FUNCTIONS],
        environment, "orion-codec-vtable-reads",
    )
    _run(
        base + ["-postScript", "GhidraStringXrefs.java", str(strings_output),
                *STRING_NEEDLES],
        environment, "orion-codec-class-strings",
    )
    _run(
        base + ["-postScript", "GhidraPointerTableDecompile.java",
                str(schema_helpers_output), *SCHEMA_HELPER_SLOTS],
        environment, "orion-schema-helpers",
    )
    _run(
        base + ["-postScript", "GhidraMemoryBytes.java",
                str(schema_constants_output), "08335abe:4"],
        environment, "orion-schema-constants",
    )

    source_marker = args.source_project / f"{args.project_name}.gpr"
    source_properties = (
        args.source_project / f"{args.project_name}.rep" / "project.prp"
    )
    manifest: dict[str, object] = {
        "schema_version": 1,
        "source_project": str(args.source_project),
        "working_project": str(args.project_directory),
        "project_name": args.project_name,
        "program": args.program,
        "source_project_fingerprints": {
            "gpr_sha256": _sha256(source_marker),
            "project_prp_sha256": _sha256(source_properties),
        },
        "core_functions": list(CORE_FUNCTIONS),
        "schema_helper_slots": list(SCHEMA_HELPER_SLOTS),
        "logical_type_part_amount": {
            "0x90": 2,
            "0xa0": 2,
            "0xb0": 1,
            "0xc0": "forced to 1 by parseDescriptions",
            "0xd0": "forced to 1 by parseDescriptions",
            "optional_member_adjustment": "+2 in-memory synthetic parts",
            "evidence": "FUN_08335a58 plus bytes 90 00 a0 00 at 08335abe",
        },
        "compression_codes": {
            "1": {
                "dispatcher": "08330224",
                "object_size": 8,
                "confirmed": "type-specialized decoder using the native type width",
            },
            "2": {
                "dispatcher": "08331050",
                "object_size": 12,
                "confirmed": (
                    "type-specialized decoder; reads a type-dependent bit-width "
                    "field into object offset +8"
                ),
            },
            "3": {
                "dispatcher": "08331740",
                "object_size": 40,
                "confirmed": (
                    "composite decoder: reads a signed 5-bit field plus one, then "
                    "a value of that width, reads an 8-bit nested compression code, "
                    "and recursively calls CDecompression::create"
                ),
            },
        },
        "important_correction": (
            "compression code 3 is not a simple width-prefixed scalar stream; "
            "treating all following bits as direct values drops its nested decoder "
            "and placement-table semantics"
        ),
        "class_mapping_policy": (
            "Byte/Bit and Plain/Bit class selection is type-specialized inside the "
            "code 1/2 dispatch tables; do not assign one global class name per code"
        ),
        "offset_layout": (
            "calculateOffsets stores a sequential running bit-size layout, advancing "
            "each member by ceil(member_bits / 8) bytes after effective widths are set"
        ),
        "network_mutation": False,
    }
    manifest_path = args.output / "manifest.json"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(manifest_path)
    artifacts = (
        core_output, dispatch_output, code3_output, vtable_output, strings_output,
        schema_helpers_output, schema_constants_output, manifest_path,
    )
    (args.output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in artifacts),
        encoding="ascii",
    )
    print(
        "orion-column-codec-re stage=complete "
        f"core={len(CORE_FUNCTIONS)} type_factories="
        f"{len(CODE1_TYPE_FACTORY_SLOTS) + len(CODE2_TYPE_FACTORY_SLOTS)} "
        f"output={args.output}",
        flush=True,
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-project", type=Path, default=DEFAULT_SOURCE_PROJECT)
    parser.add_argument(
        "--project-directory", type=Path, default=DEFAULT_PROJECT_DIRECTORY
    )
    parser.add_argument("--project-name", default=DEFAULT_PROJECT_NAME)
    parser.add_argument("--program", default=DEFAULT_PROGRAM)
    parser.add_argument("--headless", type=Path, default=DEFAULT_HEADLESS)
    parser.add_argument("--user-home", type=Path, default=DEFAULT_USER_HOME)
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"run_orion_column_codec_re: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

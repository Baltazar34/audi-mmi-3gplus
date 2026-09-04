#!/usr/bin/env python3
"""Extract repeatable ADAS-interface -> PSD1.5 profile conversion evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from run_basic_geometry_re import DEFAULT_HEADLESS, DEFAULT_USER_HOME, _run, _sha256


DEFAULT_LIBRARY = Path(
    "/private/tmp/mhi2_app50_extracted/navigation/libATFPSDAdapter15.so"
)
DEFAULT_PROJECT_DIRECTORY = Path("/private/tmp/ghidra_psd")
DEFAULT_PROJECT_NAME = "PSDAdapter15"
DEFAULT_PROGRAM = "libATFPSDAdapter15.so"

CONVERSION_WORKER = "00036050"
PROFILE_CONVERTERS = (
    "0002abd8", "0002b174", "0002e60c", "0002e6f8", "0002e7e4",
    "0002e8d0", "0002b63c", "0002e9bc", "0002eaa8", "0002eb94",
    "0002ec80", "0002ed6c", "0002bc30", "0002c160", "0002ee58",
    "0002c7c4", "0002c8ac", "0002c994", "0002ca7c", "0002cb64",
    "0002ef44", "0002d094", "0002d464", "0002f030", "0002cc4c",
    "0002d8e8", "0002f11c", "0002f208", "0002f2f4", "0002f3e0",
    "0002f4cc", "0002dd50", "00030d10", "0002f5b8", "0002f6a4",
    "00030dfc", "00030ee8", "00030fd4", "0002f790", "0002f87c",
    "00035f18", "0002f968", "0002fa54", "0002d9f8", "0002fb40",
    "0002e13c",
)

STRING_NEEDLES = (
    "ADAS_PSD15",
    "Conversion of profiles from adas interface not successful",
    "PSDATFServer: ADASInterface retrieved",
)


def _base_command(args: argparse.Namespace, script_directory: Path) -> list[str]:
    return [
        str(args.headless),
        str(args.project_directory),
        args.project_name,
        "-scriptPath",
        str(script_directory),
    ]


def run(args: argparse.Namespace) -> dict[str, object]:
    if not args.library.is_file():
        raise FileNotFoundError(args.library)
    if not args.headless.is_file():
        raise FileNotFoundError(args.headless)

    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    args.output.mkdir(parents=True, exist_ok=True)
    args.project_directory.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["JAVA_TOOL_OPTIONS"] = f"-Duser.home={args.user_home}"

    base = _base_command(args, script_directory)
    project_marker = args.project_directory / f"{args.project_name}.gpr"
    if not project_marker.exists():
        _run(
            base + ["-import", str(args.library)],
            environment,
            "psd15-import-and-analyse",
        )

    process = base + ["-process", args.program, "-noanalysis"]
    worker_output = args.output / "profile_conversion_worker.c.txt"
    converter_output = args.output / "profile_conversion_helpers.c.txt"
    string_output = args.output / "profile_conversion_strings.c.txt"

    _run(
        process + [
            "-postScript", "GhidraCreateDecompile.java",
            str(worker_output), CONVERSION_WORKER,
        ],
        environment,
        "psd15-profile-conversion-worker",
    )
    _run(
        process + [
            "-postScript", "GhidraCreateDecompile.java",
            str(converter_output), *PROFILE_CONVERTERS,
        ],
        environment,
        "psd15-profile-converters",
    )
    _run(
        process + [
            "-postScript", "GhidraStringXrefs.java",
            str(string_output), *STRING_NEEDLES,
        ],
        environment,
        "psd15-profile-strings",
    )

    manifest: dict[str, object] = {
        "schema_version": 1,
        "library": str(args.library),
        "library_size": args.library.stat().st_size,
        "library_sha256": _sha256(args.library),
        "ghidra_headless": str(args.headless),
        "project_directory": str(args.project_directory),
        "project_name": args.project_name,
        "program": args.program,
        "image_base_note": "Ghidra VA = raw ELF VA + 0x10000",
        "conversion_worker": CONVERSION_WORKER,
        "profile_converters": list(PROFILE_CONVERTERS),
        "converter_count": len(PROFILE_CONVERTERS),
        "debuglink": {
            "filename": "libATFPSDAdapter15.so-20160718160238.sym",
            "crc32": "0x6f528a2a",
            "available": False,
            "impact": (
                "public profile names cannot be assigned from stripped method order "
                "without an independent enum or unique conversion signature"
            ),
        },
        "confirmed_boundary": (
            "FUN_00036050 enumerates ADAS interface profile accessors and copies "
            "their values through 46 typed converter functions into PSD1.5 storage"
        ),
        "semantic_policy": (
            "do not equate PNAV internal attribute ids, vtable offsets, and public "
            "ADASIS profile ids unless firmware or target data supplies a direct link"
        ),
    }
    manifest_path = args.output / "manifest.json"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(manifest_path)

    artifacts = (worker_output, converter_output, string_output, manifest_path)
    (args.output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in artifacts),
        encoding="ascii",
    )
    print(
        f"psd15-profile-re stage=complete converters={len(PROFILE_CONVERTERS)} "
        f"output={args.output}",
        flush=True,
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--headless", type=Path, default=DEFAULT_HEADLESS)
    parser.add_argument(
        "--project-directory", type=Path, default=DEFAULT_PROJECT_DIRECTORY
    )
    parser.add_argument("--project-name", default=DEFAULT_PROJECT_NAME)
    parser.add_argument("--program", default=DEFAULT_PROGRAM)
    parser.add_argument("--user-home", type=Path, default=DEFAULT_USER_HOME)
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"run_psd15_profile_re: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

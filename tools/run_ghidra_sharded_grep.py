#!/usr/bin/env python3
"""Run bounded Ghidra decompiler grep in parallel, then merge its artifacts."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading

from run_basic_geometry_re import (
    DEFAULT_HEADLESS,
    DEFAULT_PROJECT_DIRECTORY,
    DEFAULT_USER_HOME,
)


SUMMARY_RE = re.compile(r"SUMMARY visited=(\d+) matched=(\d+)")
PRINT_LOCK = threading.Lock()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _split_range(start: int, end: int, jobs: int) -> list[tuple[int, int]]:
    width = end - start
    return [
        (start + width * index // jobs, start + width * (index + 1) // jobs)
        for index in range(jobs)
    ]


def _worker(
    index: int,
    span: tuple[int, int],
    part_path: Path,
    project_directory: Path,
    args: argparse.Namespace,
    script_directory: Path,
    environment: dict[str, str],
) -> tuple[int, int]:
    start, end = span
    command = [
        str(args.headless),
        str(project_directory),
        args.project_name,
        "-process",
        args.program,
        "-readOnly",
        "-noanalysis",
        "-scriptPath",
        str(script_directory),
        "-postScript",
        "GhidraRangeDecompileGrep.java",
        str(part_path),
        f"{start:08x}",
        f"{end:08x}",
        *args.needles,
    ]
    with PRINT_LOCK:
        print(
            f"ghidra-sharded-grep shard={index + 1}/{args.jobs} "
            f"range={start:08x}..{end:08x} status=start",
            flush=True,
        )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
    )
    assert process.stdout is not None
    for line in process.stdout:
        if "GhidraRangeDecompileGrep visited" in line or "ERROR" in line:
            with PRINT_LOCK:
                print(
                    f"ghidra-sharded-grep shard={index + 1}/{args.jobs} "
                    f"ghidra={line.rstrip()}",
                    flush=True,
                )
    return_code = process.wait()
    if return_code:
        raise RuntimeError(f"shard {index + 1} failed with exit code {return_code}")
    text = part_path.read_text(errors="replace")
    match = SUMMARY_RE.search(text)
    if match is None:
        raise RuntimeError(f"shard {index + 1} has no completion summary")
    counts = int(match.group(1)), int(match.group(2))
    with PRINT_LOCK:
        print(
            f"ghidra-sharded-grep shard={index + 1}/{args.jobs} "
            f"visited={counts[0]} matched={counts[1]} status=complete",
            flush=True,
        )
    return counts


def run(args: argparse.Namespace) -> dict[str, object]:
    if args.jobs < 1:
        raise ValueError("jobs must be positive")
    start = int(args.start, 16)
    end = int(args.end, 16)
    if end <= start:
        raise ValueError("end must be greater than start")
    if not args.needles:
        raise ValueError("at least one needle is required")

    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    part_paths = [
        args.output.with_name(f"{args.output.name}.part{index:02d}")
        for index in range(args.jobs)
    ]
    spans = _split_range(start, end, args.jobs)
    environment = os.environ.copy()
    environment["JAVA_TOOL_OPTIONS"] = f"-Duser.home={args.user_home}"

    source_gpr = args.project_directory / f"{args.project_name}.gpr"
    source_rep = args.project_directory / f"{args.project_name}.rep"
    if not source_gpr.exists() or not source_rep.is_dir():
        raise FileNotFoundError(f"Ghidra project not found: {source_gpr}")

    counts: list[tuple[int, int] | None] = [None] * args.jobs
    with tempfile.TemporaryDirectory(prefix="ghidra-sharded-", dir="/private/tmp") as temporary:
        temporary_root = Path(temporary)
        shard_project_directories: list[Path] = []
        for index in range(args.jobs):
            project_directory = temporary_root / f"shard{index:02d}"
            project_directory.mkdir()
            shutil.copy2(source_gpr, project_directory / source_gpr.name)
            destination_rep = project_directory / source_rep.name
            clone = subprocess.run(
                ["cp", "-cR", str(source_rep), str(destination_rep)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if clone.returncode:
                shutil.copytree(source_rep, destination_rep)
            shard_project_directories.append(project_directory)
        print(
            f"ghidra-sharded-grep project_clones={args.jobs} status=complete",
            flush=True,
        )

        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(
                    _worker,
                    index,
                    spans[index],
                    part_paths[index],
                    shard_project_directories[index],
                    args,
                    script_directory,
                    environment,
                ): index
                for index in range(args.jobs)
            }
            for future in as_completed(futures):
                counts[futures[future]] = future.result()

    completed_counts = [count for count in counts if count is not None]
    visited = sum(count[0] for count in completed_counts)
    matched = sum(count[1] for count in completed_counts)
    with args.output.open("w") as destination:
        for index, part_path in enumerate(part_paths):
            destination.write(
                f"\n######## SHARD {index + 1}/{args.jobs} "
                f"{spans[index][0]:08x}..{spans[index][1]:08x} ########\n"
            )
            destination.write(part_path.read_text(errors="replace"))
        destination.write(f"\nMERGED_SUMMARY visited={visited} matched={matched}\n")

    for part_path in part_paths:
        part_path.unlink()

    manifest = {
        "schema_version": 1,
        "status": "complete",
        "jobs": args.jobs,
        "range": [f"{start:08x}", f"{end:08x}"],
        "needles": args.needles,
        "visited": visited,
        "matched": matched,
        "artifact": {
            "path": str(args.output.resolve()),
            "size": args.output.stat().st_size,
            "sha256": _sha256(args.output),
        },
    }
    manifest_path = args.output.with_suffix(args.output.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(
        f"ghidra-sharded-grep visited={visited} matched={matched} "
        f"output={args.output.resolve()} status=complete",
        flush=True,
    )
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--needle", dest="needles", action="append", required=True)
    parser.add_argument("--headless", type=Path, default=DEFAULT_HEADLESS)
    parser.add_argument("--project-directory", type=Path, default=DEFAULT_PROJECT_DIRECTORY)
    parser.add_argument("--project-name", default="Pathfinder")
    parser.add_argument("--program", default="libPathfinderApp.so")
    parser.add_argument("--user-home", type=Path, default=DEFAULT_USER_HOME)
    return parser


def main() -> int:
    try:
        run(build_parser().parse_args())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"run_ghidra_sharded_grep: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

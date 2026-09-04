#!/usr/bin/env python3
"""Run a JSON-defined stage pipeline and persist completion state."""

from __future__ import annotations

import os

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_manifest(path: Path) -> list[dict[str, object]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not value:
        raise ValueError("manifest must be a non-empty JSON list")
    for stage in value:
        if not isinstance(stage, dict) or not isinstance(stage.get("name"), str):
            raise ValueError("each stage needs a name")
        command = stage.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
            raise ValueError(f"stage {stage['name']} needs a non-empty string command list")
    return value


def save_state(path: Path, state: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--resume", action="store_true", help="skip stages already marked complete")
    args = parser.parse_args()
    if args.poll_seconds <= 0:
        raise ValueError("poll-seconds must be positive")
    stages = load_manifest(args.manifest)
    state: dict[str, object] = {"status": "running", "started_at": now(), "stages": []}
    if args.resume and args.state.exists():
        previous = json.loads(args.state.read_text(encoding="utf-8"))
        if isinstance(previous, dict) and previous.get("status") != "failed":
            state = previous
    completed = {
        str(row.get("name"))
        for row in state.get("stages", [])
        if isinstance(row, dict) and row.get("status") == "complete"
    }
    save_state(args.state, state)
    for stage in stages:
        name = str(stage["name"])
        if args.resume and name in completed:
            print(f"stage-watcher stage={name} status=skip-complete", flush=True)
            continue
        command = [os.path.expandvars(str(arg)) for arg in stage["command"]]
        cwd = stage.get("cwd")
        workdir = str(cwd) if isinstance(cwd, str) else None
        started = now()
        print(f"stage-watcher stage={name} status=start command={command!r}", flush=True)
        process = subprocess.Popen(command, cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert process.stdout is not None
        while True:
            line = process.stdout.readline()
            if line:
                print(f"[{name}] {line.rstrip()}", flush=True)
            elif process.poll() is not None:
                break
            else:
                time.sleep(args.poll_seconds)
                print(f"stage-watcher stage={name} status=running pid={process.pid}", flush=True)
        return_code = process.wait()
        entry = {"name": name, "command": command, "started_at": started, "finished_at": now(), "exit_code": return_code, "status": "complete" if return_code == 0 else "failed"}
        stage_rows = [row for row in state.get("stages", []) if isinstance(row, dict) and row.get("name") != name]
        stage_rows.append(entry)
        state["stages"] = stage_rows
        if return_code != 0:
            state["status"] = "failed"
            state["failed_stage"] = name
            state["finished_at"] = now()
            save_state(args.state, state)
            print(f"stage-watcher stage={name} status=failed exit_code={return_code}", file=sys.stderr, flush=True)
            return return_code
        save_state(args.state, state)
        print(f"stage-watcher stage={name} status=complete", flush=True)
    state["status"] = "complete"
    state["finished_at"] = now()
    save_state(args.state, state)
    print("stage-watcher status=complete", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"stage-watcher error: {error}", file=sys.stderr)
        raise SystemExit(2)

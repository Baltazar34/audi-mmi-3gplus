#!/usr/bin/env python3
"""run_container_pipeline.py — orkestrator za container/ATLAS sloj.

Pokrece faze iz JSON manifesta.  Za razliku od `orion_stage_watcher.py`,
koji je sekvencijalan, ovde:

  * faza ima `depends_on` — pokrece se tek kad sve zavisnosti prodju;
  * nezavisne faze idu paralelno, do `--jobs` odjednom;
  * faza ima `gate`: Python izraz nad `report` (ucitani JSON izvestaja
    faze) koji mora biti tacan da bi faza prosla.  Exit code 0 nije dovoljan;
  * trijaza: ako gate padne, faza je `failed`, sve sto zavisi od nje je
    `skipped` sa razlogom, a nezavisne faze nastavljaju;
  * `on_fail` (opciono) je ime faze koja se pokrece samo ako ova padne —
    to je if/else grana za dijagnostiku;
  * stanje se cuva posle svake promene, pa `--resume` preskace prosle faze.

Manifest primer:

    [{"name": "grammar", "command": [...], "report": "out/x/report.json",
      "gate": "report['not_explained'] == 0"},
     {"name": "writer", "depends_on": ["grammar"], ...,
      "on_fail": "writer-diagnose"},
     {"name": "writer-diagnose", "manual": true, ...}]

Faze sa `manual: true` se ne pokrecu same, samo preko `on_fail`.
"""

from __future__ import annotations

import os

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_manifest(path: Path) -> dict[str, dict[str, object]]:
    stages = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, object]] = {}
    for stage in stages:
        name = stage["name"]
        if name in out:
            raise ValueError(f"duplo ime faze: {name}")
        stage.setdefault("depends_on", [])
        stage.setdefault("manual", False)
        out[name] = stage
    for stage in out.values():
        for dep in stage["depends_on"]:
            if dep not in out:
                raise ValueError(f"{stage['name']} zavisi od nepoznate faze {dep}")
    return out


def evaluate_gate(stage: dict[str, object], cwd: Path) -> tuple[bool, str]:
    gate = stage.get("gate")
    report_path = stage.get("report")
    if not gate:
        return True, "bez gate-a"
    if not report_path:
        return False, "gate bez report putanje"
    path = cwd / str(report_path)
    if not path.exists():
        return False, f"izvestaj ne postoji: {report_path}"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return False, f"izvestaj nije JSON: {error}"
    try:
        safe = {"len": len, "all": all, "any": any, "sum": sum, "min": min, "max": max,
                "int": int, "float": float, "str": str, "abs": abs, "round": round}
        ok = bool(eval(str(gate), {"__builtins__": safe}, {"report": report}))  # noqa: S307
    except Exception as error:                                              # noqa: BLE001
        return False, f"gate greska: {error}"
    return ok, "gate prosao" if ok else f"gate pao: {gate}"


def run_stage(name: str, stage: dict[str, object], cwd: Path, log_dir: Path) -> dict[str, object]:
    log_path = log_dir / f"{name}.log"
    started = time.time()
    print(f"[{now()}] START  {name}", flush=True)
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run([os.path.expandvars(str(a)) for a in stage["command"]], cwd=cwd, stdout=log,
                              stderr=subprocess.STDOUT, text=True)
    ok, reason = (False, f"exit {proc.returncode}") if proc.returncode else evaluate_gate(stage, cwd)
    status = "passed" if ok else "failed"
    print(f"[{now()}] {status.upper():<6} {name}  ({time.time() - started:.0f}s)  {reason}", flush=True)
    return {"status": status, "reason": reason, "exit_code": proc.returncode,
            "seconds": round(time.time() - started, 1), "log": str(log_path)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--state", type=Path, required=True)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--only", action="append", default=[], help="pokreni samo ove faze (i zavisnosti)")
    args = ap.parse_args()

    cwd = Path.cwd()
    stages = load_manifest(args.manifest)
    log_dir = args.state.parent / (args.state.stem + "_logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    state: dict[str, dict[str, object]] = {}
    if args.resume and args.state.exists():
        state = json.loads(args.state.read_text(encoding="utf-8")).get("stages", {})
        state = {k: v for k, v in state.items() if v.get("status") == "passed"}

    wanted = set(stages)
    if args.only:
        wanted = set()
        todo = list(args.only)
        while todo:
            n = todo.pop()
            if n in wanted:
                continue
            wanted.add(n)
            todo.extend(stages[n]["depends_on"])

    def save() -> None:
        args.state.parent.mkdir(parents=True, exist_ok=True)
        args.state.write_text(json.dumps({"updated": now(), "stages": state},
                                         indent=2, ensure_ascii=False, sort_keys=True))

    pending = {n for n in wanted if n not in state and not stages[n]["manual"]}
    running: dict[object, str] = {}
    pool = ThreadPoolExecutor(max_workers=args.jobs)

    def ready(name: str) -> bool:
        return all(state.get(d, {}).get("status") == "passed" for d in stages[name]["depends_on"])

    def blocked_by(name: str) -> str | None:
        for d in stages[name]["depends_on"]:
            if state.get(d, {}).get("status") in ("failed", "skipped"):
                return d
        return None

    while pending or running:
        progressed = False
        for name in sorted(pending):
            blocker = blocked_by(name)
            if blocker:
                state[name] = {"status": "skipped", "reason": f"zavisi od {blocker} ({state[blocker]['status']})"}
                print(f"[{now()}] SKIP   {name}  zavisi od {blocker}", flush=True)
                pending.discard(name); progressed = True; save()
                continue
            if ready(name) and len(running) < args.jobs:
                fut = pool.submit(run_stage, name, stages[name], cwd, log_dir)
                running[fut] = name
                pending.discard(name); progressed = True
        if not running:
            if pending and not progressed:
                for name in sorted(pending):
                    state[name] = {"status": "skipped", "reason": "zavisnosti nikad nisu prosle"}
                pending.clear(); save()
            break
        done, _ = wait(list(running), return_when=FIRST_COMPLETED)
        for fut in done:
            name = running.pop(fut)
            state[name] = fut.result()
            save()
            if state[name]["status"] == "failed":
                fallback = stages[name].get("on_fail")
                if fallback and fallback in stages and fallback not in state:
                    print(f"[{now()}] TRIAGE {name} pao -> pokrecem {fallback}", flush=True)
                    stages[fallback]["manual"] = False
                    stages[fallback]["depends_on"] = []
                    pending.add(fallback)
    pool.shutdown(wait=True)

    summary = {}
    for n in sorted(wanted):
        summary[state.get(n, {}).get("status", "not-run")] = summary.get(state.get(n, {}).get("status", "not-run"), 0) + 1
    print(f"\n[{now()}] rezime: {summary}")
    for n in sorted(wanted):
        s = state.get(n, {})
        print(f"  {s.get('status', 'not-run'):<8} {n:<32} {s.get('reason', '')}")
    return 0 if all(state.get(n, {}).get("status") == "passed" for n in wanted if not stages[n]["manual"]) else 1


if __name__ == "__main__":
    sys.exit(main())

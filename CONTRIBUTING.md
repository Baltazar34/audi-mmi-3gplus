# Contributing

Thanks for looking. A few rules keep this repository safe to host.

## What is welcome

- Reports from other units and regions: firmware version, map part number,
  which tools ran, what the reports said. Open an issue with the JSON report
  attached (reports contain hashes and counts, not map content).
- Writers for the layers whose format is decoded but not yet written
  (see `docs/PKGDB_LAYERS.md`): 3D cities, terrain, text, TMC, POI.
- Semantic decoding of the open AdvancedRouting / ADAS / VidTable / XAC
  parts, with firmware evidence.
- Corrections. If a claim in the docs does not hold on your data, that is
  the most valuable issue you can open.

## What will not be merged

- Map data, firmware images, extracted binaries, or links to dumps of them.
- Anything that patches firmware, forges or strips signatures, uses the
  factory skip switches, or works around the FSC licence.
- Ad-hoc analysis without a script. Every claim here is backed by a tool
  that walks the full corpus and writes a report with checksums.

## How the tools are written

- Python 3.10+, standard library only. No new dependencies.
- One tool, one job, `argparse`, a module docstring whose first line says
  what it does (it becomes the row in `docs/TOOLS.md`).
- Read-only on inputs. Outputs go under `out/<tool_name>/` with
  `report.json` and `CHECKSUMS.sha256`.
- Print progress, stop at the first inconsistency, never guess silently.
- Inputs come from environment variables (`MIB_MAP_ROOT`, `MMI3G_PKGDB`,
  `NAVCORE_ELF`, ...) or explicit arguments; never from hard-coded home
  paths.

## Before opening a pull request

```bash
python3 -m unittest discover -s tests
python3 scripts/gen_tools_index.py
```

Integration tests skip themselves when the local map or firmware is not
present, so the suite must pass on a clean checkout.

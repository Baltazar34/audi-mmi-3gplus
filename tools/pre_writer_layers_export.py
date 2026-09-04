#!/usr/bin/env python3
"""Export lossless per-edge AdvancedRouting/ADAS source before Orion writing."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from basic_geometry_decode import _build_cluster, _group_entries
from pre_writer_layers import decode_adas_cluster, decode_advanced_routing_cluster
from psf_decode import (
    PsfError,
    _decode_indexed_lzma,
    read_adas_index,
    read_advanced_routing_index,
    read_basic_triple_handle_index,
)


SCHEMA_VERSION = 1


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"pre-writer-export stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_map(index: dict[str, object]) -> dict[int, dict[str, object]]:
    return {int(entry["cluster_id"]): entry for entry in index["entries"]}


def run(basic: Path, advanced_routing: Path, adas: Path, output: Path) -> dict[str, object]:
    _progress("index")
    basic_index = read_basic_triple_handle_index(basic)
    basic_order, basic_handles = _group_entries(basic_index)
    advanced_index = read_advanced_routing_index(advanced_routing)
    adas_index = read_adas_index(adas)
    advanced_entries = _entry_map(advanced_index)
    adas_entries = _entry_map(adas_index)
    basic_ids = set(basic_order)
    adas_ids = set(adas_entries)
    if basic_ids != adas_ids:
        raise PsfError(
            f"Basic/ADAS cluster-ID mismatch: basic-only={sorted(basic_ids-adas_ids)[:8]} "
            f"adas-only={sorted(adas_ids-basic_ids)[:8]}"
        )

    output.mkdir(parents=True, exist_ok=True)
    edge_path = output / "edge_layers.jsonl"
    supra_path = output / "advanced_routing_supra.jsonl"
    edge_temporary = edge_path.with_suffix(".jsonl.tmp")
    supra_temporary = supra_path.with_suffix(".jsonl.tmp")
    edge_count = 0
    advanced_regular_count = 0
    missing_advanced_count = 0

    _progress("export-regular", clusters=len(basic_order))
    with (
        basic.open("rb") as basic_source,
        advanced_routing.open("rb") as advanced_source,
        adas.open("rb") as adas_source,
        edge_temporary.open("w", encoding="utf-8") as target,
    ):
        for ordinal, cluster_id in enumerate(basic_order, start=1):
            handles = basic_handles[cluster_id]
            topology = _decode_indexed_lzma(basic_source, handles[0])
            geometry = _decode_indexed_lzma(basic_source, handles[1])
            basic_cluster = _build_cluster(cluster_id, topology, geometry)
            adas_cluster = decode_adas_cluster(
                _decode_indexed_lzma(adas_source, adas_entries[cluster_id])
            )
            if adas_cluster.edge_count != basic_cluster.edge_count:
                raise PsfError(
                    f"cluster {cluster_id} Basic/ADAS edge-count mismatch: "
                    f"{basic_cluster.edge_count} != {adas_cluster.edge_count}"
                )
            advanced_cluster = None
            if cluster_id in advanced_entries:
                advanced_cluster = decode_advanced_routing_cluster(
                    _decode_indexed_lzma(advanced_source, advanced_entries[cluster_id])
                )
                if advanced_cluster.edge_count != basic_cluster.edge_count:
                    raise PsfError(
                        f"cluster {cluster_id} Basic/AdvancedRouting edge-count mismatch: "
                        f"{basic_cluster.edge_count} != {advanced_cluster.edge_count}"
                    )
            for edge_index in range(basic_cluster.edge_count):
                adas_record = adas_cluster.records[edge_index]
                advanced_record = (
                    advanced_cluster.records[edge_index]
                    if advanced_cluster is not None
                    else None
                )
                row = {
                    "schema_version": SCHEMA_VERSION,
                    "cluster_id": cluster_id,
                    "edge_index": edge_index,
                    "edge_id": (cluster_id << 8) | edge_index,
                    "edge_id_hex": f"0x{((cluster_id << 8) | edge_index):08x}",
                    "advanced_routing": None
                    if advanced_record is None
                    else {
                        "cluster_metadata_u16": advanced_cluster.metadata_u16,
                        "offset": advanced_record.offset,
                        "size": advanced_record.size,
                        "raw_hex": advanced_record.raw.hex(),
                    },
                    "adas": {
                        "offset": adas_record.offset,
                        "size": adas_record.size,
                        "raw_hex": adas_record.raw.hex(),
                    },
                }
                target.write(json.dumps(row, sort_keys=True) + "\n")
                edge_count += 1
                if advanced_record is None:
                    missing_advanced_count += 1
                else:
                    advanced_regular_count += 1
            if ordinal % 250 == 0 or ordinal == len(basic_order):
                _progress(
                    "export-regular-progress",
                    clusters=ordinal,
                    total=len(basic_order),
                    edges=edge_count,
                )
    edge_temporary.replace(edge_path)

    supra_ids = sorted(set(advanced_entries) - basic_ids)
    supra_record_count = 0
    _progress("export-supra", clusters=len(supra_ids))
    with advanced_routing.open("rb") as source, supra_temporary.open(
        "w", encoding="utf-8"
    ) as target:
        for cluster_id in supra_ids:
            cluster = decode_advanced_routing_cluster(
                _decode_indexed_lzma(source, advanced_entries[cluster_id])
            )
            for record in cluster.records:
                target.write(
                    json.dumps(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "cluster_id": cluster_id,
                            "record_index": record.edge_index,
                            "cluster_metadata_u16": cluster.metadata_u16,
                            "offset": record.offset,
                            "size": record.size,
                            "raw_hex": record.raw.hex(),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
                supra_record_count += 1
    supra_temporary.replace(supra_path)

    checks = {
        "basic_and_adas_cluster_ids_match": basic_ids == adas_ids,
        "all_basic_edges_have_adas": edge_count > 0,
        "advanced_regular_plus_missing_equals_basic": advanced_regular_count
        + missing_advanced_count
        == edge_count,
        "supra_cluster_count_is_seven": len(supra_ids) == 7,
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete" if all(checks.values()) else "failed",
        "sources": {
            "basic": {"path": str(basic), "sha256": _sha256(basic)},
            "advanced_routing": {
                "path": str(advanced_routing),
                "sha256": _sha256(advanced_routing),
            },
            "adas": {"path": str(adas), "sha256": _sha256(adas)},
        },
        "counts": {
            "basic_clusters": len(basic_ids),
            "edges": edge_count,
            "advanced_regular_records": advanced_regular_count,
            "advanced_missing_records": missing_advanced_count,
            "advanced_supra_clusters": len(supra_ids),
            "advanced_supra_records": supra_record_count,
            "adas_records": edge_count,
        },
        "advanced_supra_cluster_ids": supra_ids,
        "checks": checks,
        "artifacts": {
            edge_path.name: {"size": edge_path.stat().st_size, "sha256": _sha256(edge_path)},
            supra_path.name: {
                "size": supra_path.stat().st_size,
                "sha256": _sha256(supra_path),
            },
        },
    }
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        "".join(
            f"{_sha256(path)}  {path.name}\n"
            for path in (edge_path, supra_path, report_path)
        ),
        encoding="ascii",
    )
    if report["status"] != "complete":
        raise PsfError(f"pre-writer export checks failed: {checks}")
    _progress("complete", output=output, edges=edge_count, supra_records=supra_record_count)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basic", type=Path, required=True)
    parser.add_argument("--advanced-routing", type=Path, required=True)
    parser.add_argument("--adas", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.basic, args.advanced_routing, args.adas, args.output)
    except (OSError, PsfError, ValueError) as error:
        print(f"pre-writer-export error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

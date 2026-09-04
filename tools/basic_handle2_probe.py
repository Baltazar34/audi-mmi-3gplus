#!/usr/bin/env python3
"""Inventory and rank structural candidates in every Basic handle-2 payload."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import struct
import sys

from psf_decode import PsfError, _decode_indexed_lzma, read_basic_triple_handle_index


SCHEMA_VERSION = 1
ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
FIELD_SCAN_LIMIT = 64
TABLE_BASE_LIMIT = 96


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"handle2-probe stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _strict_offsets(payload: bytes, base: int, count: int) -> bool:
    if count <= 0 or base + count * 2 > len(payload):
        return False
    values = list(struct.unpack_from(f"<{count}H", payload, base))
    return (
        values == sorted(set(values))
        and base + count * 2 <= values[0]
        and values[-1] < len(payload)
    )


def _field_rank(
    records: list[dict[str, object]], width: int, target: str
) -> list[dict[str, int]]:
    scores: list[dict[str, int]] = []
    for offset in range(FIELD_SCAN_LIMIT):
        matches = 0
        available = 0
        for record in records:
            payload = record["payload"]
            assert isinstance(payload, bytes)
            if offset + width > len(payload):
                continue
            available += 1
            value = (
                payload[offset]
                if width == 1
                else struct.unpack_from("<H", payload, offset)[0]
            )
            if value == int(record[target]):
                matches += 1
        scores.append(
            {
                "offset": offset,
                "width": width,
                "matches": matches,
                "available": available,
            }
        )
    return sorted(scores, key=lambda item: (-item["matches"], item["offset"]))[:20]


def _table_rank(
    records: list[dict[str, object]], target: str
) -> list[dict[str, int]]:
    result: list[dict[str, int]] = []
    for base in range(TABLE_BASE_LIMIT):
        valid = 0
        available = 0
        for record in records:
            payload = record["payload"]
            assert isinstance(payload, bytes)
            count = int(record[target])
            if count > 0 and base + count * 2 <= len(payload):
                available += 1
                valid += int(_strict_offsets(payload, base, count))
        result.append({"base": base, "valid": valid, "available": available})
    return sorted(result, key=lambda item: (-item["valid"], item["base"]))[:20]


def _pointer_rank(records: list[dict[str, object]]) -> list[dict[str, int]]:
    result: list[dict[str, int]] = []
    for offset in range(FIELD_SCAN_LIMIT):
        valid = 0
        nonzero = 0
        available = 0
        for record in records:
            payload = record["payload"]
            assert isinstance(payload, bytes)
            if offset + 2 > len(payload):
                continue
            available += 1
            value = struct.unpack_from("<H", payload, offset)[0]
            nonzero += int(value != 0)
            valid += int(0 < value < len(payload))
        result.append(
            {
                "offset": offset,
                "valid_in_payload": valid,
                "nonzero": nonzero,
                "available": available,
            }
        )
    return sorted(
        result,
        key=lambda item: (-item["valid_in_payload"], item["offset"]),
    )[:20]


def _firmware_edge_directory_rank(
    records: list[dict[str, object]],
) -> list[dict[str, int]]:
    """Test the exact directory formula used by firmware VA 0x014a4538."""
    result: list[dict[str, int]] = []
    for config_offset in range(33):
        table_fits = 0
        pointers_in_payload = 0
        pointers_after_table = 0
        monotonic = 0
        for record in records:
            payload = record["payload"]
            assert isinstance(payload, bytes)
            edge_count = int(record["edge_count"])
            if config_offset + 2 > len(payload):
                continue
            auxiliary_count = struct.unpack_from("<H", payload, config_offset)[0]
            relative_base = 2 if auxiliary_count == 0 else auxiliary_count * 4 + 6
            table_base = config_offset + relative_base
            table_end = table_base + edge_count * 2
            if table_end > len(payload):
                continue
            table_fits += 1
            offsets = list(struct.unpack_from(f"<{edge_count}H", payload, table_base))
            pointers_in_payload += int(all(offset < len(payload) for offset in offsets))
            pointers_after_table += int(all(table_end <= offset < len(payload) for offset in offsets))
            monotonic += int(offsets == sorted(offsets))
        result.append(
            {
                "config_offset": config_offset,
                "table_fits": table_fits,
                "all_pointers_in_payload": pointers_in_payload,
                "all_pointers_after_table": pointers_after_table,
                "monotonic_offsets": monotonic,
            }
        )
    return sorted(
        result,
        key=lambda item: (
            -item["all_pointers_after_table"],
            -item["monotonic_offsets"],
            -item["table_fits"],
            item["config_offset"],
        ),
    )


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    grouped: dict[int, dict[int, dict[str, object]]] = {}
    order: list[int] = []
    for entry in index["entries"]:  # type: ignore[index]
        cluster_id = int(entry["cluster_id"])
        handle = int(entry["handle_index"])
        if cluster_id not in grouped:
            grouped[cluster_id] = {}
            order.append(cluster_id)
        grouped[cluster_id][handle] = entry
    if any(set(handles) != {0, 1, 2} for handles in grouped.values()):
        raise PsfError("Basic triple index is not complete")

    records: list[dict[str, object]] = []
    sizes: list[int] = []
    entropies: list[float] = []
    first_bytes = collections.Counter()
    first_u16 = collections.Counter()
    string_counts = collections.Counter()
    total_ascii_runs = 0
    total_ascii_bytes = 0
    hashes = collections.Counter()
    _progress("decode", clusters_total=len(order))
    with psf.open("rb") as source:
        for ordinal, cluster_id in enumerate(order, 1):
            topology = _decode_indexed_lzma(source, grouped[cluster_id][0])
            payload = _decode_indexed_lzma(source, grouped[cluster_id][2])
            if len(topology) < 5:
                raise PsfError(f"cluster {cluster_id} truncated topology")
            runs = [match.group().decode("ascii") for match in ASCII_RUN.finditer(payload)]
            total_ascii_runs += len(runs)
            total_ascii_bytes += sum(len(value) for value in runs)
            string_counts.update(runs)
            sizes.append(len(payload))
            entropies.append(_entropy(payload))
            if payload:
                first_bytes[payload[0]] += 1
            if len(payload) >= 2:
                first_u16[struct.unpack_from("<H", payload)[0]] += 1
            digest = hashlib.sha256(payload).hexdigest()
            hashes[digest] += 1
            records.append(
                {
                    "cluster_id": cluster_id,
                    "edge_count": topology[2],
                    "node_count": topology[4],
                    "payload": payload,
                    "ascii_runs": runs,
                    "sha256": digest,
                }
            )
            if ordinal % 250 == 0 or ordinal == len(order):
                _progress("decode-progress", clusters=ordinal, total=len(order))

    _progress("rank-layouts")
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "inventory-complete",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "counts": {
            "clusters": len(records),
            "decoded_bytes": sum(sizes),
            "minimum_payload_size": min(sizes),
            "median_payload_size": statistics.median(sizes),
            "maximum_payload_size": max(sizes),
            "empty_payloads": sum(size == 0 for size in sizes),
            "unique_payload_hashes": len(hashes),
            "duplicate_payload_instances": sum(count - 1 for count in hashes.values()),
            "ascii_runs": total_ascii_runs,
            "ascii_bytes": total_ascii_bytes,
            "minimum_entropy": min(entropies),
            "median_entropy": statistics.median(entropies),
            "maximum_entropy": max(entropies),
        },
        "header_histograms": {
            "byte_0": {str(key): value for key, value in first_bytes.most_common(64)},
            "u16_le_0": {str(key): value for key, value in first_u16.most_common(64)},
        },
        "layout_candidates": {
            "u8_equal_edge_count": _field_rank(records, 1, "edge_count"),
            "u16_equal_edge_count": _field_rank(records, 2, "edge_count"),
            "u8_equal_node_count": _field_rank(records, 1, "node_count"),
            "u16_equal_node_count": _field_rank(records, 2, "node_count"),
            "direct_u16_edge_offset_tables": _table_rank(records, "edge_count"),
            "direct_u16_node_offset_tables": _table_rank(records, "node_count"),
            "u16_in_payload_pointers": _pointer_rank(records),
            "firmware_edge_directory_formula": _firmware_edge_directory_rank(records),
        },
        "ascii": {
            "most_common_runs": [
                {"value": value, "count": count}
                for value, count in string_counts.most_common(100)
            ]
        },
        "interpretation": {
            "semantic_status": "unknown until firmware consumers select a layout",
            "next_step": "run_basic_handle2_re.py decompiles the dedicated loader and xrefs",
        },
    }

    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "cluster_sample.jsonl"
    sample_temporary = sample_path.with_suffix(sample_path.suffix + ".tmp")
    with sample_temporary.open("w", encoding="utf-8") as destination:
        for record in records[: sample_limit or None]:
            payload = record["payload"]
            assert isinstance(payload, bytes)
            destination.write(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "record_type": "basic-handle2-cluster-source",
                        "cluster_id": record["cluster_id"],
                        "edge_count": record["edge_count"],
                        "node_count": record["node_count"],
                        "payload_size": len(payload),
                        "payload_sha256": record["sha256"],
                        "prefix_hex": payload[:256].hex(),
                        "ascii_runs": record["ascii_runs"][:100],  # type: ignore[index]
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )
    sample_temporary.replace(sample_path)
    report["artifacts"] = {
        "report": "report.json",
        "cluster_sample": sample_path.name,
        "cluster_sample_count": len(records) if sample_limit == 0 else min(sample_limit, len(records)),
        "checksums": "CHECKSUMS.sha256",
    }
    report_path = output / "report.json"
    temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(report_path)
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n"
        f"{_sha256(sample_path)}  {sample_path.name}\n",
        encoding="ascii",
    )
    _progress("complete", output=output)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-limit", type=int, default=100)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.psf, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_handle2_probe: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "clusters": report["counts"]["clusters"],  # type: ignore[index]
                "decoded_bytes": report["counts"]["decoded_bytes"],  # type: ignore[index]
                "ascii_runs": report["counts"]["ascii_runs"],  # type: ignore[index]
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

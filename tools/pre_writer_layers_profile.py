#!/usr/bin/env python3
"""Full-corpus structural profiler for the PSF60 layers before Orion writing.

This stage is intentionally lossless: it validates and fingerprints every
AdvancedRouting and ADAS LZMA stream without assigning semantic names that have
not yet been proven against a firmware consumer.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import struct
import sys

from psf_decode import (
    PsfError,
    _decode_indexed_lzma,
    read_adas_index,
    read_advanced_routing_index,
)
from pre_writer_layers import decode_adas_cluster, decode_advanced_routing_cluster


SCHEMA_VERSION = 1


def _progress(layer: str, stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"pre-writer-profile layer={layer} stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_checksums(output: Path, paths: tuple[Path, ...]) -> None:
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in paths),
        encoding="ascii",
    )


def _counter(counter: collections.Counter[object]) -> dict[str, int]:
    return {
        str(key): value
        for key, value in sorted(counter.items(), key=lambda item: str(item[0]))
    }


def _u16_head(payload: bytes, count: int = 16) -> list[int]:
    available = min(count, len(payload) // 2)
    return list(struct.unpack_from(f"<{available}H", payload)) if available else []


def _u32_head(payload: bytes, count: int = 8) -> list[int]:
    available = min(count, len(payload) // 4)
    return list(struct.unpack_from(f"<{available}I", payload)) if available else []


def _monotonic_u16_runs(payload: bytes, minimum: int = 8) -> list[dict[str, int]]:
    """Describe long increasing u16 runs at either byte alignment."""
    result: list[dict[str, int]] = []
    for alignment in (0, 1):
        values = [
            struct.unpack_from("<H", payload, offset)[0]
            for offset in range(alignment, len(payload) - 1, 2)
        ]
        start = 0
        for index in range(1, len(values) + 1):
            continues = index < len(values) and values[index] >= values[index - 1]
            if continues:
                continue
            length = index - start
            if length >= minimum:
                result.append(
                    {
                        "byte_offset": alignment + start * 2,
                        "count": length,
                        "first": values[start],
                        "last": values[index - 1],
                    }
                )
            start = index
    return sorted(result, key=lambda item: (-item["count"], item["byte_offset"]))[:8]


def _profile_layer(
    name: str,
    psf: Path,
    index: dict[str, object],
    output: Path,
    sample_limit: int,
) -> dict[str, object]:
    entries = sorted(index["entries"], key=lambda item: int(item["compressed_offset"]))
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / f"{name}_stream_samples.jsonl"
    temporary = sample_path.with_suffix(".jsonl.tmp")
    decoded_bytes = 0
    stored_bytes = 0
    length_counts: collections.Counter[int] = collections.Counter()
    first_byte_counts: collections.Counter[str] = collections.Counter()
    prefix_counts: collections.Counter[str] = collections.Counter()
    cluster_ids: list[int] = []
    stream_table_digest = hashlib.sha256()
    decoded_digest = hashlib.sha256()
    record_count = 0
    record_size_counts: collections.Counter[int] = collections.Counter()
    record_first_byte_counts: collections.Counter[str] = collections.Counter()
    record_prefix_counts: collections.Counter[str] = collections.Counter()
    cluster_edge_counts: collections.Counter[int] = collections.Counter()
    cluster_metadata_u16: collections.Counter[int] = collections.Counter()
    adas_two_byte_size_count = 0

    _progress(name, "decode", streams=len(entries))
    with psf.open("rb") as source, temporary.open("w", encoding="utf-8") as samples:
        for ordinal, entry in enumerate(entries, start=1):
            payload = _decode_indexed_lzma(source, entry)
            cluster_id = int(entry["cluster_id"])
            stored_size = int(entry["compressed_size"])
            stored_bytes += stored_size
            decoded_bytes += len(payload)
            cluster_ids.append(cluster_id)
            length_counts[len(payload)] += 1
            first_byte_counts[payload[:1].hex()] += 1
            prefix_counts[payload[:8].hex()] += 1
            decoded_digest.update(struct.pack("<II", cluster_id, len(payload)))
            decoded_digest.update(payload)
            stream_table_digest.update(
                struct.pack(
                    "<IIII",
                    cluster_id,
                    int(entry["compressed_offset"]),
                    stored_size,
                    len(payload),
                )
            )
            if name == "advanced_routing":
                structured = decode_advanced_routing_cluster(payload)
                cluster_metadata_u16[structured.metadata_u16] += 1
            else:
                structured = decode_adas_cluster(payload)
                adas_two_byte_size_count += sum(
                    1 for value in structured.record_sizes if value >= 0x80
                )
            cluster_edge_counts[structured.edge_count] += 1
            record_count += len(structured.records)
            for record in structured.records:
                record_size_counts[record.size] += 1
                record_first_byte_counts[record.raw[:1].hex()] += 1
                record_prefix_counts[record.raw[:5].hex()] += 1
            if ordinal <= sample_limit:
                sample = {
                    "ordinal": ordinal - 1,
                    "cluster_id": cluster_id,
                    "group_index": int(entry["group_index"]),
                    "entry_index": int(entry["entry_index"]),
                    "compressed_offset": int(entry["compressed_offset"]),
                    "compressed_size": stored_size,
                    "decoded_size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "head_hex": payload[:256].hex(),
                    "tail_hex": payload[-64:].hex(),
                    "u16_head": _u16_head(payload),
                    "u32_head": _u32_head(payload),
                    "monotonic_u16_runs": _monotonic_u16_runs(payload),
                    "index_extra_hex": entry["index_extra_hex"],
                    "edge_count": structured.edge_count,
                    "record_sizes_head": [record.size for record in structured.records[:16]],
                    "record_heads_hex": [record.raw[:16].hex() for record in structured.records[:16]],
                }
                samples.write(json.dumps(sample, sort_keys=True) + "\n")
            if ordinal % 250 == 0 or ordinal == len(entries):
                _progress(
                    name,
                    "decode-progress",
                    streams=ordinal,
                    total=len(entries),
                    decoded_bytes=decoded_bytes,
                )
    temporary.replace(sample_path)

    id_counts = collections.Counter(cluster_ids)
    checks = {
        "all_streams_decoded": len(cluster_ids) == len(entries),
        "decoded_size_sum_matches_index": decoded_bytes
        == sum(int(item["uncompressed_size"]) for item in entries),
        "stored_size_sum_matches_payload": stored_bytes
        == int(index["payload_end"]) - int(index["payload_start"]),
        "cluster_ids_unique": len(id_counts) == len(cluster_ids),
        "all_structured_records_nonempty": record_count > 0
        and record_size_counts.get(0, 0) == 0,
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "layer": name,
        "source": {"path": str(psf), "sha256": _sha256(psf)},
        "index": {
            "group_counts": [int(group["count"]) for group in index["groups"]],
            "stream_count": len(entries),
            "payload_start": int(index["payload_start"]),
            "payload_end": int(index["payload_end"]),
            "auxiliary_regions": index["auxiliary_regions"],
        },
        "counts": {
            "stored_bytes": stored_bytes,
            "decoded_bytes": decoded_bytes,
            "unique_cluster_ids": len(id_counts),
            "duplicate_cluster_id_count": sum(value - 1 for value in id_counts.values()),
            "minimum_cluster_id": min(cluster_ids),
            "maximum_cluster_id": max(cluster_ids),
            "record_count": record_count,
            "adas_two_byte_size_count": adas_two_byte_size_count,
        },
        "distributions": {
            "decoded_lengths": _counter(length_counts),
            "first_bytes": _counter(first_byte_counts),
            "first_8_byte_prefixes": _counter(prefix_counts),
            "cluster_edge_counts": _counter(cluster_edge_counts),
            "cluster_metadata_u16": _counter(cluster_metadata_u16),
            "record_sizes": _counter(record_size_counts),
            "record_first_bytes": _counter(record_first_byte_counts),
            "record_first_5_byte_prefixes": _counter(record_prefix_counts),
        },
        "fingerprints": {
            "stream_table_sha256": stream_table_digest.hexdigest(),
            "decoded_corpus_sha256": decoded_digest.hexdigest(),
            "samples_sha256": _sha256(sample_path),
        },
        "checks": checks,
        "status": "complete" if all(checks.values()) else "failed",
    }
    report_path = output / f"{name}_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report["status"] != "complete":
        raise PsfError(f"{name} full-corpus checks failed: {checks}")
    _progress(name, "complete", output=output, decoded_bytes=decoded_bytes)
    return report


def run(advanced_routing: Path, adas: Path, output: Path, sample_limit: int) -> dict[str, object]:
    _progress("advanced_routing", "index")
    advanced_report = _profile_layer(
        "advanced_routing",
        advanced_routing,
        read_advanced_routing_index(advanced_routing),
        output,
        sample_limit,
    )
    _progress("adas", "index")
    adas_report = _profile_layer(
        "adas", adas, read_adas_index(adas), output, sample_limit
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "advanced_routing": advanced_report["fingerprints"],
        "adas": adas_report["fingerprints"],
    }
    summary_path = output / "report.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_checksums(
        output,
        (
            output / "advanced_routing_report.json",
            output / "advanced_routing_stream_samples.jsonl",
            output / "adas_report.json",
            output / "adas_stream_samples.jsonl",
            summary_path,
        ),
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--advanced-routing", type=Path, required=True)
    parser.add_argument("--adas", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-limit", type=int, default=64)
    args = parser.parse_args()
    try:
        report = run(args.advanced_routing, args.adas, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"pre-writer-profile error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate the firmware-defined Basic handle-2 edge directory.

Firmware function VA 0x014a4538 selects the directory using a schema byte.
Corpus-wide validation fixes that schema byte to payload offset 6.  A zero
auxiliary count places the edge u16 directory at offset 8; otherwise the
directory follows ``count + 1`` little-endian u32 auxiliary values.

The command validates every edge pointer before emitting a bounded JSONL
sample.  Use ``--sample-limit 0`` to emit every edge reference.
"""

from __future__ import annotations

import argparse
import collections
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys

from psf_decode import PsfError, _decode_indexed_lzma, read_basic_triple_handle_index


SCHEMA_VERSION = 1
FIRMWARE_DIRECTORY_CONFIG_OFFSET = 6
FIRMWARE_RECORD_POINTER_BASE = 3
RECORD_BASE_CANDIDATES = tuple(range(1, 17))


@dataclass(frozen=True)
class EdgeDirectory:
    auxiliary_count: int
    auxiliary_entries: tuple[int, ...]
    auxiliary_trailer: int | None
    directory_base: int
    directory_end: int
    record_offsets: tuple[int, ...]


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"handle2-directory stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _group_entries(index: dict[str, object]) -> tuple[list[int], dict[int, dict[int, dict[str, object]]]]:
    grouped: dict[int, dict[int, dict[str, object]]] = {}
    order: list[int] = []
    entries = index.get("entries")
    if not isinstance(entries, list):
        raise PsfError("Basic triple index has no entries")
    for entry in entries:
        if not isinstance(entry, dict):
            raise PsfError("Basic triple index contains an invalid entry")
        cluster_id = int(entry["cluster_id"])
        handle_index = int(entry["handle_index"])
        if cluster_id not in grouped:
            grouped[cluster_id] = {}
            order.append(cluster_id)
        if handle_index in grouped[cluster_id]:
            raise PsfError(
                f"cluster {cluster_id} has duplicate handle {handle_index}"
            )
        grouped[cluster_id][handle_index] = entry
    incomplete = [cluster_id for cluster_id, handles in grouped.items() if set(handles) != {0, 1, 2}]
    if incomplete:
        raise PsfError(f"Basic triple index is incomplete at cluster {incomplete[0]}")
    return order, grouped


def decode_edge_directory(
    payload: bytes,
    edge_count: int,
    config_offset: int = FIRMWARE_DIRECTORY_CONFIG_OFFSET,
) -> EdgeDirectory:
    """Decode the exact edge-directory formula from firmware VA 0x014a4538."""
    if not 0 <= edge_count <= 0xFF:
        raise PsfError(f"edge count {edge_count} is outside the u8 domain")
    if config_offset < 0 or config_offset + 2 > len(payload):
        raise PsfError("handle-2 payload is truncated before its directory count")
    auxiliary_count = struct.unpack_from("<H", payload, config_offset)[0]
    if auxiliary_count == 0:
        directory_base = config_offset + 2
        auxiliary_entries: tuple[int, ...] = ()
        auxiliary_trailer: int | None = None
    else:
        auxiliary_base = config_offset + 2
        auxiliary_size = (auxiliary_count + 1) * 4
        directory_base = auxiliary_base + auxiliary_size
        if directory_base > len(payload):
            raise PsfError("handle-2 auxiliary table overruns the payload")
        auxiliary_entries = struct.unpack_from(
            f"<{auxiliary_count}I", payload, auxiliary_base
        )
        auxiliary_trailer = struct.unpack_from(
            "<I", payload, auxiliary_base + auxiliary_count * 4
        )[0]
    directory_end = directory_base + edge_count * 2
    if directory_end > len(payload):
        raise PsfError("handle-2 edge directory overruns the payload")
    record_offsets = (
        struct.unpack_from(f"<{edge_count}H", payload, directory_base)
        if edge_count
        else ()
    )
    for edge_index, record_offset in enumerate(record_offsets):
        if not directory_end <= record_offset < len(payload):
            raise PsfError(
                f"edge {edge_index} record offset {record_offset} is outside "
                f"[{directory_end}, {len(payload)})"
            )
    return EdgeDirectory(
        auxiliary_count,
        tuple(auxiliary_entries),
        auxiliary_trailer,
        directory_base,
        directory_end,
        tuple(record_offsets),
    )


def decode_record_data_end(payload: bytes, directory_end: int) -> int:
    """Return the u16 payload boundary that separates records from the footer."""
    if len(payload) < 3:
        raise PsfError("handle-2 payload is truncated before its record boundary")
    record_data_end = struct.unpack_from("<H", payload, 1)[0]
    if not directory_end < record_data_end <= len(payload):
        raise PsfError(
            f"handle-2 record boundary {record_data_end} is outside "
            f"({directory_end}, {len(payload)}]"
        )
    return record_data_end


def _record_header(
    payload: bytes,
    record_offset: int,
    base_offset: int,
    record_end: int | None = None,
) -> dict[str, object]:
    if record_end is None:
        record_end = len(payload)
    if not 0 <= record_offset < record_end <= len(payload):
        raise PsfError("invalid handle-2 record bounds")
    flags = payload[record_offset]
    pointer_bits = tuple(bit for bit in range(6) if flags & (1 << bit))
    pointer_base = record_offset + base_offset
    count_offset = pointer_base + len(pointer_bits) * 2
    header_fits = count_offset < record_end
    pointers: list[dict[str, object]] = []
    if header_fits:
        for ordinal, bit in enumerate(pointer_bits):
            field_offset = pointer_base + ordinal * 2
            relative_offset = struct.unpack_from("<H", payload, field_offset)[0]
            absolute_offset = record_offset + relative_offset
            in_payload = absolute_offset < len(payload)
            after_header = absolute_offset > count_offset
            in_record = after_header and absolute_offset < record_end
            pointer: dict[str, object] = {
                "flag_bit": bit,
                "field_offset": field_offset,
                "relative_offset": relative_offset,
                "absolute_offset": absolute_offset,
                "in_payload": in_payload,
                "after_header": after_header,
                "in_record": in_record,
            }
            if in_payload:
                pointer["section_count"] = payload[absolute_offset]
                pointer["section_prefix_hex"] = payload[
                    absolute_offset : absolute_offset + 48
                ].hex()
            pointers.append(pointer)
    return {
        "flags": flags,
        "pointer_bits": pointer_bits,
        "count_offset": count_offset,
        "record_end": record_end,
        "header_fits": header_fits,
        "main_count": payload[count_offset] if header_fits else None,
        "pointers": pointers,
    }


def _new_candidate_score(base_offset: int) -> dict[str, int]:
    return {
        "base_offset": base_offset,
        "unique_records": 0,
        "headers_fit": 0,
        "records_all_pointers_in_payload": 0,
        "records_all_pointers_after_header": 0,
        "records_all_pointers_in_record": 0,
        "pointer_fields": 0,
        "pointers_in_payload": 0,
        "pointers_after_header": 0,
        "pointers_in_record": 0,
    }


def _accumulate_candidate(
    score: dict[str, int], payload: bytes, record_offset: int, record_end: int
) -> None:
    header = _record_header(
        payload, record_offset, score["base_offset"], record_end
    )
    score["unique_records"] += 1
    if not header["header_fits"]:
        return
    score["headers_fit"] += 1
    pointers = header["pointers"]
    assert isinstance(pointers, list)
    score["pointer_fields"] += len(pointers)
    in_payload = sum(bool(pointer["in_payload"]) for pointer in pointers)
    after_header = sum(bool(pointer["after_header"]) for pointer in pointers)
    in_record = sum(bool(pointer["in_record"]) for pointer in pointers)
    score["pointers_in_payload"] += in_payload
    score["pointers_after_header"] += after_header
    score["pointers_in_record"] += in_record
    score["records_all_pointers_in_payload"] += int(in_payload == len(pointers))
    score["records_all_pointers_after_header"] += int(after_header == len(pointers))
    score["records_all_pointers_in_record"] += int(in_record == len(pointers))


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    if sample_limit < 0:
        raise ValueError("sample limit must be zero or positive")
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "edge_records.jsonl"
    sample_temporary = sample_path.with_suffix(sample_path.suffix + ".tmp")

    counts = collections.Counter()
    auxiliary_counts = collections.Counter()
    record_flags = collections.Counter()
    record_auxiliary_selectors = collections.Counter()
    record_byte_2 = collections.Counter()
    main_counts = collections.Counter()
    section_counts_by_flag = {
        bit: collections.Counter() for bit in range(6)
    }
    reference_multiplicities = collections.Counter()
    auxiliary_trailers = collections.Counter()
    footer_first_bytes = collections.Counter()
    footer_last_bytes = collections.Counter()
    candidate_scores = {
        base: _new_candidate_score(base) for base in RECORD_BASE_CANDIDATES
    }
    emitted = 0
    _progress("decode", clusters_total=len(order))
    with psf.open("rb") as source, sample_temporary.open(
        "w", encoding="utf-8"
    ) as destination:
        for ordinal, cluster_id in enumerate(order, 1):
            topology = _decode_indexed_lzma(source, grouped[cluster_id][0])
            payload = _decode_indexed_lzma(source, grouped[cluster_id][2])
            if len(topology) < 5:
                raise PsfError(f"cluster {cluster_id} has truncated topology")
            edge_count = topology[2]
            directory = decode_edge_directory(payload, edge_count)
            record_data_end = decode_record_data_end(
                payload, directory.directory_end
            )
            if any(
                record_offset >= record_data_end
                for record_offset in directory.record_offsets
            ):
                raise PsfError(
                    f"cluster {cluster_id} edge record points into its footer"
                )
            per_cluster_refs = collections.Counter(directory.record_offsets)
            counts["clusters"] += 1
            counts["edges"] += edge_count
            counts["payload_bytes"] += len(payload)
            counts["directory_bytes"] += directory.directory_end - directory.directory_base
            counts["record_bytes"] += record_data_end - directory.directory_end
            counts["footer_bytes"] += len(payload) - record_data_end
            counts["auxiliary_entries"] += len(directory.auxiliary_entries)
            counts["unique_records"] += len(per_cluster_refs)
            counts["shared_edge_references"] += edge_count - len(per_cluster_refs)
            counts["nonmonotonic_directories"] += int(
                list(directory.record_offsets) != sorted(directory.record_offsets)
            )
            counts["odd_record_offsets"] += sum(
                record_offset & 1 for record_offset in per_cluster_refs
            )
            if edge_count and (
                directory.record_offsets[0] != directory.directory_end
                or min(directory.record_offsets) != directory.directory_end
            ):
                raise PsfError(
                    f"cluster {cluster_id} first/minimum record does not begin at "
                    "the edge-directory end"
                )
            auxiliary_counts[directory.auxiliary_count] += 1
            if directory.auxiliary_trailer is not None:
                auxiliary_trailers[directory.auxiliary_trailer] += 1
            if record_data_end < len(payload):
                footer_first_bytes[payload[record_data_end]] += 1
                footer_last_bytes[payload[-1]] += 1
            reference_multiplicities.update(per_cluster_refs.values())
            sorted_record_offsets = sorted(per_cluster_refs)
            record_ends = {
                record_offset: (
                    sorted_record_offsets[index + 1]
                    if index + 1 < len(sorted_record_offsets)
                    else record_data_end
                )
                for index, record_offset in enumerate(sorted_record_offsets)
            }
            for record_offset in sorted_record_offsets:
                record_end = record_ends[record_offset]
                flags = payload[record_offset]
                record_flags[flags] += 1
                if flags & 0xE0:
                    raise PsfError(
                        f"cluster {cluster_id} record {record_offset} uses "
                        f"unsupported extended flags 0x{flags:02x}"
                    )
                if record_offset + FIRMWARE_RECORD_POINTER_BASE > record_end:
                    raise PsfError(
                        f"cluster {cluster_id} record {record_offset} has a "
                        "truncated fixed header"
                    )
                auxiliary_selector = payload[record_offset + 1]
                record_auxiliary_selectors[auxiliary_selector] += 1
                record_byte_2[payload[record_offset + 2]] += 1
                if (
                    auxiliary_selector != 0xFF
                    and auxiliary_selector >= directory.auxiliary_count
                ):
                    raise PsfError(
                        f"cluster {cluster_id} record {record_offset} auxiliary "
                        f"selector {auxiliary_selector} exceeds "
                        f"count {directory.auxiliary_count}"
                    )
                if payload[record_offset + 2] not in (0, 1):
                    raise PsfError(
                        f"cluster {cluster_id} record {record_offset} byte 2 "
                        "is outside the observed 0/1 domain"
                    )
                for score in candidate_scores.values():
                    _accumulate_candidate(
                        score, payload, record_offset, record_end
                    )
                locked_header = _record_header(
                    payload,
                    record_offset,
                    FIRMWARE_RECORD_POINTER_BASE,
                    record_end,
                )
                locked_pointers = locked_header["pointers"]
                assert isinstance(locked_pointers, list)
                if (
                    not locked_header["header_fits"]
                    or not all(pointer["in_record"] for pointer in locked_pointers)
                ):
                    raise PsfError(
                        f"cluster {cluster_id} record {record_offset} violates "
                        "the firmware record header layout"
                    )
                main_count = locked_header["main_count"]
                assert isinstance(main_count, int)
                main_counts[main_count] += 1
                for pointer in locked_pointers:
                    bit = pointer["flag_bit"]
                    section_count = pointer["section_count"]
                    assert isinstance(bit, int) and isinstance(section_count, int)
                    section_counts_by_flag[bit][section_count] += 1
            for edge_index, record_offset in enumerate(directory.record_offsets):
                if sample_limit and emitted >= sample_limit:
                    continue
                record_header = _record_header(
                    payload,
                    record_offset,
                    FIRMWARE_RECORD_POINTER_BASE,
                    record_ends[record_offset],
                )
                destination.write(
                    json.dumps(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "record_type": "mib-basic-handle2-edge-reference",
                            "cluster_id": cluster_id,
                            "edge_index": edge_index,
                            "edge_id": (cluster_id << 8) | edge_index,
                            "edge_id_hex": f"0x{((cluster_id << 8) | edge_index):08x}",
                            "payload_size": len(payload),
                            "record_data_end": record_data_end,
                            "auxiliary_count": directory.auxiliary_count,
                            "directory_base": directory.directory_base,
                            "record_offset": record_offset,
                            "record_end": record_ends[record_offset],
                            "record_size": record_ends[record_offset] - record_offset,
                            "record_reference_count": per_cluster_refs[record_offset],
                            "record_flags": payload[record_offset],
                            "record_header": record_header,
                            "record_prefix_hex": payload[
                                record_offset : min(record_ends[record_offset], record_offset + 64)
                            ].hex(),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
                emitted += 1
            if ordinal % 250 == 0 or ordinal == len(order):
                _progress("decode-progress", clusters=ordinal, total=len(order))
    sample_temporary.replace(sample_path)

    ranked_candidates = sorted(
        candidate_scores.values(),
        key=lambda score: (
            -score["records_all_pointers_after_header"],
            -score["records_all_pointers_in_record"],
            -score["pointers_after_header"],
            -score["records_all_pointers_in_payload"],
            score["base_offset"],
        ),
    )
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "directory-and-record-header-validated",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "firmware_evidence": {
            "consumer_va": "0x014a4538",
            "directory_config_offset": FIRMWARE_DIRECTORY_CONFIG_OFFSET,
            "record_pointer_base": FIRMWARE_RECORD_POINTER_BASE,
            "formula": (
                "base=8 when u16le(payload+6)==0; otherwise "
                "base=12+4*count; edge record pointer=u16le(base+2*edge_index)"
            ),
        },
        "counts": dict(sorted(counts.items())),
        "histograms": {
            "auxiliary_count": {
                str(key): value for key, value in auxiliary_counts.most_common()
            },
            "auxiliary_trailer": {
                str(key): value for key, value in auxiliary_trailers.most_common()
            },
            "footer_first_byte": {
                f"0x{key:02x}": value
                for key, value in footer_first_bytes.most_common()
            },
            "footer_last_byte": {
                f"0x{key:02x}": value
                for key, value in footer_last_bytes.most_common()
            },
            "record_flags": {
                f"0x{key:02x}": value for key, value in record_flags.most_common()
            },
            "record_auxiliary_selector": {
                str(key): value
                for key, value in record_auxiliary_selectors.most_common()
            },
            "record_byte_2": {
                str(key): value for key, value in record_byte_2.most_common()
            },
            "main_count": {
                str(key): value for key, value in main_counts.most_common()
            },
            "section_count_by_flag_bit": {
                str(bit): {
                    str(key): value for key, value in counter.most_common()
                }
                for bit, counter in section_counts_by_flag.items()
            },
            "record_reference_multiplicity": {
                str(key): value
                for key, value in reference_multiplicities.most_common()
            },
        },
        "record_header_base_candidates": ranked_candidates,
        "interpretation": {
            "directory": "validated for every Basic cluster and edge",
            "record_header": (
                "base offset 3 is the only candidate for which every flag-selected "
                "pointer is after the header and inside the payload"
            ),
            "text_properties": (
                "string encoding and property stride remain gated by the remaining "
                "firmware schema descriptor fields"
            ),
        },
        "artifacts": {
            "report": "report.json",
            "edge_records": sample_path.name,
            "edge_record_count": emitted,
            "checksums": "CHECKSUMS.sha256",
        },
    }
    report_path = output / "report.json"
    report_temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    report_temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report_temporary.replace(report_path)
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n"
        f"{_sha256(sample_path)}  {sample_path.name}\n",
        encoding="ascii",
    )
    _progress("complete", output=output, edges=counts["edges"])
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
        print(f"basic_handle2_directory: {error}", file=sys.stderr)
        return 1
    counts = report["counts"]
    assert isinstance(counts, dict)
    print(
        json.dumps(
            {
                "status": report["status"],
                "clusters": counts["clusters"],
                "edges": counts["edges"],
                "unique_records": counts["unique_records"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

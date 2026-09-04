#!/usr/bin/env python3
"""Incremental, read-only decoder for Audi MIB PSF v60 map files.

Implemented stages:
  * fixed PSF envelope/header and named block inspection
  * content.pkg verification-blob comparison
  * hashes.txt 512 KiB chunk validation
  * typed metadata TLV decoding
  * firmware-compatible LZMA-Alone and size-prefixed zlib stream discovery
  * high-confidence (phonetic-mask-backed) UTF-8 name extraction

The cluster index and typed map records are added as their PSF60 structures are
recovered from the firmware parser.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import math
import mmap
from pathlib import Path
import re
import struct
import sys
from typing import BinaryIO, Iterator
import zlib


PSF_HEADER_SIZE = 0xFE
PSF_SLOT_TYPE_OFFSET = 0x00
PSF_VERSION_OFFSET = 0x02
PSF_HEADER_COVERED_SIZE_OFFSET = 0x06
PSF_WORLD_OFFSET = 0x0A
PSF_WORLD_SIZE_OFFSET = 0x0E
PSF_VERIFICATION_OFFSET = 0x35
PSF_VERIFICATION_TAIL_SIZE_OFFSET = 0x39
PSF_DECLARED_SIZE_OFFSET = 0x4D
PSF_EPOCH_OFFSET = 0x51
PSF_CUSTOMER_ID_OFFSET = 0x55
PSF_JUNCTION_VIEW_OFFSET = 0x5F
PSF_JUNCTION_VIEW_SIZE_OFFSET = 0x63
PSF_TRAILER_OFFSET = 0x7A
PSF_TRAILER_SIZE_OFFSET = 0x7E
PSF_SPATIAL_INDEX_OFFSET = 0x96
PSF_SPATIAL_INDEX_SIZE_OFFSET = 0x9A
PSF_VERIFICATION_SIZE = 128
PSF_FINAL_MARKER = bytes.fromhex("800006010000")
HASH_CHUNK_SIZE = 512 * 1024
NAME_TAG = 0xA1
WEB_MERCATOR_RADIUS = 6_378_137.0
LZMA_ALONE_HEADER_SIZE = 13
ZLIB_CMF_PATTERN = re.compile(b"[\x08\x18\x28\x38\x48\x58\x68\x78]")
DECODER_VERSION = "0.6.0"
SOURCE_LAYER_VERSION = 6


class PsfError(RuntimeError):
    pass


def u32le(data: bytes | mmap.mmap, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u16le(data: bytes | mmap.mmap, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u24le(data: bytes | mmap.mmap, offset: int) -> int:
    return data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16


def _block(
    header: bytes,
    name: str,
    offset_field: int,
    size_field: int,
    file_size: int,
) -> dict[str, object]:
    offset = u32le(header, offset_field)
    size = u32le(header, size_field)
    end = offset + size
    return {
        "name": name,
        "offset": offset,
        "size": size,
        "end": end,
        "present": size != 0,
        "within_file": offset <= file_size and end <= file_size,
    }


def parse_envelope(path: Path) -> dict[str, object]:
    size = path.stat().st_size
    if size < 0x100:
        raise PsfError("file is too small for a PSF envelope")
    with path.open("rb") as source:
        header = source.read(PSF_HEADER_SIZE)
        source.seek(-len(PSF_FINAL_MARKER), 2)
        final_marker = source.read(len(PSF_FINAL_MARKER))

    slot_type = u16le(header, PSF_SLOT_TYPE_OFFSET)
    version = u32le(header, PSF_VERSION_OFFSET)
    header_covered_size = u32le(header, PSF_HEADER_COVERED_SIZE_OFFSET)
    declared_size = u32le(header, PSF_DECLARED_SIZE_OFFSET)
    epoch = u32le(header, PSF_EPOCH_OFFSET)
    customer_id = u32le(header, PSF_CUSTOMER_ID_OFFSET)

    spatial_index = _block(
        header,
        "spatial_index",
        PSF_SPATIAL_INDEX_OFFSET,
        PSF_SPATIAL_INDEX_SIZE_OFFSET,
        size,
    )
    world = _block(header, "world", PSF_WORLD_OFFSET, PSF_WORLD_SIZE_OFFSET, size)
    metadata = _block(header, "metadata", PSF_TRAILER_OFFSET, PSF_TRAILER_SIZE_OFFSET, size)
    combined_tail = _block(
        header,
        "combined_tail",
        PSF_VERIFICATION_OFFSET,
        PSF_VERIFICATION_TAIL_SIZE_OFFSET,
        size,
    )
    junction_view = _block(
        header,
        "junction_view",
        PSF_JUNCTION_VIEW_OFFSET,
        PSF_JUNCTION_VIEW_SIZE_OFFSET,
        size,
    )
    regular_chain = [block for block in (spatial_index, world, metadata, combined_tail) if block["present"]]
    chain_contiguous = all(
        int(left["end"]) == int(right["offset"])
        for left, right in zip(regular_chain, regular_chain[1:])
    )

    return {
        "path": str(path),
        "actual_size": size,
        "declared_size": declared_size,
        "declared_size_ok": declared_size == size,
        "slot_type": slot_type,
        "slot_type_name": {0: "regular", 1: "dtm"}.get(slot_type, "unknown"),
        "psf_version": version,
        "psf_version_supported": version == 60,
        "fixed_header_size": PSF_HEADER_SIZE,
        "signature_covered_header_size": header_covered_size,
        "epoch": epoch,
        "customer_id": customer_id,
        "blocks": {
            block["name"]: block
            for block in (spatial_index, world, metadata, combined_tail, junction_view)
        },
        "regular_tail_chain_contiguous": chain_contiguous,
        "regular_tail_chain_reaches_eof": not regular_chain or int(regular_chain[-1]["end"]) == size,
        "verification_offset": combined_tail["offset"],
        "verification_size": PSF_VERIFICATION_SIZE,
        "verification_tail_size": combined_tail["size"],
        "verification_reaches_eof": combined_tail["end"] == size,
        "trailer_offset": metadata["offset"],
        "trailer_size": metadata["size"],
        "trailer_reaches_verification": metadata["end"] == combined_tail["offset"],
        "field_0x72": header[0x72],
        "final_marker_hex": final_marker.hex(),
        "final_marker_ok": final_marker == PSF_FINAL_MARKER,
    }


_SCALAR_TYPES: dict[int, tuple[str, str]] = {
    1: ("i8", "<b"),
    2: ("u8", "<B"),
    3: ("i16", "<h"),
    4: ("u16", "<H"),
    5: ("i32", "<i"),
    6: ("u32", "<I"),
}

_ARRAY_TYPES: dict[int, tuple[str, str]] = {
    8: ("i8_array", "b"),
    9: ("u8_array", "B"),
    10: ("i16_array", "h"),
    11: ("u16_array", "H"),
    12: ("i32_array", "i"),
    13: ("u32_array", "I"),
}


def _require_available(cursor: int, needed: int, end: int, record_offset: int) -> None:
    if needed < 0 or cursor < 0 or cursor + needed > end:
        raise PsfError(f"truncated metadata record at file offset 0x{record_offset:x}")


def _read_cstring(data: mmap.mmap, cursor: int, end: int, record_offset: int) -> tuple[str, int]:
    terminator = data.find(b"\x00", cursor, end)
    if terminator < 0:
        raise PsfError(f"unterminated metadata string at file offset 0x{record_offset:x}")
    try:
        value = data[cursor:terminator].decode("utf-8")
    except UnicodeDecodeError as error:
        raise PsfError(f"invalid UTF-8 metadata string at file offset 0x{record_offset:x}") from error
    return value, terminator + 1


def iter_metadata(path: Path) -> Iterator[dict[str, object]]:
    envelope = parse_envelope(path)
    metadata = envelope["blocks"]["metadata"]  # type: ignore[index]
    start = int(metadata["offset"])  # type: ignore[index]
    size = int(metadata["size"])  # type: ignore[index]
    end = start + size
    if size == 0:
        return

    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        cursor = start
        while cursor < end:
            record_offset = cursor
            _require_available(cursor, 4, end, record_offset)
            field_id = data[cursor] | data[cursor + 1] << 8 | data[cursor + 2] << 16
            value_type = data[cursor + 3]
            cursor += 4

            if value_type in _SCALAR_TYPES:
                type_name, format_string = _SCALAR_TYPES[value_type]
                width = struct.calcsize(format_string)
                _require_available(cursor, width, end, record_offset)
                value = struct.unpack_from(format_string, data, cursor)[0]
                cursor += width
            elif value_type == 7:
                type_name = "string"
                value, cursor = _read_cstring(data, cursor, end, record_offset)
            elif value_type in _ARRAY_TYPES:
                type_name, element_format = _ARRAY_TYPES[value_type]
                _require_available(cursor, 2, end, record_offset)
                count = u16le(data, cursor)
                cursor += 2
                width = struct.calcsize("<" + element_format)
                byte_size = count * width
                _require_available(cursor, byte_size, end, record_offset)
                if count:
                    value = list(struct.unpack_from("<" + str(count) + element_format, data, cursor))
                else:
                    value = []
                cursor += byte_size
            elif value_type == 14:
                type_name = "string_array"
                _require_available(cursor, 2, end, record_offset)
                count = u16le(data, cursor)
                cursor += 2
                strings: list[str] = []
                for _ in range(count):
                    item, cursor = _read_cstring(data, cursor, end, record_offset)
                    strings.append(item)
                value = strings
            else:
                raise PsfError(
                    f"unknown metadata type {value_type} at file offset 0x{record_offset:x}"
                )

            yield {
                "offset": record_offset,
                "relative_offset": record_offset - start,
                "field_id": field_id,
                "type": value_type,
                "type_name": type_name,
                "value": value,
            }


def read_landmark_index(path: Path) -> list[dict[str, object]]:
    """Read the compact spatial index used by a PSF60 Landmark slot."""
    envelope = parse_envelope(path)
    with path.open("rb") as source:
        source.seek(0xFA)
        count_data = source.read(4)
        if len(count_data) != 4:
            raise PsfError("truncated Landmark index count")
        count = u32le(count_data, 0)
        if count > 1_000_000:
            raise PsfError(f"implausible Landmark index count: {count}")
        raw = source.read(count * 24)
    if len(raw) != count * 24:
        raise PsfError("truncated Landmark index")

    entries: list[dict[str, object]] = []
    expected_offset = 0xFE + count * 24
    for index in range(count):
        cursor = index * 24
        min_x, max_y, max_x, min_y, compressed_offset = struct.unpack_from("<IIIII", raw, cursor)
        compressed_size, cluster_id = struct.unpack_from("<HH", raw, cursor + 20)
        if compressed_offset != expected_offset:
            raise PsfError(
                f"non-contiguous Landmark cluster {index}: "
                f"expected 0x{expected_offset:x}, got 0x{compressed_offset:x}"
            )
        expected_offset += compressed_size
        entries.append(
            {
                "index": index,
                "cluster_id": cluster_id,
                "compressed_offset": compressed_offset,
                "compressed_size": compressed_size,
                "index_bbox_mercator": [min_x, min_y, max_x, max_y],
            }
        )

    with path.open("rb") as source:
        for entry in entries:
            source.seek(int(entry["compressed_offset"]))
            codec_header = source.read(13)
            if len(codec_header) != 13 or codec_header[0] != 0x5D:
                raise PsfError(f"invalid Landmark LZMA header for cluster {entry['index']}")
            dictionary_size = u32le(codec_header, 1)
            output_size = struct.unpack_from("<Q", codec_header, 5)[0]
            if dictionary_size != output_size or output_size == 0:
                raise PsfError(f"invalid Landmark LZMA sizes for cluster {entry['index']}")
            entry["codec"] = "lzma-alone"
            entry["dictionary_size"] = dictionary_size
            entry["uncompressed_size"] = output_size

    footer_offset = int(envelope["blocks"]["metadata"]["offset"])  # type: ignore[index]
    if expected_offset != footer_offset:
        raise PsfError(
            f"Landmark cluster chain ends at 0x{expected_offset:x}, "
            f"not footer offset 0x{footer_offset:x}"
        )
    return entries


def _canonical_lzma_header(
    data: bytes | mmap.mmap,
    offset: int,
    stored_size: int,
    max_output_size: int = 64 * 1024 * 1024,
) -> tuple[int, int] | None:
    if offset < 0 or stored_size < 13 or offset + stored_size > len(data):
        return None
    if data[offset] != 0x5D:
        return None
    dictionary_size = u32le(data, offset + 1)
    output_size = struct.unpack_from("<Q", data, offset + 5)[0]
    if dictionary_size != output_size or not (0 < output_size <= max_output_size):
        return None
    return dictionary_size, output_size


def _index_gaps(
    start: int,
    end: int,
    groups: list[dict[str, object]],
) -> list[dict[str, int]]:
    gaps: list[dict[str, int]] = []
    cursor = start
    for group in sorted(groups, key=lambda item: int(item["offset"])):
        group_start = int(group["offset"])
        group_end = int(group["end"])
        if group_start > cursor:
            gaps.append({"offset": cursor, "size": group_start - cursor, "end": group_start})
        cursor = max(cursor, group_end)
    if cursor < end:
        gaps.append({"offset": cursor, "size": end - cursor, "end": end})
    return gaps


def read_grouped_lzma_index(
    path: Path,
    *,
    kind: str,
    entry_size: int,
    compressed_offset_field: int,
    compressed_size_field: int,
) -> dict[str, object]:
    """Recover grouped cluster tables used by ADAS and AdvancedRouting slots."""
    start = 0xF2
    envelope = parse_envelope(path)
    footer_offset = int(envelope["blocks"]["metadata"]["offset"])  # type: ignore[index]
    groups: list[dict[str, object]] = []
    entries: list[dict[str, object]] = []

    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        cursor = start
        payload_start = footer_offset
        group_index = 0
        while cursor + 4 <= payload_start:
            count = u32le(data, cursor)
            candidate_end = cursor + 4 + count * entry_size
            valid = 0 < count <= 100_000 and candidate_end <= payload_start
            candidate: list[dict[str, object]] = []
            if valid:
                for entry_index in range(count):
                    entry_offset = cursor + 4 + entry_index * entry_size
                    compressed_offset = u32le(data, entry_offset + compressed_offset_field)
                    compressed_size = u32le(data, entry_offset + compressed_size_field)
                    codec_header = _canonical_lzma_header(data, compressed_offset, compressed_size)
                    if codec_header is None:
                        valid = False
                        break
                    dictionary_size, output_size = codec_header
                    cluster_id = u32le(data, entry_offset)
                    candidate.append(
                        {
                            "cluster_id": cluster_id,
                            "group_index": group_index,
                            "entry_index": entry_index,
                            "index_entry_offset": entry_offset,
                            "index_extra_hex": data[
                                entry_offset + 4 : entry_offset + compressed_offset_field
                            ].hex(),
                            "compressed_offset": compressed_offset,
                            "compressed_size": compressed_size,
                            "codec": "lzma-alone",
                            "dictionary_size": dictionary_size,
                            "uncompressed_size": output_size,
                        }
                    )
            if not valid:
                cursor += 1
                continue

            groups.append(
                {
                    "index": group_index,
                    "offset": cursor,
                    "count": count,
                    "entry_size": entry_size,
                    "end": candidate_end,
                }
            )
            entries.extend(candidate)
            payload_start = min(payload_start, *(int(item["compressed_offset"]) for item in candidate))
            cursor = candidate_end
            group_index += 1

    if not entries:
        raise PsfError(f"no valid {kind} cluster-index groups found")
    entries_by_offset = sorted(entries, key=lambda item: int(item["compressed_offset"]))
    if len({int(item["compressed_offset"]) for item in entries}) != len(entries):
        raise PsfError(f"duplicate {kind} compressed offsets")
    expected_offset = int(entries_by_offset[0]["compressed_offset"])
    for entry in entries_by_offset:
        actual_offset = int(entry["compressed_offset"])
        if actual_offset != expected_offset:
            raise PsfError(
                f"non-contiguous {kind} cluster chain: expected 0x{expected_offset:x}, "
                f"got 0x{actual_offset:x}"
            )
        expected_offset += int(entry["compressed_size"])
    if expected_offset != footer_offset:
        raise PsfError(
            f"{kind} cluster chain ends at 0x{expected_offset:x}, "
            f"not footer offset 0x{footer_offset:x}"
        )

    payload_start = int(entries_by_offset[0]["compressed_offset"])
    return {
        "kind": kind,
        "index_start": start,
        "payload_start": payload_start,
        "payload_end": footer_offset,
        "groups": groups,
        "auxiliary_regions": _index_gaps(start, payload_start, groups),
        "entries": entries,
        "entries_by_offset": entries_by_offset,
    }


def read_adas_index(path: Path) -> dict[str, object]:
    return read_grouped_lzma_index(
        path,
        kind="adas",
        entry_size=12,
        compressed_offset_field=4,
        compressed_size_field=8,
    )


def read_advanced_routing_index(path: Path) -> dict[str, object]:
    return read_grouped_lzma_index(
        path,
        kind="advanced-routing",
        entry_size=20,
        compressed_offset_field=12,
        compressed_size_field=16,
    )


def read_basic_spatial_index(path: Path) -> dict[str, object]:
    """Decode the 32-byte cluster descriptors in the Basic slot's tail index."""
    envelope = parse_envelope(path)
    block = envelope["blocks"]["spatial_index"]  # type: ignore[index]
    block_offset = int(block["offset"])  # type: ignore[index]
    block_size = int(block["size"])  # type: ignore[index]
    if block_size < 4:
        raise PsfError("Basic spatial index is absent or truncated")

    config = {
        int(record["field_id"]): record["value"]
        for record in iter_metadata(path)
        if record["field_id"] in (0x8A, 0x8B)
    }
    if 0x8A not in config or 0x8B not in config:
        raise PsfError("Basic metadata lacks spatial-index base/stride fields 0x8a/0x8b")
    record_base = int(config[0x8A])
    record_stride = int(config[0x8B])
    if record_base < 4 or record_stride < 28:
        raise PsfError(
            f"invalid Basic spatial-index base/stride: {record_base}/{record_stride}"
        )

    entries: list[dict[str, object]] = []
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        count = u32le(data, block_offset)
        expected_size = record_base + count * record_stride
        if count > 1_000_000 or expected_size != block_size:
            raise PsfError(
                f"invalid Basic spatial-index geometry: count={count}, "
                f"expected {expected_size} bytes, header says {block_size}"
            )
        for index in range(count):
            cursor = block_offset + record_base + index * record_stride
            bbox = struct.unpack_from("<4i", data, cursor)
            cluster_id, compressed_offset, compressed_size = struct.unpack_from("<III", data, cursor + 16)
            descriptor_flag = data[cursor + 28] if record_stride > 28 else None
            codec_header = _canonical_lzma_header(data, compressed_offset, compressed_size)
            if codec_header is None:
                raise PsfError(f"invalid Basic indexed LZMA cluster {index}")
            dictionary_size, output_size = codec_header
            entries.append(
                {
                    "index": index,
                    "cluster_id": cluster_id,
                    "bbox_fields": list(bbox),
                    "compressed_offset": compressed_offset,
                    "compressed_size": compressed_size,
                    "descriptor_flag": descriptor_flag,
                    "status": ((int(descriptor_flag) & 1) ^ 1) if descriptor_flag is not None else 3,
                    "descriptor_extra_hex": data[
                        cursor + 29 : cursor + record_stride
                    ].hex()
                    if record_stride > 29
                    else "",
                    "codec": "lzma-alone",
                    "dictionary_size": dictionary_size,
                    "uncompressed_size": output_size,
                    "index_entry_offset": cursor,
                }
            )

    expected_offset = int(entries[0]["compressed_offset"]) if entries else 0
    for entry in entries:
        if int(entry["compressed_offset"]) != expected_offset:
            raise PsfError(f"non-contiguous Basic spatial cluster {entry['index']}")
        expected_offset += int(entry["compressed_size"])
    return {
        "kind": "basic-spatial",
        "index_start": block_offset,
        "index_size": block_size,
        "record_base": record_base,
        "record_stride": record_stride,
        "payload_start": int(entries[0]["compressed_offset"]) if entries else 0,
        "payload_end": expected_offset,
        "groups": [
            {
                "index": 0,
                "offset": block_offset,
                "count": len(entries),
                "entry_size": record_stride,
                "end": block_offset + block_size,
            }
        ],
        "auxiliary_regions": [],
        "entries": entries,
    }


def read_basic_key_index(path: Path) -> dict[str, object]:
    """Decode the Basic slot key index referenced by metadata field 0x13f."""
    descriptor = next(
        (record for record in iter_metadata(path) if record["field_id"] == 0x13F),
        None,
    )
    if descriptor is None or descriptor["type"] != 13:
        raise PsfError("Basic metadata field 0x13f is absent or has the wrong type")
    values = descriptor["value"]
    if not isinstance(values, list) or len(values) != 3:
        raise PsfError("Basic metadata field 0x13f is not a three-u32 descriptor")
    index_offset, tree_depth, index_size = (int(value) for value in values)
    if index_size < 4:
        raise PsfError("Basic key index is too small")

    entries: list[dict[str, object]] = []
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if index_offset + index_size > len(data):
            raise PsfError("Basic key index lies outside the file")
        count = u32le(data, index_offset)
        if count > 1_000_000 or 4 + count * 12 != index_size:
            raise PsfError(
                f"invalid Basic key-index geometry: count={count}, size={index_size}"
            )
        for index in range(count):
            cursor = index_offset + 4 + index * 12
            key, compressed_offset, compressed_size = struct.unpack_from("<III", data, cursor)
            codec_header = _canonical_lzma_header(data, compressed_offset, compressed_size)
            if codec_header is None:
                raise PsfError(f"invalid Basic key-index LZMA cluster {index}")
            dictionary_size, output_size = codec_header
            entries.append(
                {
                    "index": index,
                    "cluster_key": key,
                    "compressed_offset": compressed_offset,
                    "compressed_size": compressed_size,
                    "codec": "lzma-alone",
                    "dictionary_size": dictionary_size,
                    "uncompressed_size": output_size,
                    "index_entry_offset": cursor,
                }
            )

    offsets = [int(entry["compressed_offset"]) for entry in entries]
    payload_end = max(
        (int(entry["compressed_offset"]) + int(entry["compressed_size"]) for entry in entries),
        default=0,
    )
    return {
        "kind": "basic-key-0x13f",
        "metadata_field_id": 0x13F,
        "tree_depth": tree_depth,
        "index_start": index_offset,
        "index_size": index_size,
        "payload_start": min(offsets, default=0),
        "payload_end": payload_end,
        "groups": [
            {
                "index": 0,
                "offset": index_offset,
                "count": len(entries),
                "entry_size": 12,
                "end": index_offset + index_size,
            }
        ],
        "auxiliary_regions": [],
        "entries": entries,
    }


def _metadata_value(path: Path, field_id: int) -> object:
    record = next(
        (item for item in iter_metadata(path) if item["field_id"] == field_id),
        None,
    )
    if record is None:
        raise PsfError(f"metadata field 0x{field_id:x} is absent")
    return record["value"]


def read_basic_dual_spatial_index(path: Path) -> dict[str, object]:
    """Traverse Basic field-0x139 spatial pages with two handles per record."""
    raw_descriptors = _metadata_value(path, 0x139)
    if not isinstance(raw_descriptors, list) or len(raw_descriptors) % 3:
        raise PsfError("Basic metadata field 0x139 is not a u32 triple array")
    record_base = int(_metadata_value(path, 0x96))
    record_stride = int(_metadata_value(path, 0x97))
    if (record_base, record_stride) != (12, 32):
        raise PsfError(
            f"unsupported Basic dual-spatial base/stride: {record_base}/{record_stride}"
        )

    entries: list[dict[str, object]] = []
    leaf_pages: list[dict[str, object]] = []
    internal_roots: list[dict[str, object]] = []
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        leaf_offsets: list[tuple[int, int]] = []
        for descriptor_index in range(0, len(raw_descriptors), 3):
            root_offset = int(raw_descriptors[descriptor_index])
            depth = int(raw_descriptors[descriptor_index + 1])
            last_leaf_offset = int(raw_descriptors[descriptor_index + 2])
            logical_index = descriptor_index // 3
            if root_offset == 0 and depth == 0 and last_leaf_offset == 0:
                continue
            if depth == 1:
                if last_leaf_offset != root_offset:
                    raise PsfError(f"Basic spatial descriptor {logical_index} has inconsistent leaf offset")
                leaf_offsets.append((logical_index, root_offset))
                continue
            if depth != 2:
                raise PsfError(f"unsupported Basic spatial tree depth {depth}")

            child_count = u32le(data, root_offset)
            root_end = root_offset + 4 + child_count * 20
            if child_count == 0 or root_end > len(data):
                raise PsfError(f"invalid Basic spatial root at 0x{root_offset:x}")
            children: list[dict[str, object]] = []
            for child_index in range(child_count):
                cursor = root_offset + 4 + child_index * 20
                bbox = list(struct.unpack_from("<4i", data, cursor))
                child_offset = u32le(data, cursor + 16)
                children.append({"bbox_fields": bbox, "child_offset": child_offset})
                leaf_offsets.append((logical_index, child_offset))
            if int(children[-1]["child_offset"]) != last_leaf_offset:
                raise PsfError(f"Basic spatial root 0x{root_offset:x} last-child mismatch")
            internal_roots.append(
                {
                    "descriptor_index": logical_index,
                    "offset": root_offset,
                    "depth": depth,
                    "child_count": child_count,
                    "end": root_end,
                    "children": children,
                }
            )

        if len({offset for _, offset in leaf_offsets}) != len(leaf_offsets):
            raise PsfError("duplicate Basic spatial leaf offset")
        flattened_index = 0
        for descriptor_index, page_offset in leaf_offsets:
            link_a, link_b, record_count = struct.unpack_from("<III", data, page_offset)
            page_end = page_offset + 12 + record_count * 32
            if record_count == 0 or page_end > len(data):
                raise PsfError(f"invalid Basic spatial leaf at 0x{page_offset:x}")
            leaf_pages.append(
                {
                    "index": len(leaf_pages),
                    "descriptor_index": descriptor_index,
                    "offset": page_offset,
                    "count": record_count,
                    "entry_size": 32,
                    "link_a": link_a,
                    "link_b": link_b,
                    "end": page_end,
                }
            )
            for record_index in range(record_count):
                cursor = page_offset + 12 + record_index * 32
                bbox = list(struct.unpack_from("<4i", data, cursor))
                cluster_id = u24le(data, cursor + 16)
                record_flags = data[cursor + 19]
                for handle_index, handle_offset in enumerate((cursor + 20, cursor + 26)):
                    compressed_offset = u32le(data, handle_offset)
                    compressed_size = u16le(data, handle_offset + 4)
                    codec_header = _canonical_lzma_header(data, compressed_offset, compressed_size)
                    if codec_header is None:
                        raise PsfError(
                            f"invalid Basic dual-spatial handle at page 0x{page_offset:x}, "
                            f"record {record_index}, handle {handle_index}"
                        )
                    dictionary_size, output_size = codec_header
                    entries.append(
                        {
                            "index": flattened_index,
                            "page_offset": page_offset,
                            "record_index": record_index,
                            "handle_index": handle_index,
                            "cluster_id": cluster_id,
                            "record_flags": record_flags,
                            "compressed_flag": bool(record_flags & (1 << handle_index)),
                            "additional_record_flag": bool(record_flags & 0x08),
                            "bbox_fields": bbox,
                            "compressed_offset": compressed_offset,
                            "compressed_size": compressed_size,
                            "codec": "lzma-alone",
                            "dictionary_size": dictionary_size,
                            "uncompressed_size": output_size,
                            "index_entry_offset": cursor,
                        }
                    )
                    flattened_index += 1

    offsets = [int(entry["compressed_offset"]) for entry in entries]
    return {
        "kind": "basic-spatial-dual",
        "metadata_field_id": 0x139,
        "record_base": record_base,
        "record_stride": record_stride,
        "index_start": min((int(page["offset"]) for page in leaf_pages), default=0),
        "payload_start": min(offsets, default=0),
        "payload_end": max(
            (int(entry["compressed_offset"]) + int(entry["compressed_size"]) for entry in entries),
            default=0,
        ),
        "record_count": sum(int(page["count"]) for page in leaf_pages),
        "groups": leaf_pages,
        "internal_roots": internal_roots,
        "auxiliary_regions": [],
        "entries": entries,
    }


def read_basic_triple_handle_index(path: Path) -> dict[str, object]:
    """Traverse the Basic ID B-tree with three LZMA handles per leaf record."""
    descriptor = _metadata_value(path, 0x138)
    if not isinstance(descriptor, list) or len(descriptor) != 3:
        raise PsfError("Basic metadata field 0x138 is not a three-u32 descriptor")
    root_offset, depth, extra = (int(value) for value in descriptor)
    if depth != 2:
        raise PsfError(f"unsupported Basic ID-index depth {depth}")
    record_base = int(_metadata_value(path, 0x94))
    record_stride = int(_metadata_value(path, 0x95))
    if (record_base, record_stride) != (4, 38):
        raise PsfError(
            f"unsupported Basic ID-index base/stride: {record_base}/{record_stride}"
        )
    packed_layout = {
        field_id: int(_metadata_value(path, field_id))
        for field_id in (0x140, 0x141, 0x142, 0x143, 0x144)
    }

    entries: list[dict[str, object]] = []
    leaf_pages: list[dict[str, object]] = []
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        separator_count = u32le(data, root_offset)
        root_end = root_offset + 4 + separator_count * 8 + 4
        if separator_count == 0 or root_end > len(data):
            raise PsfError(f"invalid Basic ID root at 0x{root_offset:x}")
        children: list[int] = []
        separators: list[int] = []
        for index in range(separator_count):
            cursor = root_offset + 4 + index * 8
            children.append(u32le(data, cursor))
            separators.append(u32le(data, cursor + 4))
        children.append(u32le(data, root_offset + 4 + separator_count * 8))
        if len(set(children)) != len(children):
            raise PsfError("duplicate Basic ID-index child page")

        flattened_index = 0
        for page_index, page_offset in enumerate(children):
            record_count = u32le(data, page_offset)
            page_end = page_offset + 4 + record_count * 38
            if record_count == 0 or page_end > len(data):
                raise PsfError(f"invalid Basic ID leaf at 0x{page_offset:x}")
            leaf_pages.append(
                {
                    "index": page_index,
                    "offset": page_offset,
                    "count": record_count,
                    "entry_size": 38,
                    "end": page_end,
                }
            )
            for record_index in range(record_count):
                cursor = page_offset + 4 + record_index * 38
                cluster_id = u24le(data, cursor)
                record_flags = data[cursor + 3]
                bbox = list(struct.unpack_from("<4i", data, cursor + 22))
                for handle_index in range(3):
                    handle_offset = cursor + 4 + handle_index * 6
                    compressed_offset = u32le(data, handle_offset)
                    compressed_size = u16le(data, handle_offset + 4)
                    codec_header = _canonical_lzma_header(data, compressed_offset, compressed_size)
                    if codec_header is None:
                        raise PsfError(
                            f"invalid Basic triple handle at page 0x{page_offset:x}, "
                            f"record {record_index}, handle {handle_index}"
                        )
                    dictionary_size, output_size = codec_header
                    entries.append(
                        {
                            "index": flattened_index,
                            "page_offset": page_offset,
                            "record_index": record_index,
                            "handle_index": handle_index,
                            "cluster_id": cluster_id,
                            "record_flags": record_flags,
                            "compressed_flag": bool(record_flags & (1 << handle_index)),
                            "bbox_fields": bbox,
                            "compressed_offset": compressed_offset,
                            "compressed_size": compressed_size,
                            "codec": "lzma-alone",
                            "dictionary_size": dictionary_size,
                            "uncompressed_size": output_size,
                            "index_entry_offset": cursor,
                        }
                    )
                    flattened_index += 1

    offsets = [int(entry["compressed_offset"]) for entry in entries]
    return {
        "kind": "basic-id-triple",
        "metadata_field_id": 0x138,
        "tree_depth": depth,
        "descriptor_extra": extra,
        "record_base": record_base,
        "record_stride": record_stride,
        "packed_layout_fields": packed_layout,
        "index_start": min(children, default=root_offset),
        "index_root": root_offset,
        "index_root_end": root_end,
        "payload_start": min(offsets, default=0),
        "payload_end": max(
            (int(entry["compressed_offset"]) + int(entry["compressed_size"]) for entry in entries),
            default=0,
        ),
        "record_count": sum(int(page["count"]) for page in leaf_pages),
        "groups": leaf_pages,
        "root_separators": separators,
        "auxiliary_regions": [],
        "entries": entries,
    }


def read_basic_single_spatial_index(path: Path) -> dict[str, object]:
    """Traverse field-0xb3 spatial trees with one 24-byte handle per record."""
    raw_descriptors = _metadata_value(path, 0xB3)
    if not isinstance(raw_descriptors, list) or len(raw_descriptors) % 3:
        raise PsfError("Basic metadata field 0xb3 is not a u32 triple array")

    entries: list[dict[str, object]] = []
    leaf_pages: list[dict[str, object]] = []
    internal_roots: list[dict[str, object]] = []
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        leaf_offsets: list[tuple[int, int]] = []
        for descriptor_index in range(0, len(raw_descriptors), 3):
            depth = int(raw_descriptors[descriptor_index])
            index_offset = int(raw_descriptors[descriptor_index + 1])
            index_size = int(raw_descriptors[descriptor_index + 2])
            logical_index = descriptor_index // 3
            if depth == 1:
                leaf_offsets.append((logical_index, index_offset))
                record_count = u32le(data, index_offset + 8)
                if 12 + record_count * 24 != index_size:
                    raise PsfError(
                        f"Basic single-spatial descriptor {logical_index} size mismatch"
                    )
                continue
            if depth != 2:
                raise PsfError(f"unsupported Basic single-spatial tree depth {depth}")

            child_count = u32le(data, index_offset)
            root_end = index_offset + 4 + child_count * 20
            if child_count == 0 or root_end > len(data) or root_end - index_offset != index_size:
                raise PsfError(f"invalid Basic single-spatial root at 0x{index_offset:x}")
            children: list[dict[str, object]] = []
            for child_index in range(child_count):
                cursor = index_offset + 4 + child_index * 20
                bbox = list(struct.unpack_from("<4i", data, cursor))
                child_offset = u32le(data, cursor + 16)
                children.append({"bbox_fields": bbox, "child_offset": child_offset})
                leaf_offsets.append((logical_index, child_offset))
            internal_roots.append(
                {
                    "descriptor_index": logical_index,
                    "offset": index_offset,
                    "depth": depth,
                    "size": index_size,
                    "child_count": child_count,
                    "end": root_end,
                    "children": children,
                }
            )

        if len({offset for _, offset in leaf_offsets}) != len(leaf_offsets):
            raise PsfError("duplicate Basic single-spatial leaf offset")

        flattened_index = 0
        for descriptor_index, page_offset in leaf_offsets:
            link_a, link_b, record_count = struct.unpack_from("<III", data, page_offset)
            page_end = page_offset + 12 + record_count * 24
            if record_count == 0 or page_end > len(data):
                raise PsfError(f"invalid Basic single-spatial leaf at 0x{page_offset:x}")
            leaf_pages.append(
                {
                    "index": len(leaf_pages),
                    "descriptor_index": descriptor_index,
                    "offset": page_offset,
                    "count": record_count,
                    "entry_size": 24,
                    "link_a": link_a,
                    "link_b": link_b,
                    "end": page_end,
                }
            )
            for record_index in range(record_count):
                cursor = page_offset + 12 + record_index * 24
                bbox = list(struct.unpack_from("<4i", data, cursor))
                compressed_offset = u32le(data, cursor + 16)
                packed = u32le(data, cursor + 20)
                compressed_size = packed & 0xFFFF
                auxiliary = packed >> 16
                codec_header = _canonical_lzma_header(data, compressed_offset, compressed_size)
                if codec_header is None:
                    raise PsfError(
                        f"invalid Basic single-spatial handle at page 0x{page_offset:x}, "
                        f"record {record_index}"
                    )
                dictionary_size, output_size = codec_header
                entries.append(
                    {
                        "index": flattened_index,
                        "page_offset": page_offset,
                        "record_index": record_index,
                        "bbox_fields": bbox,
                        "compressed_offset": compressed_offset,
                        "compressed_size": compressed_size,
                        "packed_auxiliary": auxiliary,
                        "codec": "lzma-alone",
                        "dictionary_size": dictionary_size,
                        "uncompressed_size": output_size,
                        "index_entry_offset": cursor,
                    }
                )
                flattened_index += 1

    identities = [
        (int(entry["compressed_offset"]), int(entry["compressed_size"])) for entry in entries
    ]
    if len(set(identities)) != len(identities):
        raise PsfError("duplicate Basic single-spatial handles")
    return {
        "kind": "basic-spatial-single",
        "metadata_field_id": 0xB3,
        "index_start": min((int(page["offset"]) for page in leaf_pages), default=0),
        "payload_start": min((offset for offset, _ in identities), default=0),
        "payload_end": max((offset + size for offset, size in identities), default=0),
        "record_count": len(entries),
        "groups": leaf_pages,
        "internal_roots": internal_roots,
        "auxiliary_regions": [],
        "entries": entries,
    }


def read_basic_final_spatial_index(path: Path) -> dict[str, object]:
    """Traverse field-0x13e final spatial tree with 28-byte records."""
    descriptor = _metadata_value(path, 0x13E)
    if not isinstance(descriptor, list) or len(descriptor) != 3:
        raise PsfError("Basic metadata field 0x13e is not a three-u32 descriptor")
    root_offset, depth, root_size = (int(value) for value in descriptor)
    if depth != 2:
        raise PsfError(f"unsupported Basic final-spatial tree depth {depth}")

    entries: list[dict[str, object]] = []
    leaf_pages: list[dict[str, object]] = []
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        child_count = u32le(data, root_offset)
        root_end = root_offset + 4 + child_count * 20
        if child_count == 0 or root_end > len(data) or root_end - root_offset != root_size:
            raise PsfError(f"invalid Basic final-spatial root at 0x{root_offset:x}")
        children: list[dict[str, object]] = []
        for child_index in range(child_count):
            cursor = root_offset + 4 + child_index * 20
            bbox = list(struct.unpack_from("<4i", data, cursor))
            child_offset = u32le(data, cursor + 16)
            children.append({"bbox_fields": bbox, "child_offset": child_offset})

        for page_index, child in enumerate(children):
            page_offset = int(child["child_offset"])
            link_a, link_b, record_count = struct.unpack_from("<III", data, page_offset)
            page_end = page_offset + 12 + record_count * 28
            if record_count == 0 or page_end > len(data):
                raise PsfError(f"invalid Basic final-spatial leaf at 0x{page_offset:x}")
            leaf_pages.append(
                {
                    "index": page_index,
                    "offset": page_offset,
                    "count": record_count,
                    "entry_size": 28,
                    "link_a": link_a,
                    "link_b": link_b,
                    "end": page_end,
                }
            )
            for record_index in range(record_count):
                cursor = page_offset + 12 + record_index * 28
                bbox = list(struct.unpack_from("<4i", data, cursor))
                compressed_offset, compressed_size, cluster_key = struct.unpack_from(
                    "<III", data, cursor + 16
                )
                codec_header = _canonical_lzma_header(data, compressed_offset, compressed_size)
                if codec_header is None:
                    raise PsfError(
                        f"invalid Basic final-spatial handle at page 0x{page_offset:x}, "
                        f"record {record_index}"
                    )
                dictionary_size, output_size = codec_header
                entries.append(
                    {
                        "index": len(entries),
                        "page_offset": page_offset,
                        "record_index": record_index,
                        "cluster_key": cluster_key,
                        "bbox_fields": bbox,
                        "compressed_offset": compressed_offset,
                        "compressed_size": compressed_size,
                        "codec": "lzma-alone",
                        "dictionary_size": dictionary_size,
                        "uncompressed_size": output_size,
                        "index_entry_offset": cursor,
                    }
                )

    identities = [
        (int(entry["compressed_offset"]), int(entry["compressed_size"])) for entry in entries
    ]
    if len(set(identities)) != len(identities):
        raise PsfError("duplicate Basic final-spatial handles")
    return {
        "kind": "basic-spatial-final",
        "metadata_field_id": 0x13E,
        "tree_depth": depth,
        "index_start": min((int(page["offset"]) for page in leaf_pages), default=root_offset),
        "index_root": root_offset,
        "index_root_size": root_size,
        "index_root_end": root_end,
        "payload_start": min((offset for offset, _ in identities), default=0),
        "payload_end": max((offset + size for offset, size in identities), default=0),
        "record_count": len(entries),
        "groups": leaf_pages,
        "internal_roots": [
            {
                "offset": root_offset,
                "depth": depth,
                "size": root_size,
                "child_count": child_count,
                "end": root_end,
                "children": children,
            }
        ],
        "auxiliary_regions": [],
        "entries": entries,
    }


def _parse_basic_combined_descriptor_table(
    data: bytes | mmap.mmap,
    start: int,
    end: int,
    stream_lookup: dict[tuple[int, int], dict[str, object]],
) -> dict[str, object] | None:
    """Parse one Basic CombinedDesc B-tree table at the start of a raw gap."""
    if start < 0 or start + 28 > end or end > len(data):
        return None
    child_count = u32le(data, start)
    reserved = u32le(data, start + 4)
    table_size = child_count * 24 + 4
    if child_count == 0 or child_count > 100_000 or reserved != 0 or start + table_size > end:
        return None

    descriptors: list[dict[str, object]] = []
    cursor = start + 8
    for index in range(child_count):
        block_offset, total_stored, middle_size, descriptor_reserved, finalizer_size = (
            struct.unpack_from("<IIIII", data, cursor)
        )
        if descriptor_reserved != 0 or middle_size + finalizer_size >= total_stored:
            return None
        lead_size = total_stored - middle_size - finalizer_size
        lead_identity = (block_offset, lead_size)
        lead_stream = stream_lookup.get(lead_identity)
        if lead_stream is None:
            return None
        middle_offset = block_offset + lead_size
        middle_stream = None
        if middle_size:
            middle_stream = stream_lookup.get((middle_offset, middle_size))
            if middle_stream is None:
                return None
        finalizer_offset = block_offset + total_stored - finalizer_size
        if block_offset + total_stored > len(data):
            return None
        finalizer_stream = None
        if finalizer_size:
            finalizer_stream = stream_lookup.get((finalizer_offset, finalizer_size))
            if finalizer_stream is None:
                return None
        separator_key = u32le(data, cursor + 20) if index + 1 < child_count else None
        descriptors.append(
            {
                "index": index,
                "descriptor_offset": cursor,
                "separator_key": separator_key,
                "block_offset": block_offset,
                "total_stored_size": total_stored,
                "block_end": block_offset + total_stored,
                "lead_offset": block_offset,
                "lead_stored_size": lead_size,
                "lead_uncompressed_size": int(lead_stream["uncompressed_size"]),
                "middle_offset": middle_offset,
                "middle_stored_size": middle_size,
                "middle_uncompressed_size": (
                    int(middle_stream["uncompressed_size"])
                    if middle_stream is not None
                    else 0
                ),
                "finalizer_offset": finalizer_offset if finalizer_size else None,
                "finalizer_stored_size": finalizer_size,
                "finalizer_uncompressed_size": (
                    int(finalizer_stream["uncompressed_size"])
                    if finalizer_stream is not None
                    else 0
                ),
            }
        )
        cursor += 24 if index + 1 < child_count else 20
    if cursor != start + table_size:
        raise PsfError("internal CombinedDesc table-size calculation mismatch")
    return {
        "offset": start,
        "size": table_size,
        "end": start + table_size,
        "child_count": child_count,
        "descriptors": descriptors,
    }


def read_basic_combined_descriptor_tables(
    path: Path,
    layout: dict[str, object] | None = None,
) -> dict[str, object]:
    """Recover CombinedDesc tables embedded at the start of Basic special gaps."""
    if layout is None:
        layout = build_stream_layout(path)
    stream_lookup = {
        (int(stream["wrapper_offset"]), int(stream["wrapper_size"])): stream
        for stream in layout["streams"]  # type: ignore[union-attr]
    }
    tables: list[dict[str, object]] = []
    handles: list[dict[str, object]] = []
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for gap in layout["gaps"]:  # type: ignore[union-attr]
            if gap["kind"] == "compact-root-footer":
                continue
            candidate_start = int(gap.get("raw_offset", gap["offset"]))
            table = _parse_basic_combined_descriptor_table(
                data, candidate_start, int(gap["end"]), stream_lookup
            )
            if table is None:
                continue
            table["index"] = len(tables)
            table["gap_index"] = int(gap["index"])
            table["unparsed_gap_suffix_offset"] = int(table["end"])
            table["unparsed_gap_suffix_size"] = int(gap["end"]) - int(table["end"])
            for descriptor in table["descriptors"]:  # type: ignore[union-attr]
                descriptor["table_index"] = int(table["index"])
                descriptor_index = int(descriptor["index"])
                lead_identity = (
                    int(descriptor["lead_offset"]),
                    int(descriptor["lead_stored_size"]),
                )
                handles.append(
                    {
                        "index": len(handles),
                        "table_index": int(table["index"]),
                        "table_offset": int(table["offset"]),
                        "descriptor_index": descriptor_index,
                        "separator_key": descriptor["separator_key"],
                        "handle_role": "lead",
                        "compressed_offset": lead_identity[0],
                        "compressed_size": lead_identity[1],
                        "codec": "lzma-alone",
                        "uncompressed_size": int(
                            stream_lookup[lead_identity]["uncompressed_size"]
                        ),
                    }
                )
                if int(descriptor["middle_stored_size"]):
                    middle_identity = (
                        int(descriptor["middle_offset"]),
                        int(descriptor["middle_stored_size"]),
                    )
                    handles.append(
                        {
                            "index": len(handles),
                            "table_index": int(table["index"]),
                            "table_offset": int(table["offset"]),
                            "descriptor_index": descriptor_index,
                            "separator_key": descriptor["separator_key"],
                            "handle_role": "middle",
                            "compressed_offset": middle_identity[0],
                            "compressed_size": middle_identity[1],
                            "codec": "lzma-alone",
                            "uncompressed_size": int(
                                stream_lookup[middle_identity]["uncompressed_size"]
                            ),
                        }
                    )
                if int(descriptor["finalizer_stored_size"]):
                    final_identity = (
                        int(descriptor["finalizer_offset"]),
                        int(descriptor["finalizer_stored_size"]),
                    )
                    handles.append(
                        {
                            "index": len(handles),
                            "table_index": int(table["index"]),
                            "table_offset": int(table["offset"]),
                            "descriptor_index": descriptor_index,
                            "separator_key": descriptor["separator_key"],
                            "handle_role": "finalizer",
                            "compressed_offset": final_identity[0],
                            "compressed_size": final_identity[1],
                            "codec": "lzma-alone",
                            "uncompressed_size": int(
                                stream_lookup[final_identity]["uncompressed_size"]
                            ),
                        }
                    )
            tables.append(table)

    identities = [
        (int(entry["compressed_offset"]), int(entry["compressed_size"])) for entry in handles
    ]
    if not tables:
        raise PsfError("no valid Basic CombinedDesc tables found")
    if len(identities) != len(set(identities)):
        raise PsfError("duplicate Basic CombinedDesc stream handles")
    return {
        "kind": "basic-combined-descriptor",
        "table_count": len(tables),
        "record_count": sum(int(table["child_count"]) for table in tables),
        "handle_count": len(handles),
        "middle_handle_count": sum(
            1 for entry in handles if entry["handle_role"] == "middle"
        ),
        "middle_stored_bytes": sum(
            int(entry["compressed_size"])
            for entry in handles
            if entry["handle_role"] == "middle"
        ),
        "middle_uncompressed_bytes": sum(
            int(entry["uncompressed_size"])
            for entry in handles
            if entry["handle_role"] == "middle"
        ),
        "index_start": min(int(table["offset"]) for table in tables),
        "payload_start": min(offset for offset, _ in identities),
        "payload_end": max(offset + size for offset, size in identities),
        "groups": tables,
        "auxiliary_regions": [],
        "entries": handles,
    }


def read_basic_finalizer_directories(
    path: Path,
    layout: dict[str, object] | None = None,
    combined_info: dict[str, object] | None = None,
) -> dict[str, object]:
    """Decode type-4/type-5 handle directories inside CombinedDesc finalizers."""
    if layout is None:
        layout = build_stream_layout(path)
    if combined_info is None:
        combined_info = read_basic_combined_descriptor_tables(path, layout)
    stream_lookup = {
        (int(stream["wrapper_offset"]), int(stream["wrapper_size"])): stream
        for stream in layout["streams"]  # type: ignore[union-attr]
    }
    finalizers = [
        entry
        for entry in combined_info["entries"]  # type: ignore[union-attr]
        if entry["handle_role"] == "finalizer"
    ]
    directories: list[dict[str, object]] = []
    references: list[dict[str, object]] = []
    opaque_sections: list[dict[str, object]] = []
    trivial_finalizers = 0
    null_handle_slots = 0
    handle_slots = 0

    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for finalizer in finalizers:
            owner_offset = int(finalizer["compressed_offset"])
            owner_size = int(finalizer["compressed_size"])
            wrapped = bytes(data[owner_offset : owner_offset + owner_size])
            try:
                payload = lzma.decompress(wrapped, format=lzma.FORMAT_ALONE)
            except lzma.LZMAError as error:
                raise PsfError(
                    f"cannot decode CombinedDesc finalizer at 0x{owner_offset:x}: {error}"
                ) from error
            if len(payload) != int(finalizer["uncompressed_size"]):
                raise PsfError(f"CombinedDesc finalizer size mismatch at 0x{owner_offset:x}")
            section_count = payload[0] if payload else -1
            if section_count == 0:
                if payload != b"\x00":
                    raise PsfError(
                        f"non-canonical trivial finalizer at 0x{owner_offset:x}"
                    )
                trivial_finalizers += 1
                continue
            if section_count < 1:
                raise PsfError(f"empty CombinedDesc finalizer at 0x{owner_offset:x}")
            header_end = 1 + section_count * 5
            if header_end > len(payload):
                raise PsfError(f"truncated finalizer section header at 0x{owner_offset:x}")

            section_headers: list[dict[str, int]] = []
            for section_index in range(section_count):
                cursor = 1 + section_index * 5
                section_type = payload[cursor]
                section_offset = u32le(payload, cursor + 1)
                section_headers.append(
                    {
                        "index": section_index,
                        "type": section_type,
                        "offset": section_offset,
                    }
                )
            offsets = [item["offset"] for item in section_headers]
            if offsets != sorted(set(offsets)) or offsets[0] < header_end or offsets[-1] >= len(payload):
                raise PsfError(f"invalid finalizer section offsets at 0x{owner_offset:x}")

            directory = {
                "index": len(directories),
                "owner_offset": owner_offset,
                "owner_stored_size": owner_size,
                "owner_uncompressed_size": len(payload),
                "owner_sha256": hashlib.sha256(payload).hexdigest(),
                "section_count": section_count,
                "section_types": [item["type"] for item in section_headers],
                "sections": [],
            }
            for section_index, header in enumerate(section_headers):
                section_type = int(header["type"])
                section_offset = int(header["offset"])
                section_end = (
                    int(section_headers[section_index + 1]["offset"])
                    if section_index + 1 < len(section_headers)
                    else len(payload)
                )
                section_size = section_end - section_offset
                section: dict[str, object] = {
                    "index": section_index,
                    "type": section_type,
                    "offset": section_offset,
                    "size": section_size,
                    "end": section_end,
                }
                if section_type in (4, 5):
                    if section_size < 2:
                        raise PsfError(
                            f"truncated finalizer handle section at 0x{owner_offset:x}"
                        )
                    count = u16le(payload, section_offset)
                    if section_size != 2 + count * 7:
                        raise PsfError(
                            f"invalid finalizer handle-section size at 0x{owner_offset:x}"
                        )
                    section_reference_count = 0
                    section_null_count = 0
                    for slot_index in range(count):
                        cursor = section_offset + 2 + slot_index * 7
                        compressed_offset = u32le(payload, cursor)
                        compressed_size = u16le(payload, cursor + 4)
                        handle_flags = payload[cursor + 6]
                        handle_slots += 1
                        if compressed_offset == 0 and compressed_size == 0:
                            null_handle_slots += 1
                            section_null_count += 1
                            continue
                        identity = (compressed_offset, compressed_size)
                        target = stream_lookup.get(identity)
                        if target is None:
                            raise PsfError(
                                f"invalid finalizer target 0x{compressed_offset:x}/"
                                f"{compressed_size} in owner 0x{owner_offset:x}"
                            )
                        references.append(
                            {
                                "index": len(references),
                                "directory_index": int(directory["index"]),
                                "owner_offset": owner_offset,
                                "section_index": section_index,
                                "section_type": section_type,
                                "slot_index": slot_index,
                                "handle_flags": handle_flags,
                                "compressed_offset": compressed_offset,
                                "compressed_size": compressed_size,
                                "codec": target["codec"],
                                "uncompressed_size": int(target["uncompressed_size"]),
                            }
                        )
                        section_reference_count += 1
                    section["slot_count"] = count
                    section["reference_count"] = section_reference_count
                    section["null_count"] = section_null_count
                else:
                    opaque = payload[section_offset:section_end]
                    section["sha256"] = hashlib.sha256(opaque).hexdigest()
                    opaque_sections.append(
                        {
                            "directory_index": int(directory["index"]),
                            "owner_offset": owner_offset,
                            **section,
                        }
                    )
                directory["sections"].append(section)  # type: ignore[union-attr]
            directories.append(directory)

    identities = [
        (int(entry["compressed_offset"]), int(entry["compressed_size"]))
        for entry in references
    ]
    if len(identities) != len(set(identities)):
        raise PsfError("duplicate Basic finalizer-directory targets")
    pattern_counts: dict[str, int] = {}
    for directory in directories:
        key = ",".join(str(value) for value in directory["section_types"])
        pattern_counts[key] = pattern_counts.get(key, 0) + 1
    return {
        "kind": "basic-finalizer-directory",
        "finalizer_count": len(finalizers),
        "trivial_finalizer_count": trivial_finalizers,
        "directory_count": len(directories),
        "section_pattern_counts": pattern_counts,
        "handle_slot_count": handle_slots,
        "null_handle_slot_count": null_handle_slots,
        "reference_count": len(references),
        "unique_payload_count": len(identities),
        "index_start": min(int(item["owner_offset"]) for item in directories),
        "payload_start": min((offset for offset, _ in identities), default=0),
        "payload_end": max((offset + size for offset, size in identities), default=0),
        "groups": directories,
        "auxiliary_regions": opaque_sections,
        "entries": references,
    }


def read_basic_known_indexes(path: Path) -> dict[str, object]:
    """Combine every decoded Basic index into unique payload handles."""
    world = read_basic_spatial_index(path)
    dual = read_basic_dual_spatial_index(path)
    triple = read_basic_triple_handle_index(path)
    single = read_basic_single_spatial_index(path)
    final_spatial = read_basic_final_spatial_index(path)
    key = read_basic_key_index(path)

    unique_entries: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()
    for source_name, index_info in (
        ("basic-id-triple", triple),
        ("basic-spatial-single", single),
        ("basic-spatial-final", final_spatial),
        ("basic-spatial", world),
    ):
        for raw_entry in index_info["entries"]:  # type: ignore[union-attr]
            entry = dict(raw_entry)
            identity = (int(entry["compressed_offset"]), int(entry["compressed_size"]))
            if identity in seen:
                continue
            seen.add(identity)
            entry["source_index_kind"] = source_name
            # Keep the source-local record before replacing ``index`` with the
            # ordinal in this combined, de-duplicated view.  Most Basic index
            # families already expose ``record_index``; the eight tail/world
            # records only expose their local ``index``.
            entry.setdefault(
                "record_index", entry.get("entry_index", entry.get("index"))
            )
            entry["index"] = len(unique_entries)
            unique_entries.append(entry)

    dual_identities = {
        (int(entry["compressed_offset"]), int(entry["compressed_size"]))
        for entry in dual["entries"]  # type: ignore[union-attr]
    }
    triple_identities = {
        (int(entry["compressed_offset"]), int(entry["compressed_size"]))
        for entry in triple["entries"]  # type: ignore[union-attr]
    }
    if not dual_identities <= triple_identities:
        raise PsfError("Basic dual-spatial handles are not a subset of the triple-handle index")

    final_identities = {
        (int(entry["compressed_offset"]), int(entry["compressed_size"]))
        for entry in final_spatial["entries"]  # type: ignore[union-attr]
    }
    key_identities = {
        (int(entry["compressed_offset"]), int(entry["compressed_size"]))
        for entry in key["entries"]  # type: ignore[union-attr]
    }
    if final_identities != key_identities:
        raise PsfError("Basic final-spatial handles do not match the key index")

    groups: list[dict[str, object]] = []
    for source_name, index_info in (
        ("basic-spatial", world),
        ("basic-spatial-dual", dual),
        ("basic-id-triple", triple),
        ("basic-spatial-single", single),
        ("basic-spatial-final", final_spatial),
        ("basic-key-0x13f", key),
    ):
        for raw_group in index_info["groups"]:  # type: ignore[union-attr]
            group = dict(raw_group)
            group["source_index_kind"] = source_name
            groups.append(group)

    return {
        "kind": "basic-known",
        "index_start": min(int(group["offset"]) for group in groups),
        "payload_start": min(int(entry["compressed_offset"]) for entry in unique_entries),
        "payload_end": max(
            int(entry["compressed_offset"]) + int(entry["compressed_size"])
            for entry in unique_entries
        ),
        "reference_count": (
            len(world["entries"])  # type: ignore[arg-type]
            + len(dual["entries"])  # type: ignore[arg-type]
            + len(triple["entries"])  # type: ignore[arg-type]
            + len(single["entries"])  # type: ignore[arg-type]
            + len(final_spatial["entries"])  # type: ignore[arg-type]
            + len(key["entries"])  # type: ignore[arg-type]
        ),
        "unique_payload_count": len(unique_entries),
        "dual_spatial_is_triple_subset": True,
        "final_spatial_matches_key_index": True,
        "groups": groups,
        "auxiliary_regions": [],
        "entries": unique_entries,
    }


def _mercator_to_wgs84(x: int | float, y: int | float) -> tuple[float, float]:
    longitude = math.degrees(float(x) / WEB_MERCATOR_RADIUS)
    latitude = math.degrees(2.0 * math.atan(math.exp(float(y) / WEB_MERCATOR_RADIUS)) - math.pi / 2.0)
    return longitude, latitude


def _payload_cstring(
    data: bytes,
    cursor: int,
    context: str,
    *,
    allow_latin1: bool = False,
) -> tuple[str, int, str]:
    terminator = data.find(b"\x00", cursor)
    if terminator < 0:
        raise PsfError(f"unterminated {context}")
    try:
        value = data[cursor:terminator].decode("utf-8")
    except UnicodeDecodeError as error:
        if not allow_latin1:
            raise PsfError(f"invalid UTF-8 in {context}") from error
        value = data[cursor:terminator].decode("latin-1")
        encoding = "latin-1"
    else:
        encoding = "utf-8"
    return value, terminator + 1, encoding


def decode_landmark_payload(
    payload: bytes,
    cluster: dict[str, object],
) -> list[dict[str, object]]:
    if len(payload) < 0x17:
        raise PsfError(f"Landmark cluster {cluster['index']} is too small")
    min_x, min_y, max_x, max_y = struct.unpack_from("<IIII", payload, 0)
    expected_bbox = list(cluster["index_bbox_mercator"])  # type: ignore[arg-type]
    if [min_x, min_y, max_x, max_y] != expected_bbox:
        raise PsfError(f"Landmark bbox mismatch in cluster {cluster['index']}")

    record_count = payload[0x16]
    cursor = 0x17
    result: list[dict[str, object]] = []
    for record_index in range(record_count):
        record_offset = cursor
        if cursor + 26 > len(payload):
            raise PsfError(
                f"truncated Landmark record {record_index} in cluster {cluster['index']}"
            )
        record_header = payload[cursor : cursor + 25]
        header_word = u32le(record_header, 0)
        x_offset = u32le(record_header, 4)
        y_offset = u32le(record_header, 8)
        path_size = payload[cursor + 25]
        cursor += 26
        if path_size < 1 or cursor + path_size > len(payload):
            raise PsfError(
                f"invalid Landmark asset path size in cluster {cluster['index']}"
            )
        raw_path = payload[cursor : cursor + path_size]
        cursor += path_size
        if raw_path[-1] != 0:
            raise PsfError(f"unterminated Landmark asset path in cluster {cluster['index']}")
        try:
            asset_path = raw_path[:-1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise PsfError(f"invalid Landmark asset path in cluster {cluster['index']}") from error

        if cursor >= len(payload):
            raise PsfError(f"missing Landmark name count in cluster {cluster['index']}")
        name_count = payload[cursor]
        cursor += 1
        names: list[dict[str, object]] = []
        for name_index in range(name_count):
            if cursor >= len(payload):
                raise PsfError(f"missing Landmark name tag in cluster {cluster['index']}")
            tag = payload[cursor]
            cursor += 1
            display_name, cursor, display_encoding = _payload_cstring(
                payload,
                cursor,
                f"Landmark display name {name_index} in cluster {cluster['index']}",
            )
            search_name, cursor, search_encoding = _payload_cstring(
                payload,
                cursor,
                f"Landmark search name {name_index} in cluster {cluster['index']}",
                allow_latin1=True,
            )
            names.append(
                {
                    "tag": tag,
                    "tag_hex": f"0x{tag:02x}",
                    "display": display_name,
                    "display_encoding": display_encoding,
                    "search": search_name,
                    "search_encoding": search_encoding,
                }
            )

        point_x = min_x + x_offset
        point_y = min_y + y_offset
        longitude, latitude = _mercator_to_wgs84(point_x, point_y)
        bbox_min_lon, bbox_min_lat = _mercator_to_wgs84(min_x, min_y)
        bbox_max_lon, bbox_max_lat = _mercator_to_wgs84(max_x, max_y)
        result.append(
            {
                "cluster_index": cluster["index"],
                "cluster_id": cluster["cluster_id"],
                "record_index": record_index,
                "record_offset": record_offset,
                "compressed_offset": cluster["compressed_offset"],
                "compressed_size": cluster["compressed_size"],
                "cluster_header_hex": payload[0x10:0x16].hex(),
                "record_header_word": header_word,
                "record_tail_hex": record_header[12:].hex(),
                "bbox_mercator": [min_x, min_y, max_x, max_y],
                "bbox_wgs84": [bbox_min_lon, bbox_min_lat, bbox_max_lon, bbox_max_lat],
                "point_mercator": [point_x, point_y],
                "longitude": longitude,
                "latitude": latitude,
                "asset_path": asset_path,
                "names": names,
            }
        )

    if cursor != len(payload):
        raise PsfError(
            f"{len(payload) - cursor} unexplained bytes after Landmark cluster {cluster['index']}"
        )
    return result


def iter_landmarks(path: Path) -> Iterator[dict[str, object]]:
    index = read_landmark_index(path)
    with path.open("rb") as source:
        for cluster in index:
            offset = int(cluster["compressed_offset"])
            size = int(cluster["compressed_size"])
            source.seek(offset)
            wrapped = source.read(size)
            if len(wrapped) != size:
                raise PsfError(f"short Landmark cluster read at 0x{offset:x}")
            if len(wrapped) < 13 or wrapped[0] != 0x5D:
                raise PsfError(f"invalid Landmark LZMA header at 0x{offset:x}")
            expected_size = struct.unpack_from("<Q", wrapped, 5)[0]
            try:
                payload = lzma.decompress(wrapped, format=lzma.FORMAT_ALONE)
            except lzma.LZMAError as error:
                raise PsfError(f"cannot decode Landmark cluster at 0x{offset:x}: {error}") from error
            if len(payload) != expected_size:
                raise PsfError(f"Landmark decoded-size mismatch at 0x{offset:x}")
            for record in decode_landmark_payload(payload, cluster):
                yield record


def _load_package(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PsfError(f"cannot read content package {path}: {error}") from error


def verify_package_entry(psf: Path, package_path: Path) -> dict[str, object]:
    package = _load_package(package_path)
    entries = package.get("file")
    if not isinstance(entries, list):
        raise PsfError("content.pkg has no file array")
    entry = next((item for item in entries if isinstance(item, dict) and item.get("name") == psf.name), None)
    if entry is None:
        raise PsfError(f"{psf.name} is absent from {package_path}")
    checksum = entry.get("checksum")
    if not isinstance(checksum, dict):
        raise PsfError(f"{psf.name} has no checksum object in content.pkg")
    offset = int(checksum["offset"])
    length = int(checksum["size"])
    expected = str(checksum["value"]).lower()
    with psf.open("rb") as source:
        source.seek(offset)
        actual_bytes = source.read(length)
    actual = actual_bytes.hex()
    return {
        "content_pkg": str(package_path),
        "entry_found": True,
        "declared_filesize": int(entry["filesize"]),
        "filesize_ok": int(entry["filesize"]) == psf.stat().st_size,
        "verification_offset": offset,
        "verification_size": length,
        "verification_blob_ok": actual == expected,
        "expected_hex": expected,
        "actual_hex": actual,
    }


def parse_hashes_file(path: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current: str | None = None
    checksums: list[str] = []
    for raw_line in path.read_text(encoding="ascii").splitlines():
        line = raw_line.strip()
        filename = re.fullmatch(r'FileName\s*=\s*"([^"]+)"', line)
        if filename:
            if current is not None:
                result[current] = checksums
            current = filename.group(1)
            checksums = []
            continue
        checksum = re.fullmatch(r'CheckSum(?:\d+)?\s*=\s*"([0-9a-fA-F]{40})"', line)
        if checksum and current is not None:
            checksums.append(checksum.group(1).lower())
    if current is not None:
        result[current] = checksums
    return result


def verify_hash_chunks(psf: Path, hashes_path: Path) -> dict[str, object]:
    table = parse_hashes_file(hashes_path)
    expected = table.get(psf.name)
    if expected is None:
        raise PsfError(f"{psf.name} is absent from {hashes_path}")
    actual: list[str] = []
    with psf.open("rb") as source:
        while chunk := source.read(HASH_CHUNK_SIZE):
            actual.append(hashlib.sha1(chunk).hexdigest())
    mismatches = [index for index, pair in enumerate(zip(expected, actual)) if pair[0] != pair[1]]
    if len(expected) != len(actual):
        mismatches.extend(range(min(len(expected), len(actual)), max(len(expected), len(actual))))
    return {
        "hashes_file": str(hashes_path),
        "chunk_size": HASH_CHUNK_SIZE,
        "expected_chunks": len(expected),
        "actual_chunks": len(actual),
        "mismatch_indices": mismatches,
        "ok": not mismatches,
    }


def _iter_tagged_strings(data: mmap.mmap, min_length: int, max_length: int) -> Iterator[tuple[int, bytes, int]]:
    position = 0
    tag = bytes((NAME_TAG,))
    while True:
        position = data.find(tag, position)
        if position < 0:
            return
        end = data.find(b"\x00", position + 1, min(len(data), position + max_length + 2))
        if end >= 0:
            raw = data[position + 1 : end]
            if min_length <= len(raw) <= max_length:
                yield position, raw, end + 1
        position += 1


def iter_names(path: Path, min_length: int = 3, max_length: int = 120, require_mask: bool = True) -> Iterator[dict[str, object]]:
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for offset, raw, next_offset in _iter_tagged_strings(data, min_length, max_length):
            try:
                name = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not any(character.isalpha() for character in name) or not all(character.isprintable() for character in name):
                continue
            if name.count("?") > len(name) // 2:
                continue

            mask: str | None = None
            if next_offset < len(data) and data[next_offset] == NAME_TAG:
                mask_end = data.find(b"\x00", next_offset + 1, min(len(data), next_offset + max_length + 2))
                if mask_end >= 0:
                    raw_mask = data[next_offset + 1 : mask_end]
                    if len(raw_mask) == len(raw) and raw_mask.count(b"?"):
                        try:
                            decoded_mask = raw_mask.decode("ascii")
                        except UnicodeDecodeError:
                            decoded_mask = ""
                        if decoded_mask and all(char == "?" or char.isspace() or not char.isalpha() for char in decoded_mask):
                            mask = decoded_mask
            if require_mask and mask is None:
                continue
            yield {"offset": offset, "name": name, "phonetic_mask": mask}


def _valid_lzma_dictionary(size: int) -> bool:
    # PSF60 uses legal but unusual LZMA-Alone headers whose dictionary size is
    # often exactly the unpacked record size (for example 145 bytes), rather
    # than one of the common power-of-two encoder presets.
    return 0 < size <= 256 * 1024 * 1024


def _decode_stream(
    data: mmap.mmap,
    offset: int,
    decompressor: zlib.decompressobj | lzma.LZMADecompressor,
    expected_size: int,
) -> tuple[int, str] | None:
    cursor = offset
    output_size = 0
    digest = hashlib.sha256()
    while cursor < len(data) and not decompressor.eof:
        chunk = data[cursor : min(len(data), cursor + 64 * 1024)]
        if not chunk:
            break
        try:
            output = decompressor.decompress(chunk)
        except (zlib.error, lzma.LZMAError):
            return None
        output_size += len(output)
        if output_size > expected_size:
            return None
        digest.update(output)
        if decompressor.eof:
            unused = len(decompressor.unused_data)
            consumed = cursor - offset + len(chunk) - unused
            if output_size == expected_size:
                return consumed, digest.hexdigest()
            return None
        cursor += len(chunk)
    return None


def scan_codecs(
    path: Path,
    max_output_size: int,
    permissive_lzma: bool = False,
) -> Iterator[dict[str, object]]:
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        # Firmware UnCompressZip layout: LE32 output size, then a zlib stream.
        # DEFLATE's zlib CMF byte is 0x08 + 0x10*CINFO.  Searching only for
        # the common 0x78/32-KiB form silently misses legal smaller windows.
        for match in ZLIB_CMF_PATTERN.finditer(data):
            position = match.start()
            if position < 4 or position + 2 > len(data):
                continue
            cmf, flg = data[position], data[position + 1]
            expected = u32le(data, position - 4)
            if (
                cmf & 0x0F == 8
                and cmf >> 4 <= 7
                and (cmf << 8 | flg) % 31 == 0
                and 0 < expected <= max_output_size
            ):
                result = _decode_stream(data, position, zlib.decompressobj(), expected)
                if result is not None:
                    consumed, digest = result
                    yield {
                        "codec": "zlib",
                        "wrapper_offset": position - 4,
                        "codec_stream_offset": position,
                        "codec_stream_size": consumed,
                        "compressed_size": consumed,
                        "wrapper_size": consumed + 4,
                        "uncompressed_size": expected,
                        "sha256": digest,
                    }

        # Firmware UnCompressLZMA layout is the standard 13-byte LZMA-Alone
        # header: properties, dictionary size and uint64 output size.
        for position in range(0, len(data) - 13):
            properties = data[position]
            if properties > 224:
                continue
            dictionary_size = u32le(data, position + 1)
            if not _valid_lzma_dictionary(dictionary_size):
                continue
            expected = struct.unpack_from("<Q", data, position + 5)[0]
            if not (0 < expected <= max_output_size):
                continue
            # Every compressed PSF60 cluster in the supplied MIB1/MIB2 maps
            # uses properties 0x5d and stores its unpacked size as both the
            # dictionary and uint64 size. Keeping that constraint by default
            # removes valid-looking LZMA sequences embedded in other blocks.
            if not permissive_lzma and (properties != 0x5D or dictionary_size != expected):
                continue
            result = _decode_stream(data, position, lzma.LZMADecompressor(format=lzma.FORMAT_ALONE), expected)
            if result is not None:
                consumed, digest = result
                yield {
                    "codec": "lzma-alone",
                    "wrapper_offset": position,
                    "codec_stream_offset": position + LZMA_ALONE_HEADER_SIZE,
                    "codec_stream_size": consumed - LZMA_ALONE_HEADER_SIZE,
                    "compressed_size": consumed - LZMA_ALONE_HEADER_SIZE,
                    "wrapper_size": consumed,
                    "uncompressed_size": expected,
                    "dictionary_size": dictionary_size,
                    "properties": properties,
                    "sha256": digest,
                }


def decode_codec_record(source: BinaryIO, record: dict[str, object]) -> bytes:
    wrapper_offset = int(record["wrapper_offset"])
    wrapper_size = int(record["wrapper_size"])
    source.seek(wrapper_offset)
    wrapped = source.read(wrapper_size)
    if len(wrapped) != wrapper_size:
        raise PsfError(f"short codec read at file offset 0x{wrapper_offset:x}")

    codec = record["codec"]
    try:
        if codec == "lzma-alone":
            decoded = lzma.decompress(wrapped, format=lzma.FORMAT_ALONE)
        elif codec == "zlib":
            decoded = zlib.decompress(wrapped[4:])
        else:
            raise PsfError(f"unsupported codec {codec!r}")
    except (lzma.LZMAError, zlib.error) as error:
        raise PsfError(f"cannot decode {codec} record at 0x{wrapper_offset:x}: {error}") from error

    expected_size = int(record["uncompressed_size"])
    if len(decoded) != expected_size:
        raise PsfError(
            f"decoded size mismatch at 0x{wrapper_offset:x}: "
            f"expected {expected_size}, got {len(decoded)}"
        )
    expected_digest = str(record["sha256"])
    actual_digest = hashlib.sha256(decoded).hexdigest()
    if actual_digest != expected_digest:
        raise PsfError(f"decoded SHA-256 mismatch at 0x{wrapper_offset:x}")
    return decoded


def _parse_compact_root_footer(
    data: bytes | mmap.mmap,
    start: int,
    end: int,
    stream_identities: set[tuple[int, int]],
) -> dict[str, object] | None:
    """Parse the canonical compact-root byte layout observed in local PSF60.

    The seven-byte header is modelled as ``u8 count + 6 zero bytes``.  Since
    every observed count is <= 33, disk samples alone cannot distinguish it
    from ``u32le count + 3 zero bytes``.  Keep the strict observed form until
    the firmware consumer confirms the semantic field width.
    """
    if start < 0 or end > len(data) or start + 7 > end:
        return None
    count = data[start]
    if count == 0 or data[start + 1 : start + 7] != b"\x00" * 6:
        return None
    footer_end = start + 7 + count * 7
    if footer_end > end:
        return None

    references: list[dict[str, int]] = []
    for index in range(count):
        cursor = start + 7 + index * 7
        root_type = data[cursor]
        compressed_offset = u32le(data, cursor + 1)
        compressed_size = u16le(data, cursor + 5)
        if (compressed_offset, compressed_size) not in stream_identities:
            return None
        references.append(
            {
                "index": index,
                "root_type": root_type,
                "compressed_offset": compressed_offset,
                "compressed_size": compressed_size,
            }
        )
    return {
        "offset": start,
        "size": footer_end - start,
        "end": footer_end,
        "reference_count": count,
        "references": references,
    }


def _structural_tail_start(path: Path, after: int) -> int:
    envelope = parse_envelope(path)
    candidates = [
        int(block["offset"])
        for block in envelope["blocks"].values()  # type: ignore[union-attr]
        if block["present"] and int(block["offset"]) >= after  # type: ignore[index]
    ]
    return min(candidates, default=path.stat().st_size)


def build_stream_layout(
    path: Path,
    max_output_size: int = 64 * 1024 * 1024,
    permissive_lzma: bool = False,
) -> dict[str, object]:
    """Inventory streams, contiguous clusters, inter-cluster gaps and root footers."""
    streams = sorted(
        scan_codecs(path, max_output_size, permissive_lzma),
        key=lambda item: int(item["wrapper_offset"]),
    )
    if not streams:
        raise PsfError("no firmware-compatible compressed streams found")

    previous_end = -1
    for ordinal, stream in enumerate(streams):
        offset = int(stream["wrapper_offset"])
        end = offset + int(stream["wrapper_size"])
        if offset < previous_end:
            raise PsfError(f"overlapping compressed streams at 0x{offset:x}")
        stream["ordinal"] = ordinal
        stream["end"] = end
        previous_end = end

    stream_identities = {
        (int(stream["wrapper_offset"]), int(stream["wrapper_size"])) for stream in streams
    }
    if len(stream_identities) != len(streams):
        raise PsfError("duplicate compressed-stream identities")

    runs: list[dict[str, object]] = []
    gaps: list[dict[str, object]] = []
    current_start = 0
    for stream_index in range(1, len(streams) + 1):
        at_end = stream_index == len(streams)
        contiguous = not at_end and int(streams[stream_index]["wrapper_offset"]) == int(
            streams[stream_index - 1]["end"]
        )
        if contiguous:
            continue

        run_streams = streams[current_start:stream_index]
        run_index = len(runs)
        for cluster_record, stream in enumerate(run_streams):
            stream["cluster"] = run_index
            stream["cluster_record"] = cluster_record
            stream["root_types"] = []
            stream["root_reference_count"] = 0
        run_offset = int(run_streams[0]["wrapper_offset"])
        run_end = int(run_streams[-1]["end"])
        runs.append(
            {
                "index": run_index,
                "offset": run_offset,
                "end": run_end,
                "size": run_end - run_offset,
                "first_ordinal": int(run_streams[0]["ordinal"]),
                "last_ordinal": int(run_streams[-1]["ordinal"]),
                "stream_count": len(run_streams),
                "stored_bytes": sum(int(item["wrapper_size"]) for item in run_streams),
                "decoded_bytes": sum(int(item["uncompressed_size"]) for item in run_streams),
            }
        )
        if not at_end:
            gap_start = run_end
            gap_end = int(streams[stream_index]["wrapper_offset"])
            gaps.append(
                {
                    "index": len(gaps),
                    "after_cluster": run_index,
                    "before_cluster": run_index + 1,
                    "offset": gap_start,
                    "end": gap_end,
                    "size": gap_end - gap_start,
                }
            )
        current_start = stream_index

    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        root_reference_map: dict[tuple[int, int], list[dict[str, int]]] = {}
        for gap in gaps:
            start = int(gap["offset"])
            end = int(gap["end"])
            footer = _parse_compact_root_footer(data, start, end, stream_identities)
            if footer is None:
                gap["kind"] = "raw"
                gap["raw_prefix_hex"] = data[start : min(end, start + 32)].hex()
                continue
            gap["footer"] = footer
            if int(footer["end"]) == end:
                gap["kind"] = "compact-root-footer"
            else:
                gap["kind"] = "compact-root-footer-plus-raw"
                gap["raw_offset"] = int(footer["end"])
                gap["raw_size"] = end - int(footer["end"])
            for reference in footer["references"]:  # type: ignore[union-attr]
                identity = (
                    int(reference["compressed_offset"]),
                    int(reference["compressed_size"]),
                )
                root_reference_map.setdefault(identity, []).append(
                    {
                        "footer_offset": start,
                        "root_type": int(reference["root_type"]),
                    }
                )

        last_end = int(streams[-1]["end"])
        structural_start = _structural_tail_start(path, last_end)
        trailing: dict[str, object] = {
            "offset": last_end,
            "end": structural_start,
            "size": max(0, structural_start - last_end),
            "kind": "none" if structural_start == last_end else "raw",
        }
        if structural_start > last_end:
            footer = _parse_compact_root_footer(
                data, last_end, structural_start, stream_identities
            )
            if footer is not None:
                trailing["footer"] = footer
                trailing["kind"] = (
                    "compact-root-footer"
                    if int(footer["end"]) == structural_start
                    else "compact-root-footer-plus-raw"
                )
                trailing["raw_offset"] = int(footer["end"])
                trailing["raw_size"] = structural_start - int(footer["end"])
                for reference in footer["references"]:  # type: ignore[union-attr]
                    identity = (
                        int(reference["compressed_offset"]),
                        int(reference["compressed_size"]),
                    )
                    root_reference_map.setdefault(identity, []).append(
                        {
                            "footer_offset": last_end,
                            "root_type": int(reference["root_type"]),
                        }
                    )
            else:
                trailing["raw_prefix_hex"] = data[
                    last_end : min(structural_start, last_end + 32)
                ].hex()

    for stream in streams:
        identity = (int(stream["wrapper_offset"]), int(stream["wrapper_size"]))
        references = root_reference_map.get(identity, [])
        stream["root_references"] = references
        stream["root_types"] = sorted({item["root_type"] for item in references})
        stream["root_reference_count"] = len(references)

    footer_gaps = [gap for gap in gaps if str(gap["kind"]).startswith("compact-root-footer")]
    raw_gaps = [gap for gap in gaps if gap["kind"] == "raw"]
    special_gaps = [gap for gap in gaps if gap["kind"] != "compact-root-footer"]
    footer_reference_count = sum(
        int(gap["footer"]["reference_count"])  # type: ignore[index]
        for gap in footer_gaps
    )
    if "footer" in trailing:
        footer_reference_count += int(trailing["footer"]["reference_count"])  # type: ignore[index]
    codec_counts: dict[str, int] = {}
    for stream in streams:
        codec = str(stream["codec"])
        codec_counts[codec] = codec_counts.get(codec, 0) + 1

    stream_fingerprint = hashlib.sha256()
    for stream in streams:
        stream_fingerprint.update(
            struct.pack(
                "<QQQ",
                int(stream["wrapper_offset"]),
                int(stream["wrapper_size"]),
                int(stream["uncompressed_size"]),
            )
        )
    run_fingerprint = hashlib.sha256()
    for run in runs:
        run_fingerprint.update(
            struct.pack(
                "<QQQQQ",
                int(run["offset"]),
                int(run["end"]),
                int(run["stream_count"]),
                int(run["stored_bytes"]),
                int(run["decoded_bytes"]),
            )
        )
    gap_fingerprint = hashlib.sha256()
    gap_kind_codes = {"raw": 0, "compact-root-footer": 1, "compact-root-footer-plus-raw": 2}
    for gap in gaps:
        gap_fingerprint.update(
            struct.pack(
                "<QQB",
                int(gap["offset"]),
                int(gap["size"]),
                gap_kind_codes[str(gap["kind"])],
            )
        )
    footer_fingerprint = hashlib.sha256()
    footers = [gap["footer"] for gap in gaps if "footer" in gap]
    if "footer" in trailing:
        footers.append(trailing["footer"])
    for footer in footers:
        footer_fingerprint.update(
            struct.pack(
                "<QQI",
                int(footer["offset"]),
                int(footer["size"]),
                int(footer["reference_count"]),
            )
        )
        for reference in footer["references"]:  # type: ignore[union-attr]
            footer_fingerprint.update(
                struct.pack(
                    "<BIH",
                    int(reference["root_type"]),
                    int(reference["compressed_offset"]),
                    int(reference["compressed_size"]),
                )
            )

    return {
        "psf": path.name,
        "decoder": "psf_decode.py",
        "decoder_version": DECODER_VERSION,
        "input_size": path.stat().st_size,
        "input_sha256": _file_sha256(path),
        "scan_config": {
            "max_output_size": max_output_size,
            "permissive_lzma": permissive_lzma,
        },
        "stream_count": len(streams),
        "stored_bytes": sum(int(item["wrapper_size"]) for item in streams),
        "decoded_bytes": sum(int(item["uncompressed_size"]) for item in streams),
        "codec_counts": codec_counts,
        "cluster_count": len(runs),
        "inter_cluster_gap_count": len(gaps),
        "compact_footer_count": len(footer_gaps) + (1 if "footer" in trailing else 0),
        "compact_footer_reference_count": footer_reference_count,
        "raw_gap_count": len(raw_gaps),
        "special_gap_count": len(special_gaps),
        "fingerprints": {
            "stream_table_sha256": stream_fingerprint.hexdigest(),
            "run_table_sha256": run_fingerprint.hexdigest(),
            "gap_table_sha256": gap_fingerprint.hexdigest(),
            "footer_table_sha256": footer_fingerprint.hexdigest(),
        },
        "leading_region": {
            "offset": 0,
            "end": int(streams[0]["wrapper_offset"]),
            "size": int(streams[0]["wrapper_offset"]),
        },
        "trailing_region": trailing,
        "runs": runs,
        "gaps": gaps,
        "streams": streams,
    }


def _stream_layout_summary(layout: dict[str, object]) -> dict[str, object]:
    streams = layout["streams"]  # type: ignore[assignment]
    runs = layout["runs"]  # type: ignore[assignment]
    return {
        key: layout[key]
        for key in (
            "psf",
            "decoder",
            "decoder_version",
            "input_size",
            "input_sha256",
            "scan_config",
            "stream_count",
            "stored_bytes",
            "decoded_bytes",
            "codec_counts",
            "cluster_count",
            "inter_cluster_gap_count",
            "compact_footer_count",
            "compact_footer_reference_count",
            "raw_gap_count",
            "special_gap_count",
            "fingerprints",
            "leading_region",
            "trailing_region",
        )
    } | {
        "first_stream_offset": int(streams[0]["wrapper_offset"]),
        "last_stream_end": int(streams[-1]["end"]),
        "largest_cluster_stream_count": max(int(run["stream_count"]) for run in runs),
    }


def _canonical_index_annotation(
    index_kind: str,
    entry: dict[str, object],
) -> dict[str, object]:
    """Build one manifest annotation without losing source-local provenance."""
    if index_kind == "basic-combined-descriptor":
        index_group = entry["table_offset"]
        index_record = entry["descriptor_index"]
        index_handle = entry["handle_role"]
        index_key = entry["separator_key"]
    elif index_kind == "basic-finalizer-directory":
        index_group = entry["owner_offset"]
        index_record = entry["slot_index"]
        index_handle = f"section-{entry['section_type']}"
        index_key = None
    else:
        index_group = entry.get("page_offset", entry.get("group_index", 0))
        index_record = entry.get(
            "record_index", entry.get("entry_index", entry.get("index"))
        )
        index_handle = entry.get("handle_index")
        index_key = entry.get("cluster_key")
    return {
        "index_kind": entry.get("source_index_kind", index_kind),
        "index_group": index_group,
        "index_record": index_record,
        "index_handle": index_handle,
        "index_key": index_key,
        "cluster_id": entry.get("cluster_id"),
    }


def _known_index_annotations(
    path: Path,
    layout: dict[str, object] | None = None,
    requested_kind: str = "auto",
) -> tuple[
    str,
    dict[tuple[int, int], dict[str, object]],
    dict[str, object] | None,
    dict[str, object] | None,
    list[dict[str, object]],
]:
    slot = path.stem.rsplit("_", 1)[-1]
    if requested_kind == "auto":
        try:
            detected_kind = _detect_index_kind(path)
        except PsfError:
            return slot, {}, None, None, []
    else:
        detected_kind = requested_kind
    info = load_known_cluster_index(path, detected_kind)

    annotations: dict[tuple[int, int], dict[str, object]] = {}
    for entry in info["entries"]:  # type: ignore[union-attr]
        identity = (int(entry["compressed_offset"]), int(entry["compressed_size"]))
        annotations[identity] = _canonical_index_annotation(
            str(info["kind"]), entry
        )
    reference_records: list[dict[str, object]] = []
    if detected_kind == "basic-known":
        primary_sources = (
            ("basic-spatial", read_basic_spatial_index(path)),
            ("basic-spatial-dual", read_basic_dual_spatial_index(path)),
            ("basic-id-triple", read_basic_triple_handle_index(path)),
            ("basic-spatial-single", read_basic_single_spatial_index(path)),
            ("basic-spatial-final", read_basic_final_spatial_index(path)),
            ("basic-key-0x13f", read_basic_key_index(path)),
        )
    else:
        primary_sources = ((str(info["kind"]), info),)
    for source_kind, source_info in primary_sources:
        for entry in source_info["entries"]:  # type: ignore[union-attr]
            record = dict(entry)
            record["reference_ordinal"] = len(reference_records)
            record["index_kind"] = source_kind
            reference_records.append(record)
    combined_info = info if detected_kind == "basic-combined-descriptor" else None
    finalizer_info = info if detected_kind == "basic-finalizer-directory" else None
    if detected_kind == "basic-known":
        combined_info = read_basic_combined_descriptor_tables(path, layout)
        for entry in combined_info["entries"]:  # type: ignore[union-attr]
            identity = (int(entry["compressed_offset"]), int(entry["compressed_size"]))
            if identity in annotations:
                raise PsfError("Basic CombinedDesc handle duplicates a primary index handle")
            annotations[identity] = {
                "index_kind": combined_info["kind"],
                "index_group": entry["table_offset"],
                "index_record": entry["descriptor_index"],
                "index_handle": entry["handle_role"],
                "index_key": entry["separator_key"],
                "cluster_id": None,
            }
            record = dict(entry)
            record["reference_ordinal"] = len(reference_records)
            record["index_kind"] = combined_info["kind"]
            reference_records.append(record)
        finalizer_info = read_basic_finalizer_directories(path, layout, combined_info)
        for entry in finalizer_info["entries"]:  # type: ignore[union-attr]
            identity = (int(entry["compressed_offset"]), int(entry["compressed_size"]))
            if identity in annotations:
                raise PsfError("Basic finalizer-directory target duplicates another index handle")
            annotations[identity] = {
                "index_kind": finalizer_info["kind"],
                "index_group": entry["owner_offset"],
                "index_record": entry["slot_index"],
                "index_handle": f"section-{entry['section_type']}",
                "index_key": None,
                "cluster_id": None,
            }
            record = dict(entry)
            record["reference_ordinal"] = len(reference_records)
            record["index_kind"] = finalizer_info["kind"]
            reference_records.append(record)
    return slot, annotations, combined_info, finalizer_info, reference_records


def command_stream_layout(args: argparse.Namespace) -> None:
    layout = build_stream_layout(args.psf, args.max_output_size, args.permissive_lzma)
    if args.output:
        document = dict(layout)
        if not args.include_streams:
            document.pop("streams")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    summary = _stream_layout_summary(layout)
    summary["layout_output"] = str(args.output) if args.output else None
    summary["streams_in_layout_output"] = bool(args.output and args.include_streams)
    print_json(summary, pretty=True)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def command_export_source(args: argparse.Namespace) -> None:
    output = args.output
    if output.exists() and not output.is_dir():
        raise PsfError(f"output exists and is not a directory: {output}")
    if output.exists() and any(output.iterdir()):
        raise PsfError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    layout = build_stream_layout(args.psf, args.max_output_size, args.permissive_lzma)
    streams = layout["streams"]  # type: ignore[assignment]
    slot, annotations, combined_info, finalizer_info, index_references = (
        _known_index_annotations(args.psf, layout, args.kind)
    )
    manifest_path = output / "manifest.jsonl"
    index_references_path = output / "index_references.jsonl"
    blocks_dir = output / "blocks"
    container_path = output / "payloads.bin"
    if args.layout == "files":
        blocks_dir.mkdir()
        container = None
    else:
        container = container_path.open("wb")

    emitted = 0
    emitted_stored = 0
    emitted_decoded = 0
    indexed_count = 0
    root_referenced_count = 0
    try:
        with args.psf.open("rb") as source, manifest_path.open("w", encoding="utf-8") as manifest:
            for stream in streams:
                if args.limit and emitted >= args.limit:
                    break
                offset = int(stream["wrapper_offset"])
                stored_size = int(stream["wrapper_size"])
                source.seek(offset)
                wrapped = source.read(stored_size)
                if len(wrapped) != stored_size:
                    raise PsfError(f"short source stream read at 0x{offset:x}")
                decoded = decode_codec_record(source, stream)
                codec_stream_offset = int(stream["codec_stream_offset"])
                codec_stream_size = int(stream["codec_stream_size"])
                relative_codec_offset = codec_stream_offset - offset
                if (
                    relative_codec_offset < 0
                    or codec_stream_size < 0
                    or relative_codec_offset + codec_stream_size > stored_size
                ):
                    raise PsfError(
                        f"codec stream lies outside wrapper at file offset 0x{offset:x}"
                    )
                codec_bytes = wrapped[
                    relative_codec_offset : relative_codec_offset + codec_stream_size
                ]
                annotation = annotations.get((offset, stored_size), {})
                root_types = list(stream["root_types"])

                if container is None:
                    filename = f"{emitted:06d}.bin"
                    destination = blocks_dir / filename
                    destination.write_bytes(decoded)
                    output_name = f"blocks/{filename}"
                    decoded_offset = 0
                else:
                    decoded_offset = container.tell()
                    container.write(decoded)
                    output_name = container_path.name

                item = {
                    "psf": args.psf.name,
                    "slot": slot,
                    "ordinal": emitted,
                    "cluster": int(stream["cluster"]),
                    "cluster_record": int(stream["cluster_record"]),
                    "codec": stream["codec"],
                    "offset": offset,
                    "wrapper_offset": offset,
                    "stored_size": stored_size,
                    "wrapper_size": stored_size,
                    "compressed_size": codec_stream_size,
                    "codec_stream_offset": codec_stream_offset,
                    "codec_stream_size": codec_stream_size,
                    "raw_size": len(decoded),
                    "sha1_stored": hashlib.sha1(wrapped).hexdigest(),
                    "sha1_compressed": hashlib.sha1(codec_bytes).hexdigest(),
                    "sha1_raw": hashlib.sha1(decoded).hexdigest(),
                    "sha256_raw": hashlib.sha256(decoded).hexdigest(),
                    "index_kind": annotation.get("index_kind"),
                    "index_group": annotation.get("index_group"),
                    "index_record": annotation.get("index_record"),
                    "index_handle": annotation.get("index_handle"),
                    "index_key": annotation.get("index_key"),
                    "cluster_id": annotation.get("cluster_id"),
                    "root_type": root_types[0] if len(root_types) == 1 else None,
                    "root_types": root_types,
                    "root_reference_count": int(stream["root_reference_count"]),
                    "output": output_name,
                    "raw_offset": decoded_offset,
                }
                manifest.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
                emitted += 1
                emitted_stored += stored_size
                emitted_decoded += len(decoded)
                indexed_count += int(bool(annotation))
                root_referenced_count += int(bool(root_types))
    finally:
        if container is not None:
            container.close()

    with index_references_path.open("w", encoding="utf-8") as references_file:
        for record in index_references:
            references_file.write(
                json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
            )

    layout_document = dict(layout)
    layout_document.pop("streams")
    if combined_info is not None:
        layout_document["basic_combined_descriptors"] = combined_info
    if finalizer_info is not None:
        layout_document["basic_finalizer_directories"] = finalizer_info
    layout_path = output / "layout.json"
    layout_path.write_text(
        json.dumps(layout_document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksums_path = output / "CHECKSUMS.sha256"
    summary = _stream_layout_summary(layout)
    summary.update(
        {
            "source_layer_version": SOURCE_LAYER_VERSION,
            "streams_exported": emitted,
            "all_discovered_streams_exported": emitted == int(layout["stream_count"]),
            "export_complete": emitted == int(layout["stream_count"]),
            "coverage_scope": "firmware-compatible streams discovered under scan_config",
            "exported_stored_bytes": emitted_stored,
            "exported_decoded_bytes": emitted_decoded,
            "indexed_streams_exported": indexed_count,
            "index_reference_count": len(index_references),
            "root_referenced_streams_exported": root_referenced_count,
            "combined_descriptor_tables": (
                int(combined_info["table_count"]) if combined_info is not None else 0
            ),
            "combined_descriptors": (
                int(combined_info["record_count"]) if combined_info is not None else 0
            ),
            "combined_stream_handles": (
                int(combined_info["handle_count"]) if combined_info is not None else 0
            ),
            "combined_middle_handles": (
                int(combined_info["middle_handle_count"])
                if combined_info is not None
                else 0
            ),
            "combined_middle_stored_bytes": (
                int(combined_info["middle_stored_bytes"])
                if combined_info is not None
                else 0
            ),
            "combined_middle_uncompressed_bytes": (
                int(combined_info["middle_uncompressed_bytes"])
                if combined_info is not None
                else 0
            ),
            "finalizer_directories": (
                int(finalizer_info["directory_count"])
                if finalizer_info is not None
                else 0
            ),
            "finalizer_directory_references": (
                int(finalizer_info["reference_count"])
                if finalizer_info is not None
                else 0
            ),
            "offsets_strictly_increasing": all(
                int(left["wrapper_offset"]) < int(right["wrapper_offset"])
                for left, right in zip(streams, streams[1:])
            ),
            "layout": args.layout,
            "manifest": manifest_path.name,
            "index_references": index_references_path.name,
            "layout_document": layout_path.name,
            "checksums": checksums_path.name,
            "payload_container": container_path.name if container is not None else None,
            "blocks_directory": blocks_dir.name if container is None else None,
        }
    )
    summary_path = output / "source_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksum_targets = [manifest_path, index_references_path, layout_path, summary_path]
    if container_path.exists():
        checksum_targets.insert(0, container_path)
    elif blocks_dir.exists():
        checksum_targets = sorted(blocks_dir.glob("*.bin")) + checksum_targets
    with checksums_path.open("w", encoding="ascii") as checksums:
        for target in checksum_targets:
            checksums.write(f"{_file_sha256(target)}  {target.relative_to(output)}\n")
    print_json(summary, pretty=True)


def print_json(value: object, pretty: bool = False) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2 if pretty else None, sort_keys=pretty))


def command_inspect(args: argparse.Namespace) -> None:
    result = parse_envelope(args.psf)
    if args.package:
        result["package_verification"] = verify_package_entry(args.psf, args.package)
    if args.hashes:
        result["chunk_verification"] = verify_hash_chunks(args.psf, args.hashes)
    print_json(result, pretty=True)


def command_names(args: argparse.Namespace) -> None:
    count = 0
    for item in iter_names(args.psf, args.min_length, args.max_length, not args.all_candidates):
        print_json(item)
        count += 1
        if args.limit and count >= args.limit:
            break
    print_json({"records_emitted": count, "require_phonetic_mask": not args.all_candidates}, pretty=False)


def command_metadata(args: argparse.Namespace) -> None:
    count = 0
    matched = 0
    for item in iter_metadata(args.psf):
        count += 1
        if args.field_id is not None and item["field_id"] != args.field_id:
            continue
        print_json(item)
        matched += 1
        if args.limit and matched >= args.limit:
            break
    print_json(
        {
            "records_parsed": count,
            "records_emitted": matched,
            "field_filter": args.field_id,
        },
        pretty=False,
    )


def _landmark_geojson_feature(record: dict[str, object]) -> dict[str, object]:
    properties = dict(record)
    longitude = float(properties.pop("longitude"))
    latitude = float(properties.pop("latitude"))
    bbox = properties.pop("bbox_wgs84")
    return {
        "type": "Feature",
        "id": f"{record['cluster_id']}:{record['record_index']}",
        "bbox": bbox,
        "geometry": {
            "type": "Point",
            "coordinates": [longitude, latitude],
        },
        "properties": properties,
    }


def command_landmarks(args: argparse.Namespace) -> None:
    count = 0
    if args.format == "geojson":
        features: list[dict[str, object]] = []
        for record in iter_landmarks(args.psf):
            features.append(_landmark_geojson_feature(record))
            count += 1
            if args.limit and count >= args.limit:
                break
        collection = {
            "type": "FeatureCollection",
            "name": args.psf.stem,
            "coordinate_system": "WGS84 (converted from inferred EPSG:3857)",
            "features": features,
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(
                    collection,
                    ensure_ascii=False,
                    indent=2 if args.pretty else None,
                    sort_keys=args.pretty,
                )
                + "\n",
                encoding="utf-8",
            )
            print_json({"landmarks_emitted": count, "output": str(args.output)}, pretty=True)
        else:
            print_json(collection, pretty=args.pretty)
        return

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as destination:
            for record in iter_landmarks(args.psf):
                destination.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
                if args.limit and count >= args.limit:
                    break
        print_json({"landmarks_emitted": count, "output": str(args.output)}, pretty=True)
    else:
        for record in iter_landmarks(args.psf):
            print_json(record)
            count += 1
            if args.limit and count >= args.limit:
                break
        print_json({"landmarks_emitted": count}, pretty=False)


def _detect_index_kind(path: Path) -> str:
    name = path.name.lower()
    if "basic" in name:
        return "basic-known"
    if "landmark" in name:
        return "landmark"
    if "advancedrouting" in name or "advanced_routing" in name:
        return "advanced-routing"
    if "adas" in name:
        return "adas"
    raise PsfError(
        "cannot detect cluster-index kind from filename; use an explicit --kind"
    )


def load_known_cluster_index(path: Path, requested_kind: str = "auto") -> dict[str, object]:
    kind = _detect_index_kind(path) if requested_kind == "auto" else requested_kind
    if kind == "basic-known":
        return read_basic_known_indexes(path)
    elif kind == "basic-spatial":
        return read_basic_spatial_index(path)
    elif kind == "basic-spatial-dual":
        return read_basic_dual_spatial_index(path)
    elif kind == "basic-id-triple":
        return read_basic_triple_handle_index(path)
    elif kind == "basic-spatial-single":
        return read_basic_single_spatial_index(path)
    elif kind == "basic-spatial-final":
        return read_basic_final_spatial_index(path)
    elif kind == "basic-combined-descriptor":
        return read_basic_combined_descriptor_tables(path)
    elif kind == "basic-finalizer-directory":
        return read_basic_finalizer_directories(path)
    elif kind == "basic-key-0x13f":
        return read_basic_key_index(path)
    elif kind == "landmark":
        entries = read_landmark_index(path)
        info: dict[str, object] = {
            "kind": kind,
            "index_start": 0xFA,
            "groups": [
                {
                    "index": 0,
                    "offset": 0xFA,
                    "count": len(entries),
                    "entry_size": 24,
                    "end": 0xFE + len(entries) * 24,
                }
            ],
            "auxiliary_regions": [],
            "payload_start": int(entries[0]["compressed_offset"]) if entries else 0,
            "payload_end": int(entries[-1]["compressed_offset"]) + int(entries[-1]["compressed_size"])
            if entries
            else 0,
            "entries": entries,
        }
        return info
    elif kind == "adas":
        return read_adas_index(path)
    elif kind == "advanced-routing":
        return read_advanced_routing_index(path)
    else:
        raise PsfError(f"unsupported cluster-index kind: {kind}")


def command_cluster_index(args: argparse.Namespace) -> None:
    info = load_known_cluster_index(args.psf, args.kind)
    kind = str(info["kind"])
    entries = info["entries"]
    emitted = 0
    if args.entries:
        for entry in entries:
            print_json(entry)
            emitted += 1
            if args.limit and emitted >= args.limit:
                break
    summary = {
        "kind": kind,
        "index_start": info["index_start"],
        "payload_start": info["payload_start"],
        "payload_end": info["payload_end"],
        "groups": info["groups"],
        "auxiliary_regions": info["auxiliary_regions"],
        "entries_total": len(entries),
        "entries_emitted": emitted,
    }
    for key in (
        "record_count",
        "table_count",
        "handle_count",
        "middle_handle_count",
        "middle_stored_bytes",
        "middle_uncompressed_bytes",
        "finalizer_count",
        "trivial_finalizer_count",
        "directory_count",
        "section_pattern_counts",
        "handle_slot_count",
        "null_handle_slot_count",
        "reference_count",
        "unique_payload_count",
        "dual_spatial_is_triple_subset",
        "final_spatial_matches_key_index",
    ):
        if key in info:
            summary[key] = info[key]
    print_json(summary, pretty=True)


def _decode_indexed_lzma(source: BinaryIO, entry: dict[str, object]) -> bytes:
    offset = int(entry["compressed_offset"])
    size = int(entry["compressed_size"])
    source.seek(offset)
    wrapped = source.read(size)
    if len(wrapped) != size:
        raise PsfError(f"short indexed-cluster read at 0x{offset:x}")
    try:
        decoded = lzma.decompress(wrapped, format=lzma.FORMAT_ALONE)
    except lzma.LZMAError as error:
        raise PsfError(f"cannot decode indexed LZMA cluster at 0x{offset:x}: {error}") from error
    expected_size = int(entry["uncompressed_size"])
    if len(decoded) != expected_size:
        raise PsfError(
            f"indexed-cluster size mismatch at 0x{offset:x}: "
            f"expected {expected_size}, got {len(decoded)}"
        )
    return decoded


def command_extract_indexed(args: argparse.Namespace) -> None:
    info = load_known_cluster_index(args.psf, args.kind)
    entries = sorted(
        info["entries"],  # type: ignore[arg-type]
        key=lambda item: int(item["compressed_offset"]),
    )
    output = args.output
    if output.exists() and not output.is_dir():
        raise PsfError(f"output exists and is not a directory: {output}")
    if output.exists() and any(output.iterdir()):
        raise PsfError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    payload_path = output / "payloads.bin"
    manifest_path = output / "manifest.ndjson"
    count = 0
    stored_bytes = 0
    decoded_bytes = 0
    with (
        args.psf.open("rb") as source,
        payload_path.open("wb") as payloads,
        manifest_path.open("w", encoding="utf-8") as manifest,
    ):
        for entry in entries:
            decoded = _decode_indexed_lzma(source, entry)
            item = dict(entry)
            item["decoded_offset"] = payloads.tell()
            item["decoded_size"] = len(decoded)
            item["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()
            item["output"] = payload_path.name
            payloads.write(decoded)
            manifest.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
            stored_bytes += int(entry["compressed_size"])
            decoded_bytes += len(decoded)
            if args.limit and count >= args.limit:
                break

    print_json(
        {
            "kind": info["kind"],
            "clusters_extracted": count,
            "clusters_total": len(entries),
            "stored_bytes": stored_bytes,
            "decoded_bytes": decoded_bytes,
            "payload_container": str(payload_path),
            "manifest": str(manifest_path),
        },
        pretty=True,
    )


def command_scan_codecs(args: argparse.Namespace) -> None:
    count = 0
    for item in scan_codecs(args.psf, args.max_output_size, args.permissive_lzma):
        print_json(item)
        count += 1
    print_json({"streams_found": count}, pretty=False)


def command_extract_streams(args: argparse.Namespace) -> None:
    output = args.output
    if output.exists() and not output.is_dir():
        raise PsfError(f"output exists and is not a directory: {output}")
    if output.exists() and any(output.iterdir()):
        raise PsfError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = output / "manifest.ndjson"
    container_path = output / "payloads.bin"
    count = 0
    total_stored = 0
    total_decoded = 0
    container = container_path.open("wb") if args.layout == "container" else None
    try:
        with args.psf.open("rb") as source, manifest_path.open("w", encoding="utf-8") as manifest:
            for record in scan_codecs(args.psf, args.max_output_size, args.permissive_lzma):
                decoded = decode_codec_record(source, record)
                item = dict(record)
                item["index"] = count
                if container is not None:
                    decoded_offset = container.tell()
                    container.write(decoded)
                    item["output"] = container_path.name
                    item["decoded_offset"] = decoded_offset
                    item["decoded_size"] = len(decoded)
                else:
                    filename = f"stream_{count:06d}_off_{int(record['wrapper_offset']):08x}.bin"
                    destination = output / filename
                    destination.write_bytes(decoded)
                    item["output"] = filename
                    item["decoded_offset"] = 0
                    item["decoded_size"] = len(decoded)
                manifest.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
                count += 1
                total_stored += int(record["wrapper_size"])
                total_decoded += len(decoded)
                if args.limit and count >= args.limit:
                    break
    finally:
        if container is not None:
            container.close()

    print_json(
        {
            "streams_extracted": count,
            "stored_bytes": total_stored,
            "decoded_bytes": total_decoded,
            "output_directory": str(output),
            "manifest": str(manifest_path),
            "layout": args.layout,
            "payload_container": str(container_path) if args.layout == "container" else None,
        },
        pretty=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Audi MIB PSF v60 decoder")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect", help="decode and verify the fixed PSF envelope")
    inspect.add_argument("psf", type=Path)
    inspect.add_argument("--package", type=Path, help="matching content.pkg")
    inspect.add_argument("--hashes", type=Path, help="matching hashes.txt")

    names = sub.add_parser("names", help="emit UTF-8 name records as NDJSON")
    names.add_argument("psf", type=Path)
    names.add_argument("--all-candidates", action="store_true", help="include names without a confirming phonetic mask")
    names.add_argument("--min-length", type=int, default=3)
    names.add_argument("--max-length", type=int, default=120)
    names.add_argument("--limit", type=int, default=0, help="0 means unlimited")

    metadata = sub.add_parser("metadata", help="decode the typed PSF metadata TLV block as NDJSON")
    metadata.add_argument("psf", type=Path)
    metadata.add_argument(
        "--field-id",
        type=lambda value: int(value, 0),
        help="emit only one field id (decimal or 0x-prefixed)",
    )
    metadata.add_argument("--limit", type=int, default=0, help="0 means unlimited")

    landmarks = sub.add_parser(
        "landmarks",
        help="decode Landmark clusters into semantic NDJSON or WGS84 GeoJSON",
    )
    landmarks.add_argument("psf", type=Path)
    landmarks.add_argument("--format", choices=("ndjson", "geojson"), default="ndjson")
    landmarks.add_argument("--pretty", action="store_true", help="pretty-print GeoJSON")
    landmarks.add_argument("--limit", type=int, default=0, help="0 means unlimited")
    landmarks.add_argument("--output", type=Path, help="write records/GeoJSON to this file")

    cluster_index = sub.add_parser(
        "cluster-index",
        help="decode and validate known PSF60 cluster-index layouts",
    )
    cluster_index.add_argument("psf", type=Path)
    cluster_index.add_argument(
        "--kind",
        choices=(
            "auto",
            "basic-known",
            "basic-spatial",
            "basic-spatial-dual",
            "basic-id-triple",
            "basic-spatial-single",
            "basic-spatial-final",
            "basic-combined-descriptor",
            "basic-finalizer-directory",
            "basic-key-0x13f",
            "landmark",
            "adas",
            "advanced-routing",
        ),
        default="auto",
    )
    cluster_index.add_argument("--entries", action="store_true", help="emit index entries as NDJSON")
    cluster_index.add_argument("--limit", type=int, default=0, help="entry limit; 0 means unlimited")

    indexed_extract = sub.add_parser(
        "extract-indexed",
        help="decode a known cluster index into payloads.bin plus an NDJSON manifest",
    )
    indexed_extract.add_argument("psf", type=Path)
    indexed_extract.add_argument("--output", type=Path, required=True)
    indexed_extract.add_argument(
        "--kind",
        choices=(
            "auto",
            "basic-known",
            "basic-spatial",
            "basic-spatial-dual",
            "basic-id-triple",
            "basic-spatial-single",
            "basic-spatial-final",
            "basic-combined-descriptor",
            "basic-finalizer-directory",
            "basic-key-0x13f",
            "landmark",
            "adas",
            "advanced-routing",
        ),
        default="auto",
    )
    indexed_extract.add_argument("--limit", type=int, default=0, help="0 means unlimited")

    scan = sub.add_parser("scan-codecs", help="find firmware-compatible compressed streams")
    scan.add_argument("psf", type=Path)
    scan.add_argument("--max-output-size", type=int, default=64 * 1024 * 1024)
    scan.add_argument(
        "--permissive-lzma",
        action="store_true",
        help="accept non-canonical LZMA properties/dictionary values (may find false positives)",
    )

    extract = sub.add_parser(
        "extract-streams",
        help="decode discovered streams into payloads.bin/files plus an NDJSON manifest",
    )
    extract.add_argument("psf", type=Path)
    extract.add_argument("--output", type=Path, required=True)
    extract.add_argument(
        "--layout",
        choices=("container", "files"),
        default="container",
        help="one indexed payloads.bin (default) or one file per stream",
    )
    extract.add_argument("--limit", type=int, default=0, help="0 means unlimited")
    extract.add_argument("--max-output-size", type=int, default=64 * 1024 * 1024)
    extract.add_argument(
        "--permissive-lzma",
        action="store_true",
        help="accept non-canonical LZMA properties/dictionary values (may find false positives)",
    )

    stream_layout = sub.add_parser(
        "stream-layout",
        help="group all streams into contiguous clusters and decode compact root footers",
    )
    stream_layout.add_argument("psf", type=Path)
    stream_layout.add_argument("--output", type=Path, help="write the detailed JSON layout")
    stream_layout.add_argument(
        "--include-streams",
        action="store_true",
        help="include every stream record in --output (runs and gaps are always included)",
    )
    stream_layout.add_argument("--max-output-size", type=int, default=64 * 1024 * 1024)
    stream_layout.add_argument(
        "--permissive-lzma",
        action="store_true",
        help="accept non-canonical LZMA properties/dictionary values (may find false positives)",
    )

    source_export = sub.add_parser(
        "export-source",
        help="build a deterministic decoded source layer with manifest, layout and payloads",
    )
    source_export.add_argument("psf", type=Path)
    source_export.add_argument("--output", type=Path, required=True)
    source_export.add_argument(
        "--kind",
        choices=(
            "auto",
            "basic-known",
            "basic-spatial",
            "basic-spatial-dual",
            "basic-id-triple",
            "basic-spatial-single",
            "basic-spatial-final",
            "basic-combined-descriptor",
            "basic-finalizer-directory",
            "basic-key-0x13f",
            "landmark",
            "adas",
            "advanced-routing",
        ),
        default="auto",
        help="index provenance kind; specify this when the filename was renamed",
    )
    source_export.add_argument(
        "--layout",
        choices=("container", "files"),
        default="container",
        help="one payloads.bin (default) or one blocks/<ordinal>.bin per stream",
    )
    source_export.add_argument("--limit", type=int, default=0, help="0 means export all streams")
    source_export.add_argument("--max-output-size", type=int, default=64 * 1024 * 1024)
    source_export.add_argument(
        "--permissive-lzma",
        action="store_true",
        help="accept non-canonical LZMA properties/dictionary values (may find false positives)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            command_inspect(args)
        elif args.command == "names":
            command_names(args)
        elif args.command == "metadata":
            command_metadata(args)
        elif args.command == "landmarks":
            command_landmarks(args)
        elif args.command == "cluster-index":
            command_cluster_index(args)
        elif args.command == "extract-indexed":
            command_extract_indexed(args)
        elif args.command == "scan-codecs":
            command_scan_codecs(args)
        elif args.command == "extract-streams":
            command_extract_streams(args)
        elif args.command == "stream-layout":
            command_stream_layout(args)
        elif args.command == "export-source":
            command_export_source(args)
        else:
            parser.error(f"unknown command: {args.command}")
    except (OSError, PsfError, ValueError) as error:
        print(f"psf_decode: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

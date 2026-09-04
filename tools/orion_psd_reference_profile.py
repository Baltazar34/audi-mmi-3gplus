#!/usr/bin/env python3
"""Profile the original MMI 3G Plus Orion PSD catalog as a writer reference."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import sys
import zlib

from orion_column_codec import type_widths, validate_code1_payload_roundtrip


CATALOG_PATTERN = re.compile(rb"([\x01-\x03])([\x02-\x1f])([ -~]{2,31})")
COLUMN_PATTERN = re.compile(rb"\x02(.)(....)\x01", re.S)
PHYSICAL_TYPE_CODES = frozenset(
    (0x10, *range(0x20, 0x27), *range(0x30, 0x37), 0x45, 0x46)
)
TARGET_CONCEPTS = (
    "RoadElement",
    "NodeRoadElement",
    "EdgeRoadElement",
    "From",
    "Vias",
    "To",
    "PointLlh",
    "PointLld",
    "CenterlineGeometry",
    "ClothoidCenterlineGeometry",
    "ClothoidCenterlineGeometryPart",
    "SpeedLimitProperty",
    "NumberOfLanesProperty",
    "PassingRestrictionProperty",
    "AdasProperty",
    "Manoeuvre",
    "ManoeuvrePart",
    "Lane",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_name(header: bytes) -> str | None:
    if not header:
        return None
    length = header[0]
    raw = header[1 : 1 + length]
    if not 1 <= length <= 32 or len(raw) != length:
        return None
    if not all(32 <= byte < 127 for byte in raw):
        return None
    return raw.decode("ascii")


def _parse_chunks(block: bytes) -> tuple[int, tuple[tuple[int, int], ...], int] | None:
    if len(block) < 0x24:
        return None
    kind, count = block[0x20], block[0x21]
    if kind not in (2, 3) or not 1 <= count <= 8:
        return None
    end = 0x22 + count * 8
    if end > len(block):
        return None
    pairs = tuple(struct.unpack_from("<II", block, 0x22 + index * 8) for index in range(count))
    return kind, pairs, end


def _decompress(kind: int, compressed: bytes, expected_size: int) -> bytes:
    if kind == 3:
        filters = [{
            "id": lzma.FILTER_LZMA1,
            "lc": 3,
            "lp": 0,
            "pb": 2,
            "dict_size": 1 << 16,
        }]
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        decoded = decoder.decompress(compressed, max_length=expected_size + 1)
    else:
        decoded = b""
        for window_bits in (-15, 15):
            try:
                decoded = zlib.decompress(compressed, window_bits)
                break
            except zlib.error:
                continue
    if len(decoded) != expected_size:
        raise ValueError(
            f"Orion chunk size mismatch: expected {expected_size}, got {len(decoded)}"
        )
    return decoded


def parse_column_table(data: bytes) -> dict[str, object] | None:
    """Find the longest contiguous physical-column table and its codec bytes.

    Each descriptor is ``tag:u8, type:u8, size:u32le, 0x01``.  NavCore's
    dispatchers constrain the physical type byte to ``PHYSICAL_TYPE_CODES``.
    Exactly one compression-code byte (1..3) follows per descriptor.
    """

    best: dict[str, object] | None = None
    for start in range(max(0, len(data) - 6)):
        cursor = start
        descriptors: list[dict[str, int]] = []
        while cursor + 7 <= len(data):
            tag, type_code = data[cursor], data[cursor + 1]
            if (
                tag not in (1, 2)
                or type_code not in PHYSICAL_TYPE_CODES
                or data[cursor + 6] != 1
            ):
                break
            descriptors.append(
                {
                    "offset": cursor,
                    "tag": tag,
                    "type_code": type_code,
                    "size": struct.unpack_from("<I", data, cursor + 2)[0],
                }
            )
            cursor += 7
        count = len(descriptors)
        if count < 3 or cursor + count > len(data):
            continue
        compression_codes = data[cursor : cursor + count]
        if any(code not in (1, 2, 3) for code in compression_codes):
            continue
        candidate: dict[str, object] = {
            "offset": start,
            "descriptor_end": cursor,
            "data_offset": cursor + count,
            "descriptors": descriptors,
            "compression_codes": list(compression_codes),
        }
        if best is None or count > len(best["descriptors"]):
            best = candidate
    return best


def parse_logical_schema(data: bytes) -> dict[str, object] | None:
    """Parse the NavCore ``parseDescriptions`` layout used by PSD 5.1.2."""

    try:
        cursor = 0
        name_length = data[cursor]
        cursor += 1
        if not 1 <= name_length <= 63:
            return None
        map_name = data[cursor : cursor + name_length].decode("ascii")
        cursor += name_length
        if cursor + 22 > len(data):
            return None
        header_values = struct.unpack_from("<5I", data, cursor)
        cursor += 20
        composite_count = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        if not 1 <= composite_count <= 4096:
            return None

        composites: list[dict[str, object]] = []
        for index in range(composite_count):
            kind = data[cursor]
            cursor += 1
            if kind not in (1, 2, 3):
                return None
            length = data[cursor]
            cursor += 1
            name = data[cursor : cursor + length].decode("ascii")
            cursor += length
            base_index: int | None = None
            if kind == 1:
                base_index = struct.unpack_from("<H", data, cursor)[0]
                cursor += 2
                if base_index != 0xFFFF and base_index >= index:
                    return None
            row_count = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            member_count = data[cursor]
            cursor += 1
            composites.append(
                {
                    "index": index,
                    "kind": kind,
                    "name": name,
                    "base_index": base_index,
                    "row_count": row_count,
                    "member_count": member_count,
                    "members": [],
                }
            )

        for composite in composites:
            members: list[dict[str, object]] = []
            for member_index in range(int(composite["member_count"])):
                member_kind = data[cursor]
                cursor += 1
                if member_kind not in (1, 2):
                    return None
                member_name: str | None = None
                annotations: list[str] = []
                if member_kind == 1:
                    length = data[cursor]
                    cursor += 1
                    member_name = data[cursor : cursor + length].decode("ascii")
                    cursor += length
                    annotation_count = data[cursor]
                    cursor += 1
                    for _ in range(annotation_count):
                        annotation_length = data[cursor]
                        cursor += 1
                        annotation = data[cursor : cursor + annotation_length]
                        cursor += annotation_length
                        annotations.append(annotation.hex())
                type_code = data[cursor]
                cursor += 1
                type_composite_index: int | None = None
                if type_code > 0xAF:
                    type_composite_index = struct.unpack_from("<H", data, cursor)[0]
                    cursor += 2
                    if type_composite_index >= composite_count:
                        return None
                optional_flag: int | None = None
                if member_kind == 1:
                    optional_flag = data[cursor]
                    cursor += 1
                members.append(
                    {
                        "index": member_index,
                        "kind": member_kind,
                        "name": member_name,
                        "annotations": annotations,
                        "type_code": type_code,
                        "type_composite_index": type_composite_index,
                        "optional_flag": optional_flag,
                    }
                )
            composite["members"] = members

        return {
            "map_name": map_name,
            "data_offset": header_values[0],
            "payload_size": header_values[1],
            "header_values": list(header_values),
            "composite_count": composite_count,
            "schema_end": cursor,
            "composites": composites,
        }
    except (IndexError, UnicodeDecodeError, struct.error):
        return None


def serialize_logical_schema(schema: dict[str, object]) -> bytes:
    """Serialize the parsed NavCore logical schema without changing fields."""

    output = bytearray()
    map_name = str(schema["map_name"]).encode("ascii")
    if not 1 <= len(map_name) <= 0xFF:
        raise ValueError("invalid Orion map name length")
    output.append(len(map_name))
    output.extend(map_name)
    header_values = [int(value) for value in schema["header_values"]]
    if len(header_values) != 5:
        raise ValueError("Orion schema requires five header values")
    output.extend(struct.pack("<5I", *header_values))
    composites = schema["composites"]
    output.extend(struct.pack("<H", len(composites)))
    for composite in composites:
        output.append(int(composite["kind"]))
        name = str(composite["name"]).encode("ascii")
        output.append(len(name))
        output.extend(name)
        if int(composite["kind"]) == 1:
            output.extend(struct.pack("<H", int(composite["base_index"])))
        output.extend(struct.pack("<I", int(composite["row_count"])))
        output.append(len(composite["members"]))
    for composite in composites:
        for member in composite["members"]:
            kind = int(member["kind"])
            output.append(kind)
            if kind == 1:
                name = str(member["name"]).encode("ascii")
                output.append(len(name))
                output.extend(name)
                annotations = member["annotations"]
                output.append(len(annotations))
                for annotation_hex in annotations:
                    annotation = bytes.fromhex(str(annotation_hex))
                    output.append(len(annotation))
                    output.extend(annotation)
            type_code = int(member["type_code"])
            output.append(type_code)
            if type_code > 0xAF:
                output.extend(
                    struct.pack("<H", int(member["type_composite_index"]))
                )
            if kind == 1:
                output.append(int(member["optional_flag"]))
    return bytes(output)


def parse_exact_column_table(
    data: bytes, schema: dict[str, object]
) -> dict[str, object] | None:
    """Use header offsets to parse NavCore part descriptors and codec bytes.

    Part kinds 1/2 occupy seven bytes.  Indirect part kind 3 additionally
    stores a member index and a second u32, for twelve bytes total.  One codec
    byte follows per part because the observed decompression amount is one.
    """

    schema_end = int(schema["schema_end"])
    data_offset = int(schema["data_offset"])
    if not schema_end < data_offset <= len(data):
        return None
    descriptors: list[dict[str, int]] = []
    cursor = schema_end
    while cursor < data_offset:
        # Once the bytes left equal the number of parsed parts, the remainder
        # is the one-byte-per-part compression-code array.
        if data_offset - cursor == len(descriptors):
            break
        kind = data[cursor]
        if kind in (1, 2):
            length = 7
        elif kind == 3:
            length = 12
        else:
            return None
        if cursor + length > data_offset:
            return None
        type_code = data[cursor + 1]
        if type_code not in PHYSICAL_TYPE_CODES or data[cursor + length - 1] != 1:
            return None
        descriptor: dict[str, int] = {
            "offset": cursor,
            "tag": kind,
            "type_code": type_code,
            "size": struct.unpack_from("<I", data, cursor + length - 5)[0],
        }
        if kind == 3:
            descriptor["member_index"] = data[cursor + 2]
            descriptor["indirect_count"] = struct.unpack_from("<I", data, cursor + 3)[0]
        descriptors.append(
            descriptor
        )
        cursor += length
    descriptor_end = cursor
    compression_codes = list(data[descriptor_end:data_offset])
    if len(compression_codes) != len(descriptors) or any(
        code not in (1, 2, 3) for code in compression_codes
    ):
        return None
    return {
        "offset": schema_end,
        "descriptor_end": descriptor_end,
        "data_offset": data_offset,
        "descriptors": descriptors,
        "compression_codes": compression_codes,
    }


def serialize_exact_column_table(table: dict[str, object]) -> bytes:
    """Serialize exact kind-1/2/3 part descriptors and their codec bytes."""

    output = bytearray()
    for descriptor in table["descriptors"]:
        kind = int(descriptor["tag"])
        output.extend((kind, int(descriptor["type_code"])))
        if kind == 3:
            output.append(int(descriptor["member_index"]))
            output.extend(struct.pack("<I", int(descriptor["indirect_count"])))
        output.extend(struct.pack("<I", int(descriptor["size"])))
        output.append(1)
    output.extend(int(code) for code in table["compression_codes"])
    return bytes(output)


def candidate_serialized_member_part_count(member: dict[str, object]) -> int:
    """Firmware-derived first-pass count of on-disk parts for one member.

    ``FUN_08335a58`` assigns two logical parts to 0x90/0xa0 and one to the
    ordinary/reference types seen in PSD3.  Optional B0 object references carry
    one additional serialized reference/index part.  Remaining deltas are
    profiled explicitly rather than hidden by a heuristic parser.
    """

    type_code = int(member["type_code"])
    base = 2 if type_code in (0x90, 0xA0) else 1
    optional_reference = (
        int(member.get("kind", 0)) == 1
        and bool(member.get("optional_flag"))
        and type_code == 0xB0
    )
    return base + int(optional_reference)


def candidate_schema_serialized_part_count(schema: dict[str, object]) -> int:
    """Predict the complete serialized descriptor count for one PSD3 schema.

    Array composites carry one structural/index part.  A 0x90 member on a
    class composite shares one of its two logical parts with the base/structure
    representation, so it removes one serialized descriptor.
    """

    composites = schema["composites"]
    has_structure_90 = any(
        int(composite["kind"]) != 1 and int(member["type_code"]) == 0x90
        for composite in composites
        for member in composite["members"]
    )
    return sum(schema_member_part_counts(schema).values())


def serialized_member_part_count(
    composite: dict[str, object],
    member: dict[str, object],
    has_structure_90: bool,
    *,
    vid_table: bool = False,
) -> int:
    count = candidate_serialized_member_part_count(member)
    if (
        int(composite["kind"]) == 3
        and bool(member.get("optional_flag"))
        and int(member["type_code"]) == 0xB0
    ):
        count += 1
    if (
        has_structure_90
        and int(composite["kind"]) == 1
        and int(member["type_code"]) == 0x90
    ):
        count -= 1
    if (
        vid_table
        and bool(member.get("optional_flag"))
        and int(member["type_code"]) != 0xB0
    ):
        count += 1
    return count


def schema_member_part_counts(
    schema: dict[str, object],
) -> dict[tuple[int, int], int]:
    """Return schema-contextual serialized part counts for every member.

    In the graph schema, EdgeRoadElement and its Attributes structure have
    equal row counts, so that structure binding is implicit and consumes no
    physical part.  NodeRoadElement.PointGeometry instead owns the following
    direct handle column: it is a permutation of the complete PointGeometry
    class range.  Vias then owns its cardinality vector, flattened Edge handles
    and optional default part.  This is proven by exact target ranges and by
    ``sum(cardinalities) == flattened_handle_count``.
    """

    composites = schema["composites"]
    composite_indexes = {
        id(composite): int(composite.get("index", ordinal))
        for ordinal, composite in enumerate(composites)
    }
    by_index = {
        composite_indexes[id(composite)]: composite for composite in composites
    }
    has_structure_90 = any(
        int(composite["kind"]) != 1 and int(member["type_code"]) == 0x90
        for composite in composites
        for member in composite["members"]
    )
    counts: dict[tuple[int, int], int] = {}
    for composite in composites:
        composite_index = composite_indexes[id(composite)]
        for member_ordinal, member in enumerate(composite["members"]):
            member_index = int(member.get("index", member_ordinal))
            counts[(composite_index, member_index)] = serialized_member_part_count(
                composite,
                member,
                has_structure_90,
                vid_table=str(schema.get("map_name")) == "VidTable",
            )
    edge_attributes: tuple[int, int] | None = None
    for composite in composites:
        if str(composite.get("name")) != "EdgeRoadElement":
            continue
        for member_ordinal, member in enumerate(composite["members"]):
            if str(member.get("name")) != "Attributes":
                continue
            target = by_index.get(int(member.get("type_composite_index", -1)))
            if (
                int(member["type_code"]) == 0xC0
                and not bool(member.get("optional_flag"))
                and target is not None
                and str(target.get("name")) == "Attributes"
                and int(target["row_count"]) == int(composite["row_count"])
            ):
                edge_attributes = (
                    composite_indexes[id(composite)],
                    int(member.get("index", member_ordinal)),
                )
            break
    for composite in composites:
        if edge_attributes is None or str(composite.get("name")) != "NodeRoadElement":
            continue
        members = {str(member.get("name")): member for member in composite["members"]}
        point = members.get("PointGeometry")
        vias = members.get("Vias")
        if point is None or vias is None:
            continue
        target = by_index.get(int(point.get("type_composite_index", -1)))
        if not (
            int(point["type_code"]) == 0xB0
            and not bool(point.get("optional_flag"))
            and target is not None
            and str(target["name"]) == "PointGeometry"
            and int(target["row_count"]) == int(composite["row_count"])
            and int(vias["type_code"]) == 0xB0
            and bool(vias.get("optional_flag"))
        ):
            continue
        composite_index = composite_indexes[id(composite)]
        point_key = (
            composite_index,
            int(point.get("index", composite["members"].index(point))),
        )
        vias_key = (
            composite_index,
            int(vias.get("index", composite["members"].index(vias))),
        )
        if counts[edge_attributes] != 1 or counts[point_key] != 1:
            raise ValueError("unexpected graph Attributes/PointGeometry part count")
        counts[edge_attributes] = 0
        counts[vias_key] += 1
    return counts


def group_serialized_parts(
    schema: dict[str, object], descriptors: list[dict[str, int]]
) -> list[dict[str, object]]:
    """Assign every on-disk descriptor to its logical composite/member."""

    composites = schema["composites"]
    part_counts = schema_member_part_counts(schema)
    cursor = 0
    groups: list[dict[str, object]] = []
    for composite in composites:
        for member in composite["members"]:
            part_count = part_counts[
                (int(composite["index"]), int(member["index"]))
            ]
            end = cursor + part_count
            if end > len(descriptors):
                raise ValueError("serialized member group exceeds descriptor table")
            groups.append(
                {
                    "composite_index": int(composite["index"]),
                    "composite_name": composite["name"],
                    "member_index": int(member["index"]),
                    "member_name": member["name"],
                    "part_start": cursor,
                    "part_count": part_count,
                    "parts": descriptors[cursor:end],
                }
            )
            cursor = end
    if cursor != len(descriptors):
        raise ValueError(
            f"member grouping leaves {len(descriptors) - cursor} descriptors"
        )
    return groups


def class_object_ranges(
    schema: dict[str, object],
) -> dict[int, tuple[int, int]]:
    """Allocate Orion class-object handles in schema order.

    Handle zero is reserved as the external/null sentinel.  Structure and
    array composites do not consume handles; class rows consume one each.
    This reproduces the ranges observed in original PSD3 graph chunks.
    """

    cursor = 1
    ranges: dict[int, tuple[int, int]] = {}
    for composite in schema["composites"]:
        if int(composite["kind"]) != 1:
            continue
        row_count = int(composite["row_count"])
        start = cursor
        end = cursor + row_count - 1
        ranges[int(composite["index"])] = (start, end)
        cursor += row_count
    return ranges


def parse_catalog(data: bytes) -> tuple[list[dict[str, int | str | None]], list[tuple[int, int]]]:
    records: list[dict[str, int | str | None]] = []
    for match in CATALOG_PATTERN.finditer(data):
        tag = match.group(1)[0]
        length = match.group(2)[0]
        raw = match.group(3)
        if len(raw) < length:
            continue
        name_bytes = raw[:length]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not (
            name[:1].isalpha()
            and name.replace("_", "").isalnum()
            and any(character.islower() for character in name)
        ):
            continue
        cursor = match.start() + 2 + length
        if tag == 1:
            if cursor + 7 > len(data):
                continue
            reference = struct.unpack_from("<H", data, cursor)[0]
            count = struct.unpack_from("<I", data, cursor + 2)[0]
            code = data[cursor + 6]
        else:
            if cursor + 5 > len(data):
                continue
            reference = None
            count = struct.unpack_from("<I", data, cursor)[0]
            code = data[cursor + 4]
        records.append(
            {
                "offset": match.start(),
                "tag": tag,
                "name": name,
                "reference": reference,
                "count": count,
                "code": code,
            }
        )

    columns: list[tuple[int, int]] = []
    for match in COLUMN_PATTERN.finditer(data):
        type_code = match.group(1)[0]
        size = struct.unpack("<I", match.group(2))[0]
        if type_code in (0x23, 0x24, 0x25, 0x34, 0x35, 0x37, 0x45):
            columns.append((type_code, size))
    return records, columns


def profile_file(path: Path, block_limit: int) -> tuple[dict[str, object], Counter[str], dict[tuple[object, ...], dict[str, object]]]:
    file_size = path.stat().st_size
    block_offset = 0
    block_count = 0
    compressed_blocks = 0
    decoded_chunks = 0
    decoded_bytes = 0
    failures = 0
    block_names: Counter[str] = Counter()
    catalog_names: Counter[str] = Counter()
    unique_records: dict[tuple[object, ...], dict[str, object]] = {}
    column_signatures: Counter[str] = Counter()
    physical_type_codes: Counter[int] = Counter()
    physical_part_kinds: Counter[int] = Counter()
    indirect_member_indices: Counter[int] = Counter()
    indirect_link_candidate_counts: Counter[int] = Counter()
    indirect_size_mismatches = 0
    candidate_member_grouping_deltas: Counter[int] = Counter()
    candidate_grouping_feature_signatures: Counter[str] = Counter()
    candidate_grouping_samples: dict[str, list[dict[str, object]]] = {}
    exact_member_groupings = 0
    grouped_indirect_local_links = 0
    schema_byte_roundtrips = 0
    column_table_byte_roundtrips = 0
    decoded_chunk_byte_roundtrips = 0
    column_compression_codes: Counter[int] = Counter()
    column_table_count = 0
    logical_schema_count = 0
    exact_header_column_tables = 0
    exact_header_payload_sizes = 0
    exact_column_payloads = 0
    code1_roundtrip_payloads = 0
    column_payload_deltas: Counter[int] = Counter()
    decode_failure_reasons: Counter[str] = Counter()
    decode_failure_block_names: Counter[str] = Counter()
    decode_failure_samples: list[dict[str, int | str]] = []

    with path.open("rb") as source:
        while block_offset < file_size and (block_limit == 0 or block_count < block_limit):
            source.seek(block_offset)
            header = source.read(0x20)
            if len(header) != 0x20:
                break
            name = _read_name(header)
            size = struct.unpack_from("<I", header, 0x10)[0]
            if name is None or size < 0x20 or block_offset + size > file_size:
                raise ValueError(f"invalid Orion block at 0x{block_offset:x}")
            source.seek(block_offset)
            block = source.read(size)
            block_names[name] += 1
            chunk_info = _parse_chunks(block)
            if chunk_info is not None:
                compressed_blocks += 1
                kind, pairs, cursor = chunk_info
                for compressed_size, uncompressed_size in pairs:
                    if compressed_size == 0:
                        continue
                    payload = block[cursor : cursor + compressed_size]
                    cursor += compressed_size
                    try:
                        decoded = _decompress(kind, payload, uncompressed_size)
                    except (EOFError, lzma.LZMAError, ValueError, zlib.error) as error:
                        failures += 1
                        reason = f"{type(error).__name__}: {error}"
                        decode_failure_reasons[reason] += 1
                        decode_failure_block_names[name] += 1
                        if len(decode_failure_samples) < 20:
                            decode_failure_samples.append(
                                {
                                    "block_offset": block_offset,
                                    "block_name": name,
                                    "kind": kind,
                                    "compressed_size": compressed_size,
                                    "uncompressed_size": uncompressed_size,
                                    "reason": reason,
                                }
                            )
                        continue
                    decoded_chunks += 1
                    decoded_bytes += len(decoded)
                    records, _ = parse_catalog(decoded)
                    logical_schema = parse_logical_schema(decoded)
                    if logical_schema is not None:
                        logical_schema_count += 1
                    column_table = (
                        parse_exact_column_table(decoded, logical_schema)
                        if logical_schema is not None
                        else None
                    )
                    if column_table is not None:
                        exact_header_column_tables += 1
                    else:
                        column_table = parse_column_table(decoded)
                    if column_table is not None:
                        column_table_count += 1
                        descriptors = column_table["descriptors"]
                        compression_codes = column_table["compression_codes"]
                        if logical_schema is not None:
                            schema_bytes = serialize_logical_schema(logical_schema)
                            if schema_bytes != decoded[: int(logical_schema["schema_end"])]:
                                raise ValueError("logical schema byte round-trip mismatch")
                            schema_byte_roundtrips += 1
                            table_bytes = serialize_exact_column_table(column_table)
                            if table_bytes != decoded[
                                int(logical_schema["schema_end"])
                                : int(column_table["data_offset"])
                            ]:
                                raise ValueError("column table byte round-trip mismatch")
                            column_table_byte_roundtrips += 1
                            candidate_count = candidate_schema_serialized_part_count(
                                logical_schema
                            )
                            candidate_member_grouping_deltas[
                                len(descriptors) - candidate_count
                            ] += 1
                            delta = len(descriptors) - candidate_count
                            members = [
                                member
                                for composite in logical_schema["composites"]
                                for member in composite["members"]
                            ]
                            feature_signature = (
                                f"delta={delta},type90="
                                f"{sum(int(member['type_code']) == 0x90 for member in members)},"
                                f"typea0="
                                f"{sum(int(member['type_code']) == 0xA0 for member in members)},"
                                f"member_kind2="
                                f"{sum(int(member['kind']) == 2 for member in members)},"
                                f"composite_kind3="
                                f"{sum(int(composite['kind']) == 3 for composite in logical_schema['composites'])}"
                            )
                            candidate_grouping_feature_signatures[feature_signature] += 1
                            sample_key = str(delta)
                            samples = candidate_grouping_samples.setdefault(sample_key, [])
                            if len(samples) < 10:
                                samples.append(
                                    {
                                        "block_offset": block_offset,
                                        "map_name": logical_schema["map_name"],
                                        "descriptor_count": len(descriptors),
                                        "candidate_count": candidate_count,
                                        "feature_signature": feature_signature,
                                    }
                                )
                            if delta == 0:
                                groups = group_serialized_parts(
                                    logical_schema, descriptors
                                )
                                exact_member_groupings += 1
                                composite_by_index = {
                                    int(composite["index"]): composite
                                    for composite in logical_schema["composites"]
                                }
                                for group in groups:
                                    composite = composite_by_index[
                                        int(group["composite_index"])
                                    ]
                                    for item in group["parts"]:
                                        if int(item["tag"]) != 3:
                                            continue
                                        linked = [
                                            member
                                            for member in composite["members"]
                                            if int(member["kind"]) == 2
                                            and int(member["index"])
                                            == int(item["member_index"])
                                        ]
                                        if len(linked) != 1:
                                            raise ValueError(
                                                "indirect part lacks one local hidden member"
                                            )
                                        grouped_indirect_local_links += 1
                        columns = [
                            (int(item["type_code"]), int(item["size"]))
                            for item in descriptors
                        ]
                        physical_type_codes.update(kind for kind, _ in columns)
                        physical_part_kinds.update(
                            int(item["tag"]) for item in descriptors
                        )
                        indirect_member_indices.update(
                            int(item["member_index"])
                            for item in descriptors
                            if int(item["tag"]) == 3
                        )
                        for item in descriptors:
                            if int(item["tag"]) != 3:
                                continue
                            member_index = int(item["member_index"])
                            candidates = (
                                [
                                    member
                                    for composite in logical_schema["composites"]
                                    for member in composite["members"]
                                    if int(member["kind"]) == 2
                                    and int(member["index"]) == member_index
                                ]
                                if logical_schema is not None
                                else []
                            )
                            indirect_link_candidate_counts[len(candidates)] += 1
                            _, storage_bits = type_widths(int(item["type_code"]))
                            expected_size = (
                                int(item["indirect_count"]) * storage_bits + 7
                            ) // 8
                            if expected_size != int(item["size"]):
                                indirect_size_mismatches += 1
                        column_compression_codes.update(compression_codes)
                        payload_size = sum(length for _, length in columns)
                        if (
                            logical_schema is not None
                            and payload_size == int(logical_schema["payload_size"])
                        ):
                            exact_header_payload_sizes += 1
                        payload_available = len(decoded) - int(column_table["data_offset"])
                        payload_delta = payload_available - payload_size
                        column_payload_deltas[payload_delta] += 1
                        if payload_delta == 0:
                            exact_column_payloads += 1
                            if all(code == 1 for code in compression_codes):
                                validate_code1_payload_roundtrip(
                                    decoded,
                                    int(column_table["data_offset"]),
                                    descriptors,
                                    compression_codes,
                                )
                                code1_roundtrip_payloads += 1
                            if logical_schema is not None:
                                rebuilt = (
                                    schema_bytes
                                    + table_bytes
                                    + decoded[int(column_table["data_offset"]) :]
                                )
                                if rebuilt != decoded:
                                    raise ValueError("decoded chunk byte round-trip mismatch")
                                decoded_chunk_byte_roundtrips += 1
                        signature = ",".join(
                            f"{kind:02x}:{length}" for kind, length in columns
                        )
                        column_signatures[signature] += 1
                    for record in records:
                        record_name = str(record["name"])
                        catalog_names[record_name] += 1
                        key = (
                            record["tag"],
                            record_name,
                            record["reference"],
                            record["count"],
                            record["code"],
                        )
                        if key not in unique_records:
                            unique_records[key] = {
                                **record,
                                "atlas_file": str(path),
                                "block_offset": block_offset,
                            }
            block_offset += size
            block_count += 1
            if block_count % 1000 == 0:
                print(
                    f"orion-reference file={path.name} blocks={block_count} "
                    f"decoded_chunks={decoded_chunks} names={len(catalog_names)}",
                    flush=True,
                )

    report: dict[str, object] = {
        "path": str(path),
        "size": file_size,
        "sha256": _sha256(path),
        "block_limit": block_limit,
        "blocks_scanned": block_count,
        "bytes_scanned": block_offset,
        "file_coverage": block_offset / file_size,
        "compressed_blocks": compressed_blocks,
        "decoded_chunks": decoded_chunks,
        "decoded_bytes": decoded_bytes,
        "decode_failures": failures,
        "decode_failure_reasons": dict(decode_failure_reasons.most_common()),
        "decode_failure_block_names": dict(decode_failure_block_names.most_common()),
        "decode_failure_samples": decode_failure_samples,
        "block_names": dict(block_names),
        "catalog_name_count": len(catalog_names),
        "catalog_record_count": sum(catalog_names.values()),
        "top_catalog_names": dict(catalog_names.most_common(100)),
        "column_signature_count": len(column_signatures),
        "column_table_count": column_table_count,
        "logical_schema_count": logical_schema_count,
        "exact_header_column_tables": exact_header_column_tables,
        "exact_header_payload_sizes": exact_header_payload_sizes,
        "exact_column_payloads": exact_column_payloads,
        "code1_roundtrip_payloads": code1_roundtrip_payloads,
        "column_payload_deltas": {
            str(delta): count for delta, count in sorted(column_payload_deltas.items())
        },
        "physical_type_codes": {
            f"0x{code:02x}": count
            for code, count in sorted(physical_type_codes.items())
        },
        "physical_part_kinds": {
            str(kind): count for kind, count in sorted(physical_part_kinds.items())
        },
        "indirect_member_indices": {
            str(index): count
            for index, count in sorted(indirect_member_indices.items())
        },
        "indirect_link_candidate_counts": {
            str(count): occurrences
            for count, occurrences in sorted(indirect_link_candidate_counts.items())
        },
        "indirect_size_mismatches": indirect_size_mismatches,
        "candidate_member_grouping_deltas": {
            str(delta): count
            for delta, count in sorted(candidate_member_grouping_deltas.items())
        },
        "candidate_grouping_feature_signatures": dict(
            candidate_grouping_feature_signatures.most_common(100)
        ),
        "candidate_grouping_samples": candidate_grouping_samples,
        "exact_member_groupings": exact_member_groupings,
        "grouped_indirect_local_links": grouped_indirect_local_links,
        "schema_byte_roundtrips": schema_byte_roundtrips,
        "column_table_byte_roundtrips": column_table_byte_roundtrips,
        "decoded_chunk_byte_roundtrips": decoded_chunk_byte_roundtrips,
        "column_compression_codes": {
            str(code): count for code, count in sorted(column_compression_codes.items())
        },
    }
    return report, catalog_names, unique_records


def run(paths: list[Path], output: Path, block_limit: int) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    combined_names: Counter[str] = Counter()
    combined_records: dict[tuple[object, ...], dict[str, object]] = {}
    file_reports: list[dict[str, object]] = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        report, names, records = profile_file(path, block_limit)
        file_reports.append(report)
        combined_names.update(names)
        combined_records.update(records)

    found = {name: combined_names[name] for name in TARGET_CONCEPTS}
    report = {
        "schema_version": 1,
        "purpose": "read-only original Orion PSD schema dictionary for the future writer",
        "files": file_reports,
        "catalog_name_count": len(combined_names),
        "catalog_record_count": sum(combined_names.values()),
        "target_concepts": found,
        "all_target_concepts_seen": all(found.values()),
        "important_boundary": (
            "catalog names and counts identify the target object model, but do not by "
            "themselves define Orion column encoding, bit widths, offsets, indexes or "
            "object-reference serialization"
        ),
    }
    report_path = output / "report.json"
    records_path = output / "catalog_records.jsonl"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with records_path.open("w", encoding="utf-8") as sink:
        for record in sorted(
            combined_records.values(),
            key=lambda item: (str(item["name"]), int(item["tag"]), int(item["block_offset"])),
        ):
            sink.write(json.dumps(record, sort_keys=True) + "\n")
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n"
        f"{_sha256(records_path)}  {records_path.name}\n",
        encoding="ascii",
    )
    print(
        f"orion-reference stage=complete files={len(paths)} "
        f"names={len(combined_names)} output={output}",
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--block-limit",
        type=int,
        default=3000,
        help="blocks per file; zero scans the complete file",
    )
    args = parser.parse_args()
    try:
        run(args.atlas, args.output, args.block_limit)
    except (OSError, ValueError) as error:
        print(f"orion_psd_reference_profile: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

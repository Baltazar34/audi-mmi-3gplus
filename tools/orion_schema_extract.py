#!/usr/bin/env python3
"""Extract self-contained logical/physical schema samples from Orion ATLAS."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import lzma
from pathlib import Path
import struct
import sys
import zlib

from orion_column_codec import code1_column_layout, type_widths, unpack_code1_values
from orion_psd_reference_profile import (
    _decompress,
    _parse_chunks,
    _read_name,
    class_object_ranges,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
    serialize_exact_column_table,
    serialize_logical_schema,
)


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-schema-extract stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def schema_names(schema: dict[str, object]) -> set[str]:
    names = {str(schema["map_name"])}
    for composite in schema["composites"]:
        names.add(str(composite["name"]))
        names.update(
            str(member["name"])
            for member in composite["members"]
            if member.get("name") is not None
        )
    return names


def scalar_group_profiles(
    decoded: bytes,
    schema: dict[str, object],
    table: dict[str, object],
    groups: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Decode groups whose one physical part exactly matches the row count."""

    layouts = code1_column_layout(
        len(decoded),
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )
    composites = {
        int(composite["index"]): composite for composite in schema["composites"]
    }
    profiles: list[dict[str, object]] = []
    for group in groups:
        if int(group["part_count"]) != 1:
            continue
        row_count = int(composites[int(group["composite_index"])]["row_count"])
        if row_count == 0:
            continue
        part_index = int(group["part_start"])
        layout = layouts[part_index]
        _, storage_bits = type_widths(layout.type_code)
        expected_size = (row_count * storage_bits + 7) // 8
        if layout.payload_size != expected_size:
            continue
        payload = decoded[
            layout.payload_offset : layout.payload_offset + layout.payload_size
        ]
        values = unpack_code1_values(layout.type_code, payload, row_count)
        profiles.append(
            {
                "composite_index": int(group["composite_index"]),
                "composite_name": group["composite_name"],
                "member_index": int(group["member_index"]),
                "member_name": group["member_name"],
                "physical_type": layout.type_code,
                "row_count": row_count,
                "minimum": min(values),
                "maximum": max(values),
                "distinct_count": len(set(values)),
                "sum": sum(values),
                "first_values": values[:16],
                "last_values": values[-16:],
                "value_counts": {
                    str(value): count
                    for value, count in sorted(Counter(values).items())
                }
                if len(set(values)) <= 32
                else None,
            }
        )
    return profiles


def direct_reference_profiles(
    decoded: bytes,
    schema: dict[str, object],
    table: dict[str, object],
    groups: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Prove which B0 columns directly store global class handles."""

    layouts = code1_column_layout(
        len(decoded),
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )
    composites = {
        int(composite["index"]): composite for composite in schema["composites"]
    }
    ranges = class_object_ranges(schema)
    profiles: list[dict[str, object]] = []
    for group in groups:
        composite = composites[int(group["composite_index"])]
        member = composite["members"][int(group["member_index"])]
        if int(member["type_code"]) != 0xB0 or int(group["part_count"]) != 1:
            continue
        target_index = int(member["type_composite_index"])
        if target_index not in ranges:
            continue
        row_count = int(composite["row_count"])
        layout = layouts[int(group["part_start"])]
        _, storage_bits = type_widths(layout.type_code)
        if layout.payload_size != (row_count * storage_bits + 7) // 8:
            continue
        payload = decoded[
            layout.payload_offset : layout.payload_offset + layout.payload_size
        ]
        values = unpack_code1_values(layout.type_code, payload, row_count)
        target_start, target_end = ranges[target_index]
        invalid = [
            value
            for value in values
            if value != 0 and not target_start <= value <= target_end
        ]
        profiles.append(
            {
                "composite_name": composite["name"],
                "member_name": member["name"],
                "target_composite_index": target_index,
                "target_composite_name": composites[target_index]["name"],
                "target_handle_start": target_start,
                "target_handle_end": target_end,
                "zero_sentinel_count": values.count(0),
                "nonzero_count": len(values) - values.count(0),
                "direct_global_handle_encoding": not invalid,
                "invalid_value_count": len(invalid),
                "invalid_value_samples": invalid[:16],
            }
        )
    return profiles


def physical_part_profiles(
    decoded: bytes,
    schema: dict[str, object],
    table: dict[str, object],
    groups: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Profile every direct fixed-width part independently of logical rows."""

    layouts = code1_column_layout(
        len(decoded),
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )
    owner_by_part = {
        part_index: group
        for group in groups
        for part_index in range(
            int(group["part_start"]),
            int(group["part_start"]) + int(group["part_count"]),
        )
    }
    profiles: list[dict[str, object]] = []
    for layout in layouts:
        _, storage_bits = type_widths(layout.type_code)
        if layout.payload_size * 8 % storage_bits:
            continue
        value_count = layout.payload_size * 8 // storage_bits
        if value_count == 0:
            values: list[int] = []
        else:
            payload = decoded[
                layout.payload_offset : layout.payload_offset + layout.payload_size
            ]
            values = unpack_code1_values(layout.type_code, payload, value_count)
        owner = owner_by_part[layout.index]
        profiles.append(
            {
                "part_index": layout.index,
                "owner_composite": owner["composite_name"],
                "owner_member": owner["member_name"],
                "owner_part_index": layout.index - int(owner["part_start"]),
                "tag": layout.tag,
                "physical_type": layout.type_code,
                "value_count": value_count,
                "minimum": min(values) if values else None,
                "maximum": max(values) if values else None,
                "sum": sum(values),
                "distinct_count": len(set(values)),
                "first_values": values[:16],
                "last_values": values[-16:],
                "value_counts": {
                    str(value): count
                    for value, count in sorted(Counter(values).items())
                }
                if len(set(values)) <= 32
                else None,
            }
        )
    return profiles


def extract(
    atlas: Path,
    output: Path,
    required_names: set[str],
    sample_limit: int,
    block_limit: int,
) -> dict[str, object]:
    if sample_limit < 1:
        raise ValueError("sample-limit must be positive")
    if not required_names:
        raise ValueError("at least one required name is needed")
    output.mkdir(parents=True, exist_ok=True)
    file_size = atlas.stat().st_size
    block_offset = 0
    block_count = 0
    decoded_count = 0
    samples: list[dict[str, object]] = []
    artifacts: list[Path] = []
    _progress("scan", atlas=atlas, required=",".join(sorted(required_names)))
    with atlas.open("rb") as source:
        while (
            block_offset < file_size
            and len(samples) < sample_limit
            and (block_limit == 0 or block_count < block_limit)
        ):
            source.seek(block_offset)
            header = source.read(0x20)
            if len(header) != 0x20:
                break
            block_name = _read_name(header)
            block_size = struct.unpack_from("<I", header, 0x10)[0]
            if (
                block_name is None
                or block_size < 0x20
                or block_offset + block_size > file_size
            ):
                raise ValueError(f"invalid Orion block at 0x{block_offset:x}")
            source.seek(block_offset)
            block = source.read(block_size)
            chunk_info = _parse_chunks(block)
            if chunk_info is not None:
                kind, pairs, cursor = chunk_info
                for chunk_index, (compressed_size, uncompressed_size) in enumerate(pairs):
                    compressed = block[cursor : cursor + compressed_size]
                    cursor += compressed_size
                    if compressed_size == 0:
                        continue
                    try:
                        decoded = _decompress(kind, compressed, uncompressed_size)
                    except (EOFError, lzma.LZMAError, ValueError, zlib.error):
                        continue
                    decoded_count += 1
                    schema = parse_logical_schema(decoded)
                    if schema is None or not required_names <= schema_names(schema):
                        continue
                    table = parse_exact_column_table(decoded, schema)
                    if table is None:
                        raise ValueError("matching schema has no exact physical table")
                    groups = group_serialized_parts(schema, table["descriptors"])
                    scalar_profiles = scalar_group_profiles(
                        decoded, schema, table, groups
                    )
                    reference_profiles = direct_reference_profiles(
                        decoded, schema, table, groups
                    )
                    part_profiles = physical_part_profiles(
                        decoded, schema, table, groups
                    )
                    schema_end = int(schema["schema_end"])
                    data_offset = int(schema["data_offset"])
                    if serialize_logical_schema(schema) != decoded[:schema_end]:
                        raise ValueError("matching schema failed byte round-trip")
                    if (
                        serialize_exact_column_table(table)
                        != decoded[schema_end:data_offset]
                    ):
                        raise ValueError("matching physical table failed byte round-trip")
                    ordinal = len(samples)
                    binary_path = output / f"sample_{ordinal:02d}.decoded.bin"
                    json_path = output / f"sample_{ordinal:02d}.schema.json"
                    binary_path.write_bytes(decoded)
                    sample = {
                        "sample": ordinal,
                        "block_offset": block_offset,
                        "block_name": block_name,
                        "chunk_index": chunk_index,
                        "decoded_size": len(decoded),
                        "decoded_sha256": _sha256(binary_path),
                        "required_names": sorted(required_names),
                        "schema": schema,
                        "table": table,
                        "groups": groups,
                        "scalar_group_profiles": scalar_profiles,
                        "direct_reference_profiles": reference_profiles,
                        "physical_part_profiles": part_profiles,
                    }
                    json_path.write_text(
                        json.dumps(sample, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    artifacts.extend((binary_path, json_path))
                    samples.append(
                        {
                            "binary": binary_path.name,
                            "schema": json_path.name,
                            "block_offset": block_offset,
                            "block_name": block_name,
                            "decoded_size": len(decoded),
                            "decoded_sha256": _sha256(binary_path),
                        }
                    )
                    _progress(
                        "match",
                        sample=ordinal,
                        block=f"0x{block_offset:x}",
                        decoded_bytes=len(decoded),
                        composites=len(schema["composites"]),
                        parts=len(table["descriptors"]),
                    )
                    if len(samples) >= sample_limit:
                        break
            block_offset += block_size
            block_count += 1
            if block_count and block_count % 1000 == 0:
                _progress("scan-progress", blocks=block_count, decoded=decoded_count)
    if len(samples) != sample_limit:
        raise ValueError(
            f"found {len(samples)} matching samples, expected {sample_limit}"
        )
    manifest = {
        "schema_version": 1,
        "status": "complete",
        "source": {
            "path": str(atlas),
            "size": file_size,
            "sha256": _sha256(atlas),
            "read_only": True,
        },
        "required_names": sorted(required_names),
        "blocks_scanned": block_count + 1,
        "decoded_chunks_seen": decoded_count,
        "samples": samples,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    artifacts.append(manifest_path)
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in artifacts),
        encoding="ascii",
    )
    _progress("complete", output=output, samples=len(samples))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require", action="append", dest="required", default=[])
    parser.add_argument("--sample-limit", type=int, default=1)
    parser.add_argument("--block-limit", type=int, default=0)
    args = parser.parse_args()
    required = set(args.required) or {
        "NodeRoadElement",
        "EdgeRoadElement",
        "From",
        "To",
        "PointLlh",
    }
    try:
        manifest = extract(
            args.atlas, args.output, required, args.sample_limit, args.block_limit
        )
    except (OSError, ValueError) as error:
        print(f"orion-schema-extract error={error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

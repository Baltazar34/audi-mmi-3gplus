"""Lossless PSF60 AdvancedRouting and ADAS cluster decoders."""

from __future__ import annotations

from dataclasses import dataclass
import struct

from psf_decode import PsfError


@dataclass(frozen=True)
class LayerRecord:
    edge_index: int
    offset: int
    size: int
    raw: bytes


@dataclass(frozen=True)
class AdvancedRoutingCluster:
    edge_count: int
    metadata_u16: int
    record_offsets: tuple[int, ...]
    records: tuple[LayerRecord, ...]


@dataclass(frozen=True)
class AdasCluster:
    edge_count: int
    record_data_offset: int
    declared_size: int
    encoded_size_table: bytes
    record_sizes: tuple[int, ...]
    records: tuple[LayerRecord, ...]


def decode_advanced_routing_cluster(payload: bytes) -> AdvancedRoutingCluster:
    if len(payload) < 5:
        raise PsfError("truncated AdvancedRouting cluster header")
    edge_count = payload[0]
    if edge_count == 0:
        raise PsfError("AdvancedRouting cluster has zero records")
    metadata_u16 = struct.unpack_from("<H", payload, 1)[0]
    directory_end = 3 + edge_count * 2
    if directory_end > len(payload):
        raise PsfError("truncated AdvancedRouting offset table")
    offsets = struct.unpack_from(f"<{edge_count}H", payload, 3)
    if offsets[0] != directory_end:
        raise PsfError(
            "AdvancedRouting first record offset does not follow the directory"
        )
    if tuple(sorted(set(offsets))) != offsets:
        raise PsfError("AdvancedRouting record offsets are not strictly increasing")
    if offsets[-1] >= len(payload):
        raise PsfError("AdvancedRouting final record offset is outside the cluster")
    records = tuple(
        LayerRecord(
            edge_index=index,
            offset=start,
            size=end - start,
            raw=payload[start:end],
        )
        for index, start in enumerate(offsets)
        for end in (offsets[index + 1] if index + 1 < edge_count else len(payload),)
    )
    return AdvancedRoutingCluster(edge_count, metadata_u16, offsets, records)


def decode_adas_record_sizes(encoded: bytes, expected_count: int) -> tuple[int, ...]:
    """Decode PSF60 ADAS one/two-byte big-endian record lengths.

    Values below 0x80 occupy one byte.  A set high bit means that the low
    seven bits are the high part and one following byte is the low part.
    """
    sizes: list[int] = []
    cursor = 0
    while cursor < len(encoded):
        first = encoded[cursor]
        cursor += 1
        if first & 0x80:
            if cursor >= len(encoded):
                raise PsfError("truncated ADAS two-byte record length")
            value = ((first & 0x7F) << 8) | encoded[cursor]
            cursor += 1
            if value < 0x80:
                raise PsfError("non-canonical ADAS two-byte record length")
        else:
            value = first
        if value == 0:
            raise PsfError("ADAS record has zero length")
        sizes.append(value)
    if len(sizes) != expected_count:
        raise PsfError(
            f"ADAS size-table count mismatch: expected {expected_count}, got {len(sizes)}"
        )
    return tuple(sizes)


def decode_adas_cluster(payload: bytes) -> AdasCluster:
    if len(payload) < 8:
        raise PsfError("truncated ADAS cluster header")
    edge_count = payload[0]
    if edge_count == 0:
        raise PsfError("ADAS cluster has zero records")
    record_data_offset = struct.unpack_from("<H", payload, 1)[0]
    declared_size = struct.unpack_from("<I", payload, 3)[0]
    if declared_size != len(payload):
        raise PsfError(
            f"ADAS declared-size mismatch: expected {declared_size}, got {len(payload)}"
        )
    if not 7 <= record_data_offset <= len(payload):
        raise PsfError("ADAS record-data offset is outside the cluster")
    encoded_sizes = payload[7:record_data_offset]
    sizes = decode_adas_record_sizes(encoded_sizes, edge_count)
    if sum(sizes) != len(payload) - record_data_offset:
        raise PsfError("ADAS record sizes do not cover the record-data region")
    records: list[LayerRecord] = []
    cursor = record_data_offset
    for edge_index, size in enumerate(sizes):
        end = cursor + size
        records.append(LayerRecord(edge_index, cursor, size, payload[cursor:end]))
        cursor = end
    return AdasCluster(
        edge_count,
        record_data_offset,
        declared_size,
        encoded_sizes,
        sizes,
        tuple(records),
    )

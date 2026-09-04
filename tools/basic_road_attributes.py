#!/usr/bin/env python3
"""Firmware-backed primitives for MIB Basic road attributes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from collections.abc import Iterable
import struct

from psf_decode import PsfError


EDGE_DESCRIPTOR_SIZE = 9


class GeometryAttributeType(IntEnum):
    """Firmware EXTT enum in its contiguous stored tag order."""

    SIMPLE_SPEED_LIMIT = 1
    EXTENDED_SPEED_LIMIT = 2
    LANE_CONNECTIVITY = 3
    JUNCTION_VIEW = 4
    THROUGH_ROUTE_INFO = 5
    SIGN_INFO = 6
    GRADE_CATEGORY = 7
    STRAIGHT_ON = 8
    ATTRIBUTE_EX1 = 9
    TOLL_GATE_INFO = 10
    Z_ORDER_INFO = 11
    Z_VALUE_INFO = 12
    NUMBER_OF_LANES = 13
    SIMPLE_PASSING_RESTRICTION = 14
    EXTENDED_PASSING_RESTRICTION = 15
    LANES = 16
    ADDITIONAL_GEOMETRY = 17
    TRAFFIC_SIGNAL_INFO = 18
    UNKNOWN = 19


@dataclass(frozen=True)
class TravelDirection:
    a_to_b_allowed: bool
    b_to_a_allowed: bool

    @property
    def mode(self) -> str:
        if self.a_to_b_allowed and self.b_to_a_allowed:
            return "both"
        if self.a_to_b_allowed:
            return "a-to-b-only"
        if self.b_to_a_allowed:
            return "b-to-a-only"
        return "neither"


@dataclass(frozen=True)
class TaggedAttributeHeader:
    type_id: int
    has_next: bool


@dataclass(frozen=True)
class TaggedAttribute:
    type_id: int
    has_next: bool
    offset: int
    data: bytes


@dataclass(frozen=True)
class SimpleSpeedLimit:
    """Firmware's one-byte simple speed-limit value.

    The consumer proves the meaning and the sentinel handling.  The storage
    unit is intentionally left unnamed until an independent firmware/API
    conversion proves it.
    """

    value: int


@dataclass(frozen=True)
class ExtendedSpeedLimit:
    a_to_b: bool
    b_to_a: bool
    subtype: int
    value: int
    pair_count: int
    base_condition: int
    condition_pairs: tuple[tuple[int, int], ...]
    source_selector: int


@dataclass(frozen=True)
class NumberOfLanes:
    at_node_a: int | None
    at_node_b: int | None


@dataclass(frozen=True)
class LaneRecord:
    byte_0_low_nibble: int
    byte_0_bit_4: bool
    byte_0_bit_5: bool
    byte_0_high_2_bits: int
    byte_1_low_nibble_code: int
    byte_1_high_nibble: int
    byte_2_high_nibble_code: int
    byte_2_low_nibble: int
    byte_3_low_3_bits_code: int
    byte_3_high_5_bits: int
    firmware_category_mask: int | None
    raw: bytes


@dataclass(frozen=True)
class LanesAttribute:
    header_low_nibble: int
    records: tuple[LaneRecord, ...]


@dataclass(frozen=True)
class ExtendedPassingRestrictionHeader:
    a_to_b: bool
    b_to_a: bool
    has_detailed_records: bool
    detailed_record_count: int


@dataclass(frozen=True)
class AutomotiveAttributes:
    base_mask: int
    has_dynamic_extension: bool

    @property
    def active_bit_indices(self) -> tuple[int, ...]:
        return tuple(index for index in range(13) if self.base_mask & (1 << index))


def decode_travel_direction(descriptor: bytes) -> TravelDirection:
    """Mirror the direct checks in firmware VA 0x002e1c9c.

    Descriptor byte 3 bit 0 is A->B accessibility; bit 1 is B->A
    accessibility.  Time-dependent extensions may further restrict an allowed
    direction, so these booleans are the static/base access flags.
    """

    if len(descriptor) != EDGE_DESCRIPTOR_SIZE:
        raise PsfError(
            f"Basic edge descriptor must be {EDGE_DESCRIPTOR_SIZE} bytes, got {len(descriptor)}"
        )
    return TravelDirection(
        a_to_b_allowed=bool(descriptor[3] & 0x01),
        b_to_a_allowed=bool(descriptor[3] & 0x02),
    )


def decode_automotive_attributes(descriptor: bytes) -> AutomotiveAttributes:
    """Mirror PSLRoutingEdge::GetExtendedAttributesAutomotive at VA 0x008ce240."""

    if len(descriptor) != EDGE_DESCRIPTOR_SIZE:
        raise PsfError(
            f"Basic edge descriptor must be {EDGE_DESCRIPTOR_SIZE} bytes, got {len(descriptor)}"
        )
    encoded = struct.unpack_from("<H", descriptor, 7)[0]
    return AutomotiveAttributes(
        base_mask=encoded & 0x1FFF,
        has_dynamic_extension=bool(encoded & 0x4000),
    )


def decode_urban_road(part_secondary_flags: Iterable[int]) -> bool:
    """Decode the firmware's edge-level urban flag from geometry parts.

    The full routing-edge translator at VA ``0x002f0484`` ORs bit 5 of every
    geometry-part secondary flag and stores the result at output ``+0x168``.
    Its caller supplies ``edge_object + 4`` as the output, so this is exactly
    ``edge_object + 0x16c``.  Urban-transition logic at VA ``0x013e5be8`` reads
    that byte directly.  Therefore an edge is urban iff any part has bit
    ``0x20`` set.
    """

    urban = False
    for value in part_secondary_flags:
        if not 0 <= value <= 0xFF:
            raise PsfError(f"geometry secondary flag outside byte range: {value}")
        urban = urban or bool(value & 0x20)
    return urban


def decode_tagged_attribute_header(extension: bytes) -> TaggedAttributeHeader:
    if not extension:
        raise PsfError("empty Basic geometry attribute extension")
    type_id = extension[0] & 0x7F
    if not 1 <= type_id <= 19:
        raise PsfError(f"Basic geometry attribute type {type_id} outside 1..19")
    return TaggedAttributeHeader(type_id=type_id, has_next=bool(extension[0] & 0x80))


def decode_simple_speed_limit(attribute: TaggedAttribute) -> SimpleSpeedLimit:
    """Decode tag 1 as consumed by firmware VAs 0x002f0484/0x002e3a34."""

    if attribute.type_id != 1 or len(attribute.data) != 2:
        raise PsfError("simple speed limit requires one complete tag-1 attribute")
    value = attribute.data[1]
    if value >= 0xFE:
        raise PsfError(f"simple speed-limit sentinel 0x{value:02x} is not a value")
    return SimpleSpeedLimit(value=value)


def decode_extended_speed_limit(attribute: TaggedAttribute) -> ExtendedSpeedLimit:
    """Decode EXTT_EXTENDED_SPEED_LIMIT as consumed at VAs 0x0097e934/0x0097e848."""

    if attribute.type_id != GeometryAttributeType.EXTENDED_SPEED_LIMIT:
        raise PsfError("extended speed limit requires a tag-2 attribute")
    data = attribute.data
    if len(data) < 5:
        raise PsfError("truncated extended speed-limit attribute")
    stored_size = data[1] & 0x1F
    pair_count = data[1] >> 5
    if stored_size != len(data):
        raise PsfError(
            f"extended speed-limit stored size {stored_size} does not match {len(data)}"
        )
    flags = data[2]
    subtype = flags >> 2
    value = data[3]
    if value >= 0xFE:
        raise PsfError(f"extended speed-limit sentinel 0x{value:02x} is not a value")
    if subtype == 7 and pair_count:
        expected = 6 + pair_count * 2
        if len(data) != expected:
            raise PsfError(
                f"extended speed-limit subtype 7 with {pair_count} pairs requires {expected} bytes"
            )
        condition_pairs = tuple(
            (data[5 + index * 2], data[6 + index * 2])
            for index in range(pair_count)
        )
        source_selector = data[5 + pair_count * 2]
    else:
        if pair_count != 0:
            raise PsfError(
                f"extended speed-limit subtype {subtype} unexpectedly has {pair_count} pairs"
            )
        condition_pairs = ()
        source_selector = data[4]
    return ExtendedSpeedLimit(
        a_to_b=bool(flags & 0x01),
        b_to_a=bool(flags & 0x02),
        subtype=subtype,
        value=value,
        pair_count=pair_count,
        base_condition=data[4],
        condition_pairs=condition_pairs,
        source_selector=source_selector,
    )


def decode_number_of_lanes(attribute: TaggedAttribute) -> NumberOfLanes:
    """Decode EXTT_NUMBER_OF_LANES as consumed at firmware VA 0x0097f054."""

    if attribute.type_id != GeometryAttributeType.NUMBER_OF_LANES or len(attribute.data) != 3:
        raise PsfError("number of lanes requires one complete tag-13 attribute")

    def lane_count(value: int) -> int | None:
        return None if value == 0xFF else value

    return NumberOfLanes(
        at_node_a=lane_count(attribute.data[1]),
        at_node_b=lane_count(attribute.data[2]),
    )


def _firmware_lane_category_mask(code: int) -> int | None:
    """Mirror the direct 0..7 switch in firmware VA 0x0097f054.

    Stored codes above seven first pass through a map-version-specific lookup
    table.  Returning ``None`` for those values is deliberate: the raw code is
    retained and no host-specific table is invented.
    """

    return {
        0: 0,
        1: 0x01,
        2: 0x04,
        3: 0x20,
        4: 0x05,
        5: 0x21,
        6: 0x80,
        7: 0x80,
    }.get(code)


def decode_lanes(attribute: TaggedAttribute) -> LanesAttribute:
    """Decode the firmware-consumed fields of EXTT_LANES (tag 16).

    Public enum names are intentionally not assigned.  VA 0x0097f054 proves
    the four-byte record framing and the bit/nibble consumers exposed here.
    """

    if attribute.type_id != GeometryAttributeType.LANES:
        raise PsfError("lanes requires a tag-16 attribute")
    data = attribute.data
    if len(data) < 2:
        raise PsfError("truncated lanes attribute")
    record_count = data[1] >> 4
    expected = 2 + record_count * 4
    if len(data) != expected:
        raise PsfError(
            f"lanes record count {record_count} requires {expected} bytes, got {len(data)}"
        )
    records: list[LaneRecord] = []
    for offset in range(2, expected, 4):
        raw = data[offset : offset + 4]
        category_code = raw[2] >> 4
        records.append(
            LaneRecord(
                byte_0_low_nibble=raw[0] & 0x0F,
                byte_0_bit_4=bool(raw[0] & 0x10),
                byte_0_bit_5=bool(raw[0] & 0x20),
                byte_0_high_2_bits=raw[0] >> 6,
                byte_1_low_nibble_code=raw[1] & 0x0F,
                byte_1_high_nibble=raw[1] >> 4,
                byte_2_high_nibble_code=category_code,
                byte_2_low_nibble=raw[2] & 0x0F,
                byte_3_low_3_bits_code=raw[3] & 0x07,
                byte_3_high_5_bits=raw[3] >> 3,
                firmware_category_mask=_firmware_lane_category_mask(category_code),
                raw=raw,
            )
        )
    return LanesAttribute(
        header_low_nibble=data[1] & 0x0F,
        records=tuple(records),
    )


def decode_simple_passing_restriction(attribute: TaggedAttribute) -> None:
    """Validate the payload-free EXTT_SIMPLE_PASSING_RESTRICTION marker."""

    if (
        attribute.type_id != GeometryAttributeType.SIMPLE_PASSING_RESTRICTION
        or len(attribute.data) != 1
    ):
        raise PsfError("simple passing restriction requires one tag-14 marker")


def decode_extended_passing_restriction_header(
    attribute: TaggedAttribute,
) -> ExtendedPassingRestrictionHeader:
    """Decode direction/detail bits consumed at firmware VA 0x0097cb48."""

    if attribute.type_id != GeometryAttributeType.EXTENDED_PASSING_RESTRICTION:
        raise PsfError("extended passing restriction requires a tag-15 attribute")
    if len(attribute.data) < 2:
        raise PsfError("truncated extended passing restriction")
    flags = attribute.data[1]
    return ExtendedPassingRestrictionHeader(
        a_to_b=bool(flags & 0x01),
        b_to_a=bool(flags & 0x02),
        has_detailed_records=bool(flags & 0x04),
        detailed_record_count=(flags & 0x38) >> 3,
    )


def decode_geometry_attribute_stream(extension: bytes, subrecord_flags: int) -> bytes:
    """Remove the conditional firmware-confirmed u16 byte-length prefix.

    Geometry subrecords whose secondary flag has bit 7 set append ``u16le
    payload_size`` followed by exactly that many tagged-attribute bytes, except
    when subrecord flag bit 7 marks the final member whose boundary is supplied
    by the enclosing edge record.
    """

    if subrecord_flags & 0x80:
        if not extension:
            raise PsfError("empty final Basic geometry attribute stream")
        return extension
    if len(extension) < 3:
        raise PsfError("truncated Basic geometry attribute extension")
    declared = struct.unpack_from("<H", extension)[0]
    payload = extension[2:]
    if declared != len(payload):
        raise PsfError(
            f"Basic geometry attribute length {declared} does not match {len(payload)} bytes"
        )
    return payload


def _require(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise PsfError(f"truncated Basic geometry {label}")


def _tag6_size(data: bytes, offset: int) -> int:
    _require(data, offset, 3, "tag-6 header")
    count = data[offset + 1]
    cursor = offset + 3
    for entry_index in range(count):
        _require(data, cursor, 1, "tag-6 entry")
        cursor += 5 if data[cursor] & 0x80 else 3
        for _ in range(3):
            terminator = data.find(b"\x00", cursor)
            if terminator < 0:
                raise PsfError("unterminated Basic geometry tag-6 string")
            cursor = terminator + 1
        if entry_index + 1 < count:
            cursor += 1
    return cursor - offset


def _tag18_size(data: bytes, offset: int) -> int:
    _require(data, offset, 2, "tag-18 header")
    count = data[offset + 1]
    cursor = offset + 2
    for entry_index in range(count):
        _require(data, cursor, 1, "tag-18 entry")
        cursor += 5 if data[cursor] & 0x80 else 3
        if entry_index + 1 < count:
            cursor += 1
    return cursor - offset


def tagged_attribute_size(data: bytes, offset: int) -> int | None:
    """Mirror firmware VA 0x0149d144 for data/self-described tag sizes.

    ``None`` denotes schema-fixed tag types 7 and 19. Their boundaries are
    resolved by the complete chain parser instead of inventing constants.
    """

    header = decode_tagged_attribute_header(data[offset:])
    _require(data, offset, 1, "tag header")
    type_id = header.type_id
    if type_id == 1:
        _require(data, offset, 2, "tag-1")
        return 2
    if type_id == 2:
        _require(data, offset, 2, "tag-2")
        return data[offset + 1] & 0x1F
    if type_id == 3:
        _require(data, offset, 3, "tag-3")
        return struct.unpack_from("<H", data, offset + 1)[0]
    if type_id == 4:
        _require(data, offset, 2, "tag-4")
        return data[offset + 1]
    if type_id in (5, 8):
        _require(data, offset, 2, f"tag-{type_id}")
        value = data[offset + 1]
        return 2 + 4 * ((value & 0x0F) + (value >> 4))
    if type_id == 6:
        return _tag6_size(data, offset)
    if type_id == 7:
        return None
    if type_id == 9:
        _require(data, offset, 2, "tag-9")
        return 2
    if type_id == 10:
        _require(data, offset, 2, "tag-10")
        return data[offset + 1]
    if type_id == 11:
        return 0
    if type_id == 12:
        _require(data, offset, 3, "tag-12 header")
        count = data[offset + 1]
        packing = data[offset + 2]
        return (count * ((packing & 0x0F) + 8 + (packing >> 4)) >> 3) + 5
    if type_id == 13:
        return 3
    if type_id == 14:
        return 1
    if type_id == 15:
        _require(data, offset, 2, "tag-15")
        if data[offset + 1] & 4:
            _require(data, offset, 3, "tag-15 dynamic length")
            return data[offset + 2]
        return 2
    if type_id == 16:
        _require(data, offset, 2, "tag-16")
        return 2 + 4 * (data[offset + 1] >> 4)
    if type_id == 17:
        _require(data, offset, 2, "tag-17")
        return (data[offset + 1] * 3 + 1) * 2
    if type_id == 18:
        return _tag18_size(data, offset)
    if type_id == 19:
        return None
    raise AssertionError(type_id)


def decode_tagged_attributes(data: bytes) -> tuple[TaggedAttribute, ...]:
    """Split a complete high-bit-chained geometry attribute stream.

    Most item sizes are self-described. Schema-fixed tag types are solved from
    the unique remainder that yields a valid complete chain. Ambiguous input is
    rejected so corpus validation cannot silently choose a convenient split.
    """

    if not data:
        raise PsfError("empty Basic geometry tagged-attribute stream")

    memo: dict[int, list[tuple[TaggedAttribute, ...]]] = {}

    def parse(offset: int) -> list[tuple[TaggedAttribute, ...]]:
        if offset in memo:
            return memo[offset]
        if offset >= len(data):
            return []
        try:
            header = decode_tagged_attribute_header(data[offset:])
            size = tagged_attribute_size(data, offset)
        except PsfError:
            memo[offset] = []
            return []
        if not header.has_next:
            terminal_size = len(data) - offset
            if size not in (None, terminal_size):
                memo[offset] = []
                return []
            item = TaggedAttribute(header.type_id, False, offset, data[offset:])
            memo[offset] = [(item,)]
            return memo[offset]

        candidates: list[int]
        if size is None:
            candidates = list(range(1, len(data) - offset))
        elif size > 0:
            candidates = [size]
        else:
            candidates = []
        results: list[tuple[TaggedAttribute, ...]] = []
        for candidate_size in candidates:
            next_offset = offset + candidate_size
            if next_offset >= len(data):
                continue
            for tail in parse(next_offset):
                item = TaggedAttribute(
                    header.type_id,
                    True,
                    offset,
                    data[offset:next_offset],
                )
                results.append((item,) + tail)
                if len(results) > 1:
                    memo[offset] = results
                    return results
        memo[offset] = results
        return results

    results = parse(0)
    if len(results) != 1:
        raise PsfError(
            f"Basic geometry attribute chain has {len(results)} valid segmentations"
        )
    return results[0]

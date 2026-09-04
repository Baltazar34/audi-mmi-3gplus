#!/usr/bin/env python3
"""Firmware-backed directory decoder for Basic dynamic edge attributes."""

from __future__ import annotations

from dataclasses import dataclass

from psf_decode import PsfError


DYNAMIC_DIRECTORY_OFFSET_AT = 12
DYNAMIC_DIRECTORY_OFFSET_SIZE = 3
DYNAMIC_DIRECTORY_ENTRY_SIZE = 3


@dataclass(frozen=True)
class DynamicAttributeEntry:
    """One typed payload referenced by the topology dynamic directory."""

    type_id: int
    relative_offset: int
    absolute_offset: int
    payload: bytes


@dataclass(frozen=True)
class DynamicAttributeDirectory:
    offset: int
    header_size: int
    entries: tuple[DynamicAttributeEntry, ...]

    def get(self, type_id: int) -> DynamicAttributeEntry | None:
        return next((entry for entry in self.entries if entry.type_id == type_id), None)


@dataclass(frozen=True)
class DynamicType5EdgeRecord:
    """Firmware-decoded type-5 numeric override keyed by local edge index."""

    edge_index: int
    flag_low_bit: bool
    scale_by_16: bool
    stored_low_16: int
    value: int
    raw: bytes


@dataclass(frozen=True)
class DynamicType3EdgeRecord:
    """One edge selector pointing at a shared raw time-condition object."""

    edge_index: int
    selector_flags: int
    condition_offset: int
    condition: bytes
    raw: bytes

    @property
    def a_to_b(self) -> bool:
        """Selector bit consumed for direction argument 1 at VA 0x014a9c5c."""
        return bool(self.selector_flags & 0x01)

    @property
    def b_to_a(self) -> bool:
        """Selector bit consumed for direction argument 0 at VA 0x014a9c5c."""
        return bool(self.selector_flags & 0x02)


@dataclass(frozen=True)
class DynamicTimeCondition:
    flags: int
    year_range: tuple[int, int] | None
    month_range: tuple[int, int] | None
    month_mask: int | None
    day_of_month_range: tuple[int, int] | None
    day_of_month_mask: int | None
    weekday_mask: int | None
    start_time_slot_15m: int | None
    end_time_slot_15m: int | None
    raw: bytes

    @staticmethod
    def _slot_label(value: int | None) -> str | None:
        if value is None or value > 96:
            return None
        hours, quarter = divmod(value, 4)
        if hours == 24 and quarter == 0:
            return "24:00"
        if hours >= 24:
            return None
        return f"{hours:02d}:{quarter * 15:02d}"

    @property
    def start_time(self) -> str | None:
        return self._slot_label(self.start_time_slot_15m)

    @property
    def end_time(self) -> str | None:
        return self._slot_label(self.end_time_slot_15m)


def decode_dynamic_attribute_directory(topology: bytes) -> DynamicAttributeDirectory | None:
    """Mirror firmware helper ``FUN_014a67e0`` at Ghidra VA 0x014a67e0.

    Topology bytes 12..14 hold a little-endian 24-bit relative pointer.  The
    target begins with an entry count followed by triples of ``u8 type`` and
    ``u16le payload_offset``.  Payload offsets are relative to the directory
    start.  A zero 24-bit pointer means no directory.
    """

    required = DYNAMIC_DIRECTORY_OFFSET_AT + DYNAMIC_DIRECTORY_OFFSET_SIZE
    if len(topology) < required:
        raise PsfError("truncated Basic topology dynamic-directory pointer")
    directory_offset = int.from_bytes(
        topology[DYNAMIC_DIRECTORY_OFFSET_AT:required], "little"
    )
    if directory_offset == 0:
        return None
    if directory_offset >= len(topology):
        raise PsfError(
            f"Basic dynamic-directory offset {directory_offset} outside {len(topology)} bytes"
        )

    entry_count = topology[directory_offset]
    if entry_count == 0:
        raise PsfError("nonzero Basic dynamic-directory pointer targets zero entries")
    header_size = 1 + entry_count * DYNAMIC_DIRECTORY_ENTRY_SIZE
    if directory_offset + header_size > len(topology):
        raise PsfError("truncated Basic dynamic-directory header")

    descriptors: list[tuple[int, int]] = []
    for index in range(entry_count):
        start = directory_offset + 1 + index * DYNAMIC_DIRECTORY_ENTRY_SIZE
        type_id = topology[start]
        relative_offset = int.from_bytes(topology[start + 1 : start + 3], "little")
        descriptors.append((type_id, relative_offset))

    type_ids = [type_id for type_id, _ in descriptors]
    if len(type_ids) != len(set(type_ids)):
        raise PsfError("duplicate Basic dynamic-directory type")
    offsets = [relative_offset for _, relative_offset in descriptors]
    if offsets != sorted(set(offsets)):
        raise PsfError("Basic dynamic-directory payload offsets are not strictly increasing")
    if offsets[0] < header_size:
        raise PsfError("Basic dynamic-directory payload overlaps its header")
    if directory_offset + offsets[-1] >= len(topology):
        raise PsfError("Basic dynamic-directory payload offset outside topology")

    entries: list[DynamicAttributeEntry] = []
    for index, (type_id, relative_offset) in enumerate(descriptors):
        end_relative = offsets[index + 1] if index + 1 < len(offsets) else len(topology) - directory_offset
        absolute_offset = directory_offset + relative_offset
        absolute_end = directory_offset + end_relative
        entries.append(
            DynamicAttributeEntry(
                type_id=type_id,
                relative_offset=relative_offset,
                absolute_offset=absolute_offset,
                payload=topology[absolute_offset:absolute_end],
            )
        )
    return DynamicAttributeDirectory(
        offset=directory_offset,
        header_size=header_size,
        entries=tuple(entries),
    )


def decode_fixed_width_edge_records(
    entry: DynamicAttributeEntry, width: int
) -> tuple[bytes, ...]:
    """Decode a counted fixed-width payload, including firmware type 5/9 tables."""

    if width <= 0:
        raise ValueError("record width must be positive")
    if not entry.payload:
        raise PsfError(f"empty Basic dynamic type-{entry.type_id} payload")
    count = entry.payload[0]
    expected = 1 + count * width
    if len(entry.payload) != expected:
        raise PsfError(
            f"Basic dynamic type-{entry.type_id} count {count} at width {width} "
            f"requires {expected} bytes, got {len(entry.payload)}"
        )
    return tuple(
        entry.payload[1 + index * width : 1 + (index + 1) * width]
        for index in range(count)
    )


def decode_type5_edge_records(
    entry: DynamicAttributeEntry,
) -> tuple[DynamicType5EdgeRecord, ...]:
    """Mirror the record/value expression in firmware VA 0x014a69e8.

    The caller at VA 0x00977af8 stores ``value * 100`` in its aggregate.  The
    public field name/unit are intentionally not asserted here.
    """

    if entry.type_id != 5:
        raise PsfError("dynamic type-5 decoder requires a type-5 entry")
    result: list[DynamicType5EdgeRecord] = []
    for raw in decode_fixed_width_edge_records(entry, 4):
        flags = raw[1]
        stored_low_16 = int.from_bytes(raw[2:4], "little")
        value = stored_low_16 | ((flags & 0x01) << 16)
        if flags & 0x02:
            value <<= 4
        result.append(
            DynamicType5EdgeRecord(
                edge_index=raw[0],
                flag_low_bit=bool(flags & 0x01),
                scale_by_16=bool(flags & 0x02),
                stored_low_16=stored_low_16,
                value=value,
                raw=raw,
            )
        )
    return tuple(result)


def decode_type3_edge_records(
    entry: DynamicAttributeEntry,
) -> tuple[DynamicType3EdgeRecord, ...]:
    """Decode the active Basic schema layout consumed by VA 0x014a9858.

    The firmware makes the record base/stride schema-driven.  For this MIB1
    Basic schema, the complete corpus proves base 5 and stride 4: ``u16 count,
    u8 auxiliary_count, u16 payload_end`` followed by edge/selector/u16-offset
    records.  Condition objects are shared and therefore bounded by the next
    distinct condition offset.
    """

    if entry.type_id != 3:
        raise PsfError("dynamic type-3 decoder requires a type-3 entry")
    payload = entry.payload
    if len(payload) < 5:
        raise PsfError("truncated Basic dynamic type-3 header")
    record_count = int.from_bytes(payload[0:2], "little")
    auxiliary_count = payload[2]
    payload_end = int.from_bytes(payload[3:5], "little")
    if auxiliary_count != 0:
        raise PsfError(
            f"Basic dynamic type-3 auxiliary count {auxiliary_count} needs another schema profile"
        )
    if payload_end != len(payload):
        raise PsfError(
            f"Basic dynamic type-3 payload end {payload_end} does not match {len(payload)}"
        )
    records_end = 5 + record_count * 4
    if records_end > payload_end:
        raise PsfError("Basic dynamic type-3 records overrun payload")

    raw_records = [payload[5 + index * 4 : 9 + index * 4] for index in range(record_count)]
    condition_offsets = [int.from_bytes(raw[2:4], "little") for raw in raw_records]
    if any(offset < records_end or offset >= payload_end for offset in condition_offsets):
        raise PsfError("Basic dynamic type-3 condition offset outside condition area")
    distinct_offsets = sorted(set(condition_offsets))
    condition_ends = {
        offset: (
            distinct_offsets[index + 1]
            if index + 1 < len(distinct_offsets)
            else payload_end
        )
        for index, offset in enumerate(distinct_offsets)
    }
    return tuple(
        DynamicType3EdgeRecord(
            edge_index=raw[0],
            selector_flags=raw[1],
            condition_offset=condition_offset,
            condition=payload[condition_offset : condition_ends[condition_offset]],
            raw=raw,
        )
        for raw, condition_offset in zip(raw_records, condition_offsets)
    )


def decode_time_condition(condition: bytes) -> DynamicTimeCondition:
    """Mirror the packed readers used by firmware evaluator VA 0x014aa5f8."""

    if not condition:
        raise PsfError("empty Basic dynamic time condition")
    flags = condition[0]
    if flags & 0xE0:
        raise PsfError(f"Basic dynamic time condition has unknown flags 0x{flags:02x}")
    cursor = 1

    def take(size: int, label: str) -> bytes:
        nonlocal cursor
        end = cursor + size
        if end > len(condition):
            raise PsfError(f"truncated Basic dynamic time condition {label}")
        value = condition[cursor:end]
        cursor = end
        return value

    year_range: tuple[int, int] | None = None
    if flags & 0x01:
        raw = take(4, "year range")
        year_range = (
            int.from_bytes(raw[0:2], "little"),
            int.from_bytes(raw[2:4], "little"),
        )

    month_range: tuple[int, int] | None = None
    month_mask: int | None = None
    if flags & 0x02:
        raw = take(2, "month selector")
        encoded = int.from_bytes(raw, "little")
        if encoded & 0x8000:
            month_mask = encoded & 0x0FFF
        else:
            month_range = (raw[0] & 0x7F, raw[1])

    day_of_month_range: tuple[int, int] | None = None
    day_of_month_mask: int | None = None
    if flags & 0x04:
        raw = take(4, "day-of-month selector")
        encoded = int.from_bytes(raw, "little")
        if encoded & 0x80000000:
            day_of_month_mask = encoded & 0x7FFFFFFF
        else:
            day_of_month_range = (
                int.from_bytes(raw[0:2], "little") & 0x7FFF,
                int.from_bytes(raw[2:4], "little"),
            )

    weekday_mask: int | None = None
    if flags & 0x08:
        weekday_mask = take(1, "weekday mask")[0] & 0x7F

    start_time_slot_15m: int | None = None
    end_time_slot_15m: int | None = None
    if flags & 0x10:
        raw = take(2, "time range")
        start_time_slot_15m, end_time_slot_15m = raw

    if cursor != len(condition):
        raise PsfError(
            f"Basic dynamic time condition consumed {cursor} of {len(condition)} bytes"
        )
    return DynamicTimeCondition(
        flags=flags,
        year_range=year_range,
        month_range=month_range,
        month_mask=month_mask,
        day_of_month_range=day_of_month_range,
        day_of_month_mask=day_of_month_mask,
        weekday_mask=weekday_mask,
        start_time_slot_15m=start_time_slot_15m,
        end_time_slot_15m=end_time_slot_15m,
        raw=condition,
    )


def dynamic_selector_action(selector_flags: int, query_mask: int) -> str:
    """Mirror the skip/evaluate/immediate selector at firmware VA 0x014a94f0."""

    group = (selector_flags & 0x0C) >> 2
    if group == 0:
        skip_bit, evaluate_bit, immediate_bit = 0x01, 0x02, 0x04
    elif group == 1:
        skip_bit, evaluate_bit, immediate_bit = 0x08, 0x10, 0x20
    elif group == 2:
        skip_bit, evaluate_bit, immediate_bit = 0x40, 0x80, 0x100
    else:
        return "evaluate"
    if query_mask & skip_bit:
        return "skip"
    if query_mask & evaluate_bit:
        return "evaluate"
    if query_mask & immediate_bit:
        return "immediate"
    return "evaluate"


def time_condition_matches(
    condition: DynamicTimeCondition,
    *,
    year: int,
    month: int,
    day: int,
    weekday_index: int,
    hour: int,
    minute: int,
) -> bool:
    """Evaluate an already-local wall-clock query like firmware VA 0x014aa5f8.

    ``weekday_index`` is the firmware-native 0..6 index; this function does
    not invent a Monday/Sunday origin.  Cluster time-zone adjustment and the
    caller's optional 15-minute look-ahead are intentionally upstream.
    """

    if not (1 <= month <= 12 and 1 <= day <= 31):
        raise ValueError("month/day outside supported range")
    if not (0 <= weekday_index <= 6 and 0 <= hour < 24 and 0 <= minute < 60):
        raise ValueError("weekday/time outside supported range")

    if condition.year_range is not None:
        start_year, end_year = condition.year_range
        if start_year and end_year:
            if year < start_year or year > end_year:
                return False
            if year == start_year:
                if condition.month_range is None:
                    return True
                start_month, _ = condition.month_range
                if month < start_month:
                    return False
                if month > start_month:
                    return True
                if condition.day_of_month_range is None:
                    return True
                start_day, _ = condition.day_of_month_range
                return day >= start_day
            if year == end_year:
                if condition.month_range is None:
                    return True
                _, end_month = condition.month_range
                if month > end_month:
                    return False
                if month < end_month:
                    return True
                if condition.day_of_month_range is None:
                    return True
                _, end_day = condition.day_of_month_range
                return day <= end_day
            return True
        if year != start_year:
            return False
        if condition.month_range is not None and month != condition.month_range[0]:
            return False
        if (
            condition.day_of_month_range is not None
            and day != condition.day_of_month_range[0]
        ):
            return False
    else:
        if condition.month_mask is not None and not (
            condition.month_mask & (1 << (month - 1))
        ):
            return False
        if condition.day_of_month_mask is not None and not (
            condition.day_of_month_mask & (1 << (day - 1))
        ):
            return False
        if condition.weekday_mask is not None and not (
            condition.weekday_mask & (1 << weekday_index)
        ):
            return False

    if condition.start_time_slot_15m is None:
        return True
    assert condition.end_time_slot_15m is not None
    current_slot = hour * 4 + minute // 15
    start = condition.start_time_slot_15m
    end = condition.end_time_slot_15m
    if start < end:
        if current_slot < start or current_slot > end:
            return False
    elif current_slot < start and current_slot > end:
        return False
    if current_slot != end:
        return True
    return minute % 15 == 0

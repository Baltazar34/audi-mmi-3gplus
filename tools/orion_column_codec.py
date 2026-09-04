#!/usr/bin/env python3
"""Verified low-level primitives for original MMI 3G Orion column codecs.

This module intentionally stops at the boundary proven from NavCore.  In
particular, compression code 3 is a dictionary/composite codec, not a direct
width-prefixed scalar column.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


class OrionBitReader:
    """LSB-first reader matching NavCore's little-endian 32-bit refill logic."""

    def __init__(self, data: bytes, byte_offset: int = 0) -> None:
        if byte_offset < 0 or byte_offset > len(data):
            raise ValueError("byte_offset outside input")
        self._data = data
        self.byte_position = byte_offset
        self._buffer = 0
        self.available_bits = 0
        self.bits_read = 0

    def read(self, width: int) -> int:
        if not 1 <= width <= 32:
            raise ValueError(f"invalid Orion bit width {width}")
        if self.available_bits < width:
            if self.byte_position + 4 > len(self._data):
                raise EOFError("truncated Orion 32-bit bitstream word")
            word = int.from_bytes(
                self._data[self.byte_position : self.byte_position + 4], "little"
            )
            self.byte_position += 4
            value = self._buffer | (word << self.available_bits)
            consumed_from_word = width - self.available_bits
            self._buffer = (
                word >> consumed_from_word if consumed_from_word < 32 else 0
            )
            self.available_bits += 32 - width
        else:
            value = self._buffer
            self._buffer >>= width
            self.available_bits -= width
        self.bits_read += width
        return value & (0xFFFFFFFF if width == 32 else (1 << width) - 1)


def sign_extend(value: int, width: int) -> int:
    if width < 1:
        raise ValueError("sign extension width must be positive")
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


@dataclass(frozen=True)
class Code3Header:
    index_width: int
    dictionary_entry_count: int
    nested_compression_code: int


def parse_code3_header(reader: OrionBitReader) -> Code3Header:
    """Parse the header read by ``FUN_08331740``.

    NavCore sign-extends the first five bits and adds one.  Only a positive
    result can subsequently be used as a bit-reader width; values 0x10..0x1f
    are therefore rejected instead of silently reinterpreting them as 17..32.
    The next value is the dictionary cardinality, followed by the 8-bit codec
    used recursively to materialize dictionary entries.
    """

    raw_width = reader.read(5)
    index_width = sign_extend(raw_width, 5) + 1
    if not 1 <= index_width <= 16:
        raise ValueError(
            f"invalid code-3 signed width header 0x{raw_width:02x} -> {index_width}"
        )
    dictionary_entry_count = reader.read(index_width)
    nested_compression_code = reader.read(8)
    if nested_compression_code not in (1, 2, 3):
        raise ValueError(
            f"unsupported nested Orion compression code {nested_compression_code}"
        )
    return Code3Header(
        index_width=index_width,
        dictionary_entry_count=dictionary_entry_count,
        nested_compression_code=nested_compression_code,
    )


def decode_fixed_values(
    reader: OrionBitReader, count: int, width: int, *, signed: bool = False
) -> list[int]:
    if count < 0:
        raise ValueError("count must not be negative")
    values = [reader.read(width) for _ in range(count)]
    if signed:
        return [sign_extend(value, width) for value in values]
    return values


# Direct transcription of FUN_0833599c for the type codes used by the two
# type-dispatch factories.  The pair is (value/significant bits, storage bits).
_TYPE_WIDTHS = {
    0x10: (1, 1), 0x20: (1, 1), 0x30: (1, 1),
    0x21: (2, 2), 0x31: (2, 2),
    0x22: (4, 4), 0x32: (4, 4),
    0x23: (8, 8), 0x33: (8, 8),
    0x24: (16, 16), 0x34: (16, 16), 0x44: (16, 16),
    0x25: (32, 32), 0x35: (32, 32), 0x45: (32, 32), 0x50: (32, 32),
    0x26: (32, 64), 0x36: (32, 64), 0x46: (32, 64),
    0x4F: (32, 80),
}


def type_widths(type_code: int) -> tuple[int, int]:
    try:
        return _TYPE_WIDTHS[type_code]
    except KeyError as error:
        raise ValueError(f"unmapped Orion type code 0x{type_code:02x}") from error


def type_is_signed(type_code: int) -> bool:
    """Return whether the scalar belongs to NavCore's signed 0x3x family."""

    type_widths(type_code)
    return type_code & 0xF0 == 0x30


def pack_code1_values(
    type_code: int, values: Iterable[int], *, signed: bool | None = None
) -> bytes:
    """Pack scalar values in the native code-1 representation.

    Sub-byte values are packed least-significant bit first.  Byte-sized and
    wider values use little-endian storage, matching the firmware's readers.
    The 80-bit 0x4f representation is intentionally rejected until its value
    semantics, rather than only its storage width, are proven.
    """

    value_bits, storage_bits = type_widths(type_code)
    if storage_bits == 80:
        raise ValueError("writing Orion 80-bit type 0x4f is not yet supported")
    is_signed = type_is_signed(type_code) if signed is None else signed
    value_list = [int(value) for value in values]
    minimum = -(1 << (value_bits - 1)) if is_signed else 0
    maximum = (1 << (value_bits - int(is_signed))) - 1
    encoded: list[int] = []
    mask = (1 << value_bits) - 1
    for index, value in enumerate(value_list):
        if not minimum <= value <= maximum:
            raise ValueError(
                f"value {index}={value} outside {value_bits}-bit "
                f"{'signed' if is_signed else 'unsigned'} range"
            )
        encoded.append(value & mask)

    if storage_bits < 8:
        output = bytearray((len(encoded) * storage_bits + 7) // 8)
        bit_offset = 0
        for value in encoded:
            output[bit_offset // 8] |= value << (bit_offset % 8)
            bit_offset += storage_bits
        return bytes(output)

    byte_width = storage_bits // 8
    return b"".join(value.to_bytes(byte_width, "little") for value in encoded)


def unpack_code1_values(
    type_code: int,
    data: bytes,
    count: int,
    *,
    signed: bool | None = None,
) -> list[int]:
    """Inverse of :func:`pack_code1_values` for validation and tests."""

    if count < 0:
        raise ValueError("count must not be negative")
    value_bits, storage_bits = type_widths(type_code)
    if storage_bits == 80:
        raise ValueError("reading Orion 80-bit type 0x4f is not yet supported")
    expected_size = (count * storage_bits + 7) // 8
    if len(data) != expected_size:
        raise ValueError(
            f"expected {expected_size} bytes for {count} values, got {len(data)}"
        )
    is_signed = type_is_signed(type_code) if signed is None else signed
    mask = (1 << value_bits) - 1
    decoded: list[int] = []
    if storage_bits < 8:
        packed = int.from_bytes(data, "little")
        decoded = [
            (packed >> (index * storage_bits)) & mask for index in range(count)
        ]
    else:
        byte_width = storage_bits // 8
        decoded = [
            int.from_bytes(data[index : index + byte_width], "little") & mask
            for index in range(0, len(data), byte_width)
        ]
    if is_signed:
        decoded = [sign_extend(value, value_bits) for value in decoded]
    return decoded


@dataclass(frozen=True)
class Code1Column:
    index: int
    tag: int
    type_code: int
    payload_offset: int
    payload_size: int
    value_bits: int
    storage_bits: int


def code1_column_layout(
    data_size: int,
    data_offset: int,
    descriptors: Iterable[dict[str, int]],
    compression_codes: Iterable[int],
) -> list[Code1Column]:
    """Resolve the exact sequential payload layout for a code-1 table."""

    descriptor_list = list(descriptors)
    code_list = list(compression_codes)
    if len(descriptor_list) != len(code_list):
        raise ValueError("descriptor/compression-code count mismatch")
    columns: list[Code1Column] = []
    cursor = data_offset
    for index, (descriptor, compression_code) in enumerate(
        zip(descriptor_list, code_list)
    ):
        if compression_code != 1:
            raise ValueError(
                f"column {index} uses compression code {compression_code}, not code 1"
            )
        payload_size = descriptor["size"]
        if payload_size < 0 or cursor + payload_size > data_size:
            raise ValueError(f"column {index} payload exceeds decoded chunk")
        value_bits, storage_bits = type_widths(descriptor["type_code"])
        columns.append(
            Code1Column(
                index=index,
                tag=descriptor["tag"],
                type_code=descriptor["type_code"],
                payload_offset=cursor,
                payload_size=payload_size,
                value_bits=value_bits,
                storage_bits=storage_bits,
            )
        )
        cursor += payload_size
    if cursor != data_size:
        raise ValueError(
            f"column payload leaves {data_size - cursor} unexplained decoded bytes"
        )
    return columns


def assemble_code1_payload(
    descriptors: Iterable[dict[str, int]], payloads: Iterable[bytes]
) -> bytes:
    """Validate and concatenate native-width payloads for a future writer."""

    descriptor_list = list(descriptors)
    payload_list = list(payloads)
    if len(descriptor_list) != len(payload_list):
        raise ValueError("descriptor/payload count mismatch")
    for index, (descriptor, payload) in enumerate(zip(descriptor_list, payload_list)):
        if len(payload) != descriptor["size"]:
            raise ValueError(
                f"column {index} expected {descriptor['size']} bytes, got {len(payload)}"
            )
    return b"".join(payload_list)


def validate_code1_payload_roundtrip(
    data: bytes,
    data_offset: int,
    descriptors: Iterable[dict[str, int]],
    compression_codes: Iterable[int],
) -> list[Code1Column]:
    """Split and reassemble a decoded code-1 payload byte-for-byte."""

    descriptor_list = list(descriptors)
    columns = code1_column_layout(
        len(data), data_offset, descriptor_list, compression_codes
    )
    payloads = [
        data[column.payload_offset : column.payload_offset + column.payload_size]
        for column in columns
    ]
    if assemble_code1_payload(descriptor_list, payloads) != data[data_offset:]:
        raise ValueError("code-1 payload did not round-trip byte-for-byte")
    return columns

import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_column_codec import (
    OrionBitReader,
    assemble_code1_payload,
    code1_column_layout,
    decode_fixed_values,
    parse_code3_header,
    sign_extend,
    type_widths,
    validate_code1_payload_roundtrip,
)


def pack_word_lsb(fields: list[tuple[int, int]]) -> bytes:
    word = 0
    offset = 0
    for value, width in fields:
        word |= (value & ((1 << width) - 1)) << offset
        offset += width
    if offset > 32:
        raise ValueError("test helper only packs one word")
    return word.to_bytes(4, "little")


class OrionColumnCodecTests(unittest.TestCase):
    def test_reader_crosses_little_endian_word_boundary(self) -> None:
        data = (0xFEDCBA98).to_bytes(4, "little") + (0x76543210).to_bytes(4, "little")
        reader = OrionBitReader(data)
        self.assertEqual(reader.read(28), 0xEDCBA98)
        self.assertEqual(reader.read(8), 0x0F)
        self.assertEqual(reader.read(28), 0x7654321)

    def test_code3_header_is_dictionary_header(self) -> None:
        # width raw=6 -> 7 bits; 37 dictionary entries; nested codec 2.
        reader = OrionBitReader(pack_word_lsb([(6, 5), (37, 7), (2, 8)]))
        header = parse_code3_header(reader)
        self.assertEqual(header.index_width, 7)
        self.assertEqual(header.dictionary_entry_count, 37)
        self.assertEqual(header.nested_compression_code, 2)
        self.assertEqual(reader.bits_read, 20)

    def test_code3_rejects_old_unsigned_width_interpretation(self) -> None:
        reader = OrionBitReader(pack_word_lsb([(0x10, 5), (0, 16), (1, 8)]))
        with self.assertRaisesRegex(ValueError, "signed width"):
            parse_code3_header(reader)

    def test_fixed_signed_values_and_type_widths(self) -> None:
        reader = OrionBitReader(pack_word_lsb([(0x7F, 8), (0x80, 8), (0xFF, 8)]))
        self.assertEqual(
            decode_fixed_values(reader, 3, 8, signed=True), [127, -128, -1]
        )
        self.assertEqual(sign_extend(0x1F, 5), -1)
        self.assertEqual(type_widths(0x35), (32, 32))
        self.assertEqual(type_widths(0x46), (32, 64))

    def test_code1_layout_is_exact_and_sequential(self) -> None:
        descriptors = [
            {"tag": 2, "type_code": 0x35, "size": 8},
            {"tag": 1, "type_code": 0x24, "size": 4},
        ]
        columns = code1_column_layout(20, 8, descriptors, [1, 1])
        self.assertEqual([column.payload_offset for column in columns], [8, 16])
        self.assertEqual([column.storage_bits for column in columns], [32, 16])
        self.assertEqual(
            assemble_code1_payload(descriptors, [b"A" * 8, b"B" * 4]),
            b"A" * 8 + b"B" * 4,
        )
        with self.assertRaisesRegex(ValueError, "unexplained"):
            code1_column_layout(21, 8, descriptors, [1, 1])

    def test_code1_payload_roundtrips_byte_for_byte(self) -> None:
        descriptors = [
            {"tag": 2, "type_code": 0x35, "size": 4},
            {"tag": 3, "type_code": 0x24, "size": 2},
        ]
        data = b"header!!" + b"ABCD" + b"EF"
        columns = validate_code1_payload_roundtrip(data, 8, descriptors, [1, 1])
        self.assertEqual([column.payload_offset for column in columns], [8, 12])


if __name__ == "__main__":
    unittest.main()

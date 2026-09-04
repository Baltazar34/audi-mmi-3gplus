from __future__ import annotations

import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from basic_road_attributes import (  # noqa: E402
    GeometryAttributeType,
    TaggedAttribute,
    decode_automotive_attributes,
    decode_extended_passing_restriction_header,
    decode_extended_speed_limit,
    decode_geometry_attribute_stream,
    decode_lanes,
    decode_number_of_lanes,
    decode_simple_passing_restriction,
    decode_simple_speed_limit,
    decode_tagged_attribute_header,
    decode_tagged_attributes,
    decode_travel_direction,
    decode_urban_road,
)
from basic_dynamic_attributes import (  # noqa: E402
    decode_dynamic_attribute_directory,
    decode_fixed_width_edge_records,
    decode_type3_edge_records,
    decode_type5_edge_records,
    decode_time_condition,
    dynamic_selector_action,
    time_condition_matches,
)
from psf_decode import PsfError  # noqa: E402


class BasicRoadAttributeTests(unittest.TestCase):
    def test_extended_speed_limit_layouts(self) -> None:
        direct = decode_tagged_attributes(bytes.fromhex("02050350ff"))[0]
        decoded = decode_extended_speed_limit(direct)
        self.assertEqual(
            (decoded.a_to_b, decoded.b_to_a, decoded.subtype, decoded.value),
            (True, True, 0, 80),
        )
        self.assertEqual(decoded.source_selector, 0xFF)

        paired = decode_tagged_attributes(bytes.fromhex("02281f1e7f1c54ff"))[0]
        decoded = decode_extended_speed_limit(paired)
        self.assertEqual((decoded.subtype, decoded.value), (7, 30))
        self.assertEqual(decoded.condition_pairs, ((0x1C, 0x54),))
        self.assertEqual(decoded.source_selector, 0xFF)

    def test_dynamic_type3_shared_conditions(self) -> None:
        topology = bytearray(64)
        topology[12:15] = (24).to_bytes(3, "little")
        topology[24:28] = bytes.fromhex("01030400")
        topology[28:42] = bytes.fromhex("0200000e0007010d0008020d0010")
        del topology[42:]

        directory = decode_dynamic_attribute_directory(bytes(topology))

        assert directory is not None
        records = decode_type3_edge_records(directory.entries[0])
        self.assertEqual([record.edge_index for record in records], [7, 8])
        self.assertEqual([record.selector_flags for record in records], [1, 2])
        self.assertEqual(
            [(record.a_to_b, record.b_to_a) for record in records],
            [(True, False), (False, True)],
        )
        self.assertEqual(records[0].condition, b"\x10")
        self.assertEqual(records[0].condition, records[1].condition)

    def test_dynamic_time_condition_fields(self) -> None:
        decoded = decode_time_condition(
            bytes.fromhex("1f e907 eb07 0885 07800080 41 4c00")
        )

        self.assertEqual(decoded.year_range, (2025, 2027))
        self.assertEqual(decoded.month_mask, 0x508)
        self.assertEqual(decoded.day_of_month_mask, 0x8007)
        self.assertEqual(decoded.weekday_mask, 0x41)
        self.assertEqual((decoded.start_time, decoded.end_time), ("19:00", "00:00"))

    def test_dynamic_selector_and_time_evaluation(self) -> None:
        self.assertEqual(dynamic_selector_action(0x00, 0x01), "skip")
        self.assertEqual(dynamic_selector_action(0x04, 0x10), "evaluate")
        self.assertEqual(dynamic_selector_action(0x08, 0x100), "immediate")

        overnight = decode_time_condition(bytes.fromhex("104c00"))
        self.assertTrue(
            time_condition_matches(
                overnight, year=2026, month=9, day=1,
                weekday_index=0, hour=20, minute=0,
            )
        )
        self.assertFalse(
            time_condition_matches(
                overnight, year=2026, month=9, day=1,
                weekday_index=0, hour=18, minute=45,
            )
        )

        date_range = decode_time_condition(
            bytes.fromhex("07e907eb07080507001000")
        )
        self.assertFalse(
            time_condition_matches(
                date_range, year=2025, month=8, day=6,
                weekday_index=0, hour=0, minute=0,
            )
        )
        self.assertTrue(
            time_condition_matches(
                date_range, year=2026, month=1, day=1,
                weekday_index=0, hour=0, minute=0,
            )
        )

    def test_dynamic_directory_and_fixed_width_records(self) -> None:
        topology = bytearray(64)
        topology[12:15] = (32).to_bytes(3, "little")
        topology[32:39] = bytes.fromhex("02010700050c00")
        topology[39:44] = bytes.fromhex("0102030405")
        topology[44:53] = bytes.fromhex("020a0122330b025566")
        del topology[53:]

        directory = decode_dynamic_attribute_directory(bytes(topology))

        self.assertIsNotNone(directory)
        assert directory is not None
        self.assertEqual([entry.type_id for entry in directory.entries], [1, 5])
        records = decode_fixed_width_edge_records(directory.entries[1], 4)
        self.assertEqual(records, (bytes.fromhex("0a012233"), bytes.fromhex("0b025566")))
        decoded = decode_type5_edge_records(directory.entries[1])
        self.assertEqual((decoded[0].edge_index, decoded[0].value), (10, 0x13322))
        self.assertEqual((decoded[1].edge_index, decoded[1].value), (11, 0x6655 << 4))

    def test_static_direction_bits_are_independent(self) -> None:
        base = bytearray(9)
        expected = {
            0: (False, False, "neither"),
            1: (True, False, "a-to-b-only"),
            2: (False, True, "b-to-a-only"),
            3: (True, True, "both"),
        }
        for mask, values in expected.items():
            base[3] = mask | 0xFC
            direction = decode_travel_direction(bytes(base))
            self.assertEqual(
                (direction.a_to_b_allowed, direction.b_to_a_allowed, direction.mode),
                values,
            )

    def test_direction_requires_complete_descriptor(self) -> None:
        with self.assertRaises(PsfError):
            decode_travel_direction(b"\x00" * 8)

    def test_automotive_mask_and_dynamic_marker(self) -> None:
        descriptor = b"\x00" * 7 + b"\x34\x52"
        value = decode_automotive_attributes(descriptor)
        self.assertEqual(value.base_mask, 0x1234)
        self.assertTrue(value.has_dynamic_extension)
        self.assertEqual(value.active_bit_indices, (2, 4, 5, 9, 12))

    def test_urban_road_is_or_of_geometry_secondary_flag_bit_5(self) -> None:
        self.assertFalse(decode_urban_road([]))
        self.assertFalse(decode_urban_road([0x00, 0x10, 0x80]))
        self.assertTrue(decode_urban_road([0x00, 0x20]))
        self.assertTrue(decode_urban_road([0xA0, 0x00]))
        with self.assertRaises(PsfError):
            decode_urban_road([0x100])

    def test_tag_header_separates_type_and_continuation(self) -> None:
        self.assertEqual(decode_tagged_attribute_header(b"\x12").type_id, 18)
        chained = decode_tagged_attribute_header(b"\x81")
        self.assertEqual(chained.type_id, 1)
        self.assertTrue(chained.has_next)

    def test_tag_header_rejects_empty_or_out_of_range(self) -> None:
        for raw in (b"", b"\x00", b"\x14", b"\xff"):
            with self.assertRaises(PsfError):
                decode_tagged_attribute_header(raw)

    def test_geometry_attribute_length_prefix_is_exact(self) -> None:
        self.assertEqual(
            decode_geometry_attribute_stream(b"\x03\x00\x81\x00\x01", 0),
            b"\x81\x00\x01",
        )
        self.assertEqual(
            decode_geometry_attribute_stream(b"\x81\x00\x01", 0x80),
            b"\x81\x00\x01",
        )
        for raw in (b"", b"\x01", b"\x00\x00", b"\x04\x00\x81\x00\x01"):
            with self.assertRaises(PsfError):
                decode_geometry_attribute_stream(raw, 0)

    def test_tag_chain_uses_firmware_sizes(self) -> None:
        # tag 1 is two bytes, tag 9 is two bytes, terminal tag 14 is one byte.
        items = decode_tagged_attributes(bytes.fromhex("817889840e"))
        self.assertEqual([item.type_id for item in items], [1, 9, 14])
        self.assertEqual([len(item.data) for item in items], [2, 2, 1])

    def test_terminal_size_mismatch_is_rejected(self) -> None:
        with self.assertRaises(PsfError):
            decode_tagged_attributes(bytes.fromhex("010000"))

    def test_simple_speed_limit_is_tag_1_payload(self) -> None:
        attribute = decode_tagged_attributes(bytes.fromhex("0178"))[0]
        self.assertEqual(decode_simple_speed_limit(attribute).value, 120)

    def test_simple_speed_limit_rejects_wrong_tag_and_sentinels(self) -> None:
        for raw in ("0900", "01fe", "01ff"):
            with self.assertRaises(PsfError):
                decode_simple_speed_limit(decode_tagged_attributes(bytes.fromhex(raw))[0])

    def test_firmware_extt_enum_is_contiguous(self) -> None:
        self.assertEqual(GeometryAttributeType.SIMPLE_SPEED_LIMIT, 1)
        self.assertEqual(GeometryAttributeType.NUMBER_OF_LANES, 13)
        self.assertEqual(GeometryAttributeType.SIMPLE_PASSING_RESTRICTION, 14)
        self.assertEqual(GeometryAttributeType.EXTENDED_PASSING_RESTRICTION, 15)
        self.assertEqual(GeometryAttributeType.LANES, 16)
        self.assertEqual(GeometryAttributeType.UNKNOWN, 19)

    def test_number_of_lanes_has_node_endpoint_bytes_and_sentinel(self) -> None:
        value = decode_number_of_lanes(
            decode_tagged_attributes(bytes.fromhex("0d02ff"))[0]
        )
        self.assertEqual((value.at_node_a, value.at_node_b), (2, None))

    def test_lanes_exposes_firmware_consumed_record_fields(self) -> None:
        value = decode_lanes(
            decode_tagged_attributes(bytes.fromhex("1011100a3005"))[0]
        )
        self.assertEqual(value.header_low_nibble, 1)
        self.assertEqual(len(value.records), 1)
        record = value.records[0]
        self.assertEqual(record.byte_0_low_nibble, 0)
        self.assertTrue(record.byte_0_bit_4)
        self.assertFalse(record.byte_0_bit_5)
        self.assertEqual(record.byte_1_low_nibble_code, 10)
        self.assertEqual(record.byte_2_high_nibble_code, 3)
        self.assertEqual(record.byte_3_low_3_bits_code, 5)
        self.assertEqual(record.firmware_category_mask, 0x20)

    def test_lanes_rejects_wrong_tag_and_truncated_record_count(self) -> None:
        with self.assertRaises(PsfError):
            decode_lanes(decode_tagged_attributes(bytes.fromhex("0d0101"))[0])
        with self.assertRaises(PsfError):
            decode_lanes(
                TaggedAttribute(
                    type_id=GeometryAttributeType.LANES,
                    has_next=False,
                    offset=0,
                    data=bytes.fromhex("102110000001"),
                )
            )

    def test_passing_restriction_markers_and_direction_bits(self) -> None:
        self.assertIsNone(
            decode_simple_passing_restriction(
                decode_tagged_attributes(bytes.fromhex("0e"))[0]
            )
        )
        value = decode_extended_passing_restriction_header(
            decode_tagged_attributes(bytes.fromhex("0f2f03"))[0]
        )
        self.assertEqual(
            (
                value.a_to_b,
                value.b_to_a,
                value.has_detailed_records,
                value.detailed_record_count,
            ),
            (True, True, True, 5),
        )


if __name__ == "__main__":
    unittest.main()

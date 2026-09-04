
import os
import unittest
from pathlib import Path

from psf_decode import (
    PsfError,
    _decode_indexed_lzma,
    read_adas_index,
    read_advanced_routing_index,
)
from pre_writer_layers import (
    decode_adas_cluster,
    decode_adas_record_sizes,
    decode_advanced_routing_cluster,
)


class AdvancedRoutingClusterTests(unittest.TestCase):
    def test_offset_directory_and_records(self) -> None:
        payload = bytes.fromhex("02520207000c000102030405aabbcc")
        decoded = decode_advanced_routing_cluster(payload)
        self.assertEqual(decoded.edge_count, 2)
        self.assertEqual(decoded.metadata_u16, 0x252)
        self.assertEqual(decoded.record_offsets, (7, 12))
        self.assertEqual([record.raw.hex() for record in decoded.records], ["0102030405", "aabbcc"])

    def test_rejects_non_monotonic_offsets(self) -> None:
        with self.assertRaises(PsfError):
            decode_advanced_routing_cluster(bytes.fromhex("025202070007000102"))


class AdasClusterTests(unittest.TestCase):
    def test_size_code(self) -> None:
        self.assertEqual(decode_adas_record_sizes(bytes.fromhex("7f8123"), 2), (127, 291))

    def test_size_directory_and_records(self) -> None:
        record_a = bytes(range(127))
        record_b = bytes([0x5A]) * 291
        data_offset = 10
        total = data_offset + len(record_a) + len(record_b)
        payload = (
            bytes([2])
            + data_offset.to_bytes(2, "little")
            + total.to_bytes(4, "little")
            + bytes.fromhex("7f8123")
            + record_a
            + record_b
        )
        decoded = decode_adas_cluster(payload)
        self.assertEqual(decoded.record_sizes, (127, 291))
        self.assertEqual(decoded.records[0].raw, record_a)
        self.assertEqual(decoded.records[1].raw, record_b)

    def test_rejects_noncanonical_two_byte_size(self) -> None:
        with self.assertRaises(PsfError):
            decode_adas_record_sizes(bytes.fromhex("8001"), 1)


MAP_ROOT = Path(
    os.environ.get(
        "MIB_MAP_ROOT",
        "/private/tmp/mib/Mib1/NavDB/SerbiaMontenegroKosovo_eu/0/default",
    )
)
ADAS = MAP_ROOT / "SerbiaMontenegroKosovo_ADAS.psf"
ADVANCED_ROUTING = MAP_ROOT / "SerbiaMontenegroKosovo_AdvancedRouting.psf"


class FullCorpusLayerTests(unittest.TestCase):
    @unittest.skipUnless(ADVANCED_ROUTING.exists(), "local AdvancedRouting corpus missing")
    def test_every_advanced_routing_cluster(self) -> None:
        index = read_advanced_routing_index(ADVANCED_ROUTING)
        records = 0
        with ADVANCED_ROUTING.open("rb") as source:
            for entry in index["entries"]:
                records += len(
                    decode_advanced_routing_cluster(
                        _decode_indexed_lzma(source, entry)
                    ).records
                )
        self.assertEqual(len(index["entries"]), 3342)
        self.assertEqual(records, 839501)

    @unittest.skipUnless(ADAS.exists(), "local ADAS corpus missing")
    def test_every_adas_cluster(self) -> None:
        index = read_adas_index(ADAS)
        records = 0
        with ADAS.open("rb") as source:
            for entry in index["entries"]:
                records += len(
                    decode_adas_cluster(_decode_indexed_lzma(source, entry)).records
                )
        self.assertEqual(len(index["entries"]), 3336)
        self.assertEqual(records, 838433)


if __name__ == "__main__":
    unittest.main()

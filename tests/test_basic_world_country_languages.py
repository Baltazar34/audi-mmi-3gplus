from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from basic_world_country_languages import (  # noqa: E402
    _decode_country_trailer,
    _decode_directory,
)
from psf_decode import PsfError  # noqa: E402


class BasicWorldCountryLanguageTests(unittest.TestCase):
    def test_one_byte_self_relative_directory(self) -> None:
        world = b"\xa9\x00\x00\x01\x00\x00\x04\x00\x00\x00AL\x00\x01\x1f"
        width, starts = _decode_directory(world)
        self.assertEqual(width, 1)
        self.assertEqual(starts, (10,))
        country = _decode_country_trailer(world, 10, len(world))
        self.assertEqual(country["country_code"], "AL")
        self.assertEqual(country["official_language_identifiers"], [31])

    def test_two_byte_self_relative_directory_and_padding(self) -> None:
        world = bytearray(36)
        world[3:5] = (2).to_bytes(2, "little")
        world[5] = 1
        world[6:8] = (6).to_bytes(2, "little")
        world[8:10] = (14).to_bytes(2, "little")
        world[12:19] = b"MNE\x00\x01\x30\x00"
        world[22:30] = b"BIH\x00\x02\x1e\x21\x00"
        width, starts = _decode_directory(bytes(world))
        self.assertEqual(width, 2)
        self.assertEqual(starts, (12, 22))
        first = _decode_country_trailer(bytes(world), 12, 22)
        second = _decode_country_trailer(bytes(world), 22, len(world))
        self.assertEqual(first["official_language_identifiers"], [48])
        self.assertEqual(second["official_language_identifiers"], [30, 33])

    def test_nonzero_trailing_data_is_rejected(self) -> None:
        world = b"AL\x00\x01\x1f\x01"
        with self.assertRaises(PsfError):
            _decode_country_trailer(world, 0, len(world))


if __name__ == "__main__":
    unittest.main()

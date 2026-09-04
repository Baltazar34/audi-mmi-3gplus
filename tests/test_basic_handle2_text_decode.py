from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from basic_handle2_text_decode import (  # noqa: E402
    TextSchema,
    _decode_terminated,
    decode_text_entry,
)
from basic_handle2_name_profile import classify_script  # noqa: E402
from psf_decode import PsfError  # noqa: E402


class BasicHandle2TextDecodeTests(unittest.TestCase):
    def test_tagged_utf8_entry_with_secondary_text(self) -> None:
        data = b"\x1fMain road\x00m eI n\x00"
        schema = TextSchema(
            tagged=True,
            secondary_present=True,
            secondary_tagged=False,
            default_identifier=31,
            primary_encoding=1,
        )
        entry = decode_text_entry(data, 0, len(data), schema)
        self.assertEqual(entry.identifier, 31)
        self.assertFalse(entry.alternate)
        self.assertEqual(entry.primary, ("Main road",))
        self.assertEqual(entry.secondary, ("m eI n",))
        self.assertEqual(entry.end, len(data))

    def test_latin1_and_utf16_terminators(self) -> None:
        value, cursor = _decode_terminated(b"Stra\xdfe\x00x", 0, 8, 0)
        self.assertEqual(value, "Straße")
        self.assertEqual(cursor, 7)
        encoded = "Put".encode("utf-16le") + b"\x00\x00"
        value, cursor = _decode_terminated(encoded, 0, len(encoded), 2)
        self.assertEqual(value, "Put")
        self.assertEqual(cursor, len(encoded))

    def test_secondary_identifier_precedes_secondary_string(self) -> None:
        data = b"\x21Name\x00\x1fphonetic\x00"
        schema = TextSchema(
            tagged=True,
            secondary_present=True,
            secondary_tagged=True,
            default_identifier=33,
            primary_encoding=1,
        )
        entry = decode_text_entry(data, 0, len(data), schema)
        self.assertEqual(entry.identifier, 33)
        self.assertEqual(entry.secondary_identifier, 31)
        self.assertEqual(entry.primary, ("Name",))
        self.assertEqual(entry.secondary, ("phonetic",))
        self.assertEqual(entry.end, len(data))

    def test_missing_terminator_is_rejected(self) -> None:
        with self.assertRaises(PsfError):
            _decode_terminated(b"broken", 0, 6, 1)

    def test_unicode_script_classifier(self) -> None:
        self.assertEqual(classify_script("Улица"), "cyrillic")
        self.assertEqual(classify_script("Ulica"), "latin")
        self.assertEqual(classify_script("AБ"), "cyrillic+latin")
        self.assertEqual(classify_script("75"), "numeric-symbol")


if __name__ == "__main__":
    unittest.main()

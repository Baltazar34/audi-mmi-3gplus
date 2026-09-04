"""Unit tests for the XAC inner-block reader/round-trip."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from xac_inner import HEADER_LEN, XacInnerError, parse, rebuild  # noqa: E402


def make_block(magic: bytes, version: int, entries: list[tuple[int, int]], data_len: int) -> bytes:
    body = bytearray(data_len)
    table = b"".join(struct.pack(">II", o, s) for o, s in entries) if version == 3 else b""
    payload = magic.ljust(16)[:16] + struct.pack(">IHH", 0, version, len(entries)) + table + bytes(body)
    content_size = len(payload) - 20
    out = bytearray(payload)
    struct.pack_into(">I", out, 16, content_size)
    return bytes(out)


class XacInnerTests(unittest.TestCase):
    def test_parse_v3_table(self) -> None:
        blk = make_block(b"ORTSNAMEN", 3, [(48, 4), (52, 8)], 64)
        info = parse(blk)
        self.assertEqual(info["magic"], "ORTSNAMEN")
        self.assertEqual(info["version"], 3)
        self.assertEqual(info["count"], 2)
        self.assertEqual(info["entries"][1], {"offset": 52, "size": 8})
        self.assertTrue(info["size_matches_minus20"])

    def test_v9_has_no_table(self) -> None:
        blk = make_block(b"XAC HEADER", 9, [], 128)
        info = parse(blk)
        self.assertFalse(info["has_table"])
        self.assertEqual(info["data_start"], HEADER_LEN)

    def test_roundtrip_byte_identical(self) -> None:
        for magic, ver, ents in [
            (b"GR POSTLEITZAHL", 3, []),
            (b"ORTSNAMEN", 3, [(40, 4), (44, 12), (56, 8)]),
            (b"XAC HEADER", 9, []),
        ]:
            blk = make_block(magic, ver, ents, 96)
            rebuilt, _ = rebuild(blk)
            self.assertEqual(rebuilt, blk, f"round-trip failed for {magic!r}")

    def test_rejects_truncated(self) -> None:
        with self.assertRaises(XacInnerError):
            parse(b"ORTSNAMEN")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the FLDB container reader/round-trip/writer."""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from fldb_container import (  # noqa: E402
    ENTRY_SIZE,
    FldbError,
    build_directory_bytes,
    cmd_build,
    parse_directory,
    parse_header,
    verify_roundtrip,
)


def make_fldb(files: dict[str, bytes], header_size: int = 0x20) -> bytes:
    """Build a minimal but structurally exact FLDB image for tests."""
    directory_offset = header_size + 8
    payload_start = directory_offset + len(files) * ENTRY_SIZE
    header = bytearray(directory_offset)
    struct.pack_into("<I", header, 0x00, header_size)
    struct.pack_into("<I", header, 0x0C, len(files))
    struct.pack_into("<I", header, 0x10, ENTRY_SIZE)
    header[0x14:0x18] = b"FLDB"
    entries, blobs, cursor = [], [], payload_start
    for name, blob in files.items():
        entries.append({"name": name, "crc32": zlib.crc32(blob) & 0xFFFFFFFF,
                        "offset": cursor, "size": len(blob)})
        blobs.append(blob)
        cursor += len(blob)
    return bytes(header) + build_directory_bytes(entries) + b"".join(blobs)


class FldbContainerTests(unittest.TestCase):
    def test_header_and_directory_parse(self) -> None:
        image = make_fldb({"A.poi": b"hello", "B.xac": b"world!!"})
        header_size, file_count, entry_size = parse_header(image)
        self.assertEqual((header_size, file_count, entry_size), (0x20, 2, ENTRY_SIZE))
        _, entries = parse_directory(image)
        self.assertEqual([e["name"] for e in entries], ["A.poi", "B.xac"])
        self.assertEqual(entries[0]["size"], 5)

    def test_rejects_non_fldb(self) -> None:
        with self.assertRaises(FldbError):
            parse_header(b"\x00" * 64)

    def test_roundtrip_is_byte_identical(self) -> None:
        image = make_fldb({"A.poi": b"abc", "B.xac": b"defgh", "C.ras": b"z" * 40})
        result = verify_roundtrip(image)
        self.assertTrue(result["directory_regenerates_identical"])
        self.assertEqual(result["payload_overlaps"], 0)
        self.assertTrue(result["byte_identical"])

    def test_roundtrip_tolerates_unowned_gaps(self) -> None:
        # Insert an unowned region before the first payload (like the real XAC).
        image = bytearray(make_fldb({"A.poi": b"abc"}))
        _, entries = parse_directory(image)
        gap = 128
        patched = image[: entries[0]["offset"]] + b"\xcc" * gap + image[entries[0]["offset"]:]
        struct.pack_into("<III", patched, (0x20 + 8) + 24,
                         entries[0]["crc32"], entries[0]["offset"] + gap, entries[0]["size"])
        result = verify_roundtrip(bytes(patched))
        self.assertTrue(result["byte_identical"])
        self.assertGreaterEqual(result["unowned_bytes"], gap)

    def test_build_then_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template.db"
            template.write_bytes(make_fldb({"orig.poi": b"x"}))
            a = tmp_path / "one.poi"; a.write_bytes(b"first")
            b = tmp_path / "two.xac"; b.write_bytes(b"second!!")
            out = tmp_path / "built.db"
            self.assertEqual(cmd_build(template, [a, b], out), 0)
            data = out.read_bytes()
            _, entries = parse_directory(data)
            self.assertEqual([e["name"] for e in entries], ["one.poi", "two.xac"])
            for e in entries:
                payload = data[e["offset"]: e["offset"] + e["size"]]
                self.assertEqual(zlib.crc32(payload) & 0xFFFFFFFF, e["crc32"])
            self.assertTrue(verify_roundtrip(data)["byte_identical"])


if __name__ == "__main__":
    unittest.main()

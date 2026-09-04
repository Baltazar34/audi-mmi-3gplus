"""Testovi za ATLAS container sloj: gramatika bloka, indeks, kljuc."""

from __future__ import annotations

import lzma
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from orion_block_writer import (  # noqa: E402
    CODEC_LZMA, CODEC_STORED, TERMINATOR, align16, build_block, compress, parse_block)
from orion_index_decode import decode_index_block  # noqa: E402
from orion_tile_formula_verify import block_key, cell_origin, exponents, interleave  # noqa: E402

K_BASE = 0x1018000000


def synthetic_container(codec: int, payload_raw: bytes, header: bytes) -> bytes:
    name = b"CONTAINER"
    out = bytearray([len(name)]) + name + b"\xcb" * (0x10 - 1 - len(name))
    out += struct.pack("<I", 0) + header
    out.append(codec)
    if codec == CODEC_STORED:
        body = payload_raw
    else:
        body = compress(codec, payload_raw)
        out.append(3)
        out += struct.pack("<II", len(body), len(payload_raw))
        out += struct.pack("<II", 0, 0) * 2
    out += body
    size = align16(len(out) + 16)
    out += b"\xcc" * (size - 16 - len(out)) + TERMINATOR
    struct.pack_into("<I", out, 0x10, size)
    return bytes(out)


class BlockGrammarTests(unittest.TestCase):
    header = bytes([5, 1, 0, 0]) + struct.pack("<HHI", 21, 0x6000, 0x101B414F)

    def test_lzma_block_parses_and_rebuilds_identically(self):
        raw = bytes(range(256)) * 40
        block = synthetic_container(CODEC_LZMA, raw, self.header)
        parsed = parse_block(block)
        self.assertEqual(parsed["codec"], CODEC_LZMA)
        self.assertEqual(parsed["chunks"][0][1], len(raw))
        self.assertEqual(build_block(parsed, parsed["payload"]), block)
        self.assertEqual(len(block) % 16, 0)
        self.assertEqual(block[-16:], TERMINATOR)

    def test_stored_block_payload_starts_at_0x21(self):
        raw = b"\x03Map" + b"\x00" * 50
        block = synthetic_container(CODEC_STORED, raw, self.header)
        parsed = parse_block(block)
        self.assertEqual(parsed["data_offset"], 0x21)
        self.assertTrue(parsed["payload"].startswith(b"\x03Map"))
        self.assertEqual(build_block(parsed, parsed["payload"]), block)

    def test_size_invariant(self):
        raw = b"x" * 1000
        block = synthetic_container(CODEC_LZMA, raw, self.header)
        parsed = parse_block(block)
        expected = align16(parsed["data_offset"] + len(parsed["payload"]) + 16)
        self.assertEqual(expected, len(block))

    def test_lzma_parameters_round_trip(self):
        raw = b"abc" * 5000
        packed = compress(CODEC_LZMA, raw)
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
            {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}])
        self.assertEqual(dec.decompress(packed), raw)


class IndexDecodeTests(unittest.TestCase):
    def test_synthetic_leaf_layout(self):
        entries = 4
        block = bytearray(b"\x05INDEX" + b"\xcc" * 10)
        block += struct.pack("<I", 0) + bytes([5, 1, 1, 0]) + bytes([2, 2, 1]) + b"\x00" * 8
        self.assertEqual(len(block), 0x23)
        seps = [(21, K_BASE + 1), (22, K_BASE + 2), (23, K_BASE + 3)]
        for a, k in seps:
            block += a.to_bytes(3, "little") + k.to_bytes(5, "little")
        offsets = [0x1000, 0x1100, 0x1300, 0x1600]
        sizes = [0x100, 0x200, 0x300, 0x400]
        for o in offsets:
            block += struct.pack("<Q", o)
        for s in sizes:
            block += struct.pack("<I", s)
        block += b"\xcc" * 5 + TERMINATOR
        struct.pack_into("<I", block, 0x10, len(block))
        decoded = decode_index_block(bytes(block), 0, len(block))
        self.assertEqual(decoded["entries"], entries)
        self.assertEqual(decoded["level"], 2)
        self.assertEqual(decoded["separators"], seps)
        self.assertEqual(decoded["offsets"], offsets)
        self.assertEqual(decoded["sizes"], sizes)
        self.assertEqual(decoded["trailing"], 5)
        for i in range(entries - 1):
            self.assertEqual(offsets[i] + sizes[i], offsets[i + 1])


class KeyFormulaTests(unittest.TestCase):
    def test_exponents_alternate_axes(self):
        self.assertEqual(exponents(21), (19, 18))
        self.assertEqual(exponents(20), (18, 18))
        self.assertEqual(exponents(19), (18, 17))
        self.assertEqual(exponents(18), (17, 17))

    def test_known_block_key(self):
        # prvi graph blok PSD3 @0x1000: A=21, B=0x60, C=0x101b414f
        k = block_key(21, 862978600, 543687100)
        self.assertEqual(k, 0x101B414F60)
        self.assertEqual(k >> 8, 0x101B414F)
        self.assertEqual(k & 0xFF, 0x60)

    def test_second_known_block(self):
        self.assertEqual(block_key(20, 862978100, 543988100), 0x101B414F68)

    def test_western_hemisphere_block(self):
        # PSD deo 0 @0x4e11b0: A=28, lon negativan
        self.assertEqual(block_key(28, -312549500, 393750100), 0x100D9ECC00)


if __name__ == "__main__":
    unittest.main()


from orion_atlas_assemble import (  # noqa: E402
    build_index_block, build_revision, index_block_size, pow2_at_least)


class AssemblerTests(unittest.TestCase):
    def test_index_block_sizes_match_original(self):
        self.assertEqual(index_block_size(2048), 41008)
        self.assertEqual(index_block_size(1024), 20528)
        self.assertEqual(index_block_size(128), 2608)

    def test_pow2(self):
        self.assertEqual(pow2_at_least(125), 128)
        self.assertEqual(pow2_at_least(876), 1024)
        self.assertEqual(pow2_at_least(2048), 2048)

    def test_leaf_block_roundtrips_through_decoder(self):
        version = bytes([5, 1, 1, 0])
        ents = [(0x4E11A0 + i * 0x100, 0x100) for i in range(5)]
        seps = [(20 + i, K_BASE + i) for i in range(4)]
        blob = build_index_block(2, ents, seps, version, (19, K_BASE - 1))
        self.assertEqual(len(blob), index_block_size(8))
        self.assertEqual(blob[-16:], TERMINATOR)
        decoded = decode_index_block(blob, 0, len(blob))
        self.assertEqual(decoded["entries"], 8)
        self.assertEqual(decoded["offsets"][:5], [e[0] for e in ents])
        self.assertEqual(decoded["offsets"][5:], [ents[-1][0]] * 3)
        self.assertEqual(decoded["separators"][:4], seps)
        self.assertEqual(decoded["separators"][4:], [seps[-1]] * 3)
        self.assertEqual(blob[0x1B:0x23], (19).to_bytes(3, "little") + (K_BASE - 1).to_bytes(5, "little"))

    def test_revision_points_to_root(self):
        blob = build_revision(bytes([5, 1, 1, 0]), 2608, 8192)
        self.assertEqual(len(blob), 4096)
        self.assertEqual(struct.unpack_from("<H", blob, 0x18)[0], 1)
        self.assertEqual(struct.unpack_from("<II", blob, 0x1C), (2608, 8192))
        self.assertEqual(blob[-16:], TERMINATOR)


from orion_cell_chunk_writer import container_block  # noqa: E402


class CellChunkWriterTests(unittest.TestCase):
    def test_container_block_carries_key_and_roundtrips(self):
        decoded = b"\x03Map" + bytes(range(256)) * 8
        block = container_block(21, 0x101B414F60, decoded)
        parsed = parse_block(block)
        self.assertEqual(parsed["codec"], CODEC_LZMA)
        self.assertEqual(struct.unpack_from("<H", block, 0x18)[0], 21)
        self.assertEqual(struct.unpack_from("<H", block, 0x1A)[0] >> 8, 0x60)
        self.assertEqual(struct.unpack_from("<I", block, 0x1C)[0], 0x101B414F)
        self.assertEqual(block[0x14:0x18], bytes([5, 1, 0, 0]))
        self.assertEqual(parsed["chunks"][0][1], len(decoded))
        self.assertEqual(build_block(parsed, parsed["payload"]), block)
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
            {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}])
        self.assertEqual(dec.decompress(parsed["payload"]), decoded)

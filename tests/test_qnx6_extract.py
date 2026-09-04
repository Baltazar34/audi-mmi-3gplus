#!/usr/bin/env python3
from __future__ import annotations

import os

import hashlib
from pathlib import Path
import stat
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from qnx6_extract import Inode, Qnx6Error, Qnx6FS, _extract_inode  # noqa: E402


APP50 = Path(
    os.environ.get(
        "MHI2_APP_IMG",
        "/private/tmp/mhi2_k3663/K3663_1/1/MMX2/app/50/default/app.img",
    )
)


class _PayloadFS:
    def iter_inode_data(self, _inode: Inode):
        yield b"replacement"


class ExtractionSafetyUnitTests(unittest.TestCase):
    def test_existing_output_symlink_cannot_escape_destination(self) -> None:
        inode = Inode(
            number=2,
            size=11,
            uid=0,
            gid=0,
            mode=stat.S_IFREG | 0o644,
            pointers=(),
            levels=0,
            status=0,
            mtime=0,
            atime=0,
            ctime=0,
        )
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            output_root = temporary_root / "output"
            output_root.mkdir()
            outside = temporary_root / "outside"
            outside.mkdir()

            parent_link = output_root / "navigation"
            parent_link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(Qnx6Error, "output symlink"):
                _extract_inode(
                    _PayloadFS(),
                    inode,
                    parent_link / "libPathfinderApp.so",
                    output_root,
                )
            self.assertFalse((outside / "libPathfinderApp.so").exists())

            victim = outside / "victim"
            victim.write_bytes(b"unchanged")
            leaf_link = output_root / "payload"
            leaf_link.symlink_to(victim)
            with self.assertRaisesRegex(Qnx6Error, "output symlink"):
                _extract_inode(_PayloadFS(), inode, leaf_link, output_root)
            self.assertEqual(victim.read_bytes(), b"unchanged")


@unittest.skipUnless(APP50.exists(), "local MHI2 app/50 image is not extracted")
class Mhi2App50IntegrationTests(unittest.TestCase):
    def test_geometry_and_navigation_root(self) -> None:
        with Qnx6FS(APP50) as fs:
            self.assertEqual(fs.superblock.variant, "standard")
            self.assertEqual(fs.superblock.offset, 0x2000)
            self.assertTrue(fs.superblock.checksum_ok)
            self.assertEqual(fs.block_size, 1024)
            self.assertEqual(fs.superblock.num_blocks, 733136)
            navigation, canonical = fs.resolve("/navigation")
            self.assertEqual(canonical, "/navigation")
            self.assertEqual(navigation.number, 6)
            self.assertEqual(navigation.size, 4096)

    def test_pathfinder_hash_matches_extracted_firmware(self) -> None:
        expected = "636b7d1440938928d97435efc3897cf5baed0b1f768ad03f7efd0b6b109c4ee9"
        with Qnx6FS(APP50) as fs:
            inode, _ = fs.resolve("/navigation/libPathfinderApp.so")
            digest = hashlib.sha256()
            for chunk in fs.iter_inode_data(inode):
                digest.update(chunk)
        self.assertEqual(digest.hexdigest(), expected)

    def test_parent_traversal_is_rejected(self) -> None:
        with Qnx6FS(APP50) as fs:
            with self.assertRaises(Qnx6Error):
                fs.resolve("/navigation/../root")


if __name__ == "__main__":
    unittest.main()

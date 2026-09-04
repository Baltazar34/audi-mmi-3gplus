#!/usr/bin/env python3
"""Read-only QNX6 filesystem inspector/extractor.

This intentionally implements only the on-disk structures needed for static
firmware analysis.  It never modifies the source image and has no third-party
dependencies.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
from typing import BinaryIO, Iterator


QNX6_MAGIC = 0x68191122
SUPERBLOCK_SIZE = 0x200
SUPERBLOCK_AREA = 0x1000
BOOTBLOCK_SIZE = 0x2000
INODE_SIZE = 0x80
DIR_ENTRY_SIZE = 0x20
SHORT_NAME_MAX = 27
UNUSED_BLOCK = 0xFFFFFFFF


class Qnx6Error(RuntimeError):
    pass


def crc32_be(data: bytes, seed: int = 0) -> int:
    """Linux crc32_be(), polynomial 0x04c11db7, initial value supplied."""
    crc = seed & 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc


@dataclasses.dataclass(frozen=True)
class RootNode:
    size: int
    pointers: tuple[int, ...]
    levels: int
    mode: int


@dataclasses.dataclass(frozen=True)
class Superblock:
    offset: int
    variant: str
    endian: str
    checksum: int
    checksum_ok: bool
    serial: int
    block_size: int
    num_inodes: int
    free_inodes: int
    num_blocks: int
    free_blocks: int
    inode_root: RootNode
    bitmap_root: RootNode
    longfile_root: RootNode


@dataclasses.dataclass(frozen=True)
class Inode:
    number: int
    size: int
    uid: int
    gid: int
    mode: int
    pointers: tuple[int, ...]
    levels: int
    status: int
    mtime: int
    atime: int
    ctime: int


@dataclasses.dataclass(frozen=True)
class DirEntry:
    name: str
    inode_number: int


def _root_node(data: bytes, offset: int, endian: str) -> RootNode:
    size = struct.unpack_from(endian + "Q", data, offset)[0]
    pointers = struct.unpack_from(endian + "16I", data, offset + 8)
    levels, mode = struct.unpack_from("BB", data, offset + 72)
    return RootNode(size=size, pointers=pointers, levels=levels, mode=mode)


def _parse_superblock(data: bytes, offset: int, variant: str) -> Superblock:
    if len(data) != SUPERBLOCK_SIZE:
        raise Qnx6Error(f"short superblock at 0x{offset:x}")

    magic_le = struct.unpack_from("<I", data, 0)[0]
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_le == QNX6_MAGIC:
        endian = "<"
    elif magic_be == QNX6_MAGIC:
        endian = ">"
    else:
        raise Qnx6Error(f"no QNX6 magic at 0x{offset:x}")

    checksum = struct.unpack_from(endian + "I", data, 4)[0]
    serial = struct.unpack_from(endian + "Q", data, 8)[0]
    if variant == "standard":
        fields_offset = 48
        roots_offset = 72
    elif variant == "mmi":
        fields_offset = 40
        roots_offset = 64
    else:
        raise AssertionError(variant)

    block_size, num_inodes, free_inodes, num_blocks, free_blocks = struct.unpack_from(
        endian + "5I", data, fields_offset
    )
    return Superblock(
        offset=offset,
        variant=variant,
        endian=endian,
        checksum=checksum,
        checksum_ok=checksum == crc32_be(data[8:]),
        serial=serial,
        block_size=block_size,
        num_inodes=num_inodes,
        free_inodes=free_inodes,
        num_blocks=num_blocks,
        free_blocks=free_blocks,
        inode_root=_root_node(data, roots_offset, endian),
        bitmap_root=_root_node(data, roots_offset + 80, endian),
        longfile_root=_root_node(data, roots_offset + 160, endian),
    )


class Qnx6FS:
    def __init__(self, image: os.PathLike[str] | str):
        self.path = Path(image)
        self._file: BinaryIO = self.path.open("rb")
        self.image_size = self.path.stat().st_size
        self.superblock = self._load_superblock()
        self.endian = self.superblock.endian
        self.block_size = self.superblock.block_size
        if self.block_size < 512 or self.block_size & (self.block_size - 1):
            raise Qnx6Error(f"invalid QNX6 block size: {self.block_size}")
        self.pointer_bits = (self.block_size // 4).bit_length() - 1
        self.pointer_mask = (1 << self.pointer_bits) - 1
        if self.superblock.variant == "standard":
            self.data_block_offset = (BOOTBLOCK_SIZE + SUPERBLOCK_AREA) // self.block_size
        else:
            self.data_block_offset = SUPERBLOCK_AREA // self.block_size
        self._inode_cache: dict[int, Inode] = {}
        self._pointer_block_cache: dict[int, tuple[int, ...]] = {}

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> "Qnx6FS":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.image_size:
            raise Qnx6Error(f"read outside image: offset=0x{offset:x}, size={size}")
        self._file.seek(offset)
        data = self._file.read(size)
        if len(data) != size:
            raise Qnx6Error(f"short read at 0x{offset:x}: wanted {size}, got {len(data)}")
        return data

    def _candidate_at(self, offset: int, variant: str) -> Superblock | None:
        try:
            return _parse_superblock(self._read_at(offset, SUPERBLOCK_SIZE), offset, variant)
        except Qnx6Error:
            return None

    def _load_superblock(self) -> Superblock:
        first = self._candidate_at(BOOTBLOCK_SIZE, "standard")
        if first is None:
            first = self._candidate_at(0, "mmi")
        if first is None:
            raise Qnx6Error("not a supported QNX6 image (magic absent at 0x2000 and 0x0)")
        if first.block_size == 0 or first.num_blocks == 0:
            raise Qnx6Error("invalid first superblock geometry")

        leading = BOOTBLOCK_SIZE if first.variant == "standard" else 0
        second_offset = leading + SUPERBLOCK_AREA + first.num_blocks * first.block_size
        second = self._candidate_at(second_offset, first.variant)
        valid = [sb for sb in (first, second) if sb is not None and sb.checksum_ok]
        if valid:
            return max(valid, key=lambda sb: sb.serial)
        # Some vendor images are distributed with stale checksums.  Keep the
        # reader useful, but expose checksum_ok=False in `info`.
        candidates = [sb for sb in (first, second) if sb is not None]
        return max(candidates, key=lambda sb: sb.serial)

    def _read_physical_block(self, block_number: int) -> bytes:
        if block_number < 0:
            raise Qnx6Error(f"negative block number: {block_number}")
        return self._read_at(block_number * self.block_size, self.block_size)

    def _pointer_block(self, physical_block: int) -> tuple[int, ...]:
        cached = self._pointer_block_cache.get(physical_block)
        if cached is not None:
            return cached
        count = self.block_size // 4
        values = struct.unpack(self.endian + f"{count}I", self._read_physical_block(physical_block))
        self._pointer_block_cache[physical_block] = values
        return values

    def _map_block(self, pointers: tuple[int, ...], levels: int, logical_block: int) -> int:
        if logical_block < 0 or levels < 0 or levels > 5:
            raise Qnx6Error(f"invalid block mapping request: block={logical_block}, levels={levels}")
        bit_delta = self.pointer_bits * levels
        direct_index = logical_block >> bit_delta
        if direct_index >= len(pointers):
            raise Qnx6Error(f"logical block {logical_block} exceeds inode pointer tree")
        block = pointers[direct_index]
        if block == UNUSED_BLOCK:
            raise Qnx6Error(f"logical block {logical_block} maps through an unused pointer")
        physical = block + self.data_block_offset
        for _ in range(levels):
            bit_delta -= self.pointer_bits
            index = (logical_block >> bit_delta) & self.pointer_mask
            block = self._pointer_block(physical)[index]
            if block == UNUSED_BLOCK:
                raise Qnx6Error(f"logical block {logical_block} maps through an unused pointer")
            physical = block + self.data_block_offset
        return physical

    def _read_tree_range(
        self, pointers: tuple[int, ...], levels: int, total_size: int, offset: int, size: int
    ) -> bytes:
        if offset < 0 or size < 0 or offset + size > total_size:
            raise Qnx6Error(f"read outside QNX6 object: offset={offset}, size={size}, object={total_size}")
        result = bytearray()
        remaining = size
        position = offset
        while remaining:
            logical_block, within = divmod(position, self.block_size)
            physical = self._map_block(pointers, levels, logical_block)
            take = min(remaining, self.block_size - within)
            result += self._read_at(physical * self.block_size + within, take)
            remaining -= take
            position += take
        return bytes(result)

    def _iter_tree(
        self, pointers: tuple[int, ...], levels: int, total_size: int, chunk_size: int = 1024 * 1024
    ) -> Iterator[bytes]:
        offset = 0
        while offset < total_size:
            take = min(chunk_size, total_size - offset)
            yield self._read_tree_range(pointers, levels, total_size, offset, take)
            offset += take

    def inode(self, number: int) -> Inode:
        if number < 1 or number > self.superblock.num_inodes:
            raise Qnx6Error(f"inode {number} outside 1..{self.superblock.num_inodes}")
        cached = self._inode_cache.get(number)
        if cached is not None:
            return cached
        offset = (number - 1) * INODE_SIZE
        raw = self._read_tree_range(
            self.superblock.inode_root.pointers,
            self.superblock.inode_root.levels,
            self.superblock.inode_root.size,
            offset,
            INODE_SIZE,
        )
        size = struct.unpack_from(self.endian + "Q", raw, 0)[0]
        uid, gid, _ftime, mtime, atime, ctime = struct.unpack_from(self.endian + "6I", raw, 8)
        mode = struct.unpack_from(self.endian + "H", raw, 32)[0]
        pointers = struct.unpack_from(self.endian + "16I", raw, 36)
        levels, status = struct.unpack_from("BB", raw, 100)
        inode = Inode(
            number=number,
            size=size,
            uid=uid,
            gid=gid,
            mode=mode,
            pointers=pointers,
            levels=levels,
            status=status,
            mtime=mtime,
            atime=atime,
            ctime=ctime,
        )
        self._inode_cache[number] = inode
        return inode

    def read_inode_range(self, inode: Inode, offset: int, size: int) -> bytes:
        return self._read_tree_range(inode.pointers, inode.levels, inode.size, offset, size)

    def iter_inode_data(self, inode: Inode, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        return self._iter_tree(inode.pointers, inode.levels, inode.size, chunk_size)

    def _long_name(self, logical_block: int) -> str:
        root = self.superblock.longfile_root
        offset = logical_block * self.block_size
        raw_size = self._read_tree_range(root.pointers, root.levels, root.size, offset, 2)
        name_size = struct.unpack(self.endian + "H", raw_size)[0]
        if name_size > 510:
            raise Qnx6Error(f"invalid long filename size {name_size}")
        raw_name = self._read_tree_range(root.pointers, root.levels, root.size, offset + 2, name_size)
        return raw_name.decode("utf-8", errors="surrogateescape")

    def iterdir(self, inode: Inode) -> Iterator[DirEntry]:
        if not stat.S_ISDIR(inode.mode):
            raise Qnx6Error(f"inode {inode.number} is not a directory")
        for offset in range(0, inode.size - (inode.size % DIR_ENTRY_SIZE), DIR_ENTRY_SIZE):
            raw = self.read_inode_range(inode, offset, DIR_ENTRY_SIZE)
            inode_number = struct.unpack_from(self.endian + "I", raw, 0)[0]
            name_size = raw[4]
            if inode_number == 0 or name_size == 0:
                continue
            if name_size <= SHORT_NAME_MAX:
                raw_name = raw[5 : 5 + name_size]
                name = raw_name.decode("utf-8", errors="surrogateescape")
            elif name_size == 0xFF:
                long_block = struct.unpack_from(self.endian + "I", raw, 8)[0]
                name = self._long_name(long_block)
            else:
                raise Qnx6Error(f"invalid directory name size 0x{name_size:02x} in inode {inode.number}")
            yield DirEntry(name=name, inode_number=inode_number)

    @staticmethod
    def _parts(path: str) -> tuple[str, ...]:
        pure = PurePosixPath("/" + path.lstrip("/"))
        parts = tuple(part for part in pure.parts if part not in ("/", "."))
        if any(part == ".." for part in parts):
            raise Qnx6Error("parent traversal is not allowed")
        return parts

    def resolve(self, path: str) -> tuple[Inode, str]:
        inode = self.inode(1)
        canonical: list[str] = []
        for wanted in self._parts(path):
            found = None
            for entry in self.iterdir(inode):
                if entry.name == wanted:
                    found = entry
                    break
            if found is None:
                raise Qnx6Error(f"path not found: /{'/'.join(canonical + [wanted])}")
            inode = self.inode(found.inode_number)
            canonical.append(wanted)
        return inode, "/" + "/".join(canonical)

    def walk(self, path: str = "/") -> Iterator[tuple[str, Inode]]:
        inode, canonical = self.resolve(path)
        yield canonical, inode
        if stat.S_ISDIR(inode.mode):
            for entry in self.iterdir(inode):
                if entry.name in (".", ".."):
                    continue
                child_path = canonical.rstrip("/") + "/" + entry.name
                yield from self.walk(child_path)


def mode_label(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "d"
    if stat.S_ISREG(mode):
        return "-"
    if stat.S_ISLNK(mode):
        return "l"
    return "?"


def command_info(fs: Qnx6FS, _args: argparse.Namespace) -> None:
    sb = fs.superblock
    byte_order = "little" if sb.endian == "<" else "big"
    print(f"image: {fs.path}")
    print(f"variant: {sb.variant}")
    print(f"byte_order: {byte_order}")
    print(f"active_superblock_offset: 0x{sb.offset:x}")
    print(f"superblock_serial: {sb.serial}")
    print(f"superblock_checksum_ok: {str(sb.checksum_ok).lower()}")
    print(f"block_size: {sb.block_size}")
    print(f"data_block_offset: {fs.data_block_offset}")
    print(f"inodes: {sb.num_inodes} ({sb.free_inodes} free)")
    print(f"blocks: {sb.num_blocks} ({sb.free_blocks} free)")


def command_ls(fs: Qnx6FS, args: argparse.Namespace) -> None:
    if args.recursive:
        for path, inode in fs.walk(args.path):
            print(f"{mode_label(inode.mode)} {inode.mode & 0o7777:04o} {inode.size:12d} {inode.number:7d} {path}")
        return
    inode, canonical = fs.resolve(args.path)
    if not stat.S_ISDIR(inode.mode):
        print(f"{mode_label(inode.mode)} {inode.mode & 0o7777:04o} {inode.size:12d} {inode.number:7d} {canonical}")
        return
    for entry in fs.iterdir(inode):
        child = fs.inode(entry.inode_number)
        print(f"{mode_label(child.mode)} {child.mode & 0o7777:04o} {child.size:12d} {child.number:7d} {entry.name}")


def _safe_component(name: str) -> str:
    if name in ("", ".", "..") or "/" in name or "\x00" in name:
        raise Qnx6Error(f"unsafe filename in image: {name!r}")
    return name


def _assert_safe_output_path(destination: Path, output_root: Path) -> None:
    """Reject an existing symlink anywhere below the extraction root."""
    try:
        relative = destination.relative_to(output_root)
    except ValueError as error:
        raise Qnx6Error(f"output path escapes extraction root: {destination}") from error

    current = output_root
    for component in (None, *relative.parts):
        if component is not None:
            current /= component
        if current.is_symlink():
            raise Qnx6Error(f"refusing to follow output symlink: {current}")
        if not current.exists():
            break


def _open_output_file(destination: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    return os.fdopen(descriptor, "wb")


def _extract_inode(
    fs: Qnx6FS,
    inode: Inode,
    destination: Path,
    output_root: Path,
) -> None:
    _assert_safe_output_path(destination, output_root)
    if stat.S_ISDIR(inode.mode):
        destination.mkdir(parents=True, exist_ok=True)
        _assert_safe_output_path(destination, output_root)
        for entry in fs.iterdir(inode):
            if entry.name in (".", ".."):
                continue
            child = fs.inode(entry.inode_number)
            _extract_inode(
                fs,
                child,
                destination / _safe_component(entry.name),
                output_root,
            )
        return
    if stat.S_ISREG(inode.mode):
        destination.parent.mkdir(parents=True, exist_ok=True)
        _assert_safe_output_path(destination, output_root)
        with _open_output_file(destination) as output:
            for chunk in fs.iter_inode_data(inode):
                output.write(chunk)
            os.fchmod(output.fileno(), inode.mode & 0o777)
        return
    if stat.S_ISLNK(inode.mode):
        # Firmware images are untrusted input.  Save link targets as plain text
        # so an absolute or parent-traversing link cannot escape the output tree.
        target = b"".join(fs.iter_inode_data(inode))
        link_dump = destination.with_name(destination.name + ".symlink")
        _assert_safe_output_path(link_dump, output_root)
        link_dump.parent.mkdir(parents=True, exist_ok=True)
        _assert_safe_output_path(link_dump, output_root)
        with _open_output_file(link_dump) as output:
            output.write(target)
        return
    print(f"warning: skipped special inode {inode.number} at {destination}", file=sys.stderr)


def command_extract(fs: Qnx6FS, args: argparse.Namespace) -> None:
    inode, canonical = fs.resolve(args.path)
    name = PurePosixPath(canonical).name or "root"
    requested_root = Path(os.path.abspath(args.output))
    if requested_root.is_symlink():
        raise Qnx6Error(f"refusing symlink extraction root: {requested_root}")
    requested_root.mkdir(parents=True, exist_ok=True)
    if not requested_root.is_dir():
        raise Qnx6Error(f"extraction root is not a directory: {requested_root}")
    output_root = requested_root.resolve()
    destination = output_root / _safe_component(name)
    _extract_inode(fs, inode, destination, output_root)
    print(destination)


def command_cat(fs: Qnx6FS, args: argparse.Namespace) -> None:
    inode, _canonical = fs.resolve(args.path)
    if not (stat.S_ISREG(inode.mode) or stat.S_ISLNK(inode.mode)):
        raise Qnx6Error("cat requires a regular file or symlink")
    for chunk in fs.iter_inode_data(inode):
        sys.stdout.buffer.write(chunk)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only QNX6 image inspector/extractor")
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="show filesystem geometry")
    info.add_argument("image", type=Path)

    ls = sub.add_parser("ls", help="list a path")
    ls.add_argument("image", type=Path)
    ls.add_argument("path", nargs="?", default="/")
    ls.add_argument("-R", "--recursive", action="store_true")

    extract = sub.add_parser("extract", help="extract one file or tree")
    extract.add_argument("image", type=Path)
    extract.add_argument("path")
    extract.add_argument("-o", "--output", type=Path, required=True)

    cat = sub.add_parser("cat", help="write one file to stdout")
    cat.add_argument("image", type=Path)
    cat.add_argument("path")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        with Qnx6FS(args.image) as fs:
            if args.command == "info":
                command_info(fs, args)
            elif args.command == "ls":
                command_ls(fs, args)
            elif args.command == "extract":
                command_extract(fs, args)
            elif args.command == "cat":
                command_cat(fs, args)
            else:
                parser.error(f"unknown command: {args.command}")
    except (OSError, Qnx6Error) as error:
        print(f"qnx6_extract: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

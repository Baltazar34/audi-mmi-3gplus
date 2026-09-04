#!/usr/bin/env python3
from __future__ import annotations

import os

import argparse
import contextlib
import hashlib
import io
import json
import lzma
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from psf_decode import (  # noqa: E402
    PSF_FINAL_MARKER,
    _canonical_index_annotation,
    build_stream_layout,
    command_export_source,
    iter_metadata,
    iter_landmarks,
    iter_names,
    parse_envelope,
    read_adas_index,
    read_advanced_routing_index,
    read_basic_spatial_index,
    read_basic_key_index,
    read_basic_dual_spatial_index,
    read_basic_combined_descriptor_tables,
    read_basic_final_spatial_index,
    read_basic_finalizer_directories,
    read_basic_known_indexes,
    read_basic_single_spatial_index,
    read_basic_triple_handle_index,
    read_landmark_index,
    scan_codecs,
    verify_hash_chunks,
    verify_package_entry,
)
from basic_semantic_probe import (  # noqa: E402
    Cluster as BasicSemanticCluster,
    _edge_endpoints,
    geometry_record_offsets,
    run as run_basic_semantic_probe,
    topology_node_offsets,
)
from basic_geometry_grammar import (  # noqa: E402
    Grammar as BasicGeometryGrammar,
    run as run_basic_geometry_grammar,
    split_subrecords,
)
from basic_geometry_decode import (  # noqa: E402
    GeometryCluster as BasicDecodedGeometryCluster,
    decode_geometry_record,
    run as run_basic_geometry_decode,
)
from basic_graph_export import run as run_basic_graph_export  # noqa: E402


MAP_ROOT = Path(
    os.environ.get(
        "MIB_MAP_ROOT",
        "/private/tmp/mib/Mib1/NavDB/SerbiaMontenegroKosovo_eu/0/default",
    )
)
BASIC = MAP_ROOT / "SerbiaMontenegroKosovo_Basic.psf"
LANDMARK = MAP_ROOT / "SerbiaMontenegroKosovo_Landmark.psf"
ADAS = MAP_ROOT / "SerbiaMontenegroKosovo_ADAS.psf"
ADVANCED_ROUTING = MAP_ROOT / "SerbiaMontenegroKosovo_AdvancedRouting.psf"
GLOBAL_POI = MAP_ROOT / "SerbiaMontenegroKosovo_GlobalPOIIndices.psf"


class BasicSemanticUnitTests(unittest.TestCase):
    def test_compact_node_offset_table(self) -> None:
        payload = bytearray(256)
        struct.pack_into("<H", payload, 0, 0x8100)
        payload[4] = 4
        struct.pack_into("<H", payload, 15, 200)
        payload[143:146] = bytes((10, 20, 30))

        offsets, required_end = topology_node_offsets(bytes(payload), 15)

        self.assertEqual(offsets, [200, 210, 220, 230])
        self.assertEqual(required_end, 146)

    def test_direct_geometry_offset_table(self) -> None:
        payload = bytearray(256)
        payload[20] = 0
        payload[23] = 3
        struct.pack_into("<3H", payload, 24, 100, 120, 180)

        offsets, required_end = geometry_record_offsets(bytes(payload), 24)

        self.assertEqual(offsets, [100, 120, 180])
        self.assertEqual(required_end, 30)

    def test_external_node_table_is_even_aligned_like_firmware(self) -> None:
        topology = bytearray(256)
        struct.pack_into("<H", topology, 0, 100)
        topology[2] = 1
        topology[4] = 2
        topology[100:109] = bytes.fromhex("000000004000010000")
        struct.pack_into("<I", topology, 110, 0x00123456)
        cluster = BasicSemanticCluster(
            cluster_id=0x1234,
            topology_entry={},
            geometry_entry={},
            topology=bytes(topology),
            geometry=bytes(24),
            node_offsets=[200, 220],
        )

        endpoint_a, endpoint_b = _edge_endpoints(cluster, 0x00123400, 0, 9)

        self.assertEqual(endpoint_a["node_id"], 0x00123456)
        self.assertEqual(endpoint_a["encoding"], "external-u32-table")
        self.assertEqual(endpoint_b["node_id"], 0x00123401)
        self.assertEqual(endpoint_b["encoding"], "local-u8")

    def test_geometry_nested_subrecord_boundaries(self) -> None:
        record = bytes.fromhex(
            "000205c200d021ba241200817889841033122010011140100110002001"
            "86c201e122d021ba2481780984"
        )

        parts = split_subrecords(
            record,
            cluster_flags=0,
            grammar=BasicGeometryGrammar(
                record_header_base=2,
                subrecord_base=3,
                subrecord_stride=2,
            ),
        )

        self.assertEqual(parts, [(2, 29), (29, 42)])

    @staticmethod
    def _geometry_cluster(
        record: bytes,
        *,
        header_flags: int,
        component_width: int,
        scale: int,
        coordinate_entries: bytes = b"",
        coordinate_count: int = 0,
    ) -> BasicDecodedGeometryCluster:
        topology = bytearray(32)
        struct.pack_into("<H", topology, 0, 16)
        topology[2] = 1
        topology[4] = coordinate_count
        topology[16:25] = bytes.fromhex("000000000000010000")
        record_offset = 24 + len(coordinate_entries)
        geometry = bytearray(record_offset + len(record))
        struct.pack_into("<4i", geometry, 0, 1_000, 2_000, 20_000, 30_000)
        struct.pack_into("<H", geometry, 16, 24)
        geometry[20] = header_flags
        geometry[21] = scale
        geometry[22] = coordinate_count
        geometry[23] = 1
        geometry[24:record_offset] = coordinate_entries
        geometry[record_offset:] = record
        return BasicDecodedGeometryCluster(
            cluster_id=0x1234,
            topology=bytes(topology),
            geometry=bytes(geometry),
            bbox=(1_000, 2_000, 20_000, 30_000),
            header_flags=header_flags,
            scale=scale,
            coordinate_count=coordinate_count,
            coordinate_table_offset=24,
            component_width=component_width,
            coordinate_entry_stride=1 + component_width * 2,
            edge_descriptor_base=16,
            edge_count=1,
            node_count=coordinate_count,
            geometry_offsets=(record_offset,),
            geometry_offset_table_end=24,
        )

    def test_geometry_coordinate_table_and_signed_deltas(self) -> None:
        entries = (
            bytes((0xAA,))
            + struct.pack("<HH", 2, 3)
            + bytes((0xBB,))
            + struct.pack("<HH", 9, 11)
        )
        cluster = self._geometry_cluster(
            bytes.fromhex("000103000201fe0304"),
            header_flags=0,
            component_width=2,
            scale=10,
            coordinate_entries=entries,
            coordinate_count=2,
        )

        parts = decode_geometry_record(cluster, 0)

        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0].start_source, "coordinate-table")
        self.assertEqual(parts[0].end_source, "coordinate-table")
        self.assertEqual(
            [point.as_list() for point in parts[0].points],
            [[1_020, 2_030], [1_030, 2_010], [1_060, 2_050], [1_090, 2_110]],
        )

    def test_geometry_wide_explicit_coordinates_follow_delta_array(self) -> None:
        subrecord = (
            bytes.fromhex("000001ff02")
            + struct.pack("<II", 100, 200)
            + struct.pack("<II", 150, 250)
        )
        cluster = self._geometry_cluster(
            bytes.fromhex("0001") + subrecord,
            header_flags=1,
            component_width=4,
            scale=4,
        )

        parts = decode_geometry_record(cluster, 0)

        self.assertEqual(parts[0].start_source, "explicit")
        self.assertEqual(parts[0].end_source, "explicit")
        self.assertEqual(
            [point.as_list() for point in parts[0].points],
            [[1_400, 2_800], [1_396, 2_808], [1_600, 3_000]],
        )


class SourceExportUnitTests(unittest.TestCase):
    @staticmethod
    def _write_psf(path: Path, wrapped: bytes) -> None:
        header = bytearray(0xFE)
        struct.pack_into("<H", header, 0x00, 0)
        struct.pack_into("<I", header, 0x02, 60)
        struct.pack_into("<I", header, 0x06, 0xFE)
        struct.pack_into("<I", header, 0x4D, len(header) + len(wrapped) + 6)
        path.write_bytes(header + wrapped + PSF_FINAL_MARKER)

    @staticmethod
    def _export(psf: Path, output: Path) -> dict[str, object]:
        args = argparse.Namespace(
            psf=psf,
            output=output,
            kind="auto",
            layout="container",
            limit=0,
            max_output_size=64 * 1024 * 1024,
            permissive_lzma=False,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            command_export_source(args)
        return json.loads((output / "manifest.jsonl").read_text())

    def test_synthetic_source_export_is_self_verifying(self) -> None:
        payload = bytes(range(256)) * 16
        wrapped = bytearray(
            lzma.compress(
                payload,
                format=lzma.FORMAT_ALONE,
                filters=[{"id": lzma.FILTER_LZMA1, "dict_size": len(payload)}],
            )
        )
        wrapped[5:13] = struct.pack("<Q", len(payload))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            psf = root / "renamed.psf"
            self._write_psf(psf, wrapped)
            output = root / "source"
            item = self._export(psf, output)

            summary = json.loads((output / "source_summary.json").read_text())
            manifest = [json.loads(line) for line in (output / "manifest.jsonl").read_text().splitlines()]
            self.assertEqual(summary["source_layer_version"], 6)
            self.assertTrue(summary["all_discovered_streams_exported"])
            self.assertEqual(summary["input_size"], psf.stat().st_size)
            self.assertEqual(summary["scan_config"]["max_output_size"], 64 * 1024 * 1024)
            self.assertEqual((output / "payloads.bin").read_bytes(), payload)
            self.assertEqual(len(manifest), 1)
            self.assertEqual(manifest[0]["stored_size"], len(wrapped))
            self.assertEqual(manifest[0]["raw_size"], len(payload))
            self.assertEqual(item["wrapper_offset"], 0xFE)
            self.assertEqual(item["wrapper_size"], len(wrapped))
            self.assertEqual(item["codec_stream_offset"], 0xFE + 13)
            self.assertEqual(item["codec_stream_size"], len(wrapped) - 13)
            self.assertEqual(item["compressed_size"], len(wrapped) - 13)
            self.assertEqual(item["sha1_stored"], hashlib.sha1(wrapped).hexdigest())
            self.assertEqual(item["sha1_compressed"], hashlib.sha1(wrapped[13:]).hexdigest())
            self.assertEqual((output / "index_references.jsonl").read_text(), "")
            checksum_names = {
                line.split("  ", 1)[1]
                for line in (output / "CHECKSUMS.sha256").read_text().splitlines()
            }
            self.assertEqual(
                checksum_names,
                {
                    "payloads.bin",
                    "manifest.jsonl",
                    "index_references.jsonl",
                    "layout.json",
                    "source_summary.json",
                },
            )

    def test_zlib_source_export_hashes_only_codec_stream(self) -> None:
        payload = bytes(range(251)) * 8
        codec_stream = zlib.compress(payload)
        wrapped = struct.pack("<I", len(payload)) + codec_stream

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            psf = root / "zlib.psf"
            self._write_psf(psf, wrapped)
            output = root / "source"
            item = self._export(psf, output)

            self.assertEqual((output / "payloads.bin").read_bytes(), payload)
            self.assertEqual(item["codec"], "zlib")
            self.assertEqual(item["offset"], 0xFE)
            self.assertEqual(item["wrapper_offset"], 0xFE)
            self.assertEqual(item["stored_size"], len(wrapped))
            self.assertEqual(item["wrapper_size"], len(wrapped))
            self.assertEqual(item["codec_stream_offset"], 0xFE + 4)
            self.assertEqual(item["codec_stream_size"], len(codec_stream))
            self.assertEqual(item["compressed_size"], len(codec_stream))
            self.assertEqual(item["sha1_stored"], hashlib.sha1(wrapped).hexdigest())
            self.assertEqual(
                item["sha1_compressed"], hashlib.sha1(codec_stream).hexdigest()
            )


class CodecScannerUnitTests(unittest.TestCase):
    @staticmethod
    def _zlib_stream(payload: bytes, cinfo: int) -> bytes:
        if not 0 <= cinfo <= 7:
            raise ValueError(cinfo)
        compressor = zlib.compressobj(level=6, wbits=max(9, cinfo + 8))
        stream = bytearray(compressor.compress(payload) + compressor.flush())
        if cinfo == 0:
            cmf = 0x08
            flg_prefix = stream[1] & 0xE0
            flg = next(
                flg_prefix | check
                for check in range(32)
                if ((cmf << 8) | flg_prefix | check) % 31 == 0
            )
            stream[0] = cmf
            stream[1] = flg
        return bytes(stream)

    def test_scan_zlib_accepts_every_valid_cinfo_window(self) -> None:
        payload = (b"0123456789abcdef" * 4) + bytes(range(64))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for cinfo in range(8):
                codec_stream = self._zlib_stream(payload, cinfo)
                self.assertEqual(codec_stream[0] >> 4, cinfo)
                wrapped = struct.pack("<I", len(payload)) + codec_stream
                path = root / f"cinfo-{cinfo}.bin"
                path.write_bytes(b"prefix!" + wrapped + b"suffix")

                records = list(scan_codecs(path, 1024 * 1024))
                self.assertEqual(len(records), 1, f"CINFO={cinfo}")
                record = records[0]
                self.assertEqual(record["codec"], "zlib")
                self.assertEqual(record["wrapper_offset"], 7)
                self.assertEqual(record["wrapper_size"], len(wrapped))
                self.assertEqual(record["codec_stream_offset"], 11)
                self.assertEqual(record["codec_stream_size"], len(codec_stream))
                self.assertEqual(record["compressed_size"], len(codec_stream))


@unittest.skipUnless(BASIC.exists(), "local MIB1 Serbia map sample is not extracted")
class BasicPsfIntegrationTests(unittest.TestCase):
    def test_envelope_and_tail_chain(self) -> None:
        envelope = parse_envelope(BASIC)
        self.assertEqual(envelope["slot_type_name"], "regular")
        self.assertEqual(envelope["psf_version"], 60)
        self.assertEqual(envelope["fixed_header_size"], 0xFE)
        self.assertEqual(envelope["signature_covered_header_size"], 0xF2)
        self.assertEqual(envelope["actual_size"], 47_262_023)
        self.assertTrue(envelope["declared_size_ok"])
        self.assertTrue(envelope["regular_tail_chain_contiguous"])
        self.assertTrue(envelope["regular_tail_chain_reaches_eof"])
        self.assertTrue(envelope["final_marker_ok"])

        blocks = envelope["blocks"]
        self.assertEqual(blocks["spatial_index"]["offset"], 47_252_377)
        self.assertEqual(blocks["spatial_index"]["size"], 260)
        self.assertEqual(blocks["world"]["offset"], 47_252_637)
        self.assertEqual(blocks["world"]["size"], 6_451)
        self.assertEqual(blocks["metadata"]["offset"], 47_259_088)
        self.assertEqual(blocks["metadata"]["size"], 2_673)
        self.assertEqual(blocks["combined_tail"]["offset"], 47_261_761)
        self.assertEqual(blocks["combined_tail"]["size"], 262)

    def test_content_package_and_chunk_hashes(self) -> None:
        package = verify_package_entry(BASIC, MAP_ROOT / "content.pkg")
        hashes = verify_hash_chunks(BASIC, MAP_ROOT / "hashes.txt")
        self.assertTrue(package["filesize_ok"])
        self.assertTrue(package["verification_blob_ok"])
        self.assertEqual(package["verification_size"], 128)
        self.assertTrue(hashes["ok"])
        self.assertEqual(hashes["actual_chunks"], 91)

    def test_typed_metadata_records(self) -> None:
        records = list(iter_metadata(BASIC))
        self.assertEqual(len(records), 283)
        self.assertEqual(
            records[0],
            {
                "offset": 47_259_088,
                "relative_offset": 0,
                "field_id": 1,
                "type": 4,
                "type_name": "u16",
                "value": 9,
            },
        )
        self.assertEqual(records[-1]["field_id"], 576)
        self.assertEqual(records[-1]["value"], 8)

    def test_first_mask_backed_names(self) -> None:
        records = []
        for record in iter_names(BASIC):
            records.append(record)
            if len(records) == 5:
                break
        self.assertEqual(
            [(item["offset"], item["name"]) for item in records],
            [
                (43_228_993, "Bajmok"),
                (43_229_011, "R122 (Ulica Glavna)"),
                (43_229_055, "Ram"),
                (43_229_067, "Topolovnik"),
                (43_229_130, "Petrovac"),
            ],
        )

    def test_basic_spatial_tail_index(self) -> None:
        index = read_basic_spatial_index(BASIC)
        self.assertEqual(len(index["entries"]), 8)
        self.assertEqual(index["index_start"], 47_252_377)
        self.assertEqual(index["index_size"], 260)
        self.assertEqual(index["record_base"], 4)
        self.assertEqual(index["record_stride"], 32)
        self.assertEqual(index["payload_start"], 0x8622B9)
        self.assertEqual(index["payload_end"], 0x8694A7)
        self.assertEqual(
            [entry["uncompressed_size"] for entry in index["entries"]],
            [1060, 11586, 5696, 4933, 8918, 4798, 4909, 6510],
        )

    def test_basic_metadata_key_index(self) -> None:
        index = read_basic_key_index(BASIC)
        self.assertEqual(index["metadata_field_id"], 0x13F)
        self.assertEqual(index["tree_depth"], 1)
        self.assertEqual(index["index_start"], 622_510)
        self.assertEqual(index["index_size"], 4_372)
        self.assertEqual(len(index["entries"]), 364)
        self.assertEqual(index["entries"][0]["cluster_key"], 0)
        self.assertEqual(index["entries"][-1]["cluster_key"], 363)

    def test_basic_dual_spatial_index(self) -> None:
        index = read_basic_dual_spatial_index(BASIC)
        self.assertEqual(index["record_count"], 3_336)
        self.assertEqual(len(index["entries"]), 6_672)
        self.assertEqual(
            [page["count"] for page in index["groups"]],
            [49, 83, 125, 255, 18] + [255] * 11 + [1],
        )
        self.assertEqual(
            [(root["offset"], root["child_count"]) for root in index["internal_roots"]],
            [(0x436E, 2), (0x1A2BE, 11)],
        )
        self.assertEqual(index["entries"][0]["compressed_offset"], 0xBB46F)
        self.assertEqual(index["entries"][0]["compressed_size"], 0x60A)
        self.assertEqual(index["entries"][0]["cluster_id"], 0x65C0)
        self.assertEqual(index["entries"][0]["record_flags"], 3)
        self.assertTrue(index["entries"][0]["compressed_flag"])

    def test_basic_triple_handle_index(self) -> None:
        index = read_basic_triple_handle_index(BASIC)
        self.assertEqual(index["record_count"], 3_336)
        self.assertEqual(len(index["entries"]), 10_008)
        self.assertEqual([page["count"] for page in index["groups"]], [215] * 15 + [111])
        self.assertEqual(index["index_start"], 0x1A3CA)
        self.assertEqual(index["index_root"], 0x3933A)
        self.assertEqual(index["index_root_end"], 0x393BA)
        self.assertEqual(
            [entry["compressed_offset"] for entry in index["entries"][:3]],
            [0x990C2, 0x8694A7, 0x17DAE82],
        )
        self.assertEqual(index["entries"][0]["cluster_id"], 0x6590)
        self.assertEqual(index["entries"][0]["record_flags"], 7)
        self.assertTrue(index["entries"][0]["compressed_flag"])

    def test_basic_single_spatial_index(self) -> None:
        index = read_basic_single_spatial_index(BASIC)
        self.assertEqual(index["record_count"], 15_676)
        self.assertEqual(len(index["entries"]), 15_676)
        self.assertEqual(len(index["groups"]), 54)
        self.assertEqual(
            [(root["offset"], root["child_count"]) for root in index["internal_roots"]],
            [(0x412C2, 3), (0x516A6, 9), (0x954DA, 35)],
        )
        self.assertEqual(index["entries"][0]["compressed_offset"], 0x17DB560)
        self.assertEqual(index["entries"][0]["compressed_size"], 499)
        self.assertEqual(index["entries"][-1]["compressed_offset"], 0x2153270)
        self.assertEqual(index["entries"][-1]["compressed_size"], 76)
        self.assertEqual(
            sorted({entry["packed_auxiliary"] for entry in index["entries"]}),
            [0, 1, 2, 3, 4],
        )

    def test_basic_final_spatial_matches_key_index(self) -> None:
        spatial = read_basic_final_spatial_index(BASIC)
        key = read_basic_key_index(BASIC)
        self.assertEqual(spatial["record_count"], 364)
        self.assertEqual([page["count"] for page in spatial["groups"]], [292, 72])
        self.assertEqual(spatial["index_root"], 0x97F82)
        self.assertEqual(spatial["index_root_size"], 44)
        self.assertEqual(
            {
                (entry["compressed_offset"], entry["compressed_size"])
                for entry in spatial["entries"]
            },
            {
                (entry["compressed_offset"], entry["compressed_size"])
                for entry in key["entries"]
            },
        )

    def test_basic_combined_known_indexes(self) -> None:
        index = read_basic_known_indexes(BASIC)
        self.assertEqual(index["reference_count"], 33_092)
        self.assertEqual(index["unique_payload_count"], 26_056)
        self.assertEqual(len(index["entries"]), 26_056)
        self.assertTrue(index["dual_spatial_is_triple_subset"])
        self.assertTrue(index["final_spatial_matches_key_index"])
        self.assertEqual(index["payload_start"], 0x990C2)

    def test_basic_spatial_canonical_provenance_keeps_local_record(self) -> None:
        index = read_basic_known_indexes(BASIC)
        entries = [
            entry
            for entry in index["entries"]
            if entry["source_index_kind"] == "basic-spatial"
        ]
        self.assertEqual(
            [entry["index"] for entry in entries],
            list(range(26_048, 26_056)),
        )
        annotations = [
            _canonical_index_annotation(index["kind"], entry) for entry in entries
        ]
        self.assertEqual(
            [annotation["index_kind"] for annotation in annotations],
            ["basic-spatial"] * 8,
        )
        self.assertEqual(
            [annotation["index_record"] for annotation in annotations],
            list(range(8)),
        )

    def test_complete_basic_stream_layout(self) -> None:
        layout = build_stream_layout(BASIC)
        self.assertEqual(layout["stream_count"], 65_527)
        self.assertEqual(layout["stored_bytes"], 44_487_407)
        self.assertEqual(layout["decoded_bytes"], 82_275_083)
        self.assertEqual(layout["cluster_count"], 9_051)
        self.assertEqual(layout["inter_cluster_gap_count"], 9_050)
        self.assertEqual(layout["compact_footer_count"], 9_041)
        self.assertEqual(layout["compact_footer_reference_count"], 9_242)
        self.assertEqual(layout["special_gap_count"], 10)
        self.assertEqual(layout["runs"][0]["stream_count"], 25_692)
        self.assertEqual(layout["runs"][-1]["stream_count"], 364)
        self.assertEqual(
            layout["fingerprints"],
            {
                "stream_table_sha256": "502ecbf310e7bf2fe341099c59b47381c628d8cf8bd3b9477e14937dd730aced",
                "run_table_sha256": "4bd6eee0120204d42036803a0c932fdcdfa3553cfa1924bb74e4266a13ec9b2c",
                "gap_table_sha256": "4bc70fbe02f70a5a106eb71d23caecdd79b9bcaa128c15d25605cb16fce492b7",
                "footer_table_sha256": "9c42f3f0f4ad1807303726c82dab866d206b77624864b732cdaa675d578d53bb",
            },
        )
        combined = read_basic_combined_descriptor_tables(BASIC, layout)
        self.assertEqual(combined["table_count"], 4)
        self.assertEqual(combined["record_count"], 233)
        self.assertEqual(combined["handle_count"], 689)
        self.assertEqual(combined["middle_handle_count"], 226)
        self.assertEqual(combined["middle_stored_bytes"], 665_962)
        self.assertEqual(combined["middle_uncompressed_bytes"], 1_115_682)
        self.assertEqual(
            [(table["offset"], table["child_count"]) for table in combined["groups"]],
            [(0x2281F32, 40), (0x28F2E9E, 166), (0x2936D7A, 25), (0x2938EDF, 2)],
        )
        finalizers = read_basic_finalizer_directories(BASIC, layout, combined)
        self.assertEqual(finalizers["finalizer_count"], 230)
        self.assertEqual(finalizers["trivial_finalizer_count"], 151)
        self.assertEqual(finalizers["directory_count"], 79)
        self.assertEqual(finalizers["section_pattern_counts"], {"5,4,1,2": 59, "4,2": 20})
        self.assertEqual(finalizers["handle_slot_count"], 9_208)
        self.assertEqual(finalizers["null_handle_slot_count"], 7_618)
        self.assertEqual(finalizers["reference_count"], 1_590)
        self.assertEqual(finalizers["unique_payload_count"], 1_590)
        self.assertTrue(all(entry["handle_flags"] == 0 for entry in finalizers["entries"]))

    def test_basic_semantic_topology_geometry_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "semantic"
            with contextlib.redirect_stderr(io.StringIO()):
                report = run_basic_semantic_probe(BASIC, output, sample_limit=3)

            self.assertEqual(report["status"], "validated")
            self.assertEqual(report["counts"]["clusters"], 3_336)
            self.assertEqual(report["counts"]["edges"], 838_433)
            self.assertEqual(report["counts"]["nodes"], 717_730)
            self.assertEqual(report["counts"]["geometry_records"], 838_433)
            self.assertEqual(report["inferred_layout"]["edge_descriptor_stride"], 9)
            self.assertEqual(report["inferred_layout"]["node_adjacency_offset"], 2)
            self.assertTrue(report["validation"]["all_geometry_bboxes_match_index"])
            self.assertTrue(
                report["validation"]["resolved_node_adjacencies_match_edge_endpoints"]
            )
            self.assertEqual(len((output / "edge_sample.jsonl").read_text().splitlines()), 3)

    def test_basic_nested_geometry_grammar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "geometry-grammar"
            with contextlib.redirect_stderr(io.StringIO()):
                report = run_basic_geometry_grammar(
                    BASIC,
                    output,
                    inference_limit=10_000,
                    sample_limit=3,
                )

            self.assertEqual(report["status"], "validated")
            self.assertEqual(report["counts"]["geometry_records"], 838_433)
            self.assertEqual(report["validation"]["total_subrecords"], 903_487)
            self.assertEqual(report["validation"]["failure_count"], 0)
            self.assertEqual(report["grammar"]["record_header_base"], 2)
            self.assertEqual(report["grammar"]["subrecord_base"], 3)
            self.assertEqual(report["grammar"]["subrecord_stride"], 2)
            self.assertEqual(
                len((output / "geometry_sample.jsonl").read_text().splitlines()), 3
            )

    def test_basic_normalized_geometry_decode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "geometry-decode"
            with contextlib.redirect_stderr(io.StringIO()):
                report = run_basic_geometry_decode(BASIC, output, sample_limit=3)

            self.assertEqual(report["status"], "validated")
            self.assertEqual(report["counts"]["clusters"], 3_336)
            self.assertEqual(report["counts"]["edges_decoded"], 838_433)
            self.assertEqual(report["counts"]["subrecords"], 903_487)
            self.assertEqual(report["counts"]["points"], 3_960_735)
            self.assertEqual(report["counts"]["delta_pairs"], 2_153_761)
            self.assertEqual(
                report["counts"]["coordinate_modes"],
                {"u16-components": 3_335, "u32-components": 1},
            )
            self.assertTrue(report["validation"]["all_edges_decoded"])
            self.assertTrue(
                report["validation"]["all_decoded_points_inside_cluster_bbox"]
            )
            self.assertEqual(
                len((output / "edge_geometry_sample.jsonl").read_text().splitlines()),
                3,
            )

    def test_basic_validated_graph_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "graph"
            with contextlib.redirect_stderr(io.StringIO()):
                report = run_basic_graph_export(BASIC, output, sample_limit=3)

            self.assertEqual(report["status"], "validated")
            self.assertEqual(report["counts"]["nodes"], 717_730)
            self.assertEqual(report["counts"]["edges"], 838_433)
            self.assertEqual(report["counts"]["geometry_parts"], 903_487)
            self.assertEqual(report["counts"]["centerline_points"], 3_895_681)
            self.assertEqual(
                report["counts"]["unique_semantic_records"], 182_377
            )
            self.assertEqual(
                report["counts"]["unique_semantic_text_entries"], 271_823
            )
            self.assertEqual(
                report["counts"]["edges_with_name_candidates"], 549_784
            )
            self.assertEqual(
                report["counts"]["edge_name_candidate_references"], 995_298
            )
            self.assertEqual(
                report["counts"]["geometry_part_join_comparisons"], 65_054
            )
            self.assertEqual(report["counts"]["simple_speed_limit_values"], 156_406)
            self.assertEqual(report["counts"]["extended_speed_limit_values"], 61_618)
            self.assertEqual(report["counts"]["number_of_lanes_values"], 1_632)
            self.assertEqual(
                report["counts"]["simple_passing_restriction_markers"], 50_617
            )
            self.assertEqual(
                report["counts"]["extended_passing_restrictions"], 9_942
            )
            self.assertEqual(report["counts"]["lanes_attributes"], 15_614)
            self.assertEqual(report["counts"]["lane_records"], 39_538)
            self.assertEqual(
                report["counts"]["clusters_with_dynamic_directory"], 868
            )
            self.assertEqual(report["counts"]["dynamic_directory_entries"], 1_178)
            self.assertEqual(report["counts"]["dynamic_type_5_records"], 1_819)
            self.assertEqual(report["counts"]["dynamic_type_3_records"], 308)
            self.assertEqual(
                report["validation"]["node_adjacency_mismatch_count"], 0
            )
            self.assertEqual(
                report["validation"]["coordinate_table_endpoint_mismatch_count"],
                0,
            )
            self.assertEqual(
                report["validation"]["geometry_part_join_mismatch_count"], 0
            )
            self.assertEqual(
                report["validation"]["explicit_endpoint_coordinate_difference_count"],
                4,
            )
            self.assertEqual(len((output / "nodes.jsonl").read_text().splitlines()), 3)
            self.assertEqual(len((output / "edges.jsonl").read_text().splitlines()), 3)
            first_edge = json.loads((output / "edges.jsonl").read_text().splitlines()[0])
            self.assertEqual(
                first_edge["name_candidates"][0]["values"],
                ["Rruga Ibrahim Rugova"],
            )
            self.assertIn("semantic_record", first_edge)
            self.assertEqual(first_edge["schema_version"], 7)
            self.assertIn("static_travel_direction", first_edge["road_attributes"])
            self.assertIn(
                "extended_automotive_attributes", first_edge["road_attributes"]
            )
            self.assertIn(
                "dynamic_topology_attributes", first_edge["road_attributes"]
            )


@unittest.skipUnless(LANDMARK.exists(), "local MIB1 Serbia landmark sample is not extracted")
class LandmarkCodecIntegrationTests(unittest.TestCase):
    def test_all_canonical_lzma_clusters_decode(self) -> None:
        streams = list(scan_codecs(LANDMARK, 64 * 1024 * 1024))
        self.assertEqual(len(streams), 72)
        self.assertEqual(streams[0]["wrapper_offset"], 0x7BE)
        self.assertEqual(streams[0]["uncompressed_size"], 145)
        self.assertEqual(streams[-1]["wrapper_offset"], 0x336D)
        self.assertEqual(streams[-1]["uncompressed_size"], 173)
        self.assertTrue(all(item["properties"] == 0x5D for item in streams))

    def test_index_and_semantic_landmark_records(self) -> None:
        index = read_landmark_index(LANDMARK)
        self.assertEqual(len(index), 72)
        self.assertEqual(index[0]["cluster_id"], 201)
        self.assertEqual(index[0]["compressed_offset"], 0x7BE)
        self.assertEqual(index[-1]["compressed_offset"], 0x336D)

        records = list(iter_landmarks(LANDMARK))
        self.assertEqual(len(records), 78)
        first = records[0]
        self.assertEqual(first["asset_path"], "SerbiaMontenegroKosovo\\MNE_HI2029_HERCEGNOVI_SAVINA_MONASTERY")
        self.assertEqual(first["names"][0]["display"], "Manastir Savina")
        self.assertEqual(first["names"][0]["search"], "Manastir Savina")
        self.assertAlmostEqual(first["longitude"], 18.5338972, places=6)
        self.assertAlmostEqual(first["latitude"], 42.4134708, places=6)


@unittest.skipUnless(ADAS.exists(), "local MIB1 Serbia ADAS sample is not extracted")
class GroupedClusterIndexIntegrationTests(unittest.TestCase):
    def test_adas_index(self) -> None:
        index = read_adas_index(ADAS)
        self.assertEqual(len(index["entries"]), 3_336)
        self.assertEqual([group["count"] for group in index["groups"]], [682, 682, 682, 682, 608])
        self.assertEqual(index["payload_start"], 0x9D8E)
        self.assertEqual(index["payload_end"], 0x1BE3A09)
        self.assertEqual(index["auxiliary_regions"], [{"offset": 0x9D66, "size": 40, "end": 0x9D8E}])

    @unittest.skipUnless(
        ADVANCED_ROUTING.exists(),
        "local MIB1 Serbia AdvancedRouting sample is not extracted",
    )
    def test_advanced_routing_index(self) -> None:
        index = read_advanced_routing_index(ADVANCED_ROUTING)
        self.assertEqual(len(index["entries"]), 3_342)
        self.assertEqual(
            [group["count"] for group in index["groups"]],
            [409, 409, 409, 409, 409, 409, 409, 409, 63, 7],
        )
        self.assertEqual(index["payload_start"], 0x1067A)
        self.assertEqual(index["payload_end"], 0x364BF5)
        self.assertEqual(index["auxiliary_regions"], [{"offset": 0x105A2, "size": 72, "end": 0x105EA}])


@unittest.skipUnless(GLOBAL_POI.exists(), "local MIB1 Serbia GlobalPOI sample is not extracted")
class GlobalPoiLayoutIntegrationTests(unittest.TestCase):
    def test_complete_global_poi_stream_layout(self) -> None:
        layout = build_stream_layout(GLOBAL_POI)
        self.assertEqual(layout["stream_count"], 7_069)
        self.assertEqual(layout["stored_bytes"], 6_158_795)
        self.assertEqual(layout["decoded_bytes"], 11_650_848)
        self.assertEqual(layout["cluster_count"], 522)
        self.assertEqual(layout["inter_cluster_gap_count"], 521)
        self.assertEqual(layout["special_gap_count"], 6)
        self.assertEqual(layout["trailing_region"]["footer"]["reference_count"], 1)
        self.assertEqual(
            layout["fingerprints"]["stream_table_sha256"],
            "e1f67bebe325622c54ca19873042927fa94d940e4f4e6dacf25eea88df8fb8ff",
        )


if __name__ == "__main__":
    unittest.main()

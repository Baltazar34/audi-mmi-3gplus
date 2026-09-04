#!/usr/bin/env python3
"""Infer and validate the first semantic layer of MIB PSF60 Basic clusters.

The script intentionally separates confirmed topology/record boundaries from
still-opaque record bodies.  It runs against every three-handle Basic cluster,
infers firmware-backed layout constants from the payloads, validates the result
globally, and writes a compact machine-readable report plus an edge sample.

It is a research/verification companion to psf_decode.py.  A layout is accepted
only when it is the unique candidate that survives the complete input corpus.
"""

from __future__ import annotations

import argparse
import collections
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import BinaryIO, Iterator

from psf_decode import (
    PsfError,
    _decode_indexed_lzma,
    _mercator_to_wgs84,
    read_basic_triple_handle_index,
)


SCHEMA_VERSION = 1
EDGE_CLUSTER_MASK = 0xE7FFFFFF
TOPOLOGY_BASE_CANDIDATES = range(2, 97)
EDGE_STRIDE_CANDIDATES = range(1, 17)
NODE_ADJACENCY_OFFSET_CANDIDATES = range(1, 41)
GEOMETRY_BASE_CANDIDATES = range(16, 129)


@dataclass
class Cluster:
    cluster_id: int
    topology_entry: dict[str, object]
    geometry_entry: dict[str, object]
    topology: bytes
    geometry: bytes
    node_offsets: list[int] | None = None
    geometry_offsets: list[int] | None = None

    @property
    def edge_count(self) -> int:
        return self.topology[2]

    @property
    def node_count(self) -> int:
        return self.topology[4]

    @property
    def edge_descriptor_base(self) -> int:
        return struct.unpack_from("<H", self.topology)[0] & 0x7FFF


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(f"basic-semantic stage={stage}{' ' if suffix else ''}{suffix}", file=sys.stderr, flush=True)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_record_offsets(values: list[int], required_end: int, payload_size: int) -> bool:
    return bool(
        values
        and values == sorted(set(values))
        and required_end <= values[0]
        and values[-1] < payload_size
    )


def topology_node_offsets(payload: bytes, table_base: int) -> tuple[list[int], int]:
    if len(payload) < 15:
        raise PsfError("truncated Basic topology header")
    node_count = payload[4]
    if node_count == 0:
        raise PsfError("Basic topology cluster has no nodes")
    compressed = bool(struct.unpack_from("<H", payload)[0] & 0x8000)
    result: list[int] = []
    required_end = table_base
    for node_index in range(node_count):
        if compressed:
            group = node_index >> 2
            absolute_at = table_base + group * 2
            required_end = max(required_end, absolute_at + 2)
            try:
                value = struct.unpack_from("<H", payload, absolute_at)[0]
                if node_index & 3:
                    delta_at = table_base + 0x7F + node_index - group
                    required_end = max(required_end, delta_at + 1)
                    value += payload[delta_at]
            except (IndexError, struct.error) as error:
                raise PsfError("truncated compressed Basic node-offset table") from error
        else:
            absolute_at = table_base + node_index * 2
            required_end = max(required_end, absolute_at + 2)
            try:
                value = struct.unpack_from("<H", payload, absolute_at)[0]
            except struct.error as error:
                raise PsfError("truncated Basic node-offset table") from error
        result.append(value & 0xFFFF)
    return result, required_end


def geometry_record_offsets(payload: bytes, table_base: int) -> tuple[list[int], int]:
    if len(payload) < 24:
        raise PsfError("truncated Basic geometry header")
    edge_count = payload[23]
    if edge_count == 0:
        raise PsfError("Basic geometry cluster has no edge records")
    compressed = bool(payload[20] & 0x02)
    result: list[int] = []
    required_end = table_base
    for edge_index in range(edge_count):
        if compressed:
            group = edge_index >> 3
            absolute_at = table_base + group * 2
            required_end = max(required_end, absolute_at + 2)
            try:
                value = struct.unpack_from("<H", payload, absolute_at)[0]
                if edge_index & 7:
                    delta_at = table_base + 0x3F + edge_index - group
                    required_end = max(required_end, delta_at + 1)
                    value += payload[delta_at]
            except (IndexError, struct.error) as error:
                raise PsfError("truncated compressed Basic geometry-offset table") from error
        else:
            absolute_at = table_base + edge_index * 2
            required_end = max(required_end, absolute_at + 2)
            try:
                value = struct.unpack_from("<H", payload, absolute_at)[0]
            except struct.error as error:
                raise PsfError("truncated Basic geometry-offset table") from error
        result.append(value & 0xFFFF)
    return result, required_end


def _infer_table_base(
    clusters: list[Cluster],
    candidates: range,
    payload_getter,
    offset_reader,
    label: str,
) -> tuple[int, dict[int, int]]:
    survivors = set(candidates)
    pass_counts = collections.Counter()
    for cluster in clusters:
        payload = payload_getter(cluster)
        for candidate in list(survivors):
            try:
                offsets, required_end = offset_reader(payload, candidate)
            except PsfError:
                survivors.remove(candidate)
                continue
            if not _strict_record_offsets(offsets, required_end, len(payload)):
                survivors.remove(candidate)
                continue
            pass_counts[candidate] += 1
    if len(survivors) != 1:
        raise PsfError(f"{label} is not uniquely inferred: {sorted(survivors)}")
    return next(iter(survivors)), dict(sorted(pass_counts.items()))


def _infer_edge_stride(clusters: list[Cluster]) -> tuple[int, dict[int, dict[str, int]]]:
    scores: dict[int, collections.Counter[str]] = {
        stride: collections.Counter() for stride in EDGE_STRIDE_CANDIDATES
    }
    for cluster in clusters:
        assert cluster.node_offsets is not None
        first_node = cluster.node_offsets[0]
        for stride, score in scores.items():
            descriptor_end = cluster.edge_descriptor_base + cluster.edge_count * stride
            # The ARM consumer advances an odd table end by one byte before
            # assembling each external u32 node ID from two u16 loads.
            external_base = descriptor_end + (descriptor_end & 1)
            if external_base > first_node:
                score["layout_overrun"] += 1
                continue
            external_capacity = (first_node - external_base) // 4
            for edge_index in range(cluster.edge_count):
                start = cluster.edge_descriptor_base + edge_index * stride
                if start + 7 > len(cluster.topology):
                    score["descriptor_overrun"] += 1
                    break
                flags = cluster.topology[start + 4]
                for slot, external_mask in ((5, 0x40), (6, 0x80)):
                    value = cluster.topology[start + slot]
                    if flags & external_mask:
                        if value >= external_capacity:
                            score["external_slot_bad"] += 1
                    elif value >= cluster.node_count:
                        score["local_slot_bad"] += 1
    survivors = [stride for stride, score in scores.items() if not score]
    if len(survivors) != 1:
        raise PsfError(f"edge descriptor stride is not uniquely inferred: {survivors}")
    return survivors[0], {stride: dict(score) for stride, score in scores.items()}


def _edge_cluster_id(edge_id: int) -> int:
    return (edge_id & EDGE_CLUSTER_MASK) >> 8


def _infer_adjacency_offset(
    clusters: list[Cluster],
    by_id: dict[int, Cluster],
) -> tuple[int, dict[int, dict[str, int]]]:
    scores: dict[int, collections.Counter[str]] = {
        candidate: collections.Counter()
        for candidate in NODE_ADJACENCY_OFFSET_CANDIDATES
    }
    for cluster in clusters:
        assert cluster.node_offsets is not None
        ends = cluster.node_offsets[1:] + [len(cluster.topology)]
        for start, end in zip(cluster.node_offsets, ends):
            local_count = cluster.topology[start] >> 4
            external_count = cluster.topology[start] & 0x0F
            for candidate, score in scores.items():
                required = candidate + local_count + external_count * 4
                if required > end - start:
                    score["record_overrun"] += 1
                    continue
                cursor = start + candidate
                for edge_index in cluster.topology[cursor : cursor + local_count]:
                    if edge_index >= cluster.edge_count:
                        score["local_slot_bad"] += 1
                cursor += local_count
                for _ in range(external_count):
                    edge_id = struct.unpack_from("<I", cluster.topology, cursor)[0]
                    cursor += 4
                    target = by_id.get(_edge_cluster_id(edge_id))
                    if target is None or (edge_id & 0xFF) >= target.edge_count:
                        score["external_target_outside_main_corpus"] += 1

    def rank(item: tuple[int, collections.Counter[str]]) -> tuple[int, int, int]:
        _, score = item
        structural = score["record_overrun"] + score["local_slot_bad"]
        return structural, score["external_target_outside_main_corpus"], sum(score.values())

    ranked = sorted(scores.items(), key=rank)
    if len(ranked) < 2 or rank(ranked[0]) == rank(ranked[1]):
        raise PsfError("node adjacency offset is not uniquely inferred")
    winner, winner_score = ranked[0]
    if winner_score["record_overrun"] or winner_score["local_slot_bad"]:
        raise PsfError(f"best node adjacency offset is structurally invalid: {winner_score}")
    return winner, {candidate: dict(score) for candidate, score in scores.items()}


def _edge_endpoints(
    cluster: Cluster,
    edge_id: int,
    edge_index: int,
    edge_stride: int,
) -> tuple[dict[str, object], dict[str, object]]:
    if edge_index >= cluster.edge_count:
        raise PsfError(f"edge index {edge_index} outside cluster {cluster.cluster_id}")
    assert cluster.node_offsets is not None
    start = cluster.edge_descriptor_base + edge_index * edge_stride
    descriptor = cluster.topology[start : start + edge_stride]
    flags = descriptor[4]
    descriptor_end = cluster.edge_descriptor_base + cluster.edge_count * edge_stride
    external_base = descriptor_end + (descriptor_end & 1)
    external_capacity = (cluster.node_offsets[0] - external_base) // 4
    result: list[dict[str, object]] = []
    for name, slot, external_mask in (("a", 5, 0x40), ("b", 6, 0x80)):
        value = descriptor[slot]
        if flags & external_mask:
            if value >= external_capacity:
                raise PsfError(
                    f"external node slot {value} outside cluster {cluster.cluster_id} table"
                )
            node_id = struct.unpack_from("<I", cluster.topology, external_base + value * 4)[0]
            encoding = "external-u32-table"
        else:
            node_id = (edge_id & 0xE7FFFF00) | value
            encoding = "local-u8"
        result.append(
            {
                "endpoint": name,
                "node_id": node_id,
                "node_id_hex": f"0x{node_id:08x}",
                "encoding": encoding,
                "encoded_value": value,
            }
        )
    return result[0], result[1]


def _node_adjacencies(
    cluster: Cluster,
    node_index: int,
    adjacency_offset: int,
) -> tuple[list[int], int, int]:
    assert cluster.node_offsets is not None
    start = cluster.node_offsets[node_index]
    marker = cluster.topology[start]
    local_count = marker >> 4
    external_count = marker & 0x0F
    cursor = start + adjacency_offset
    result = [
        (cluster.cluster_id << 8) | value
        for value in cluster.topology[cursor : cursor + local_count]
    ]
    cursor += local_count
    for _ in range(external_count):
        result.append(struct.unpack_from("<I", cluster.topology, cursor)[0])
        cursor += 4
    return result, local_count, external_count


def _node_summary(
    node: dict[str, object],
    by_id: dict[int, Cluster],
    adjacency_offset: int,
) -> dict[str, object]:
    result = dict(node)
    node_id = int(node["node_id"])
    cluster = by_id.get(node_id >> 8)
    node_index = node_id & 0xFF
    resolved = cluster is not None and node_index < cluster.node_count
    result["resolved_in_main_triple_handle_corpus"] = resolved
    if resolved:
        assert cluster is not None and cluster.node_offsets is not None
        start = cluster.node_offsets[node_index]
        end = (
            cluster.node_offsets[node_index + 1]
            if node_index + 1 < cluster.node_count
            else len(cluster.topology)
        )
        edge_ids, local_count, external_count = _node_adjacencies(
            cluster, node_index, adjacency_offset
        )
        result.update(
            {
                "record_decoded_offset": start,
                "record_size": end - start,
                "record_hex": cluster.topology[start:end].hex(),
                "adjacent_edge_ids": edge_ids,
                "local_adjacent_edge_count": local_count,
                "external_adjacent_edge_count": external_count,
            }
        )
    return result


def _iter_samples(
    clusters: list[Cluster],
    by_id: dict[int, Cluster],
    edge_stride: int,
    adjacency_offset: int,
    limit: int,
) -> Iterator[dict[str, object]]:
    emitted = 0
    for cluster in clusters:
        assert cluster.geometry_offsets is not None
        bbox = list(struct.unpack_from("<4i", cluster.geometry))
        min_lon, min_lat = _mercator_to_wgs84(bbox[0], bbox[1])
        max_lon, max_lat = _mercator_to_wgs84(bbox[2], bbox[3])
        geometry_ends = cluster.geometry_offsets[1:] + [len(cluster.geometry)]
        for edge_index, (geometry_start, geometry_end) in enumerate(
            zip(cluster.geometry_offsets, geometry_ends)
        ):
            edge_id = (cluster.cluster_id << 8) | edge_index
            endpoint_a, endpoint_b = _edge_endpoints(
                cluster, edge_id, edge_index, edge_stride
            )
            descriptor_start = cluster.edge_descriptor_base + edge_index * edge_stride
            geometry_record = cluster.geometry[geometry_start:geometry_end]
            yield {
                "schema_version": SCHEMA_VERSION,
                "record_type": "basic-edge-source",
                "cluster_id": cluster.cluster_id,
                "edge_index": edge_index,
                "edge_id": edge_id,
                "edge_id_hex": f"0x{edge_id:08x}",
                "bbox_mercator": bbox,
                "bbox_wgs84": [min_lon, min_lat, max_lon, max_lat],
                "descriptor_decoded_offset": descriptor_start,
                "descriptor_size": edge_stride,
                "descriptor_hex": cluster.topology[
                    descriptor_start : descriptor_start + edge_stride
                ].hex(),
                "node_a": _node_summary(endpoint_a, by_id, adjacency_offset),
                "node_b": _node_summary(endpoint_b, by_id, adjacency_offset),
                "geometry_record_decoded_offset": geometry_start,
                "geometry_record_size": len(geometry_record),
                "geometry_record_sha256": hashlib.sha256(geometry_record).hexdigest(),
                "geometry_record_hex": geometry_record.hex(),
                "provenance": {
                    "index_kind": "basic-id-triple",
                    "index_record_offset": cluster.topology_entry["index_entry_offset"],
                    "topology_handle": {
                        "handle_index": 0,
                        "compressed_offset": cluster.topology_entry["compressed_offset"],
                        "compressed_size": cluster.topology_entry["compressed_size"],
                    },
                    "geometry_handle": {
                        "handle_index": 1,
                        "compressed_offset": cluster.geometry_entry["compressed_offset"],
                        "compressed_size": cluster.geometry_entry["compressed_size"],
                    },
                },
            }
            emitted += 1
            if limit and emitted >= limit:
                return


def _write_json_atomic(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _write_jsonl_atomic(path: Path, records: Iterator[dict[str, object]]) -> int:
    temporary = path.with_suffix(path.suffix + ".tmp")
    count = 0
    with temporary.open("w", encoding="utf-8") as destination:
        for record in records:
            destination.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    temporary.replace(path)
    return count


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    grouped: dict[int, dict[int, dict[str, object]]] = {}
    cluster_order: list[int] = []
    for entry in index["entries"]:  # type: ignore[union-attr]
        cluster_id = int(entry["cluster_id"])
        handle_index = int(entry["handle_index"])
        if cluster_id not in grouped:
            grouped[cluster_id] = {}
            cluster_order.append(cluster_id)
        if handle_index in grouped[cluster_id]:
            raise PsfError(f"duplicate handle {handle_index} for Basic cluster {cluster_id}")
        grouped[cluster_id][handle_index] = entry
    if any(set(handles) != {0, 1, 2} for handles in grouped.values()):
        raise PsfError("Basic triple index does not contain exactly three handles per cluster")

    clusters: list[Cluster] = []
    _progress("decode", clusters_total=len(cluster_order))
    with psf.open("rb") as source:
        for ordinal, cluster_id in enumerate(cluster_order, 1):
            handles = grouped[cluster_id]
            topology = _decode_indexed_lzma(source, handles[0])
            geometry = _decode_indexed_lzma(source, handles[1])
            clusters.append(
                Cluster(
                    cluster_id=cluster_id,
                    topology_entry=handles[0],
                    geometry_entry=handles[1],
                    topology=topology,
                    geometry=geometry,
                )
            )
            if ordinal % 250 == 0 or ordinal == len(cluster_order):
                _progress("decode-progress", clusters=ordinal, total=len(cluster_order))
    by_id = {cluster.cluster_id: cluster for cluster in clusters}

    _progress("infer-topology-layout")
    topology_base, topology_base_passes = _infer_table_base(
        clusters,
        TOPOLOGY_BASE_CANDIDATES,
        lambda item: item.topology,
        topology_node_offsets,
        "topology node-offset table base",
    )
    for cluster in clusters:
        offsets, required_end = topology_node_offsets(cluster.topology, topology_base)
        if not _strict_record_offsets(offsets, required_end, len(cluster.topology)):
            raise PsfError(f"invalid node record offsets in cluster {cluster.cluster_id}")
        cluster.node_offsets = offsets
    edge_stride, edge_stride_scores = _infer_edge_stride(clusters)
    adjacency_offset, adjacency_scores = _infer_adjacency_offset(clusters, by_id)

    _progress("infer-geometry-layout")
    geometry_base, geometry_base_passes = _infer_table_base(
        clusters,
        GEOMETRY_BASE_CANDIDATES,
        lambda item: item.geometry,
        geometry_record_offsets,
        "geometry record-offset table base",
    )
    for cluster in clusters:
        offsets, required_end = geometry_record_offsets(cluster.geometry, geometry_base)
        if not _strict_record_offsets(offsets, required_end, len(cluster.geometry)):
            raise PsfError(f"invalid geometry record offsets in cluster {cluster.cluster_id}")
        cluster.geometry_offsets = offsets

    _progress("validate", clusters_total=len(clusters))
    bbox_mismatches: list[dict[str, object]] = []
    count_mismatches: list[dict[str, object]] = []
    endpoint_counts = collections.Counter()
    endpoint_outside_main = 0
    adjacency_counts = collections.Counter()
    adjacency_outside_main = 0
    adjacency_endpoint_mismatches: list[dict[str, object]] = []
    seen_incidence = {
        cluster.cluster_id: bytearray(cluster.edge_count) for cluster in clusters
    }
    topology_flags = collections.Counter(
        "compressed" if struct.unpack_from("<H", cluster.topology)[0] & 0x8000 else "direct"
        for cluster in clusters
    )
    geometry_flags = collections.Counter(cluster.geometry[20] for cluster in clusters)

    for ordinal, cluster in enumerate(clusters, 1):
        expected_bbox = list(cluster.geometry_entry["bbox_fields"])
        expected_payload_bbox = [
            expected_bbox[0],
            expected_bbox[3],
            expected_bbox[2],
            expected_bbox[1],
        ]
        payload_bbox = list(struct.unpack_from("<4i", cluster.geometry))
        if payload_bbox != expected_payload_bbox:
            bbox_mismatches.append(
                {
                    "cluster_id": cluster.cluster_id,
                    "payload": payload_bbox,
                    "expected": expected_payload_bbox,
                }
            )
        if cluster.geometry[23] != cluster.edge_count:
            count_mismatches.append(
                {
                    "cluster_id": cluster.cluster_id,
                    "topology_edge_count": cluster.edge_count,
                    "geometry_record_count": cluster.geometry[23],
                }
            )

        for edge_index in range(cluster.edge_count):
            edge_id = (cluster.cluster_id << 8) | edge_index
            endpoints = _edge_endpoints(cluster, edge_id, edge_index, edge_stride)
            for endpoint in endpoints:
                endpoint_counts[str(endpoint["encoding"])] += 1
                node_id = int(endpoint["node_id"])
                target = by_id.get(node_id >> 8)
                if target is None or (node_id & 0xFF) >= target.node_count:
                    endpoint_outside_main += 1

        assert cluster.node_offsets is not None
        for node_index in range(cluster.node_count):
            node_id = (cluster.cluster_id << 8) | node_index
            edge_ids, local_count, external_count = _node_adjacencies(
                cluster, node_index, adjacency_offset
            )
            adjacency_counts["local-u8"] += local_count
            adjacency_counts["external-u32"] += external_count
            for edge_id in edge_ids:
                target = by_id.get(_edge_cluster_id(edge_id))
                edge_index = edge_id & 0xFF
                if target is None or edge_index >= target.edge_count:
                    adjacency_outside_main += 1
                    continue
                endpoint_a, endpoint_b = _edge_endpoints(
                    target, edge_id, edge_index, edge_stride
                )
                bit = 0
                if node_id == int(endpoint_a["node_id"]):
                    bit |= 1
                if node_id == int(endpoint_b["node_id"]):
                    bit |= 2
                if not bit:
                    if len(adjacency_endpoint_mismatches) < 100:
                        adjacency_endpoint_mismatches.append(
                            {
                                "node_id": node_id,
                                "edge_id": edge_id,
                                "edge_node_a": endpoint_a["node_id"],
                                "edge_node_b": endpoint_b["node_id"],
                            }
                        )
                else:
                    seen_incidence[target.cluster_id][edge_index] |= bit
        if ordinal % 500 == 0 or ordinal == len(clusters):
            _progress("validate-progress", clusters=ordinal, total=len(clusters))

    missing_incidences = 0
    missing_incidence_examples: list[dict[str, object]] = []
    for cluster in clusters:
        for edge_index in range(cluster.edge_count):
            edge_id = (cluster.cluster_id << 8) | edge_index
            endpoint_a, endpoint_b = _edge_endpoints(cluster, edge_id, edge_index, edge_stride)
            expected = 0
            for bit, endpoint in ((1, endpoint_a), (2, endpoint_b)):
                node_id = int(endpoint["node_id"])
                target = by_id.get(node_id >> 8)
                if target is not None and (node_id & 0xFF) < target.node_count:
                    expected |= bit
            missing = expected & ~seen_incidence[cluster.cluster_id][edge_index]
            if missing:
                missing_incidences += missing.bit_count()
                if len(missing_incidence_examples) < 100:
                    missing_incidence_examples.append(
                        {
                            "edge_id": edge_id,
                            "expected_mask": expected,
                            "seen_mask": seen_incidence[cluster.cluster_id][edge_index],
                            "missing_mask": missing,
                        }
                    )

    total_edges = sum(cluster.edge_count for cluster in clusters)
    total_nodes = sum(cluster.node_count for cluster in clusters)
    validation_ok = not (
        bbox_mismatches
        or count_mismatches
        or adjacency_endpoint_mismatches
        or missing_incidences
    )
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated" if validation_ok else "validation-failed",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256_path(psf),
        },
        "scope": {
            "index_kind": "basic-id-triple",
            "handles_decoded": [0, 1],
            "handle_0_role": "routing topology: fixed edge descriptors plus variable node records",
            "handle_1_role": "one variable geometry record per fixed edge descriptor",
            "handle_2_role": "names/attributes (not decoded by this stage)",
            "limitations": [
                "this topology probe keeps geometry bodies raw; basic_geometry_decode.py and basic_graph_export.py provide normalized coordinates",
                "references outside the main 3,336-record triple-handle corpus are retained unresolved",
                "endpoint labels a/b preserve firmware slot order; travel direction semantics are not asserted",
            ],
        },
        "inferred_layout": {
            "topology_node_offset_table_base": topology_base,
            "topology_node_offset_table_base_pass_counts": topology_base_passes,
            "topology_offset_encoding": "u16 every 4 nodes plus three u8 deltas; high bit of header u16 selects compact form",
            "edge_descriptor_stride": edge_stride,
            "edge_descriptor_stride_scores": edge_stride_scores,
            "node_adjacency_offset": adjacency_offset,
            "node_adjacency_offset_scores": adjacency_scores,
            "geometry_record_offset_table_base": geometry_base,
            "geometry_record_offset_table_base_pass_counts": geometry_base_passes,
            "geometry_offset_encoding": "direct u16 or u16 every 8 edges plus seven u8 deltas, selected by header byte 20 bit 1",
        },
        "counts": {
            "clusters": len(clusters),
            "edges": total_edges,
            "nodes": total_nodes,
            "geometry_records": sum(len(cluster.geometry_offsets or []) for cluster in clusters),
            "topology_offset_modes": dict(topology_flags),
            "geometry_header_byte20_values": {
                str(key): value for key, value in sorted(geometry_flags.items())
            },
            "endpoint_encodings": dict(endpoint_counts),
            "endpoint_references_outside_main_corpus": endpoint_outside_main,
            "node_adjacency_encodings": dict(adjacency_counts),
            "adjacent_edge_references_outside_main_corpus": adjacency_outside_main,
        },
        "validation": {
            "all_geometry_bboxes_match_index": not bbox_mismatches,
            "bbox_mismatch_count": len(bbox_mismatches),
            "bbox_mismatch_examples": bbox_mismatches[:100],
            "all_geometry_counts_match_topology_edges": not count_mismatches,
            "count_mismatch_count": len(count_mismatches),
            "count_mismatch_examples": count_mismatches[:100],
            "resolved_node_adjacencies_match_edge_endpoints": not adjacency_endpoint_mismatches,
            "adjacency_endpoint_mismatch_count": len(adjacency_endpoint_mismatches),
            "adjacency_endpoint_mismatch_examples": adjacency_endpoint_mismatches,
            "resolved_edge_endpoints_have_reverse_node_adjacency": missing_incidences == 0,
            "missing_reverse_incidence_count": missing_incidences,
            "missing_reverse_incidence_examples": missing_incidence_examples,
        },
        "evidence": {
            "firmware_image": "MHI2_ER_AU57x_K3663_1_MU1425_AIO",
            "firmware_library": "navigation/libPathfinderApp.so",
            "firmware_functions_ghidra_va": {
                "node_record_accessor": "0x0154f730",
                "edge_descriptor_accessor": "0x0154f8c4",
                "external_node_id_accessor": "0x0154f7f0",
                "node_adjacency_reader": "0x01550354",
            },
            "ghidra_image_base_slide": "+0x10000",
        },
    }

    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "edge_sample.jsonl"
    _progress("write-sample", limit=sample_limit)
    sample_count = _write_jsonl_atomic(
        sample_path,
        _iter_samples(clusters, by_id, edge_stride, adjacency_offset, sample_limit),
    )
    report["artifacts"] = {
        "report": "report.json",
        "edge_sample": sample_path.name,
        "edge_sample_count": sample_count,
        "checksums": "CHECKSUMS.sha256",
    }
    report_path = output / "report.json"
    _write_json_atomic(report_path, report)
    checksum_targets = (report_path, sample_path)
    checksums_path = output / "CHECKSUMS.sha256"
    checksums_path.write_text(
        "".join(f"{_sha256_path(path)}  {path.name}\n" for path in checksum_targets),
        encoding="ascii",
    )
    _progress("complete", status=report["status"], output=output)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Infer and globally validate Basic node/edge/geometry record boundaries"
    )
    parser.add_argument("psf", type=Path, help="Basic.psf input")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=100,
        help="edge source records to emit; 0 emits every edge",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.psf, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_semantic_probe: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "clusters": report["counts"]["clusters"],  # type: ignore[index]
                "edges": report["counts"]["edges"],  # type: ignore[index]
                "nodes": report["counts"]["nodes"],  # type: ignore[index]
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Export a validated MIB Basic routing graph for the Orion/ATLAS adapter.

The command decodes every cluster, node, edge, geometry part and direct
handle-2 name candidate before it writes a bounded source sample.  Use
``--sample-limit 0`` to stream the full 717k-node / 838k-edge graph.  Semantic
attributes that are not yet decoded remain attached as raw provenance fields.
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

from basic_geometry_decode import (
    DecodedPart,
    EDGE_DESCRIPTOR_STRIDE,
    GeometryCluster,
    Point,
    _build_cluster,
    _group_entries,
    coordinate_table_entry,
    decode_geometry_record,
)
from basic_dynamic_attributes import (
    DynamicAttributeDirectory,
    DynamicType3EdgeRecord,
    DynamicType5EdgeRecord,
    decode_dynamic_attribute_directory,
    decode_type3_edge_records,
    decode_type5_edge_records,
    decode_time_condition,
)
from basic_road_attributes import (
    GeometryAttributeType,
    TaggedAttribute,
    decode_automotive_attributes,
    decode_extended_passing_restriction_header,
    decode_extended_speed_limit,
    decode_geometry_attribute_stream,
    decode_lanes,
    decode_number_of_lanes,
    decode_simple_passing_restriction,
    decode_simple_speed_limit,
    decode_tagged_attributes,
    decode_travel_direction,
    decode_urban_road,
)
from basic_handle2_directory import (
    EdgeDirectory,
    decode_edge_directory,
    decode_record_data_end,
)
from basic_handle2_text_decode import (
    TextEntry,
    decode_direct_texts,
    schema_from_payload,
)
from basic_name_semantics import (
    LogicalName,
    LANGUAGE_LABELS,
    group_logical_names,
    nonempty,
    select_display_name,
)
from basic_semantic_probe import EDGE_CLUSTER_MASK, topology_node_offsets
from psf_decode import (
    PsfError,
    _decode_indexed_lzma,
    _mercator_to_wgs84,
    read_basic_triple_handle_index,
)


SCHEMA_VERSION = 7
NODE_OFFSET_TABLE_BASE = 15
NODE_ADJACENCY_OFFSET = 2


@dataclass(frozen=True)
class GraphCluster:
    geometry: GeometryCluster
    node_offsets: tuple[int, ...]
    semantic_payload: bytes
    semantic_directory: EdgeDirectory
    semantic_record_ends: dict[int, int]
    semantic_texts: dict[int, tuple[TextEntry, ...]]
    dynamic_directory: DynamicAttributeDirectory | None
    dynamic_type5_by_edge: dict[int, DynamicType5EdgeRecord]
    dynamic_type3_by_edge: dict[int, tuple[DynamicType3EdgeRecord, ...]]


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"basic-graph stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_clusters(psf: Path) -> list[GraphCluster]:
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    result: list[GraphCluster] = []
    with psf.open("rb") as source:
        for ordinal, cluster_id in enumerate(order, 1):
            handles = grouped[cluster_id]
            topology = _decode_indexed_lzma(source, handles[0])
            geometry = _decode_indexed_lzma(source, handles[1])
            semantic_payload = _decode_indexed_lzma(source, handles[2])
            decoded = _build_cluster(cluster_id, topology, geometry)
            offsets, required_end = topology_node_offsets(
                topology, NODE_OFFSET_TABLE_BASE
            )
            if (
                len(offsets) != decoded.node_count
                or offsets != sorted(set(offsets))
                or not offsets
                or offsets[0] < required_end
                or offsets[-1] >= len(topology)
            ):
                raise PsfError(f"cluster {cluster_id} invalid node record offsets")
            semantic_directory = decode_edge_directory(
                semantic_payload, decoded.edge_count
            )
            semantic_record_data_end = decode_record_data_end(
                semantic_payload, semantic_directory.directory_end
            )
            semantic_offsets = sorted(set(semantic_directory.record_offsets))
            semantic_record_ends = {
                record_offset: (
                    semantic_offsets[index + 1]
                    if index + 1 < len(semantic_offsets)
                    else semantic_record_data_end
                )
                for index, record_offset in enumerate(semantic_offsets)
            }
            semantic_schema = schema_from_payload(semantic_payload)
            semantic_texts = {
                record_offset: decode_direct_texts(
                    semantic_payload,
                    record_offset,
                    semantic_record_ends[record_offset],
                    semantic_schema,
                )
                for record_offset in semantic_offsets
            }
            dynamic_directory = decode_dynamic_attribute_directory(topology)
            dynamic_type5_by_edge: dict[int, DynamicType5EdgeRecord] = {}
            dynamic_type3_by_edge: dict[int, tuple[DynamicType3EdgeRecord, ...]] = {}
            if dynamic_directory is not None:
                type3 = dynamic_directory.get(3)
                if type3 is not None:
                    type3_records = decode_type3_edge_records(type3)
                    grouped_type3: dict[int, list[DynamicType3EdgeRecord]] = collections.defaultdict(list)
                    for record in type3_records:
                        if record.edge_index >= decoded.edge_count:
                            raise PsfError(f"cluster {cluster_id} dynamic type-3 edge key outside cluster")
                        grouped_type3[record.edge_index].append(record)
                    dynamic_type3_by_edge = {
                        edge: tuple(records) for edge, records in grouped_type3.items()
                    }
                type5 = dynamic_directory.get(5)
                if type5 is not None:
                    records = decode_type5_edge_records(type5)
                    dynamic_type5_by_edge = {record.edge_index: record for record in records}
                    if len(dynamic_type5_by_edge) != len(records):
                        raise PsfError(f"cluster {cluster_id} duplicate dynamic type-5 edge key")
                    if any(edge >= decoded.edge_count for edge in dynamic_type5_by_edge):
                        raise PsfError(f"cluster {cluster_id} dynamic type-5 edge key outside cluster")
            result.append(
                GraphCluster(
                    decoded,
                    tuple(offsets),
                    semantic_payload,
                    semantic_directory,
                    semantic_record_ends,
                    semantic_texts,
                    dynamic_directory,
                    dynamic_type5_by_edge,
                    dynamic_type3_by_edge,
                )
            )
            if ordinal % 250 == 0 or ordinal == len(order):
                _progress("load-progress", clusters=ordinal, total=len(order))
    return result


def _edge_endpoints(
    cluster: GraphCluster, edge_index: int
) -> tuple[dict[str, object], dict[str, object]]:
    geometry = cluster.geometry
    descriptor_at = geometry.edge_descriptor_base + edge_index * EDGE_DESCRIPTOR_STRIDE
    descriptor = geometry.topology[
        descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE
    ]
    if len(descriptor) != EDGE_DESCRIPTOR_STRIDE:
        raise PsfError(f"cluster {geometry.cluster_id} truncated edge descriptor")
    descriptor_end = geometry.edge_descriptor_base + geometry.edge_count * EDGE_DESCRIPTOR_STRIDE
    external_base = descriptor_end + (descriptor_end & 1)
    external_capacity = (cluster.node_offsets[0] - external_base) // 4
    endpoints: list[dict[str, object]] = []
    for label, slot, mask in (("a", 5, 0x40), ("b", 6, 0x80)):
        encoded = descriptor[slot]
        if descriptor[4] & mask:
            if encoded >= external_capacity:
                raise PsfError(
                    f"cluster {geometry.cluster_id} external node index {encoded} "
                    f"outside capacity {external_capacity}"
                )
            node_id = struct.unpack_from(
                "<I", geometry.topology, external_base + encoded * 4
            )[0]
            encoding = "external-u32-table"
        else:
            node_id = (geometry.cluster_id << 8) | encoded
            encoding = "local-u8"
        endpoints.append(
            {
                "slot": label,
                "node_id": node_id,
                "node_id_hex": f"0x{node_id:08x}",
                "encoding": encoding,
                "encoded_value": encoded,
            }
        )
    return endpoints[0], endpoints[1]


def _node_record(
    cluster: GraphCluster, node_index: int
) -> tuple[list[int], int, int, bytes, bytes]:
    geometry = cluster.geometry
    start = cluster.node_offsets[node_index]
    end = (
        cluster.node_offsets[node_index + 1]
        if node_index + 1 < geometry.node_count
        else len(geometry.topology)
    )
    marker = geometry.topology[start]
    local_count = marker >> 4
    external_count = marker & 0x0F
    cursor = start + NODE_ADJACENCY_OFFSET
    required = cursor + local_count + external_count * 4
    if required > end:
        raise PsfError(
            f"cluster {geometry.cluster_id} node {node_index} adjacency overruns record"
        )
    edge_ids = [
        (geometry.cluster_id << 8) | value
        for value in geometry.topology[cursor : cursor + local_count]
    ]
    cursor += local_count
    for _ in range(external_count):
        edge_ids.append(struct.unpack_from("<I", geometry.topology, cursor)[0])
        cursor += 4
    return (
        edge_ids,
        local_count,
        external_count,
        geometry.topology[cursor:end],
        geometry.topology[start:end],
    )


def _point_fields(point: Point) -> dict[str, object]:
    longitude, latitude = _mercator_to_wgs84(point.x, point.y)
    return {
        "mercator": point.as_list(),
        "wgs84": [longitude, latitude],
    }


def _part_tagged_attributes(part: DecodedPart) -> tuple[TaggedAttribute, ...]:
    if not part.extension:
        return ()
    stream = decode_geometry_attribute_stream(part.extension, part.flags)
    return decode_tagged_attributes(stream)


def _time_condition_fields(raw: bytes) -> dict[str, object]:
    condition = decode_time_condition(raw)
    return {
        "flags": condition.flags,
        "year_range": list(condition.year_range) if condition.year_range else None,
        "month_range": list(condition.month_range) if condition.month_range else None,
        "month_mask": condition.month_mask,
        "months": (
            [month for month in range(1, 13) if condition.month_mask & (1 << (month - 1))]
            if condition.month_mask is not None
            else None
        ),
        "day_of_month_range": (
            list(condition.day_of_month_range) if condition.day_of_month_range else None
        ),
        "day_of_month_mask": condition.day_of_month_mask,
        "days_of_month": (
            [day for day in range(1, 32) if condition.day_of_month_mask & (1 << (day - 1))]
            if condition.day_of_month_mask is not None
            else None
        ),
        "weekday_mask": condition.weekday_mask,
        "start_time_slot_15m": condition.start_time_slot_15m,
        "end_time_slot_15m": condition.end_time_slot_15m,
        "start_time": condition.start_time,
        "end_time": condition.end_time,
        "raw_hex": condition.raw.hex(),
    }


def _part_road_attribute_fields(part: DecodedPart) -> dict[str, object]:
    attributes = _part_tagged_attributes(part)
    speed_limits = [
        decode_simple_speed_limit(attribute).value
        for attribute in attributes
        if attribute.type_id == 1
    ]
    extended_speed_limits = [
        decode_extended_speed_limit(attribute)
        for attribute in attributes
        if attribute.type_id == GeometryAttributeType.EXTENDED_SPEED_LIMIT
    ]
    lane_counts = [
        decode_number_of_lanes(attribute)
        for attribute in attributes
        if attribute.type_id == GeometryAttributeType.NUMBER_OF_LANES
    ]
    simple_passing_restriction = any(
        attribute.type_id == GeometryAttributeType.SIMPLE_PASSING_RESTRICTION
        for attribute in attributes
    )
    if simple_passing_restriction:
        for attribute in attributes:
            if attribute.type_id == GeometryAttributeType.SIMPLE_PASSING_RESTRICTION:
                decode_simple_passing_restriction(attribute)
    extended_passing = [
        decode_extended_passing_restriction_header(attribute)
        for attribute in attributes
        if attribute.type_id == GeometryAttributeType.EXTENDED_PASSING_RESTRICTION
    ]
    lanes = [
        (decode_lanes(attribute), attribute)
        for attribute in attributes
        if attribute.type_id == GeometryAttributeType.LANES
    ]
    return {
        "tagged_attributes": [
            {
                "type_id": attribute.type_id,
                "type": GeometryAttributeType(attribute.type_id).name.lower(),
                "has_next": attribute.has_next,
                "offset": attribute.offset,
                "data_hex": attribute.data.hex(),
            }
            for attribute in attributes
        ],
        "simple_speed_limits": [
            {
                "value": value,
                "unit": None,
                "unit_status": "not independently proven",
            }
            for value in speed_limits
        ],
        "extended_speed_limits": [
            {
                "a_to_b": value.a_to_b,
                "b_to_a": value.b_to_a,
                "subtype": value.subtype,
                "subtype_name": "SLT_GENERAL" if value.subtype == 0 else None,
                "value": value.value,
                "unit": None,
                "unit_status": "not independently proven",
                "base_condition": value.base_condition,
                "condition_pairs": [list(pair) for pair in value.condition_pairs],
                "source_selector": value.source_selector,
                "raw_hex": attribute.data.hex(),
            }
            for value, attribute in zip(
                extended_speed_limits,
                (
                    attribute
                    for attribute in attributes
                    if attribute.type_id == GeometryAttributeType.EXTENDED_SPEED_LIMIT
                ),
            )
        ],
        "number_of_lanes": [
            {
                "at_node_a": value.at_node_a,
                "at_node_b": value.at_node_b,
            }
            for value in lane_counts
        ],
        "simple_passing_restriction": simple_passing_restriction,
        "extended_passing_restrictions": [
            {
                "a_to_b": value.a_to_b,
                "b_to_a": value.b_to_a,
                "has_detailed_records": value.has_detailed_records,
                "detailed_record_count": value.detailed_record_count,
                "raw_hex": attribute.data.hex(),
            }
            for value, attribute in zip(
                extended_passing,
                (
                    attribute
                    for attribute in attributes
                    if attribute.type_id
                    == GeometryAttributeType.EXTENDED_PASSING_RESTRICTION
                ),
            )
        ],
        "lanes": [
            {
                "record_count": len(value.records),
                "header_low_nibble": value.header_low_nibble,
                "records_hex": [record.raw.hex() for record in value.records],
                "records": [
                    {
                        "raw_hex": record.raw.hex(),
                        "byte_0_low_nibble": record.byte_0_low_nibble,
                        "byte_0_bit_4": record.byte_0_bit_4,
                        "byte_0_bit_5": record.byte_0_bit_5,
                        "byte_0_high_2_bits": record.byte_0_high_2_bits,
                        "byte_1_low_nibble_code": record.byte_1_low_nibble_code,
                        "byte_1_high_nibble": record.byte_1_high_nibble,
                        "byte_2_high_nibble_code": record.byte_2_high_nibble_code,
                        "byte_2_low_nibble": record.byte_2_low_nibble,
                        "byte_3_low_3_bits_code": record.byte_3_low_3_bits_code,
                        "byte_3_high_5_bits": record.byte_3_high_5_bits,
                        "firmware_category_mask": record.firmware_category_mask,
                    }
                    for record in value.records
                ],
                "record_semantics": (
                    "consumed bit fields and direct category switch from firmware "
                    "VA 0x0097f054; public enum names remain unassigned"
                ),
                "raw_hex": attribute.data.hex(),
            }
            for value, attribute in lanes
        ],
    }


def _name_candidate_fields(entry: TextEntry) -> dict[str, object]:
    return {
        "identifier": entry.identifier,
        "language": LANGUAGE_LABELS.get(entry.identifier),
        "alternate": entry.alternate,
        "variant": "transliteration" if entry.alternate else "base",
        "values": list(entry.primary),
        "secondary_identifier": entry.secondary_identifier,
        "phonetics": list(entry.secondary),
        "nonempty_phonetics": list(nonempty(entry.secondary)),
    }


def _logical_name_fields(
    name: LogicalName, transliterate_identifiers: frozenset[int]
) -> dict[str, object]:
    selection = select_display_name(name, transliterate_identifiers)
    return {
        "identifier": name.identifier,
        "language": name.language,
        "physical_entry_indices": {
            "base": name.base_index,
            "transliteration": name.transliteration_index,
        },
        "base": _name_candidate_fields(name.base),
        "transliteration": (
            _name_candidate_fields(name.transliteration)
            if name.transliteration is not None
            else None
        ),
        "display_selection": {
            "status": selection.status,
            "source": selection.source,
            "values": list(selection.entry.primary) if selection.entry else [],
            "phonetics": (
                list(nonempty(selection.entry.secondary)) if selection.entry else []
            ),
        },
    }


def _node_item(cluster: GraphCluster, node_index: int) -> dict[str, object]:
    geometry = cluster.geometry
    node_id = (geometry.cluster_id << 8) | node_index
    point, coordinate_marker, encoded = coordinate_table_entry(geometry, node_index)
    edge_ids, local_count, external_count, trailing, record = _node_record(
        cluster, node_index
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "mib-basic-routing-node",
        "cluster_id": geometry.cluster_id,
        "node_index": node_index,
        "node_id": node_id,
        "node_id_hex": f"0x{node_id:08x}",
        "coordinate": _point_fields(point),
        "encoded_coordinate": list(encoded),
        "coordinate_marker": coordinate_marker,
        "adjacent_edge_ids": edge_ids,
        "local_adjacent_edge_count": local_count,
        "external_adjacent_edge_count": external_count,
        "trailing_attributes_hex": trailing.hex(),
        "source_record_hex": record.hex(),
    }


def _edge_item(
    cluster: GraphCluster,
    edge_index: int,
    endpoint_a: dict[str, object],
    endpoint_b: dict[str, object],
    transliterate_identifiers: frozenset[int],
) -> dict[str, object]:
    geometry = cluster.geometry
    edge_id = (geometry.cluster_id << 8) | edge_index
    descriptor_at = geometry.edge_descriptor_base + edge_index * EDGE_DESCRIPTOR_STRIDE
    descriptor = geometry.topology[
        descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE
    ]
    record_start = geometry.geometry_offsets[edge_index]
    record_end = (
        geometry.geometry_offsets[edge_index + 1]
        if edge_index + 1 < geometry.edge_count
        else len(geometry.geometry)
    )
    record = geometry.geometry[record_start:record_end]
    parts = decode_geometry_record(geometry, edge_index)
    first_part = parts[0].offset if parts else len(record)
    centerline: list[Point] = []
    for part in parts:
        if centerline and centerline[-1] == part.points[0]:
            centerline.extend(part.points[1:])
        else:
            centerline.extend(part.points)
    semantic_record_offset = cluster.semantic_directory.record_offsets[edge_index]
    semantic_record_end = cluster.semantic_record_ends[semantic_record_offset]
    semantic_texts = cluster.semantic_texts[semantic_record_offset]
    logical_names = group_logical_names(semantic_texts)
    direction = decode_travel_direction(descriptor)
    automotive = decode_automotive_attributes(descriptor)
    is_urban = decode_urban_road(part.secondary_flags for part in parts)
    dynamic_type5 = cluster.dynamic_type5_by_edge.get(edge_index)
    dynamic_type3 = cluster.dynamic_type3_by_edge.get(edge_index, ())
    part_attribute_fields = [_part_road_attribute_fields(part) for part in parts]
    speed_limit_candidates = [
        {
            "part_index": part.index,
            **speed_limit,
        }
        for part, fields in zip(parts, part_attribute_fields)
        for speed_limit in fields["simple_speed_limits"]  # type: ignore[union-attr]
    ]
    extended_speed_limit_candidates = [
        {"part_index": part.index, **speed_limit}
        for part, fields in zip(parts, part_attribute_fields)
        for speed_limit in fields["extended_speed_limits"]  # type: ignore[union-attr]
    ]
    number_of_lanes_candidates = [
        {"part_index": part.index, **lane_count}
        for part, fields in zip(parts, part_attribute_fields)
        for lane_count in fields["number_of_lanes"]  # type: ignore[union-attr]
    ]
    simple_passing_part_indices = [
        part.index
        for part, fields in zip(parts, part_attribute_fields)
        if fields["simple_passing_restriction"]
    ]
    extended_passing_restrictions = [
        {"part_index": part.index, **restriction}
        for part, fields in zip(parts, part_attribute_fields)
        for restriction in fields["extended_passing_restrictions"]  # type: ignore[union-attr]
    ]
    lanes_candidates = [
        {"part_index": part.index, **lanes}
        for part, fields in zip(parts, part_attribute_fields)
        for lanes in fields["lanes"]  # type: ignore[union-attr]
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "mib-basic-routing-edge",
        "cluster_id": geometry.cluster_id,
        "edge_index": edge_index,
        "edge_id": edge_id,
        "edge_id_hex": f"0x{edge_id:08x}",
        "from": endpoint_a,
        "to": endpoint_b,
        "descriptor_hex": descriptor.hex(),
        "geometry_record_header_hex": record[:first_part].hex(),
        "centerline_points": [_point_fields(point) for point in centerline],
        "road_attributes": {
            "urban": {
                "value": is_urban,
                "source": "OR of geometry_parts[].secondary_flags bit 5 (0x20)",
                "firmware_decoder_ghidra_va": "0x002f0484",
                "firmware_consumer_ghidra_va": "0x013e5be8",
            },
            "static_travel_direction": {
                "a_to_b_allowed": direction.a_to_b_allowed,
                "b_to_a_allowed": direction.b_to_a_allowed,
                "mode": direction.mode,
                "endpoint_orientation": "A=from descriptor slot +5; B=to descriptor slot +6",
                "time_dependent_note": (
                    "extended restrictions may further restrict a statically allowed direction"
                ),
            },
            "extended_automotive_attributes": {
                "base_mask": automotive.base_mask,
                "base_mask_hex": f"0x{automotive.base_mask:04x}",
                "active_bit_indices": list(automotive.active_bit_indices),
                "has_dynamic_extension": automotive.has_dynamic_extension,
                "bit_meanings": "raw pending per-bit public enum proof",
            },
            "dynamic_topology_attributes": {
                "directory_present": cluster.dynamic_directory is not None,
                "directory_types": (
                    [entry.type_id for entry in cluster.dynamic_directory.entries]
                    if cluster.dynamic_directory is not None
                    else []
                ),
                "type_5_numeric_override": (
                    {
                        "value": dynamic_type5.value,
                        "caller_scaled_value_x100": dynamic_type5.value * 100,
                        "flag_low_bit": dynamic_type5.flag_low_bit,
                        "scale_by_16": dynamic_type5.scale_by_16,
                        "stored_low_16": dynamic_type5.stored_low_16,
                        "raw_hex": dynamic_type5.raw.hex(),
                        "semantic_status": (
                            "record/value expression firmware-confirmed; public field name and unit pending"
                        ),
                    }
                    if dynamic_type5 is not None
                    else None
                ),
                "type_3_time_condition_records": [
                    {
                        "selector_flags": record.selector_flags,
                        "a_to_b": record.a_to_b,
                        "b_to_a": record.b_to_a,
                        "selector_group": (record.selector_flags & 0x0C) >> 2,
                        "query_group_policy": "skip/evaluate/immediate bit triplet",
                        "time_zone_table_index": (record.selector_flags & 0x70) >> 4,
                        "condition_offset": record.condition_offset,
                        "condition": _time_condition_fields(record.condition),
                        "record_hex": record.raw.hex(),
                        "semantic_status": (
                            "edge direction selector and calendar/time fields firmware-confirmed"
                        ),
                    }
                    for record in dynamic_type3
                ],
                "time_vehicle_payload_status": (
                    "type-3 records and condition fields are edge-mapped; query-time evaluation "
                    "policy and type-7 vehicle restrictions remain pending"
                ),
            },
            "simple_speed_limit_candidates": speed_limit_candidates,
            "simple_speed_limit_edge_min_candidate": (
                min(item["value"] for item in speed_limit_candidates)
                if speed_limit_candidates
                else None
            ),
            "simple_speed_limit_edge_min_note": (
                "raw minimum only; firmware also applies a configured geometry-class mask"
            ),
            "extended_speed_limit_candidates": extended_speed_limit_candidates,
            "number_of_lanes_candidates": number_of_lanes_candidates,
            "simple_passing_restriction_part_indices": simple_passing_part_indices,
            "extended_passing_restrictions": extended_passing_restrictions,
            "lanes_candidates": lanes_candidates,
        },
        "geometry_parts": [
            {
                "part_index": part.index,
                "flags": part.flags,
                "secondary_flags": part.secondary_flags,
                "start_source": part.start_source,
                "end_source": part.end_source,
                "points": [_point_fields(point) for point in part.points],
                "extension_hex": part.extension.hex(),
                "road_attributes": attribute_fields,
            }
            for part, attribute_fields in zip(parts, part_attribute_fields)
        ],
        "name_candidates": [
            _name_candidate_fields(entry) for entry in semantic_texts
        ],
        "logical_names": [
            _logical_name_fields(name, transliterate_identifiers)
            for name in logical_names
        ],
        "semantic_record": {
            "offset": semantic_record_offset,
            "end": semantic_record_end,
            "flags": cluster.semantic_payload[semantic_record_offset],
            "auxiliary_selector": cluster.semantic_payload[
                semantic_record_offset + 1
            ],
        },
    }


def run(
    psf: Path,
    output: Path,
    sample_limit: int,
    transliterate_identifiers: frozenset[int] = frozenset(),
) -> dict[str, object]:
    _progress("load")
    clusters = _load_clusters(psf)
    by_cluster = {cluster.geometry.cluster_id: cluster for cluster in clusters}
    node_coordinates: dict[int, Point] = {}
    for cluster in clusters:
        geometry = cluster.geometry
        for node_index in range(geometry.node_count):
            point, _, _ = coordinate_table_entry(geometry, node_index)
            node_coordinates[(geometry.cluster_id << 8) | node_index] = point

    output.mkdir(parents=True, exist_ok=True)
    nodes_path = output / "nodes.jsonl"
    edges_path = output / "edges.jsonl"
    nodes_temporary = nodes_path.with_suffix(nodes_path.suffix + ".tmp")
    edges_temporary = edges_path.with_suffix(edges_path.suffix + ".tmp")

    counts = collections.Counter()
    for key in (
        "edge_display_selection_selected_references",
        "edge_display_selection_base_references",
        "edge_display_selection_transliteration_references",
        "edge_display_selection_missing-transliteration_references",
    ):
        counts[key] = 0
    counts["unique_semantic_records"] = sum(
        len(cluster.semantic_texts) for cluster in clusters
    )
    counts["unique_semantic_text_entries"] = sum(
        len(entries)
        for cluster in clusters
        for entries in cluster.semantic_texts.values()
    )
    counts["unique_semantic_primary_strings"] = sum(
        len(entry.primary)
        for cluster in clusters
        for entries in cluster.semantic_texts.values()
        for entry in entries
    )
    counts["unique_semantic_secondary_strings"] = sum(
        len(entry.secondary)
        for cluster in clusters
        for entries in cluster.semantic_texts.values()
        for entry in entries
    )
    unique_logical_names = [
        name
        for cluster in clusters
        for entries in cluster.semantic_texts.values()
        for name in group_logical_names(entries)
    ]
    counts["unique_semantic_logical_names"] = len(unique_logical_names)
    counts["unique_semantic_transliteration_pairs"] = sum(
        name.transliteration is not None for name in unique_logical_names
    )
    counts["clusters_with_dynamic_directory"] = sum(
        cluster.dynamic_directory is not None for cluster in clusters
    )
    counts["dynamic_directory_entries"] = sum(
        len(cluster.dynamic_directory.entries)
        for cluster in clusters
        if cluster.dynamic_directory is not None
    )
    counts["dynamic_type_5_records"] = sum(
        len(cluster.dynamic_type5_by_edge) for cluster in clusters
    )
    counts["dynamic_type_3_records"] = sum(
        len(records)
        for cluster in clusters
        for records in cluster.dynamic_type3_by_edge.values()
    )
    node_adjacency_mismatch_count = 0
    node_adjacency_mismatch_examples: list[dict[str, object]] = []
    geometry_outer_endpoint_mismatch_count = 0
    geometry_outer_endpoint_mismatch_examples: list[dict[str, object]] = []
    geometry_table_endpoint_mismatch_count = 0
    geometry_explicit_endpoint_difference_count = 0
    geometry_explicit_endpoint_max_component_delta = 0
    geometry_part_join_mismatch_count = 0
    geometry_part_join_mismatch_examples: list[dict[str, object]] = []
    nodes_emitted = 0
    edges_emitted = 0
    direction_modes = collections.Counter()
    simple_speed_limit_values = collections.Counter()
    number_of_lanes_pairs = collections.Counter()
    extended_passing_headers = collections.Counter()
    extended_speed_limit_values = collections.Counter()
    extended_speed_limit_subtypes = collections.Counter()
    lanes_record_counts = collections.Counter()
    lane_firmware_category_masks = collections.Counter()
    automotive_base_masks = collections.Counter()
    automotive_active_bits = collections.Counter()
    automotive_dynamic_extension = collections.Counter()

    _progress("validate-nodes", nodes=len(node_coordinates))
    with nodes_temporary.open("w", encoding="utf-8") as node_destination:
        for cluster_ordinal, cluster in enumerate(clusters, 1):
            geometry = cluster.geometry
            for node_index in range(geometry.node_count):
                node_id = (geometry.cluster_id << 8) | node_index
                edge_ids, local_count, external_count, _, _ = _node_record(
                    cluster, node_index
                )
                counts["nodes"] += 1
                counts["node_adjacency_references"] += len(edge_ids)
                counts["local_node_adjacency_references"] += local_count
                counts["external_node_adjacency_references"] += external_count
                for edge_id in edge_ids:
                    target = by_cluster.get((edge_id & EDGE_CLUSTER_MASK) >> 8)
                    target_edge_index = edge_id & 0xFF
                    if target is None or target_edge_index >= target.geometry.edge_count:
                        counts["node_adjacencies_outside_main_corpus"] += 1
                        continue
                    endpoint_a, endpoint_b = _edge_endpoints(target, target_edge_index)
                    if node_id not in (
                        int(endpoint_a["node_id"]),
                        int(endpoint_b["node_id"]),
                    ):
                        node_adjacency_mismatch_count += 1
                        if len(node_adjacency_mismatch_examples) < 100:
                            node_adjacency_mismatch_examples.append(
                                {
                                    "node_id": node_id,
                                    "edge_id": edge_id,
                                    "edge_node_a": endpoint_a["node_id"],
                                    "edge_node_b": endpoint_b["node_id"],
                                }
                            )
                if sample_limit == 0 or nodes_emitted < sample_limit:
                    node_destination.write(
                        json.dumps(
                            _node_item(cluster, node_index),
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    nodes_emitted += 1
            if cluster_ordinal % 500 == 0 or cluster_ordinal == len(clusters):
                _progress(
                    "node-progress",
                    clusters=cluster_ordinal,
                    total=len(clusters),
                    mismatches=node_adjacency_mismatch_count,
                )
    nodes_temporary.replace(nodes_path)

    _progress("validate-edges")
    with edges_temporary.open("w", encoding="utf-8") as edge_destination:
        for cluster in clusters:
            geometry = cluster.geometry
            for edge_index in range(geometry.edge_count):
                endpoint_a, endpoint_b = _edge_endpoints(cluster, edge_index)
                parts = decode_geometry_record(geometry, edge_index)
                descriptor_at = (
                    geometry.edge_descriptor_base
                    + edge_index * EDGE_DESCRIPTOR_STRIDE
                )
                descriptor = geometry.topology[
                    descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE
                ]
                direction_modes[decode_travel_direction(descriptor).mode] += 1
                automotive = decode_automotive_attributes(descriptor)
                automotive_base_masks[automotive.base_mask] += 1
                for bit_index in automotive.active_bit_indices:
                    automotive_active_bits[bit_index] += 1
                automotive_dynamic_extension[
                    automotive.has_dynamic_extension
                ] += 1
                counts["urban_edges"] += int(
                    decode_urban_road(part.secondary_flags for part in parts)
                )
                counts["edges_with_dynamic_type_5_record"] += int(
                    edge_index in cluster.dynamic_type5_by_edge
                )
                counts["edges_with_dynamic_type_3_record"] += int(
                    edge_index in cluster.dynamic_type3_by_edge
                )
                edge_simple_speed_limits: list[int] = []
                edge_has_extended_speed_limit = False
                edge_has_number_of_lanes = False
                edge_has_simple_passing = False
                edge_has_extended_passing = False
                edge_has_lanes = False
                for part in parts:
                    attributes = _part_tagged_attributes(part)
                    if attributes:
                        counts["geometry_parts_with_tagged_road_attributes"] += 1
                    for attribute in attributes:
                        counts["tagged_road_attributes"] += 1
                        if attribute.type_id == 1:
                            value = decode_simple_speed_limit(attribute).value
                            edge_simple_speed_limits.append(value)
                            simple_speed_limit_values[value] += 1
                            counts["simple_speed_limit_values"] += 1
                        elif attribute.type_id == GeometryAttributeType.EXTENDED_SPEED_LIMIT:
                            value = decode_extended_speed_limit(attribute)
                            edge_has_extended_speed_limit = True
                            extended_speed_limit_values[value.value] += 1
                            extended_speed_limit_subtypes[value.subtype] += 1
                            counts["extended_speed_limit_values"] += 1
                        elif attribute.type_id == GeometryAttributeType.NUMBER_OF_LANES:
                            lane_counts = decode_number_of_lanes(attribute)
                            edge_has_number_of_lanes = True
                            number_of_lanes_pairs[
                                (lane_counts.at_node_a, lane_counts.at_node_b)
                            ] += 1
                            counts["number_of_lanes_values"] += 1
                        elif attribute.type_id == GeometryAttributeType.SIMPLE_PASSING_RESTRICTION:
                            decode_simple_passing_restriction(attribute)
                            edge_has_simple_passing = True
                            counts["simple_passing_restriction_markers"] += 1
                        elif attribute.type_id == GeometryAttributeType.EXTENDED_PASSING_RESTRICTION:
                            passing = decode_extended_passing_restriction_header(
                                attribute
                            )
                            edge_has_extended_passing = True
                            extended_passing_headers[
                                (
                                    passing.a_to_b,
                                    passing.b_to_a,
                                    passing.has_detailed_records,
                                    passing.detailed_record_count,
                                )
                            ] += 1
                            counts["extended_passing_restrictions"] += 1
                        elif attribute.type_id == GeometryAttributeType.LANES:
                            lanes = decode_lanes(attribute)
                            edge_has_lanes = True
                            lanes_record_counts[len(lanes.records)] += 1
                            counts["lane_records"] += len(lanes.records)
                            for record in lanes.records:
                                lane_firmware_category_masks[
                                    record.firmware_category_mask
                                ] += 1
                            counts["lanes_attributes"] += 1
                if edge_simple_speed_limits:
                    counts["edges_with_simple_speed_limit"] += 1
                counts["edges_with_extended_speed_limit"] += int(
                    edge_has_extended_speed_limit
                )
                counts["edges_with_number_of_lanes"] += int(edge_has_number_of_lanes)
                counts["edges_with_simple_passing_restriction"] += int(
                    edge_has_simple_passing
                )
                counts["edges_with_extended_passing_restriction"] += int(
                    edge_has_extended_passing
                )
                counts["edges_with_lanes_attributes"] += int(edge_has_lanes)
                counts["edges"] += 1
                counts["geometry_parts"] += len(parts)
                counts["geometry_points"] += sum(len(part.points) for part in parts)
                semantic_record_offset = cluster.semantic_directory.record_offsets[
                    edge_index
                ]
                semantic_texts = cluster.semantic_texts[semantic_record_offset]
                logical_names = group_logical_names(semantic_texts)
                counts["edges_with_name_candidates"] += int(bool(semantic_texts))
                counts["edge_name_candidate_references"] += len(semantic_texts)
                counts["edge_primary_string_references"] += sum(
                    len(entry.primary) for entry in semantic_texts
                )
                counts["edge_secondary_string_references"] += sum(
                    len(entry.secondary) for entry in semantic_texts
                )
                counts["edge_logical_name_references"] += len(logical_names)
                counts["edges_with_logical_names"] += int(bool(logical_names))
                for name in logical_names:
                    selection = select_display_name(
                        name, transliterate_identifiers
                    )
                    counts[
                        f"edge_display_selection_{selection.status}_references"
                    ] += 1
                    if selection.source is not None:
                        counts[
                            f"edge_display_selection_{selection.source}_references"
                        ] += 1
                counts["centerline_points"] += sum(len(part.points) for part in parts) - max(
                    0, len(parts) - 1
                )
                expected_a = node_coordinates.get(int(endpoint_a["node_id"]))
                expected_b = node_coordinates.get(int(endpoint_b["node_id"]))
                if expected_a is None:
                    counts["edge_endpoint_references_outside_main_corpus"] += 1
                if expected_b is None:
                    counts["edge_endpoint_references_outside_main_corpus"] += 1
                if not parts:
                    geometry_outer_endpoint_mismatch_count += 1
                    if len(geometry_outer_endpoint_mismatch_examples) < 100:
                        geometry_outer_endpoint_mismatch_examples.append(
                            {
                                "edge_id": (geometry.cluster_id << 8) | edge_index,
                                "error": "edge has no geometry parts",
                            }
                        )
                else:
                    if expected_a is not None:
                        counts["geometry_outer_endpoint_comparisons"] += 1
                        if parts[0].points[0] != expected_a:
                            geometry_outer_endpoint_mismatch_count += 1
                            dx = parts[0].points[0].x - expected_a.x
                            dy = parts[0].points[0].y - expected_a.y
                            if parts[0].start_source == "coordinate-table":
                                geometry_table_endpoint_mismatch_count += 1
                            else:
                                geometry_explicit_endpoint_difference_count += 1
                                geometry_explicit_endpoint_max_component_delta = max(
                                    geometry_explicit_endpoint_max_component_delta,
                                    abs(dx),
                                    abs(dy),
                                )
                            if len(geometry_outer_endpoint_mismatch_examples) < 100:
                                geometry_outer_endpoint_mismatch_examples.append(
                                    {
                                        "edge_id": (geometry.cluster_id << 8) | edge_index,
                                        "endpoint": "a",
                                        "expected": expected_a.as_list(),
                                        "actual": parts[0].points[0].as_list(),
                                        "delta": [dx, dy],
                                        "endpoint_encoding": endpoint_a["encoding"],
                                        "geometry_source": parts[0].start_source,
                                    }
                                )
                    if expected_b is not None:
                        counts["geometry_outer_endpoint_comparisons"] += 1
                        if parts[-1].points[-1] != expected_b:
                            geometry_outer_endpoint_mismatch_count += 1
                            dx = parts[-1].points[-1].x - expected_b.x
                            dy = parts[-1].points[-1].y - expected_b.y
                            if parts[-1].end_source == "coordinate-table":
                                geometry_table_endpoint_mismatch_count += 1
                            else:
                                geometry_explicit_endpoint_difference_count += 1
                                geometry_explicit_endpoint_max_component_delta = max(
                                    geometry_explicit_endpoint_max_component_delta,
                                    abs(dx),
                                    abs(dy),
                                )
                            if len(geometry_outer_endpoint_mismatch_examples) < 100:
                                geometry_outer_endpoint_mismatch_examples.append(
                                    {
                                        "edge_id": (geometry.cluster_id << 8) | edge_index,
                                        "endpoint": "b",
                                        "expected": expected_b.as_list(),
                                        "actual": parts[-1].points[-1].as_list(),
                                        "delta": [dx, dy],
                                        "endpoint_encoding": endpoint_b["encoding"],
                                        "geometry_source": parts[-1].end_source,
                                    }
                                )
                    for left, right in zip(parts, parts[1:]):
                        counts["geometry_part_join_comparisons"] += 1
                        if left.points[-1] != right.points[0]:
                            geometry_part_join_mismatch_count += 1
                            if len(geometry_part_join_mismatch_examples) < 100:
                                geometry_part_join_mismatch_examples.append(
                                    {
                                        "edge_id": (geometry.cluster_id << 8) | edge_index,
                                        "left_part": left.index,
                                        "right_part": right.index,
                                        "left_end": left.points[-1].as_list(),
                                        "right_start": right.points[0].as_list(),
                                    }
                                )
                if sample_limit == 0 or edges_emitted < sample_limit:
                    edge_destination.write(
                        json.dumps(
                            _edge_item(
                                cluster,
                                edge_index,
                                endpoint_a,
                                endpoint_b,
                                transliterate_identifiers,
                            ),
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    edges_emitted += 1
                if counts["edges"] % 100_000 == 0:
                    _progress(
                        "edge-progress",
                        edges=counts["edges"],
                        outer_mismatches=geometry_outer_endpoint_mismatch_count,
                        join_mismatches=geometry_part_join_mismatch_count,
                    )
    edges_temporary.replace(edges_path)

    validation_ok = (
        node_adjacency_mismatch_count == 0
        and geometry_table_endpoint_mismatch_count == 0
        and geometry_part_join_mismatch_count == 0
        and counts["nodes"] == len(node_coordinates)
    )
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated" if validation_ok else "validation-failed",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "counts": dict(counts),
        "validation": {
            "all_resolved_node_adjacencies_match_edge_endpoints": node_adjacency_mismatch_count == 0,
            "node_adjacency_mismatch_count": node_adjacency_mismatch_count,
            "node_adjacency_mismatch_examples": node_adjacency_mismatch_examples,
            "all_resolved_outer_geometry_endpoints_match_graph_nodes": geometry_outer_endpoint_mismatch_count == 0,
            "geometry_outer_endpoint_mismatch_count": geometry_outer_endpoint_mismatch_count,
            "geometry_outer_endpoint_mismatch_examples": geometry_outer_endpoint_mismatch_examples,
            "all_coordinate_table_outer_endpoints_match_graph_nodes": geometry_table_endpoint_mismatch_count == 0,
            "coordinate_table_endpoint_mismatch_count": geometry_table_endpoint_mismatch_count,
            "explicit_endpoint_coordinate_difference_count": geometry_explicit_endpoint_difference_count,
            "explicit_endpoint_max_component_delta_mercator": geometry_explicit_endpoint_max_component_delta,
            "explicit_endpoint_note": "explicit endpoint pairs are independently quantized; topology node IDs remain authoritative",
            "all_geometry_parts_form_continuous_centerlines": geometry_part_join_mismatch_count == 0,
            "geometry_part_join_mismatch_count": geometry_part_join_mismatch_count,
            "geometry_part_join_mismatch_examples": geometry_part_join_mismatch_examples,
        },
        "name_display_policy": {
            "firmware_selector": "0x012a97e0",
            "transliterate_identifiers": sorted(transliterate_identifiers),
            "rule": (
                "base unless its language identifier is configured for "
                "transliteration; then paired alternate is required"
            ),
            "global_language_or_alias_preference": (
                "not selected; all logical language/alias candidates remain exported"
            ),
        },
        "orion_adapter_mapping": {
            "NodeRoadElement": "nodes.jsonl records",
            "EdgeRoadElement": "edges.jsonl records",
            "From": "edge.from.node_id",
            "To": "edge.to.node_id",
            "CenterlineGeometry": "edge.centerline_points",
            "Parts": "geometry_parts[]",
            "PointLld": "geometry_parts[].points[].wgs84",
            "NameCandidates": "edge.name_candidates[]",
            "Name": "edge.name_candidates[].values[]",
            "PhoneticName": "edge.name_candidates[].phonetics[]",
            "LogicalNames": "edge.logical_names[]",
            "DisplayName": "edge.logical_names[].display_selection.values[]",
            "StaticTravelDirection": "edge.road_attributes.static_travel_direction",
            "UrbanPropertySource": "edge.road_attributes.urban.value",
            "SpeedLimitPropertySource": (
                "edge.road_attributes.simple_speed_limit_candidates[]"
            ),
            "ExtendedSpeedLimitPropertySource": (
                "edge.road_attributes.extended_speed_limit_candidates[]"
            ),
            "NumberOfLanesPropertySource": (
                "edge.road_attributes.number_of_lanes_candidates[]"
            ),
            "PassingRestrictionPropertySource": (
                "edge.road_attributes simple/extended passing fields"
            ),
            "LanesSource": "edge.road_attributes.lanes_candidates[]",
            "ExtendedAutomotiveAttributesSource": (
                "edge.road_attributes.extended_automotive_attributes"
            ),
            "DynamicTopologyAttributesSource": (
                "edge.road_attributes.dynamic_topology_attributes"
            ),
            "not_yet_available": [
                "ClothoidCenterlineGeometry parameters",
                "consumer/UI policy selecting one language or alias globally",
                "remaining extended-speed subtype enum names and final consumer policy",
                "field semantics inside four-byte lane topology records",
                "vehicle restrictions",
                "turn manoeuvres and restrictions",
                "ADAS properties",
            ],
        },
        "road_attribute_semantics": {
            "direction_modes": dict(direction_modes),
            "simple_speed_limit_value_distribution": {
                str(value): count
                for value, count in sorted(simple_speed_limit_values.items())
            },
            "firmware_evidence": {
                "static_direction": "Ghidra VA 0x002e1c9c",
                "simple_speed_limit_storage": "Ghidra VA 0x002f0484",
                "simple_speed_limit_api": "Ghidra VA 0x002e3a34",
                "urban_decode": "Ghidra VA 0x002f0484: OR of part secondary bit 5",
                "urban_consumer": "Ghidra VA 0x013e5be8: edge object +0x16c",
            },
            "urban": {
                "edge_count": counts["urban_edges"],
                "source": "OR of geometry-part secondary flag bit 5 (0x20)",
            },
            "simple_speed_limit_unit": None,
            "simple_speed_limit_unit_status": "not independently proven",
            "extended_speed_limit": {
                "value_distribution": {
                    str(value): count
                    for value, count in sorted(extended_speed_limit_values.items())
                },
                "subtype_distribution": {
                    str(value): count
                    for value, count in sorted(extended_speed_limit_subtypes.items())
                },
                "subtype_0": "SLT_GENERAL",
                "unit": None,
                "firmware_evidence": ["Ghidra VA 0x0097e934", "0x0097e848", "0x0097e4a0"],
            },
            "number_of_lanes_pair_distribution": {
                str(pair): count
                for pair, count in sorted(
                    number_of_lanes_pairs.items(), key=lambda item: str(item[0])
                )
            },
            "extended_passing_header_distribution": {
                str(header): count
                for header, count in sorted(
                    extended_passing_headers.items(), key=lambda item: str(item[0])
                )
            },
            "lanes_record_count_distribution": {
                str(count): occurrences
                for count, occurrences in sorted(lanes_record_counts.items())
            },
            "lane_firmware_category_mask_distribution": {
                str(value): occurrences
                for value, occurrences in sorted(
                    lane_firmware_category_masks.items(), key=lambda item: str(item[0])
                )
            },
            "lane_passing_firmware_evidence": {
                "tag_enum": "EXTT contiguous order 13..16",
                "number_of_lanes_and_lanes": "Ghidra VA 0x0097f054",
                "passing_restrictions": "Ghidra VA 0x0097cb48",
            },
            "automotive_attributes": {
                "base_mask_distribution": {
                    str(mask): count
                    for mask, count in sorted(automotive_base_masks.items())
                },
                "active_bit_edge_counts": {
                    str(bit_index): count
                    for bit_index, count in sorted(automotive_active_bits.items())
                },
                "dynamic_extension_marker_distribution": {
                    str(value): count
                    for value, count in sorted(automotive_dynamic_extension.items())
                },
                "firmware_evidence": "Ghidra VA 0x008ce240",
                "bit_meanings": "raw pending per-bit public enum proof",
            },
            "dynamic_topology_attributes": {
                "directory_format": (
                    "topology u24le pointer at +12; u8 count; repeated u8 type/u16le offset"
                ),
                "directory_firmware_evidence": "Ghidra VA 0x014a67e0",
                "type_5_record_firmware_evidence": "Ghidra VA 0x014a69e8",
                "type_5_caller_evidence": (
                    "Ghidra VA 0x00977af8 stores decoded numeric value multiplied by 100"
                ),
                "type_5_public_name_and_unit": None,
                "type_3_time_conditions_status": (
                    "308 records edge-mapped; A-to-B/B-to-A selector and condition fields decoded"
                ),
                "type_7_vehicle_restrictions_status": (
                    "firmware decoder identified; no type-7 directory entry in this corpus"
                ),
            },
        },
        "artifacts": {
            "nodes": nodes_path.name,
            "nodes_emitted": nodes_emitted,
            "edges": edges_path.name,
            "edges_emitted": edges_emitted,
            "sample_limit": sample_limit,
            "checksums": "CHECKSUMS.sha256",
        },
    }
    report_path = output / "report.json"
    temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(report_path)
    checksums_path = output / "CHECKSUMS.sha256"
    checksums_path.write_text(
        f"{_sha256(report_path)}  {report_path.name}\n"
        f"{_sha256(nodes_path)}  {nodes_path.name}\n"
        f"{_sha256(edges_path)}  {edges_path.name}\n",
        encoding="ascii",
    )
    _progress("complete", status=report["status"], output=output)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=100,
        help="nodes and edges to emit after full validation; 0 emits the full graph",
    )
    parser.add_argument(
        "--transliterate-identifier",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        metavar="ID",
        help=(
            "repeatable low-7-bit language ID for firmware-style alternate "
            "selection; omitted means select every base form"
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        invalid_identifiers = [
            identifier
            for identifier in args.transliterate_identifier
            if not 0 <= identifier < 0x80
        ]
        if invalid_identifiers:
            raise ValueError(
                f"transliteration identifier outside low-7-bit range: "
                f"{invalid_identifiers[0]}"
            )
        report = run(
            args.psf,
            args.output,
            args.sample_limit,
            frozenset(args.transliterate_identifier),
        )
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_graph_export: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "nodes": report["counts"].get("nodes", 0),  # type: ignore[union-attr]
                "edges": report["counts"].get("edges", 0),  # type: ignore[union-attr]
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())

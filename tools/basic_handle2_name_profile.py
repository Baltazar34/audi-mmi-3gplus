#!/usr/bin/env python3
"""Profile Basic handle-2 name identifiers, scripts and ordering.

This command does not assign language labels by guesswork.  It decodes every
unique direct-text record, correlates identifier/alternate bits with Unicode
script, record order, cluster default identifier and edge references, and
writes evidence for the firmware preference analysis.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys
import unicodedata

from basic_geometry_decode import _build_cluster
from basic_handle2_directory import (
    _group_entries,
    decode_edge_directory,
    decode_record_data_end,
)
from basic_handle2_text_decode import (
    TextEntry,
    decode_direct_texts,
    schema_from_payload,
)
from basic_name_semantics import LANGUAGE_LABELS, group_logical_names
from psf_decode import (
    PsfError,
    _decode_indexed_lzma,
    _mercator_to_wgs84,
    read_basic_triple_handle_index,
)


SCHEMA_VERSION = 1


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"handle2-name-profile stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def classify_script(value: str) -> str:
    scripts: set[str] = set()
    has_number = False
    for character in value:
        category = unicodedata.category(character)
        if category.startswith("N"):
            has_number = True
        if not category.startswith("L"):
            continue
        name = unicodedata.name(character, "")
        if "CYRILLIC" in name:
            scripts.add("cyrillic")
        elif "LATIN" in name:
            scripts.add("latin")
        elif "GREEK" in name:
            scripts.add("greek")
        else:
            scripts.add("other-letter")
    if not scripts:
        return "numeric-symbol" if has_number else "empty-symbol"
    return "+".join(sorted(scripts))


def _entry_key(entry: TextEntry) -> str:
    return f"{entry.identifier}:{'alternate' if entry.alternate else 'primary'}"


def _entry_fields(entry: TextEntry, position: int) -> dict[str, object]:
    value = entry.primary[0] if entry.primary else ""
    return {
        "position": position,
        "identifier": entry.identifier,
        "alternate": entry.alternate,
        "script": classify_script(value),
        "primary": list(entry.primary),
        "secondary_identifier": entry.secondary_identifier,
        "secondary": list(entry.secondary),
    }


def _update_geo_extent(
    extents: dict[int, list[float]], identifier: int, longitude: float, latitude: float
) -> None:
    extent = extents.setdefault(
        identifier, [longitude, latitude, longitude, latitude]
    )
    extent[0] = min(extent[0], longitude)
    extent[1] = min(extent[1], latitude)
    extent[2] = max(extent[2], longitude)
    extent[3] = max(extent[3], latitude)


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    if sample_limit < 0:
        raise ValueError("sample limit must be zero or positive")
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "record_name_profiles.jsonl"
    sample_temporary = sample_path.with_suffix(sample_path.suffix + ".tmp")

    counts = collections.Counter()
    identifier_records = collections.Counter()
    identifier_edges = collections.Counter()
    identifier_alternate_records = collections.Counter()
    identifier_script_records: dict[int, collections.Counter[str]] = {}
    identifier_position_records: dict[int, collections.Counter[int]] = {}
    identifier_default_match = collections.Counter()
    identifier_secondary_nonempty = collections.Counter()
    identifier_examples: dict[int, collections.Counter[str]] = {}
    record_combinations = collections.Counter()
    edge_combinations = collections.Counter()
    entry_count_records = collections.Counter()
    transitions = collections.Counter()
    default_identifier_clusters = collections.Counter()
    default_identifier_geo_extents: dict[int, list[float]] = {}
    entry_identifier_geo_extents: dict[int, list[float]] = {}
    emitted = 0

    _progress("decode", clusters_total=len(order))
    with psf.open("rb") as source, sample_temporary.open(
        "w", encoding="utf-8"
    ) as destination:
        for ordinal, cluster_id in enumerate(order, 1):
            topology = _decode_indexed_lzma(source, grouped[cluster_id][0])
            geometry_payload = _decode_indexed_lzma(source, grouped[cluster_id][1])
            payload = _decode_indexed_lzma(source, grouped[cluster_id][2])
            geometry = _build_cluster(cluster_id, topology, geometry_payload)
            center_x = (geometry.bbox[0] + geometry.bbox[2]) // 2
            center_y = (geometry.bbox[1] + geometry.bbox[3]) // 2
            longitude, latitude = _mercator_to_wgs84(center_x, center_y)
            directory = decode_edge_directory(payload, geometry.edge_count)
            record_data_end = decode_record_data_end(
                payload, directory.directory_end
            )
            schema = schema_from_payload(payload)
            default_identifier_clusters[schema.default_identifier] += 1
            _update_geo_extent(
                default_identifier_geo_extents,
                schema.default_identifier,
                longitude,
                latitude,
            )
            unique_offsets = sorted(set(directory.record_offsets))
            record_ends = {
                record_offset: (
                    unique_offsets[index + 1]
                    if index + 1 < len(unique_offsets)
                    else record_data_end
                )
                for index, record_offset in enumerate(unique_offsets)
            }
            edge_multiplicity = collections.Counter(directory.record_offsets)
            for record_offset in unique_offsets:
                entries = decode_direct_texts(
                    payload,
                    record_offset,
                    record_ends[record_offset],
                    schema,
                )
                logical_names = group_logical_names(entries)
                multiplicity = edge_multiplicity[record_offset]
                counts["unique_records"] += 1
                counts["edge_references"] += multiplicity
                counts["unique_entries"] += len(entries)
                counts["edge_entry_references"] += len(entries) * multiplicity
                counts["records_with_entries"] += int(bool(entries))
                counts["edge_references_with_entries"] += int(bool(entries)) * multiplicity
                counts["multi_entry_records"] += int(len(entries) > 1)
                counts["logical_names"] += len(logical_names)
                counts["edge_logical_name_references"] += (
                    len(logical_names) * multiplicity
                )
                counts["transliteration_pairs"] += sum(
                    name.transliteration is not None for name in logical_names
                )
                counts["edge_transliteration_pair_references"] += sum(
                    name.transliteration is not None for name in logical_names
                ) * multiplicity
                counts["multi_logical_name_records"] += int(
                    len(logical_names) > 1
                )
                entry_count_records[len(entries)] += 1
                combination = tuple(_entry_key(entry) for entry in entries)
                combination_key = "|".join(combination) if combination else "<empty>"
                record_combinations[combination_key] += 1
                edge_combinations[combination_key] += multiplicity
                for left, right in zip(combination, combination[1:]):
                    transitions[f"{left}->{right}"] += 1
                for position, entry in enumerate(entries):
                    value = entry.primary[0] if entry.primary else ""
                    script = classify_script(value)
                    identifier_records[entry.identifier] += 1
                    identifier_edges[entry.identifier] += multiplicity
                    identifier_alternate_records[
                        (entry.identifier, int(entry.alternate))
                    ] += 1
                    identifier_script_records.setdefault(
                        entry.identifier, collections.Counter()
                    )[script] += 1
                    identifier_position_records.setdefault(
                        entry.identifier, collections.Counter()
                    )[position] += 1
                    identifier_default_match[entry.identifier] += int(
                        entry.identifier == schema.default_identifier
                    )
                    identifier_secondary_nonempty[entry.identifier] += int(
                        any(entry.secondary)
                    )
                    identifier_examples.setdefault(
                        entry.identifier, collections.Counter()
                    )[value] += 1
                    _update_geo_extent(
                        entry_identifier_geo_extents,
                        entry.identifier,
                        longitude,
                        latitude,
                    )
                if sample_limit == 0 or emitted < sample_limit:
                    destination.write(
                        json.dumps(
                            {
                                "schema_version": SCHEMA_VERSION,
                                "record_type": "mib-basic-handle2-name-profile",
                                "cluster_id": cluster_id,
                                "cluster_center_wgs84": [longitude, latitude],
                                "default_identifier": schema.default_identifier,
                                "record_offset": record_offset,
                                "record_end": record_ends[record_offset],
                                "edge_reference_count": multiplicity,
                                "entries": [
                                    _entry_fields(entry, position)
                                    for position, entry in enumerate(entries)
                                ],
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    emitted += 1
            counts["clusters"] += 1
            if ordinal % 250 == 0 or ordinal == len(order):
                _progress("decode-progress", clusters=ordinal, total=len(order))
    sample_temporary.replace(sample_path)

    identifiers = sorted(identifier_records)
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "profile-complete",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "counts": dict(sorted(counts.items())),
        "identifiers": {
            str(identifier): {
                "language": LANGUAGE_LABELS.get(identifier),
                "unique_record_entries": identifier_records[identifier],
                "edge_entry_references": identifier_edges[identifier],
                "default_identifier_matches": identifier_default_match[identifier],
                "nonempty_secondary_entries": identifier_secondary_nonempty[identifier],
                "alternate": {
                    "false": identifier_alternate_records[(identifier, 0)],
                    "true": identifier_alternate_records[(identifier, 1)],
                },
                "scripts": dict(
                    identifier_script_records[identifier].most_common()
                ),
                "positions": {
                    str(position): count
                    for position, count in identifier_position_records[
                        identifier
                    ].most_common()
                },
                "cluster_center_extent_wgs84": entry_identifier_geo_extents[
                    identifier
                ],
                "examples": [
                    {"value": value, "count": count}
                    for value, count in identifier_examples[identifier].most_common(30)
                ],
            }
            for identifier in identifiers
        },
        "cluster_defaults": {
            str(identifier): {
                "clusters": count,
                "cluster_center_extent_wgs84": default_identifier_geo_extents[
                    identifier
                ],
            }
            for identifier, count in default_identifier_clusters.most_common()
        },
        "record_entry_count": {
            str(key): value for key, value in entry_count_records.most_common()
        },
        "record_combinations": [
            {"combination": key, "records": count}
            for key, count in record_combinations.most_common(100)
        ],
        "edge_combinations": [
            {"combination": key, "edge_references": count}
            for key, count in edge_combinations.most_common(100)
        ],
        "transitions": [
            {"transition": key, "records": count}
            for key, count in transitions.most_common(100)
        ],
        "interpretation": {
            "identifier_labels": {
                str(identifier): label
                for identifier, label in sorted(LANGUAGE_LABELS.items())
                if identifier in identifiers
            },
            "identifier_evidence": (
                "Basic world-country official-language trailers plus independent "
                "Albania/Bosnia regional corpus cross-checks"
            ),
            "alternate_rule": (
                "every alternate is paired immediately after a base entry with the "
                "same language identifier; full-corpus grouping rejected no record"
            ),
            "display_selection": (
                "firmware VA 0x012a97e0 selects base unless the language ID is in "
                "the consumer transliteration set, then requires the paired alternate"
            ),
            "global_preferred_name": (
                "not encoded by identifier order; language and alias selection remains "
                "an explicit consumer/UI policy"
            ),
        },
        "artifacts": {
            "report": "report.json",
            "record_name_profiles": sample_path.name,
            "record_name_profile_count": emitted,
            "checksums": "CHECKSUMS.sha256",
        },
    }
    report_path = output / "report.json"
    report_temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    report_temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_temporary.replace(report_path)
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n"
        f"{_sha256(sample_path)}  {sample_path.name}\n",
        encoding="ascii",
    )
    _progress("complete", output=output, identifiers=len(identifiers))
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-limit", type=int, default=100)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.psf, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_handle2_name_profile: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "identifiers": sorted(report["identifiers"]),
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

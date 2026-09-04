#!/usr/bin/env python3
"""Run the repeatable Ghidra batch for Basic road-attribute reconstruction."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from run_basic_geometry_re import (
    DEFAULT_HEADLESS,
    DEFAULT_PROJECT_DIRECTORY,
    DEFAULT_USER_HOME,
    _run,
    _sha256,
)


HELPER_ADDRESSES = (
    "0154f730",  # node record accessor
    "0154f7f0",  # external node-ID accessor
    "0154f864",  # edge endpoint-A accessor
    "0154f894",  # edge endpoint-B accessor
    "0154f8c4",  # raw fixed edge-descriptor accessor
    "0154f990",  # cluster-level edge property accessor
    "0154faec",  # endpoint/edge-class nibble accessor
    "0154ff6c",  # adjacent-edge accessor using node attribute table
    "01550354",  # node adjacency reader
    "01553940",  # complete routing-edge attribute aggregate loader
    "00982ce4",  # public routing-edge load path
    "009791dc",  # reduced routing-edge load path
    "00977af8",  # aggregate post-processor
    "00977034",  # aggregate post-processor
    "0097a360",  # aggregate validation
    "00979058",  # directional adjacency expansion
    "00979354",  # directional attribute consumer
    "0097d2b0",  # aggregate attribute consumer
    "009828cc",  # aggregate attribute consumer
    "00977a20",  # directional attribute consumer
    "0097695c",  # aggregate attribute consumer
    "0097bd10",  # aggregate attribute consumer
    "00978558",  # geometry tag-18 consumer
    "0097e934",  # geometry tag-1/tag-2 consumer
    "0097e848",  # extended speed-limit condition decoder
    "0097e4a0",  # extended speed-limit packed condition parser
    "0097c7e0",  # speed-limit segment/result inserter
    "009823c0",  # geometry tag-10 consumer
    "009788ac",  # geometry tag-6 consumer
    "0097cb48",  # geometry tag-14/tag-15 consumer
    "0097b180",  # geometry tag-5 consumer
    "0097f054",  # geometry tag-3/tag-13/tag-16 consumer
    "0149cb90",  # guidance tagged-field stride decoder
    "0149cc7c",  # geometry tagged-field semantic helper
    "0149cda8",  # geometry tagged-field semantic helper
    "0149ced4",  # geometry tagged-field semantic helper
    "0149d000",  # geometry tagged-field semantic helper
    "0149d144",  # geometry tagged-field byte-length decoder
    "014a6878",  # extended edge boolean accessor
    "014a67e0",  # dynamic vehicle/time record selector
    "014a6930",  # extended edge boolean accessor
    "014a69e8",  # extended edge length/value accessor
    "014a6a88",  # time-dependent direction accessor
    "014a6e8c",  # extended edge boolean accessor
    "014a6f44",  # vehicle/HOV access-state accessor
    "014a714c",  # vehicle/HOV access-state accessor
    "014a72b4",  # vehicle/HOV restriction accessor
    "014a7a2c",  # dynamic restriction direction helper
    "014a7b68",  # dynamic restriction direction helper
    "014a7dc4",  # vehicle-class restriction record decoder
    "014a7e0c",  # vehicle-class restriction record decoder
    "014a7ef0",  # vehicle-class/time restriction evaluator
    "014a7f60",  # vehicle-class restriction matcher
    "014a80c8",  # vehicle/HOV access evaluator
    "014a81c0",  # vehicle/HOV access evaluator
    "014a9028",  # timed restriction-list evaluator
    "014a9308",  # dynamic direction fallback evaluator
    "014a9f98",  # time-condition table evaluator
    "014a9c5c",  # time-condition table evaluator implementation
    "014a9858",  # time-condition payload unpacker
    "014a94f0",  # time-condition applicability selector
    "014aa5f8",  # decoded calendar/time interval evaluator
    "014aa33c",  # date-condition sentinel helper
    "014aa364",  # date-condition sentinel helper
    "014aa39c",  # weekday-mask decoder
    "014aa3d8",  # date-field decoder
    "014aa40c",  # date-field decoder
    "014aa438",  # month-mask decoder
    "014aa498",  # date-field decoder
    "014aa4f0",  # date-field decoder
    "014aa544",  # week-mask decoder
    "014aa580",  # start-time decoder
    "014aa5bc",  # end-time decoder
    "014a7004",  # extended automotive attribute dispatcher
    "008ce240",  # public extended-automotive mask API
    "008d0e40",  # routing consumer of extended-automotive mask
    "008d2950",  # routing consumer of extended-automotive mask
    "008d3bf8",  # routing-edge aggregate/property loader
    "008e2338",  # route-state consumer of extended-automotive mask
    "008e489c",  # route-state consumer of extended-automotive mask
    "008f94f8",  # public road/HOV/pedestrian property dispatcher
    "009d195c",  # pedestrian-zone consumer
    "00adf7a4",  # public HOV-attribute consumer
    "008cf868",  # public time-dependent restriction API
    "002e1c9c",  # public static/time-dependent direction API
    "002e3a34",  # public simple/extended speed-limit API
    "002e6734",  # public HOV-lane API
    "002f0484",  # full simplified-storage routing-edge translator
)

XREF_ADDRESSES = (
    "0154f730",
    "0154f864",
    "0154f894",
    "0154f8c4",
    "0154f990",
    "0154faec",
    "0154ff6c",
    "01550354",
    "01553940",
    "00978558",
    "0097e934",
    "0097e848",
    "0097e4a0",
    "0097c7e0",
    "009823c0",
    "009788ac",
    "0097cb48",
    "0097b180",
    "0097f054",
    "014a6878",
    "014a6930",
    "014a69e8",
    "014a6a88",
    "014a6e8c",
    "014a6f44",
    "014a714c",
    "014a72b4",
    "014a67e0",
    "014a7004",
    "014a7a2c",
    "014a7b68",
    "014a7dc4",
    "014a7e0c",
    "014a7ef0",
    "014a7f60",
    "014a80c8",
    "014a81c0",
    "014a9028",
    "014a9308",
    "014a9f98",
    "014a9c5c",
    "014a9858",
    "014a94f0",
    "014aa5f8",
    "014aa33c",
    "014aa364",
    "014aa39c",
    "014aa3d8",
    "014aa40c",
    "014aa438",
    "014aa498",
    "014aa4f0",
    "014aa544",
    "014aa580",
    "014aa5bc",
    "008ce240",
    "008d0e40",
    "008d2950",
    "008d3bf8",
    "008e2338",
    "008e489c",
    "008f94f8",
    "009d195c",
    "00adf7a4",
    "008cf868",
)

STRING_NEEDLES = (
    "DATA_ACCESS_LOAD_ROUTINGEDGE_ATTRIBUTES",
    "PSLRoutingEdge::IsAccessibleAtoBAtTime",
    "PSLRoutingEdge::IsAccessibleBtoAAtTime",
    "PSLRoutingEdge::HasNonHOVLane",
    "extended sppeed limit",
    "ReadDividerInformation",
    "DATA_ACCESS_LOAD_GUIDANCE_DATA",
    "LOAD_ROAD_CLASS",
    "numberOfLanesTotal",
    "numberOfEntranceLanes",
    "HOVLanesAllowed",
    "PSLRoutingEdge::IsWithinPedestrianZone",
    "SL_SPEED_LIMITS_VALUE",
    "CUR_SPEED_LIMIT",
    "numberOfLanesOtherRoad",
    "numberOfLanesExitRoad",
    "PassingRestriction",
    "VehicleType",
    "vehicle restriction",
    "overtaking",
    "EXTT_SIMPLE_SPEED_LIMIT",
    "EXTT_EXTENDED_SPEED_LIMIT",
    "EXTT_LANE_CONNECTIVITY",
    "EXTT_JUNCTION_VIEW",
    "EXTT_THROUGH_ROUTE_INFO",
    "EXTT_SIGN_INFO",
    "EXTT_GRADE_CATEGORY",
    "EXTT_STRAIGHT_ON",
    "EXTT_ATTRIBUTE_EX1",
    "EXTT_TOLL_GATE_INFO",
    "EXTT_Z_ORDER_INFO",
    "EXTT_Z_VALUE_INFO",
    "EXTT_NUMBER_OF_LANES",
    "EXTT_SIMPLE_PASSING_RESTRICTION",
    "EXTT_EXTENDED_PASSING_RESTRICTION",
    "EXTT_LANES",
    "EXTT_ADDITIONAL_GEOMETRY",
    "EXTT_TRAFFIC_SIGNAL_INFO",
    "PSLRoutingEdge::HasHOVAttributes",
    "PSLRoutingEdge::GetGeneralHOVStatus",
    "PSLRoutingEdge::GetHOVStatusAtTime",
    "PSLRoutingEdge::GetExtendedAttributesAutomotive",
    "PSLRoutingEdge::IsRestrictedAtoBAtTime",
    "PSLRoutingEdge::IsRestrictedBtoAAtTime",
    "PSLSupraRoutingEdge::HasNonHOVLane",
    # Urban-semantics probes.  These are deliberately distinctive strings;
    # plain "Urban" would also match unrelated UI/geocoder diagnostics.
    "UrbanRoad",
    "BuiltUpArea",
    "PedestrianZone",
    "is urban:",
)


def run(args: argparse.Namespace) -> dict[str, object]:
    script_directory = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    if not args.headless.is_file():
        raise FileNotFoundError(args.headless)
    args.output.mkdir(parents=True, exist_ok=True)
    helpers = args.output / "road_attribute_helpers.c.txt"
    xrefs = args.output / "road_attribute_xrefs.c.txt"
    string_xrefs = args.output / "road_attribute_string_xrefs.c.txt"
    environment = os.environ.copy()
    environment["JAVA_TOOL_OPTIONS"] = f"-Duser.home={args.user_home}"
    base = [
        str(args.headless),
        str(args.project_directory),
        args.project_name,
        "-process",
        args.program,
        "-noanalysis",
        "-scriptPath",
        str(script_directory),
    ]
    _run(
        base + ["-postScript", "GhidraCreateDecompile.java", str(helpers), *HELPER_ADDRESSES],
        environment,
        "decompile-helpers",
    )
    _run(
        base + ["-postScript", "GhidraAddressXrefs.java", str(xrefs), *XREF_ADDRESSES],
        environment,
        "decompile-xrefs",
    )
    _run(
        base + ["-postScript", "GhidraStringXrefs.java", str(string_xrefs), *STRING_NEEDLES],
        environment,
        "decompile-string-xrefs",
    )
    artifacts = {
        path.name: {"size": path.stat().st_size, "sha256": _sha256(path)}
        for path in (helpers, xrefs, string_xrefs)
    }
    manifest: dict[str, object] = {
        "schema_version": 1,
        "ghidra_headless": str(args.headless),
        "project_directory": str(args.project_directory),
        "project_name": args.project_name,
        "program": args.program,
        "image_base_note": "Ghidra VA = raw ELF VA + 0x10000",
        "helper_addresses": list(HELPER_ADDRESSES),
        "xref_addresses": list(XREF_ADDRESSES),
        "string_needles": list(STRING_NEEDLES),
        "artifacts": artifacts,
    }
    manifest_path = args.output / "manifest.json"
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(manifest_path)
    checksum_paths = (helpers, xrefs, string_xrefs, manifest_path)
    (args.output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
    )
    print(f"road-attributes-re stage=complete output={args.output}", flush=True)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--headless", type=Path, default=DEFAULT_HEADLESS)
    parser.add_argument("--project-directory", type=Path, default=DEFAULT_PROJECT_DIRECTORY)
    parser.add_argument("--project-name", default="Pathfinder")
    parser.add_argument("--program", default="libPathfinderApp.so")
    parser.add_argument("--user-home", type=Path, default=DEFAULT_USER_HOME)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"run_basic_road_attributes_re: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

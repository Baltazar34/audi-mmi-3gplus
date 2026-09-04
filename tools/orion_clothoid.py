"""Geometry-neutral Orion clothoid source primitives."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable

from basic_geometry_decode import Point


@dataclass(frozen=True)
class ClothoidSegment:
    index: int
    start: Point
    end: Point
    heading_radians: float
    length: float
    start_curvature: float
    curvature_rate: float

    def endpoint(self) -> tuple[float, float]:
        """Evaluate the exact endpoint for the zero-curvature source segment."""
        return (
            self.start.x + self.length * math.cos(self.heading_radians),
            self.start.y + self.length * math.sin(self.heading_radians),
        )


def piecewise_linear_clothoids(points: Iterable[Point]) -> tuple[ClothoidSegment, ...]:
    """Represent every non-zero polyline leg as a zero-curvature clothoid.

    A straight line is the kappa=0, dkappa/ds=0 special case of an Euler
    spiral.  Keeping one segment per source leg preserves every source vertex
    without inventing a curve fit.  Tangent continuity is intentionally not
    claimed at polyline corners.
    """
    source = tuple(points)
    result: list[ClothoidSegment] = []
    for left, right in zip(source, source[1:]):
        dx = right.x - left.x
        dy = right.y - left.y
        length = math.hypot(dx, dy)
        if length == 0.0:
            continue
        result.append(
            ClothoidSegment(
                index=len(result),
                start=left,
                end=right,
                heading_radians=math.atan2(dy, dx),
                length=length,
                start_curvature=0.0,
                curvature_rate=0.0,
            )
        )
    return tuple(result)

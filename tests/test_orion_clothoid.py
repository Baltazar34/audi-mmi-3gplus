import math
import unittest

from basic_geometry_decode import Point
from orion_clothoid import piecewise_linear_clothoids


class OrionClothoidTests(unittest.TestCase):
    def test_straight_legs_preserve_vertices(self) -> None:
        segments = piecewise_linear_clothoids(
            [Point(0, 0), Point(3, 4), Point(3, 4), Point(3, 10)]
        )
        self.assertEqual(len(segments), 2)
        self.assertEqual(segments[0].length, 5.0)
        self.assertAlmostEqual(segments[0].heading_radians, math.atan2(4, 3))
        self.assertEqual(segments[0].start_curvature, 0.0)
        self.assertEqual(segments[0].curvature_rate, 0.0)
        for segment in segments:
            end_x, end_y = segment.endpoint()
            self.assertAlmostEqual(end_x, segment.end.x)
            self.assertAlmostEqual(end_y, segment.end.y)

    def test_empty_and_single_point_have_no_segments(self) -> None:
        self.assertEqual(piecewise_linear_clothoids([]), ())
        self.assertEqual(piecewise_linear_clothoids([Point(1, 2)]), ())


if __name__ == "__main__":
    unittest.main()

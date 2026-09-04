from pathlib import Path
import sys
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_mib_direction_profile import path_direction


class OrionMibDirectionProfileTests(unittest.TestCase):
    def test_reversed_reported_edge_order_is_reconstructed_as_connected_chain(self) -> None:
        both = {
            "a_to_b_allowed": True,
            "b_to_a_allowed": True,
        }
        mib = {
            10: {
                "from_node_id": 1,
                "to_node_id": 2,
                "centerline": [
                    {"longitude": 19.0, "latitude": 42.0},
                    {"longitude": 19.1, "latitude": 42.0},
                ],
                "travel_direction": both,
            },
            11: {
                "from_node_id": 2,
                "to_node_id": 3,
                "centerline": [
                    {"longitude": 19.1, "latitude": 42.0},
                    {"longitude": 19.2, "latitude": 42.0},
                ],
                "travel_direction": both,
            },
        }
        mode, edge_ids, traversals, basis = path_direction(
            {"from": {"longitude": 19.0, "latitude": 42.0}}, [11, 10], mib
        )
        self.assertEqual(mode, "both")
        self.assertEqual(edge_ids, [10, 11])
        self.assertEqual(traversals, ["a_to_b", "a_to_b"])
        self.assertEqual(basis, "from_node")


if __name__ == "__main__":
    unittest.main()

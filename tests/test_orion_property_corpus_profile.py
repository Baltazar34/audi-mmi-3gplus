from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_property_corpus_profile import _decode_part


class OrionPropertyCorpusProfileTests(unittest.TestCase):
    def test_constant_part_is_broadcast(self) -> None:
        table = {"descriptors": [{"tag": 1, "type_code": 0x25, "size": 4}]}
        layouts = [SimpleNamespace(payload_offset=0, payload_size=4)]
        self.assertEqual(
            _decode_part((3).to_bytes(4, "little"), table, layouts, 0, 5),
            [3, 3, 3, 3, 3],
        )

    def test_subbyte_padding_is_not_decoded_as_rows(self) -> None:
        table = {"descriptors": [{"tag": 2, "type_code": 0x21, "size": 2}]}
        layouts = [SimpleNamespace(payload_offset=0, payload_size=2)]
        self.assertEqual(_decode_part(bytes((0xE4, 0xFF)), table, layouts, 0, 4), [0, 1, 2, 3])


if __name__ == "__main__":
    unittest.main()

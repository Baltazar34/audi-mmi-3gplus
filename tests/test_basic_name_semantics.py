from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from basic_handle2_text_decode import TextEntry  # noqa: E402
from basic_name_semantics import (  # noqa: E402
    group_logical_names,
    nonempty,
    select_display_name,
)
from psf_decode import PsfError  # noqa: E402


def entry(identifier: int, alternate: bool, value: str) -> TextEntry:
    return TextEntry(identifier, alternate, (value,), identifier, ("",), 0, 0)


class BasicNameSemanticsTests(unittest.TestCase):
    def test_base_alternate_pair_and_alias_are_preserved(self) -> None:
        entries = (
            entry(33, False, "Улица"),
            entry(33, True, "Ulica"),
            entry(33, False, "Главни пут"),
            entry(33, True, "Glavni put"),
        )
        names = group_logical_names(entries)
        self.assertEqual(len(names), 2)
        self.assertEqual(names[0].language, "Serbian")
        self.assertEqual(names[0].base.primary, ("Улица",))
        self.assertEqual(names[0].transliteration.primary, ("Ulica",))  # type: ignore[union-attr]
        self.assertEqual(names[1].base_index, 2)

    def test_selection_mirrors_consumer_language_set(self) -> None:
        name = group_logical_names(
            (entry(33, False, "Улица"), entry(33, True, "Ulica"))
        )[0]
        base = select_display_name(name, set())
        latin = select_display_name(name, {33})
        self.assertEqual((base.status, base.source), ("selected", "base"))
        self.assertEqual(base.entry.primary, ("Улица",))  # type: ignore[union-attr]
        self.assertEqual((latin.status, latin.source), ("selected", "transliteration"))
        self.assertEqual(latin.entry.primary, ("Ulica",))  # type: ignore[union-attr]

    def test_requested_missing_transliteration_is_not_silently_fallbacked(self) -> None:
        name = group_logical_names((entry(31, False, "Rruga"),))[0]
        selection = select_display_name(name, {31})
        self.assertEqual(selection.status, "missing-transliteration")
        self.assertIsNone(selection.entry)

    def test_orphan_or_mismatched_alternate_is_rejected(self) -> None:
        with self.assertRaises(PsfError):
            group_logical_names((entry(33, True, "Ulica"),))
        with self.assertRaises(PsfError):
            group_logical_names(
                (entry(33, False, "Улица"), entry(31, True, "Ulica"))
            )

    def test_empty_phonetic_placeholders_are_removed(self) -> None:
        self.assertEqual(nonempty(("", "ulitsa", "")), ("ulitsa",))


if __name__ == "__main__":
    unittest.main()

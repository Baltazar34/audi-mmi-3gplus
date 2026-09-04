#!/usr/bin/env python3
"""Language, transliteration and display selection for Basic SDStrings.

Firmware VA 0x014915e8 stores ``tag & 0x7f`` as the language identifier and
``tag >> 7`` as the alternate/transliteration flag.  VA 0x012a97e0 applies a
consumer-provided set of language identifiers: use the base form when its
identifier is not in that set, otherwise require and use its paired alternate.

This module deliberately does not choose one global road name among different
languages or aliases.  That remains a caller/UI policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Collection, Sequence

from basic_handle2_text_decode import TextEntry
from psf_decode import PsfError


LANGUAGE_LABELS: dict[int, str] = {
    # Proven by the Basic world-country official-language lists and
    # cross-checked against the corresponding regional name corpora.
    30: "Bosnian",
    31: "Albanian",
    33: "Serbian",
    48: "Montenegrin",
}


@dataclass(frozen=True)
class LogicalName:
    identifier: int
    language: str | None
    base: TextEntry
    transliteration: TextEntry | None
    base_index: int
    transliteration_index: int | None


@dataclass(frozen=True)
class DisplaySelection:
    status: str
    source: str | None
    entry: TextEntry | None


def group_logical_names(entries: Sequence[TextEntry]) -> tuple[LogicalName, ...]:
    """Pair only an immediately following alternate with its base entry.

    Repeated non-alternate entries remain separate logical aliases.  This
    preserves the on-disk order and avoids inventing a priority between aliases.
    """

    result: list[LogicalName] = []
    index = 0
    while index < len(entries):
        base = entries[index]
        if base.alternate:
            raise PsfError(
                f"orphan alternate SDString at physical entry {index} "
                f"for identifier {base.identifier}"
            )
        alternate: TextEntry | None = None
        alternate_index: int | None = None
        if index + 1 < len(entries) and entries[index + 1].alternate:
            candidate = entries[index + 1]
            if candidate.identifier != base.identifier:
                raise PsfError(
                    f"alternate SDString identifier {candidate.identifier} does not "
                    f"match base identifier {base.identifier} at entry {index}"
                )
            alternate = candidate
            alternate_index = index + 1
            index += 1
        result.append(
            LogicalName(
                identifier=base.identifier,
                language=LANGUAGE_LABELS.get(base.identifier),
                base=base,
                transliteration=alternate,
                base_index=index if alternate is None else index - 1,
                transliteration_index=alternate_index,
            )
        )
        index += 1
    return tuple(result)


def select_display_name(
    name: LogicalName, transliterate_identifiers: Collection[int]
) -> DisplaySelection:
    """Mirror the language-list decision made by firmware VA 0x012a97e0."""

    if name.identifier not in transliterate_identifiers:
        return DisplaySelection("selected", "base", name.base)
    if name.transliteration is None:
        return DisplaySelection("missing-transliteration", None, None)
    return DisplaySelection("selected", "transliteration", name.transliteration)


def nonempty(values: Sequence[str]) -> tuple[str, ...]:
    """Drop empty phonetic/string placeholders without changing order."""

    return tuple(value for value in values if value)

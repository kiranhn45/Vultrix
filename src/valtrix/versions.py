"""Compare Python package versions (a practical subset of PEP 440).

Handles epochs, release numbers, pre-releases (a, b, rc), post-releases, dev
releases, and local suffixes. Anything that does not parse returns None, and
callers must treat "cannot compare" as unknown rather than guessing.

Only the standard library is used. The tests cross-check this module against
the `packaging` library when it is installed.
"""

from __future__ import annotations

import re
from functools import total_ordering
from typing import Any, Optional, Sequence, Tuple

_VERSION = re.compile(
    r"""
    ^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>\d+)?)?
    (?:(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_MAX_LENGTH = 100


@total_ordering
class Version:
    """A parsed version. Compare with <, >, ==. Build with parse_version()."""

    def __init__(self, text: str, release: Tuple[int, ...], key: Tuple[Any, ...]) -> None:
        self.text = text
        self.release = release
        self._key = key

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._key == other._key

    def __lt__(self, other: "Version") -> bool:
        return self._key < other._key

    def __hash__(self) -> int:
        return hash(self._key)

    def __repr__(self) -> str:
        return f"Version({self.text!r})"


def parse_version(text: str) -> Optional[Version]:
    if not isinstance(text, str) or len(text) > _MAX_LENGTH:
        return None
    match = _VERSION.match(text)
    if not match:
        return None

    epoch = int(match.group("epoch") or 0)
    release = tuple(int(part) for part in match.group("release").split("."))

    stripped = list(release)
    while len(stripped) > 1 and stripped[-1] == 0:
        stripped.pop()

    pre = None
    if match.group("pre_l"):
        pre = (_PRE_RANK[match.group("pre_l").lower()], int(match.group("pre_n") or 0))

    post = None
    if match.group("post_n1") is not None:
        post = int(match.group("post_n1"))
    elif match.group("post_l"):
        post = int(match.group("post_n2") or 0)

    dev = None
    if match.group("dev_l"):
        dev = int(match.group("dev_n") or 0)

    # A dev release of a final version sorts before that version's pre-releases.
    if pre is None and post is None and dev is not None:
        pre_key: Tuple[int, int] = (-1, 0)
    elif pre is None:
        pre_key = (3, 0)
    else:
        pre_key = pre
    post_key = -1 if post is None else post
    dev_key = (1, 0) if dev is None else (0, dev)

    local = match.group("local")
    if local is None:
        local_key: Tuple[Any, ...] = (0,)
    else:
        parts = []
        for piece in re.split(r"[-_.]", local.lower()):
            parts.append((1, int(piece), "") if piece.isdigit() else (0, 0, piece))
        local_key = (1, tuple(parts))

    key = (epoch, tuple(stripped), pre_key, post_key, dev_key, local_key)
    return Version(text, release, key)


def choose_fix(installed: str, fixed_versions: Sequence[str]) -> Optional[str]:
    """Pick the fixed version that applies to `installed`.

    Advisories list a fix per release line (for example 2.2.28, 3.2.13 and
    4.0.4). The one that matters is the lowest fix above the installed version:
    when a fix exists on the installed release line it is always the lowest
    above, and otherwise it is the smallest jump available. Fixes at or below
    the installed version belong to other release lines and are ignored.

    Returns None if no fix above the installed version is listed, or if the
    versions cannot be compared.
    """
    current = parse_version(installed)
    if current is None:
        return None

    candidates = []
    for text in fixed_versions:
        version = parse_version(text)
        if version is not None and version > current:
            candidates.append(version)
    return min(candidates).text if candidates else None


def sort_versions(versions: Sequence[str]) -> Tuple[str, ...]:
    """Sort oldest to newest. Versions that cannot be parsed go last, in order."""
    parsed = [(parse_version(v), v) for v in versions]
    good = sorted((p for p in parsed if p[0] is not None), key=lambda item: item[0])
    bad = [p for p in parsed if p[0] is None]
    return tuple(v for _, v in good + bad)

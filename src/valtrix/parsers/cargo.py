"""Rust: Cargo.lock.

Every [[package]] entry has a name and version. Entries without a `source`
are the project's own crates; what they depend on is direct.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from valtrix.models import CARGO, Dependency, ParseIssue, ParseResult
from valtrix.parsers.common import MAX_DEPENDENCIES, clean, items
from valtrix.parsers.python_project import _lock_packages

_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_VERSION = re.compile(r"^[0-9][A-Za-z0-9.+_-]{0,99}$")

Node = Tuple[str, str, str]


def parse_cargo_lock(path: Path, source: str) -> ParseResult:
    packages, lines = _lock_packages(path)
    result = ParseResult()
    by_name: Dict[str, List[Node]] = {}
    crates: List[Tuple[Node, int, bool, List[str]]] = []

    for package, line in zip(packages[:MAX_DEPENDENCIES], lines):
        name, version = clean(package.get("name"), 100), clean(package.get("version"), 100)
        if not _NAME.match(name) or not _VERSION.match(version):
            result.issues.append(ParseIssue(source, line, "Package entry without a usable name and version skipped"))
            continue
        node = (CARGO, name, version)
        by_name.setdefault(name, []).append(node)
        local = not clean(package.get("source"), 300)
        crates.append((node, line, local, [clean(d, 300) for d in items(package.get("dependencies"))]))

    def lookup(text: str):
        # "name", "name version" or "name version (source)"
        parts = text.split()
        if not parts:
            return None
        candidates = by_name.get(parts[0], [])
        if len(parts) > 1:
            candidates = [n for n in candidates if n[2] == parts[1]]
        return candidates[0] if candidates else None

    direct: Set[Node] = set()
    have_root = any(local for _, _, local, _ in crates)
    for node, _, local, wants in crates:
        for text in wants:
            child = lookup(text)
            if child is None:
                continue
            if local:
                direct.add(child)
            else:
                result.edges.append((node, child))

    for node, line, local, _ in crates:
        if local:
            continue  # the project's own crate, not a third-party dependency
        result.dependencies.append(
            Dependency(node[1], node[2], f"=={node[2]}", (), None, source, line,
                       CARGO, (node in direct) if have_root else None, False)
        )
    return result

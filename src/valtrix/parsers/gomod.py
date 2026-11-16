"""Go: go.mod.

go.mod lists the exact version of every module the build uses. Modules marked
`// indirect` are only pulled in by other modules. It does not record which
module pulls in which, so there are no graph edges.
"""

from __future__ import annotations

import re
from pathlib import Path

from valtrix.models import GO, Dependency, ParseIssue, ParseResult
from valtrix.parsers.common import MAX_DEPENDENCIES, clean, read_text

_MODULE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~/-]{0,300}$")
_VERSION = re.compile(r"^v([0-9][A-Za-z0-9.+_-]{0,99})$")


def parse_go_mod(path: Path, source: str) -> ParseResult:
    result = ParseResult()
    in_block = False
    for number, raw in enumerate(read_text(path, 5_000_000).splitlines(), start=1):
        code, _, comment = raw.partition("//")
        line = code.strip()
        if not line:
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            entry = line
        elif line.startswith("require"):
            rest = line[len("require"):].strip()
            if rest == "(":
                in_block = True
                continue
            if not line[len("require"):][:1].isspace():
                continue
            entry = rest
        else:
            continue

        parts = entry.split()
        module = clean(parts[0], 301).strip('"') if parts else ""
        version = _VERSION.match(parts[1]) if len(parts) > 1 else None
        if len(parts) != 2 or not _MODULE.match(module) or not version:
            result.issues.append(ParseIssue(source, number, f"Could not parse requirement: {clean(entry, 80)}"))
            continue
        if len(result.dependencies) >= MAX_DEPENDENCIES:
            result.issues.append(ParseIssue(source, number, f"Only the first {MAX_DEPENDENCIES} modules were read"))
            break
        # "+incompatible" is build metadata, not part of the version OSV knows.
        pinned = version.group(1).split("+", 1)[0]
        result.dependencies.append(
            Dependency(module, pinned, f"=={pinned}", (), None, source, number,
                       GO, comment.strip() != "indirect", False)
        )
    return result

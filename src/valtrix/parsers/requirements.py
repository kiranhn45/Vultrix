"""Parser for pip requirements files (requirements.txt).

Project files are untrusted input. This module only reads text and never
runs, imports, or installs anything from the files it parses. Limits on file
size and include depth keep a hostile or broken file from causing harm.
"""

from __future__ import annotations

import codecs
import re
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Set, Tuple, Union

from valtrix.models import Dependency, ParseIssue, ParseResult, normalize_name

MAX_FILE_BYTES = 1_000_000
MAX_INCLUDE_DEPTH = 10
_SHORTEN_AT = 80


class RequirementsError(Exception):
    """A requirements file could not be read."""


# ---------------------------------------------------------------- patterns

# pip treats "#" as a comment only at the start of a line or after whitespace,
# so URL fragments like "pkg.zip#egg=pkg" survive.
_COMMENT = re.compile(r"(^|\s+)#.*$")

# "-r file", "-rfile", "--requirement file", "--requirement=file"
_INCLUDE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)?(?P<target>.+)$")

# Per-requirement options such as "--hash=sha256:..." start with " --".
_OPTION_SPLIT = re.compile(r"\s+--")

_REQUIREMENT = re.compile(
    r"""
    ^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)
    \s*(?:\[(?P<extras>[^\]]*)\])?
    \s*(?P<rest>.*)$
    """,
    re.VERBOSE,
)

_CLAUSE = re.compile(r"^(===|==|~=|!=|<=|>=|<|>)\s*([A-Za-z0-9][A-Za-z0-9.*+!_-]*)$")


# ----------------------------------------------------------------- reading

def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise RequirementsError(
                f"{path}: file is larger than {MAX_FILE_BYTES} bytes"
            )
        data = path.read_bytes()
    except OSError as exc:
        raise RequirementsError(f"{path}: {exc.strerror or exc}") from exc

    # Windows PowerShell's ">" writes UTF-16, so `pip freeze > requirements.txt`
    # can produce a UTF-16 file. "utf-8-sig" also strips a UTF-8 BOM.
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    else:
        encoding = "utf-8-sig"
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise RequirementsError(f"{path}: not valid {encoding} text") from exc


def _logical_lines(text: str) -> Iterator[Tuple[int, str]]:
    """Yield (first line number, cleaned line), joining "\\" continuations
    and dropping comments and blank lines."""
    parts: List[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not parts and raw.lstrip().startswith("#"):
            continue
        if not parts:
            start = number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            parts.append(stripped[:-1])
            continue
        parts.append(raw)
        line = _COMMENT.sub("", "".join(parts)).strip()
        parts = []
        if line:
            yield start, line
    if parts:
        line = _COMMENT.sub("", "".join(parts)).strip()
        if line:
            yield start, line


def _shorten(text: str) -> str:
    return text if len(text) <= _SHORTEN_AT else text[: _SHORTEN_AT - 3] + "..."


# ----------------------------------------------------------- one requirement

def _parse_requirement(line: str, source: str, number: int, result: ParseResult) -> None:
    body = _OPTION_SPLIT.split(line, maxsplit=1)[0]
    body, _, marker_text = body.partition(";")
    marker = marker_text.strip() or None

    match = _REQUIREMENT.match(body.strip())
    if not match:
        result.issues.append(
            ParseIssue(source, number, f"Could not parse requirement: {_shorten(line)}")
        )
        return

    name = normalize_name(match.group("name"))
    extras = tuple(
        sorted({e.strip().lower() for e in (match.group("extras") or "").split(",") if e.strip()})
    )
    rest = match.group("rest").strip()

    if rest.startswith("@"):
        result.dependencies.append(
            Dependency(name, None, rest, extras, marker, source, number)
        )
        result.issues.append(
            ParseIssue(source, number, f"'{name}' points to a direct URL, so its version is unknown")
        )
        return

    clauses: List[Tuple[str, str]] = []
    if rest:
        for piece in rest.split(","):
            clause = _CLAUSE.match(piece.strip())
            if not clause:
                result.issues.append(
                    ParseIssue(source, number, f"Could not parse requirement: {_shorten(line)}")
                )
                return
            clauses.append((clause.group(1), clause.group(2)))

    version: Optional[str] = None
    for op, ver in clauses:
        if op in ("==", "===") and "*" not in ver:
            version = ver
            break

    specifier = ",".join(f"{op}{ver}" for op, ver in clauses)
    result.dependencies.append(
        Dependency(name, version, specifier, extras, marker, source, number)
    )


# ------------------------------------------------------------------- files

def _parse_text(
    text: str,
    source: str,
    result: ParseResult,
    follow: Callable[[str, int], None],
) -> None:
    for number, line in _logical_lines(text):
        if line.startswith("-"):
            include = _INCLUDE.match(line)
            if include:
                follow(include.group("target").strip(), number)
            else:
                result.issues.append(
                    ParseIssue(source, number, f"Unsupported option skipped: {_shorten(line)}")
                )
            continue
        _parse_requirement(line, source, number, result)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _display(path: Path, root: Path) -> str:
    resolved = path.resolve()
    if _is_within(resolved, root):
        return resolved.relative_to(root).as_posix()
    return str(path)


def _parse_file(
    path: Path, root: Path, depth: int, active: Set[Path], result: ParseResult
) -> None:
    resolved = path.resolve()
    text = _read_text(path)
    source = _display(path, root)
    active.add(resolved)

    def follow(target: str, number: int) -> None:
        def skip(message: str) -> None:
            result.issues.append(ParseIssue(source, number, message))

        if "://" in target:
            skip(f"URL includes are not supported: {_shorten(target)}")
            return
        if depth >= MAX_INCLUDE_DEPTH:
            skip(f"Include skipped, nested more than {MAX_INCLUDE_DEPTH} levels deep: {target}")
            return
        child = path.parent / target
        try:
            child_resolved = child.resolve()
        except (OSError, RuntimeError):
            skip(f"Include could not be resolved: {_shorten(target)}")
            return
        if not _is_within(child_resolved, root):
            skip(f"Include outside the project folder skipped: {_shorten(target)}")
            return
        if child_resolved in active:
            skip(f"Circular include skipped: {target}")
            return
        try:
            _parse_file(child, root, depth + 1, active, result)
        except RequirementsError as exc:
            skip(f"Could not read include: {exc}")

    try:
        _parse_text(text, source, result, follow)
    finally:
        active.discard(resolved)


# --------------------------------------------------------------- public API

def parse_requirements(
    path: Union[str, Path], root: Union[str, Path, None] = None
) -> ParseResult:
    """Parse a requirements file and any files it includes with `-r`.

    `root` is the project folder. Includes that resolve outside it are skipped
    with an issue. It defaults to the folder containing `path`.

    Raises RequirementsError if `path` itself cannot be read. Problems with
    individual lines or included files are reported in `result.issues`.
    """
    top = Path(path)
    root_dir = (Path(root) if root is not None else top.parent).resolve()
    result = ParseResult()
    _parse_file(top, root_dir, 0, set(), result)
    return result


def parse_requirements_text(text: str, source: str = "<text>") -> ParseResult:
    """Parse requirements from a string. `-r` includes are reported, not followed."""
    result = ParseResult()

    def follow(target: str, number: int) -> None:
        result.issues.append(
            ParseIssue(source, number, f"Include not followed when parsing text: {_shorten(target)}")
        )

    _parse_text(text, source, result, follow)
    return result

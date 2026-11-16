"""Python project files other than requirements.txt.

    pyproject.toml   what the project asks for (PEP 621, dependency groups,
                     Poetry, uv, PDM tables)
    poetry.lock      the resolved tree, with which package pulls in which
    uv.lock          the same, written by uv
    Pipfile.lock     pinned versions, split into default and develop

Nothing here is executed or installed; the files are only read as data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from valtrix.models import PYPI, Dependency, ParseIssue, ParseResult, normalize_name
from valtrix.parsers.common import (
    MAX_DEPENDENCIES,
    ParseError,
    clean,
    items,
    read_json,
    read_text,
    read_toml,
    table,
)
from valtrix.parsers.requirements import _parse_requirement

# Optional-dependency groups with these names are tooling, not part of the product.
_DEV_EXTRAS = frozenset({"dev", "develop", "development", "test", "tests", "testing",
                         "doc", "docs", "lint", "linting", "typing", "ci", "qa", "bench"})
_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_EXACT = re.compile(r"^(?:==\s*)?([0-9][A-Za-z0-9.+!_-]*)$")
_PACKAGE_NAME_LINE = re.compile(r'^name\s*=\s*"([^"]*)"')


@dataclass
class Declared:
    """What pyproject.toml asks for.

    requirements  (PEP 508 text, dev) pairs.
    poetry        (name, constraint, dev) triples from Poetry's own tables.
    direct        normalized name -> dev flag, for every package named above.
    """

    requirements: List[Tuple[str, bool]] = field(default_factory=list)
    poetry: List[Tuple[str, Any, bool]] = field(default_factory=list)
    direct: Dict[str, bool] = field(default_factory=dict)

    def note(self, name: str, dev: bool) -> None:
        key = normalize_name(name)
        # Needed in production wins over "also listed for development".
        self.direct[key] = self.direct.get(key, True) and dev


def read_pyproject(path: Path) -> Declared:
    data = read_toml(path)
    declared = Declared()

    def add_strings(values: Any, dev: bool) -> None:
        for value in items(values):
            text = clean(value, 500)
            match = _REQ_NAME.match(text)
            if match:
                declared.requirements.append((text, dev))
                declared.note(match.group(1), dev)

    def add_poetry(values: Any, dev: bool) -> None:
        for name, spec in table(values).items():
            name = clean(name, 200)
            if name.lower() == "python" or not _NAME.match(name):
                continue
            declared.poetry.append((name, spec, dev))
            declared.note(name, dev)

    project = table(data.get("project"))
    add_strings(project.get("dependencies"), False)
    for extra, values in table(project.get("optional-dependencies")).items():
        add_strings(values, extra.lower() in _DEV_EXTRAS)
    for values in table(data.get("dependency-groups")).values():
        add_strings(values, True)  # {include-group = ...} entries are not strings and are skipped

    tool = table(data.get("tool"))
    poetry = table(tool.get("poetry"))
    add_poetry(poetry.get("dependencies"), False)
    add_poetry(poetry.get("dev-dependencies"), True)
    for group in table(poetry.get("group")).values():
        add_poetry(table(group).get("dependencies"), True)
    add_strings(table(tool.get("uv")).get("dev-dependencies"), True)
    for values in table(table(tool.get("pdm")).get("dev-dependencies")).values():
        add_strings(values, True)
    return declared


def _line_finder(path: Path):
    try:
        lines = read_text(path).splitlines()
    except ParseError:
        lines = []

    def find(needle: str) -> int:
        for number, line in enumerate(lines, start=1):
            if needle in line:
                return number
        return 1

    return find


def parse_pyproject(path: Path, source: str, declared: Optional[Declared] = None) -> ParseResult:
    """The dependencies pyproject.toml declares. Only exact `==` pins can be checked."""
    declared = declared if declared is not None else read_pyproject(path)
    find = _line_finder(path)
    result = ParseResult()

    for text, dev in declared.requirements:
        before = len(result.dependencies)
        _parse_requirement(text, source, find(text), result)
        for index in range(before, len(result.dependencies)):
            dep = result.dependencies[index]
            result.dependencies[index] = replace(dep, direct=True, dev=dev)

    for name, spec, dev in declared.poetry:
        line = find(name)
        version, specifier = _poetry_constraint(spec)
        result.dependencies.append(
            Dependency(normalize_name(name), version, specifier, (), None, source, line,
                       PYPI, True, dev)
        )
    return result


def _poetry_constraint(spec: Any) -> Tuple[Optional[str], str]:
    """(exact version or None, constraint text) for a Poetry dependency value."""
    if isinstance(spec, list):
        spec = spec[0] if spec else ""
    if isinstance(spec, dict):
        if any(key in spec for key in ("git", "path", "url")):
            return None, "@ " + clean(spec.get("git") or spec.get("path") or spec.get("url"), 200)
        spec = spec.get("version", "")
    text = clean(spec, 200)
    match = _EXACT.match(text)
    if match and "*" not in text:
        return match.group(1), "==" + match.group(1)
    return None, text.replace(" ", "")


# ------------------------------------------------------------------ lock files

def _package_lines(path: Path) -> List[int]:
    """Line number of each [[package]] entry's name, in file order."""
    numbers: List[int] = []
    waiting = False
    for number, line in enumerate(read_text(path).splitlines(), start=1):
        stripped = line.strip()
        if stripped == "[[package]]":
            waiting = True
        elif waiting and _PACKAGE_NAME_LINE.match(stripped):
            numbers.append(number)
            waiting = False
    return numbers


def _lock_packages(path: Path) -> Tuple[List[Dict[str, Any]], List[int]]:
    data = read_toml(path)
    packages = [table(p) for p in items(data.get("package")) if isinstance(p, dict)]
    lines = _package_lines(path)
    if len(lines) != len(packages):
        lines = [0] * len(packages)
    return packages, lines


def parse_poetry_lock(path: Path, source: str, direct: Optional[Dict[str, bool]] = None) -> ParseResult:
    """`direct` maps the names pyproject.toml asks for to their dev flag (None if unknown)."""
    packages, lines = _lock_packages(path)
    result = ParseResult()
    by_name: Dict[str, Tuple[str, str, str]] = {}
    wanted: List[Tuple[Tuple[str, str, str], List[str]]] = []

    for package, line in zip(packages[:MAX_DEPENDENCIES], lines):
        name, version = clean(package.get("name"), 200), clean(package.get("version"), 100)
        if not _NAME.match(name) or not version:
            result.issues.append(ParseIssue(source, line, "Package entry without a usable name and version skipped"))
            continue
        name = normalize_name(name)
        is_direct = None if direct is None else name in direct
        dev = bool(direct and direct.get(name)) or package.get("category") == "dev"
        dep = Dependency(name, version, f"=={version}", (), None, source, line, PYPI, is_direct, dev)
        result.dependencies.append(dep)
        by_name.setdefault(name, dep.node)
        wanted.append((dep.node, [normalize_name(clean(n, 200)) for n in table(package.get("dependencies"))]))

    for parent, names in wanted:
        for name in names:
            if name in by_name:
                result.edges.append((parent, by_name[name]))
    if len(packages) > MAX_DEPENDENCIES:
        result.issues.append(ParseIssue(source, 0, f"Only the first {MAX_DEPENDENCIES} packages were read"))
    return result


def _uv_names(values: Any) -> List[Tuple[str, str]]:
    out = []
    for entry in items(values):
        entry = table(entry)
        name = clean(entry.get("name"), 200)
        if name:
            out.append((normalize_name(name), clean(entry.get("version"), 100)))
    return out


def parse_uv_lock(path: Path, source: str) -> ParseResult:
    packages, lines = _lock_packages(path)
    result = ParseResult()
    by_name: Dict[str, List[Tuple[str, str, str]]] = {}
    wanted: List[Tuple[Tuple[str, str, str], List[Tuple[str, str]]]] = []
    direct: Dict[str, bool] = {}
    have_root = False
    entries: List[Tuple[str, str, int]] = []

    for package, line in zip(packages[:MAX_DEPENDENCIES], lines):
        name, version = clean(package.get("name"), 200), clean(package.get("version"), 100)
        if not _NAME.match(name):
            result.issues.append(ParseIssue(source, line, "Package entry without a usable name skipped"))
            continue
        name = normalize_name(name)
        origin = table(package.get("source"))
        if any(key in origin for key in ("editable", "virtual")):
            # The project itself (or a workspace member): what it lists is direct.
            have_root = True
            for dep_name, _ in _uv_names(package.get("dependencies")):
                direct[dep_name] = False
            for values in table(package.get("optional-dependencies")).values():
                for dep_name, _ in _uv_names(values):
                    direct.setdefault(dep_name, False)
            for values in table(package.get("dev-dependencies")).values():
                for dep_name, _ in _uv_names(values):
                    direct.setdefault(dep_name, True)
            continue
        if not version:
            result.issues.append(ParseIssue(source, line, f"'{name}' has no version in the lock file"))
            continue
        entries.append((name, version, line))
        node = (PYPI, name, version)
        by_name.setdefault(name, []).append(node)
        children = _uv_names(package.get("dependencies"))
        for values in table(package.get("optional-dependencies")).values():
            children.extend(_uv_names(values))
        wanted.append((node, children))

    for name, version, line in entries:
        is_direct = (name in direct) if have_root else None
        dev = bool(direct.get(name))
        result.dependencies.append(
            Dependency(name, version, f"=={version}", (), None, source, line, PYPI, is_direct, dev)
        )
    for parent, children in wanted:
        for name, version in children:
            for node in by_name.get(name, ()):
                if not version or node[2] == version:
                    result.edges.append((parent, node))
                    break
    return result


def parse_pipfile_lock(path: Path, source: str, direct: Optional[Dict[str, bool]] = None) -> ParseResult:
    data = read_json(path)
    find = _line_finder(path)
    result = ParseResult()
    for section, dev in (("default", False), ("develop", True)):
        for raw_name, info in table(data.get(section)).items():
            name = clean(raw_name, 200)
            line = find(f'"{raw_name}"')
            if not _NAME.match(name):
                result.issues.append(ParseIssue(source, line, "Package entry without a usable name skipped"))
                continue
            name = normalize_name(name)
            is_direct = None if direct is None else name in direct
            pinned = _EXACT.match(clean(table(info).get("version"), 100))
            if pinned:
                version: Optional[str] = pinned.group(1)
                specifier = f"=={version}"
            else:
                version, specifier = None, "@ " + source if not table(info).get("version") else clean(table(info).get("version"), 100)
            result.dependencies.append(
                Dependency(name, version, specifier, (), None, source, line, PYPI, is_direct, dev)
            )
    return result


def read_pipfile(path: Path) -> Dict[str, bool]:
    """Names the Pipfile asks for, mapped to their dev flag."""
    data = read_toml(path)
    direct: Dict[str, bool] = {}
    for name in table(data.get("dev-packages")):
        direct[normalize_name(name)] = True
    for name in table(data.get("packages")):
        direct[normalize_name(name)] = False
    return direct

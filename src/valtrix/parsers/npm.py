"""npm lock files: package-lock.json and npm-shrinkwrap.json.

Lock file versions 2 and 3 list every installed package under "packages",
keyed by its folder ("node_modules/a/node_modules/b"). Version 1 nests them
under "dependencies". Both record which package needs which, so the result
includes graph edges.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from valtrix.models import NPM, Dependency, ParseIssue, ParseResult
from valtrix.parsers.common import MAX_DEPENDENCIES, ParseError, clean, read_json, read_text, table

_NAME = re.compile(r"^(?:@[A-Za-z0-9~_-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~_-][A-Za-z0-9._~-]*$")
_VERSION = re.compile(r"^[0-9][A-Za-z0-9.+_-]{0,99}$")
_KEY_LINE = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*:\s*\{')
_MAX_DEPTH = 50
_MODULES = "node_modules/"
_DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")

Node = Tuple[str, str, str]


def _key_lines(path: Path) -> Dict[str, int]:
    found: Dict[str, int] = {}
    try:
        lines = read_text(path).splitlines()
    except ParseError:
        return found
    for number, line in enumerate(lines, start=1):
        match = _KEY_LINE.match(line)
        if match:
            found.setdefault(match.group(1), number)
    return found


def parse_package_lock(path: Path, source: str, package_json: Optional[Path] = None) -> ParseResult:
    data = read_json(path)
    lines = _key_lines(path)
    if isinstance(data.get("packages"), dict):
        return _parse_packages(table(data["packages"]), source, lines)
    if isinstance(data.get("dependencies"), dict):
        return _parse_nested(table(data["dependencies"]), source, lines, _declared(package_json))
    result = ParseResult()
    result.issues.append(ParseIssue(source, 1, "No packages are listed in this lock file"))
    return result


def _declared(package_json: Optional[Path]) -> Optional[Dict[str, bool]]:
    """Names package.json asks for, mapped to their dev flag (None if it cannot be read)."""
    if package_json is None or not package_json.is_file():
        return None
    try:
        data = read_json(package_json)
    except ParseError:
        return None
    direct: Dict[str, bool] = {name: True for name in table(data.get("devDependencies"))}
    for field in _DEP_FIELDS:
        for name in table(data.get(field)):
            direct[name] = False
    return direct


def _usable(name: str, version: str) -> bool:
    return bool(_NAME.match(name) and _VERSION.match(version))


# ------------------------------------------------------------ versions 2 and 3

def _resolve(packages: Dict[str, Any], start: str, name: str) -> Optional[str]:
    """Find the folder npm would load `name` from, starting inside `start`."""
    base = start
    while True:
        candidate = f"{base}/{_MODULES}{name}" if base else f"{_MODULES}{name}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        cut = base.rfind("/" + _MODULES)
        base = base[:cut] if cut >= 0 else ""


def _parse_packages(packages: Dict[str, Any], source: str, lines: Dict[str, int]) -> ParseResult:
    result = ParseResult()
    nodes: Dict[str, Node] = {}
    listed: List[Tuple[str, Dict[str, Any]]] = []

    for key, raw in packages.items():
        entry = table(raw)
        if _MODULES not in key or entry.get("link"):
            continue  # the project itself, a workspace folder, or a symlink to one
        name = clean(entry.get("name"), 214) or key.rsplit(_MODULES, 1)[1]
        version = clean(entry.get("version"), 100)
        if not _usable(name, version):
            result.issues.append(ParseIssue(source, lines.get(key, 0), f"Entry skipped, no usable name and version: {clean(key, 80)}"))
            continue
        if len(listed) >= MAX_DEPENDENCIES:
            result.issues.append(ParseIssue(source, 0, f"Only the first {MAX_DEPENDENCIES} packages were read"))
            break
        nodes[key] = (NPM, name, version)
        listed.append((key, entry))

    # Roots: the project ("") and workspace folders. What they ask for is direct.
    direct: Dict[str, bool] = {}
    for key, raw in packages.items():
        if _MODULES in key:
            continue
        entry = table(raw)
        for field, dev in (("devDependencies", True),) + tuple((f, False) for f in _DEP_FIELDS):
            for name in table(entry.get(field)):
                target = _resolve(packages, key, name)
                if target in nodes:
                    direct[target] = direct.get(target, True) and dev

    for key, entry in listed:
        _, name, version = nodes[key]
        dev = bool(entry.get("dev")) or direct.get(key, False)
        result.dependencies.append(
            Dependency(name, version, f"=={version}", (), None, source, lines.get(key, 0),
                       NPM, key in direct, dev)
        )
        for field in _DEP_FIELDS:
            for child in table(entry.get(field)):
                target = _resolve(packages, key, child)
                if target in nodes:
                    result.edges.append((nodes[key], nodes[target]))
    return result


# ------------------------------------------------------------------- version 1

def _parse_nested(
    tree: Dict[str, Any], source: str, lines: Dict[str, int], direct: Optional[Dict[str, bool]]
) -> ParseResult:
    result = ParseResult()
    seen: Set[int] = set()

    def walk(level: Dict[str, Any], scopes: List[Dict[str, Node]], depth: int) -> None:
        here: Dict[str, Node] = {}
        usable: List[Tuple[str, Dict[str, Any]]] = []
        for name, raw in level.items():
            entry = table(raw)
            version = clean(entry.get("version"), 100)
            if not _usable(name, version):
                result.issues.append(ParseIssue(source, lines.get(name, 0), f"Entry skipped, no usable name and version: {clean(name, 80)}"))
                continue
            here[name] = (NPM, name, version)
            usable.append((name, entry))
        chain = scopes + [here]

        for name, entry in usable:
            if len(result.dependencies) >= MAX_DEPENDENCIES or id(entry) in seen:
                return
            seen.add(id(entry))
            node = here[name]
            top = depth == 0
            is_direct = None if direct is None else (top and name in direct)
            dev = bool(entry.get("dev")) or bool(top and direct and direct.get(name))
            result.dependencies.append(
                Dependency(name, node[2], f"=={node[2]}", (), None, source, lines.get(name, 0),
                           NPM, is_direct, dev)
            )
            nested = table(entry.get("dependencies"))
            inner = {n: (NPM, n, clean(table(v).get("version"), 100)) for n, v in nested.items()}
            for child in table(entry.get("requires")):
                for scope in [inner] + chain[::-1]:
                    if child in scope and scope[child][2]:
                        result.edges.append((node, scope[child]))
                        break
            if nested and depth < _MAX_DEPTH:
                walk(nested, chain, depth + 1)

    walk(tree, [], 0)
    return result

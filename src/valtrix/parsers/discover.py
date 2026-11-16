"""Find every dependency file in a project folder and read them all.

Supported files (in the project folder itself, not subfolders):

    Python   requirements.txt and common dev variants, pyproject.toml,
             poetry.lock, uv.lock, Pipfile.lock
    npm      package-lock.json, npm-shrinkwrap.json
    Rust     Cargo.lock
    Go       go.mod

Lock files win over declarations: when a lock file or requirements.txt is
present, pyproject.toml is only used to tell direct dependencies from
transitive ones, because the lock has the exact versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Union

from valtrix.models import Dependency, DependencyGraph, ParseIssue, ParseResult, node_label
from valtrix.parsers.cargo import parse_cargo_lock
from valtrix.parsers.common import ParseError
from valtrix.parsers.gomod import parse_go_mod
from valtrix.parsers.npm import parse_package_lock
from valtrix.parsers.python_project import (
    Declared,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject,
    parse_uv_lock,
    read_pipfile,
    read_pyproject,
)
from valtrix.parsers.requirements import parse_requirements

DEV_REQUIREMENTS = (
    "requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt",
    "requirements-test.txt", "requirements_test.txt", "test-requirements.txt",
)
SUPPORTED_FILES = (
    "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock",
    "package-lock.json", "npm-shrinkwrap.json", "Cargo.lock", "go.mod",
)


@dataclass
class Project:
    """Everything found in a project folder.

    sources  Files that were read, relative to the folder. Empty means no
             supported dependency file exists.
    """

    dependencies: List[Dependency] = field(default_factory=list)
    issues: List[ParseIssue] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    graph: DependencyGraph = field(default_factory=DependencyGraph)


def discover(root: Union[str, Path]) -> Project:
    """Read every supported dependency file in `root`.

    Raises ParseError if a file exists but cannot be read at all. Problems
    with single lines or entries are reported in `issues`.
    """
    folder = Path(root).resolve()
    project = Project()
    files: List[str] = []

    def present(name: str) -> Optional[Path]:
        path = folder / name
        return path if path.is_file() else None

    def take(name: str, parsed: ParseResult, dev: bool = False) -> None:
        files.append(name)
        deps = [replace(d, dev=True) for d in parsed.dependencies] if dev else parsed.dependencies
        project.dependencies.extend(deps)
        project.issues.extend(parsed.issues)
        for parent, child in parsed.edges:
            project.graph.add_edge(parent, child)

    # ------------------------------------------------------------- Python
    pyproject = present("pyproject.toml")
    declared: Optional[Declared] = read_pyproject(pyproject) if pyproject else None
    python_pins = False

    if present("requirements.txt"):
        python_pins = True
        take("requirements.txt", parse_requirements(folder / "requirements.txt", root=folder))
    for name in DEV_REQUIREMENTS:
        if present(name) and name not in {d.source for d in project.dependencies}:
            python_pins = True
            take(name, parse_requirements(folder / name, root=folder), dev=True)
    if present("poetry.lock"):
        python_pins = True
        take("poetry.lock", parse_poetry_lock(folder / "poetry.lock", "poetry.lock",
                                              declared.direct if declared else None))
    if present("uv.lock"):
        python_pins = True
        take("uv.lock", parse_uv_lock(folder / "uv.lock", "uv.lock"))
    if present("Pipfile.lock"):
        python_pins = True
        direct: Optional[Dict[str, bool]] = None
        if present("Pipfile"):
            try:
                direct = read_pipfile(folder / "Pipfile")
            except ParseError:
                direct = None
        take("Pipfile.lock", parse_pipfile_lock(folder / "Pipfile.lock", "Pipfile.lock", direct))
    if pyproject and declared is not None and not python_pins:
        parsed = parse_pyproject(pyproject, "pyproject.toml", declared)
        if parsed.dependencies or parsed.issues:
            take("pyproject.toml", parsed)

    # ---------------------------------------------------------------- npm
    lock = present("package-lock.json") or present("npm-shrinkwrap.json")
    if lock:
        take(lock.name, parse_package_lock(lock, lock.name, folder / "package.json"))
    elif present("package.json"):
        files.append("package.json")
        project.issues.append(ParseIssue(
            "package.json", 1,
            "No package-lock.json next to it, so exact versions are unknown. "
            "Run `npm install --package-lock-only` and scan again"))

    # ------------------------------------------------------------ Rust, Go
    if present("Cargo.lock"):
        take("Cargo.lock", parse_cargo_lock(folder / "Cargo.lock", "Cargo.lock"))
    elif present("Cargo.toml"):
        files.append("Cargo.toml")
        project.issues.append(ParseIssue(
            "Cargo.toml", 1,
            "No Cargo.lock next to it, so exact versions are unknown. "
            "Run `cargo generate-lockfile` and scan again"))
    if present("go.mod"):
        take("go.mod", parse_go_mod(folder / "go.mod", "go.mod"))

    _annotate(project)
    project.sources = sorted({d.source for d in project.dependencies if d.source} | set(files))
    return project


def _annotate(project: Project) -> None:
    """Use the graph to fill in each dependency's path and dev-only status."""
    graph = project.graph
    for dep in project.dependencies:
        if dep.direct:
            graph.add_root(dep.node)
    if not graph.children:
        return

    paths = graph.shortest_paths()
    production = graph.reachable(d.node for d in project.dependencies if d.direct and not d.dev)
    development = graph.reachable(d.node for d in project.dependencies if d.direct and d.dev)

    for index, dep in enumerate(project.dependencies):
        changes = {}
        chain = paths.get(dep.node, ())
        if dep.direct is False and len(chain) > 1:
            changes["path"] = tuple(node_label(node) for node in chain)
        if not dep.dev and dep.node in development and dep.node not in production:
            changes["dev"] = True
        if changes:
            project.dependencies[index] = replace(dep, **changes)

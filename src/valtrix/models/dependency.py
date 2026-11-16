"""The Dependency model: one package requirement found in a project."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple


PYPI = "PyPI"
NPM = "npm"
CARGO = "crates.io"
GO = "Go"
ECOSYSTEMS = (PYPI, NPM, CARGO, GO)


def normalize_name(name: str) -> str:
    """Normalize a package name the way PyPI does (PEP 503).

    `Flask_SQLAlchemy`, `flask.sqlalchemy` and `flask-sqlalchemy` are all the
    same package, so we compare and look up the normalized form.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Dependency:
    """A single requirement, as written in a project file.

    name       Normalized package name, e.g. "flask-sqlalchemy".
    version    The exact pinned version ("2.31.0"), or None if the file does
               not pin one. Vulnerability lookups need an exact version.
    specifier  The version constraint as written, normalized without spaces,
               e.g. "==2.31.0", ">=3.2,<4.0", or "" when there is none.
    extras     Optional feature groups requested, e.g. ("security",).
    marker     Environment marker text, e.g. 'sys_platform == "win32"'.
    source     File the requirement came from, relative to the project root.
    line       1-based line number in that file (0 when the format has none).
    ecosystem  The package registry, using OSV's names: "PyPI", "npm",
               "crates.io" or "Go".
    direct     True if the project asks for this package itself, False if it
               is only pulled in by another package, None if the file does
               not say.
    dev        True if it is only needed for development or testing.
    path       For a transitive dependency, the chain that pulls it in,
               starting at a direct dependency and ending at this package,
               e.g. ("flask 2.0.1", "jinja2 3.0.1"). Empty when unknown.
    """

    name: str
    version: Optional[str] = None
    specifier: str = ""
    extras: Tuple[str, ...] = ()
    marker: Optional[str] = None
    source: str = ""
    line: int = 0
    ecosystem: str = PYPI
    direct: Optional[bool] = None
    dev: bool = False
    path: Tuple[str, ...] = ()

    @property
    def is_pinned(self) -> bool:
        return self.version is not None

    @property
    def node(self) -> Tuple[str, str, str]:
        """Identity in the dependency graph: (ecosystem, name, version)."""
        return (self.ecosystem, self.name, self.version or "")

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name

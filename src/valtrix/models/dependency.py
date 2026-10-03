"""The Dependency model: one package requirement found in a project."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple


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
    line       1-based line number in that file.
    """

    name: str
    version: Optional[str] = None
    specifier: str = ""
    extras: Tuple[str, ...] = ()
    marker: Optional[str] = None
    source: str = ""
    line: int = 0

    @property
    def is_pinned(self) -> bool:
        return self.version is not None

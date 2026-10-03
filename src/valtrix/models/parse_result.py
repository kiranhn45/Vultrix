"""What a parser returns: the dependencies it found plus anything it skipped."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from valtrix.models.dependency import Dependency


@dataclass(frozen=True)
class ParseIssue:
    """A line or file the parser could not use. Never silently dropped."""

    source: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.source}:{self.line}: {self.message}"


@dataclass
class ParseResult:
    dependencies: List[Dependency] = field(default_factory=list)
    issues: List[ParseIssue] = field(default_factory=list)

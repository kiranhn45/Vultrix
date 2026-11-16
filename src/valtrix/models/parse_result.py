"""What a parser returns: the dependencies it found plus anything it skipped."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from valtrix.models.dependency import Dependency


@dataclass(frozen=True)
class ParseIssue:
    """A line or file the parser could not use. Never silently dropped."""

    source: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.source}:{self.line}: {self.message}"


Node = Tuple[str, str, str]  # (ecosystem, name, version)


@dataclass
class ParseResult:
    """dependencies  Everything the file lists.
    issues        Lines or entries that could not be used.
    edges         (parent, child) pairs when the file records which package
                  pulls in which. Lock files do; requirements.txt does not.
    """

    dependencies: List[Dependency] = field(default_factory=list)
    issues: List[ParseIssue] = field(default_factory=list)
    edges: List[Tuple[Node, Node]] = field(default_factory=list)

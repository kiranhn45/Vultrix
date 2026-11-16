"""Scan results: what was found, what could not be checked, and why."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from valtrix.models.dependency import Dependency
from valtrix.models.graph import DependencyGraph
from valtrix.models.parse_result import ParseIssue
from valtrix.models.vulnerability import Vulnerability

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def severity_rank(label: Optional[str]) -> int:
    """0 is most severe. Unknown severity sorts after LOW, not as "safe"."""
    return SEVERITY_ORDER.index(label) if label in SEVERITY_ORDER else len(SEVERITY_ORDER)


PRIORITIES = ("fix now", "fix soon", "plan", "monitor")


@dataclass(frozen=True)
class Factor:
    """One reason a finding scored what it did.

    name    "Severity", "Exploitation", "Exposure" or "Fix".
    points  What this factor added to the score.
    detail  A sentence a person can read.
    """

    name: str
    points: int
    detail: str


@dataclass(frozen=True)
class Risk:
    """How urgently a finding should be fixed, and why.

    score       0 to 100. The sum of the factor points.
    priority    One of PRIORITIES.
    factors     Every factor that went into the score, in a fixed order.
    severity    The label used for scoring: the published one, or the
                estimate when none is published, or "UNKNOWN".
    estimated   True if `severity` is an estimate, not a published value.
    cvss_score  CVSS base score computed from the published vector, if any.
    """

    score: int
    priority: str
    factors: Tuple[Factor, ...] = ()
    severity: str = "UNKNOWN"
    estimated: bool = False
    cvss_score: Optional[float] = None


@dataclass(frozen=True)
class Finding:
    """One vulnerability affecting one dependency.

    fix   The fixed version that applies to the installed version, or None if
          no usable fix is listed. The vulnerability itself keeps every fixed
          version the database mentions.
    risk  Filled in by valtrix.risk.prioritize(); None before that.
    """

    dependency: Dependency
    vulnerability: Vulnerability
    fix: Optional[str] = None
    risk: Optional[Risk] = None


@dataclass(frozen=True)
class Unchecked:
    """A dependency that was not checked against the database.

    failed  True if a lookup was attempted and failed (counts as an incomplete
            scan). False if it was skipped by design, e.g. the version is not
            pinned.
    """

    dependency: Dependency
    reason: str
    failed: bool = False


@dataclass(frozen=True)
class Ignored:
    """A finding the project chose to accept, with the reason on record."""

    finding: Finding
    reason: str
    expires: Optional[str] = None


def count_by_severity(findings: Sequence[Finding]) -> Dict[str, int]:
    """Counts per severity label, with unknown severity under "UNKNOWN"."""
    counts: Dict[str, int] = {}
    for finding in findings:
        label = finding.vulnerability.severity_label or "UNKNOWN"
        counts[label] = counts.get(label, 0) + 1
    return counts


@dataclass
class ScanResult:
    sources: List[str] = field(default_factory=list)
    scanned: List[Dependency] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    unchecked: List[Unchecked] = field(default_factory=list)
    parse_issues: List[ParseIssue] = field(default_factory=list)
    ignored: List["Ignored"] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    graph: DependencyGraph = field(default_factory=DependencyGraph)

    @property
    def incomplete(self) -> bool:
        """True if any lookup failed, so the result may be missing vulnerabilities."""
        return any(item.failed for item in self.unchecked)

    @property
    def vulnerable_dependencies(self) -> List[Dependency]:
        seen: List[Dependency] = []
        for finding in self.findings:
            if finding.dependency not in seen:
                seen.append(finding.dependency)
        return seen

    def findings_for(self, dependency: Dependency) -> List[Finding]:
        return [f for f in self.findings if f.dependency == dependency]

"""Scan results: what was found, what could not be checked, and why."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from valtrix.models.dependency import Dependency
from valtrix.models.parse_result import ParseIssue
from valtrix.models.vulnerability import Vulnerability

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def severity_rank(label: Optional[str]) -> int:
    """0 is most severe. Unknown severity sorts after LOW, not as "safe"."""
    return SEVERITY_ORDER.index(label) if label in SEVERITY_ORDER else len(SEVERITY_ORDER)


@dataclass(frozen=True)
class Finding:
    """One vulnerability affecting one dependency.

    fix  The fixed version that applies to the installed version, or None if
         no usable fix is listed. The vulnerability itself keeps every fixed
         version the database mentions.
    """

    dependency: Dependency
    vulnerability: Vulnerability
    fix: Optional[str] = None


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

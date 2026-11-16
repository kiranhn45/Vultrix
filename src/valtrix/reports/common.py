"""Pieces every report format shares."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from valtrix import __version__
from valtrix.databases.exploits import ExploitData
from valtrix.models import PRIORITIES, SEVERITY_ORDER, Finding, ScanResult, severity_rank

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BAD_INPUT = 2
EXIT_INCOMPLETE = 3

FAIL_RANK = {"low": 3, "medium": 2, "high": 1, "critical": 0}


@dataclass
class ReportMeta:
    """Facts about the run that are not part of the scan result itself."""

    target: str = ""
    version: str = __version__
    generated_at: str = ""
    fail_on: str = "low"
    exploit_data: Optional[ExploitData] = None
    model_used: bool = True
    config_source: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = (
                datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            )


def plural(count: int, singular: str, many: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (many or singular + 's')}"


def one_line(text: str) -> str:
    return " ".join(text.split())


def effective_severity(finding: Finding) -> str:
    """The published label, or the one used for scoring, or "UNKNOWN"."""
    if finding.vulnerability.severity_label:
        return finding.vulnerability.severity_label
    return finding.risk.severity if finding.risk else "UNKNOWN"


def fails(finding: Finding, fail_on: str) -> bool:
    """Does this finding reach the `fail_on` level? Unknown severity always does."""
    if fail_on == "none":
        return False
    severity = effective_severity(finding)
    if severity not in SEVERITY_ORDER:
        return True
    return severity_rank(severity) <= FAIL_RANK[fail_on]


def exit_code(result: ScanResult, fail_on: str = "low") -> int:
    if any(fails(f, fail_on) for f in result.findings):
        return EXIT_FINDINGS
    if result.incomplete:
        return EXIT_INCOMPLETE
    return EXIT_OK


def count_by_priority(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {name: 0 for name in PRIORITIES}
    for finding in findings:
        if finding.risk:
            counts[finding.risk.priority] += 1
    return counts


def exploit_notes(meta: ReportMeta) -> List[str]:
    return list(meta.exploit_data.notes) if meta.exploit_data else []

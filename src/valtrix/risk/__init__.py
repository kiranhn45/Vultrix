"""Risk prioritization: decide what to fix first, and say why."""

from __future__ import annotations

from dataclasses import replace
from typing import Optional

from valtrix.databases.exploits import ExploitData
from valtrix.models import ScanResult, severity_rank
from valtrix.risk.cvss import best_score, cvss3_base_score, label_for_score
from valtrix.risk.rules import priority_for, score_finding
from valtrix.risk.severity_model import (
    Estimate,
    SeverityModel,
    default_model,
    estimate_severity,
    keyword_estimate,
)

__all__ = [
    "Estimate",
    "SeverityModel",
    "best_score",
    "cvss3_base_score",
    "default_model",
    "estimate_severity",
    "keyword_estimate",
    "label_for_score",
    "prioritize",
    "priority_for",
    "score_finding",
]


def needs_estimate(finding) -> bool:
    vuln = finding.vulnerability
    if vuln.id.upper().startswith("MAL-") or vuln.severity_label:
        return False
    score = best_score(vuln.cvss)
    return score is None or score <= 0


def prioritize(
    result: ScanResult,
    exploit_data: Optional[ExploitData] = None,
    use_model: bool = True,
    model: Optional[SeverityModel] = None,
) -> ScanResult:
    """Score every finding and put the most urgent first. Changes `result` in place.

    use_model  When False, missing severities are estimated by the keyword
               rules instead of the trained model (the rule-only baseline).
    """
    scored = []
    for finding in result.findings:
        estimate = estimate_severity(finding.vulnerability, model, use_model) if needs_estimate(finding) else None
        scored.append(replace(finding, risk=score_finding(finding, exploit_data, estimate)))
    scored.sort(key=lambda f: (
        -f.risk.score,
        severity_rank(f.risk.severity),
        f.dependency.name,
        f.vulnerability.id,
    ))
    result.findings = scored
    return result

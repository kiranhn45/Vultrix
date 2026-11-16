"""SARIF 2.1.0 output, the format GitHub code scanning and other CI tools read.

Each finding becomes a result pointing at the line of the dependency file
that brings the vulnerable package in.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from valtrix.models import Finding, ScanResult
from valtrix.reports.common import ReportMeta, effective_severity, one_line
from valtrix.risk.rules import LABEL_SCORE, UNKNOWN_SCORE

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def _security_severity(finding: Finding) -> str:
    risk = finding.risk
    if risk and risk.cvss_score:
        return f"{risk.cvss_score:.1f}"
    return f"{LABEL_SCORE.get(effective_severity(finding), UNKNOWN_SCORE):.1f}"


def build_sarif(result: ScanResult, meta: ReportMeta) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for finding in result.findings:
        vuln, dep = finding.vulnerability, finding.dependency
        summary = one_line(vuln.summary) or f"Known vulnerability in {dep.name}"
        if vuln.id not in index:
            index[vuln.id] = len(rules)
            rules.append({
                "id": vuln.id,
                "name": "VulnerableDependency",
                "shortDescription": {"text": summary[:300]},
                "fullDescription": {"text": (one_line(vuln.details) or summary)[:1000]},
                "helpUri": vuln.osv_url,
                "properties": {
                    "security-severity": _security_severity(finding),
                    "tags": ["security", "dependency"] + list(vuln.cwes[:5]),
                },
            })
        fix = f" Upgrade to {finding.fix}." if finding.fix else " No fixed version is listed."
        text = f"{dep.label} ({dep.ecosystem}) is affected by {vuln.id}: {summary}.{fix}"
        if finding.risk:
            text += f" Risk score {finding.risk.score}/100 ({finding.risk.priority})."
        results.append({
            "ruleId": vuln.id,
            "ruleIndex": index[vuln.id],
            "level": _LEVEL.get(effective_severity(finding), "warning"),
            "message": {"text": text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": dep.source or "requirements.txt"},
                    "region": {"startLine": max(1, dep.line)},
                }
            }],
            "partialFingerprints": {
                "valtrix/v1": f"{dep.ecosystem}/{dep.name}@{dep.version}/{vuln.id}",
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Valtrix",
                "version": meta.version,
                "informationUri": "https://github.com/kiranhn45/Vultrix",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def render_sarif(result: ScanResult, meta: ReportMeta) -> str:
    return json.dumps(build_sarif(result, meta), indent=2, ensure_ascii=False)

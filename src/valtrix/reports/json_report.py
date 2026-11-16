"""The JSON report: the stable, machine-readable interface for CI and other tools.

The layout is documented in docs/json-report.md. `schema_version` only
changes when a field is removed or changes meaning; new fields may be added
at any time, so readers should ignore keys they do not know.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from valtrix.models import Dependency, Finding, ScanResult, Vulnerability, count_by_severity
from valtrix.reports.common import ReportMeta, count_by_priority, effective_severity, exit_code, fails
from valtrix.risk.cvss import cvss3_base_score
from valtrix.risk.severity_model import default_model

SCHEMA_VERSION = 1


def _dependency(dep: Dependency) -> Dict[str, Any]:
    return {
        "name": dep.name,
        "version": dep.version,
        "ecosystem": dep.ecosystem,
        "specifier": dep.specifier,
        "source": dep.source,
        "line": dep.line,
        "direct": dep.direct,
        "dev": dep.dev,
        "path": list(dep.path),
    }


def _vulnerability(vuln: Vulnerability) -> Dict[str, Any]:
    return {
        "id": vuln.id,
        "aliases": list(vuln.aliases),
        "summary": vuln.summary,
        "severity": vuln.severity_label,
        "cvss": [
            {"type": kind, "vector": vector, "score": cvss3_base_score(vector)}
            for kind, vector in vuln.cvss
        ],
        "cwes": list(vuln.cwes),
        "fixed_versions": list(vuln.fixed_versions),
        "references": list(vuln.references),
        "published": vuln.published,
        "modified": vuln.modified,
        "url": vuln.osv_url,
    }


def _finding(finding: Finding, rank: Optional[int], fail_on: str) -> Dict[str, Any]:
    risk = finding.risk
    return {
        "rank": rank,
        "dependency": _dependency(finding.dependency),
        "vulnerability": _vulnerability(finding.vulnerability),
        "fix": finding.fix,
        "severity": effective_severity(finding),
        "severity_estimated": bool(risk and risk.estimated),
        "fails_build": fails(finding, fail_on),
        "risk": None if risk is None else {
            "score": risk.score,
            "priority": risk.priority,
            "cvss_score": risk.cvss_score,
            "factors": [
                {"name": f.name, "points": f.points, "detail": f.detail} for f in risk.factors
            ],
        },
    }


def build_report(result: ScanResult, meta: ReportMeta) -> Dict[str, Any]:
    """The report as plain dicts and lists, ready for json.dumps."""
    exploit = meta.exploit_data
    model = default_model() if meta.model_used else None
    code = exit_code(result, meta.fail_on)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "valtrix", "version": meta.version},
        "generated_at": meta.generated_at,
        "target": meta.target,
        "sources": list(result.sources),
        "settings": {
            "fail_on": meta.fail_on,
            "config": meta.config_source,
            "exploit_data": {
                "epss": exploit.epss_status if exploit else "disabled",
                "kev": exploit.kev_status if exploit else "disabled",
            },
            "severity_model": None if model is None else {
                "trained_on": model.info.get("trained_on"),
                "evaluation": model.info.get("evaluation"),
            },
        },
        "summary": {
            "dependencies": len(result.scanned) + len(result.unchecked),
            "checked": len(result.scanned),
            "vulnerable": len(result.vulnerable_dependencies),
            "findings": len(result.findings),
            "ignored": len(result.ignored),
            "unchecked": len(result.unchecked),
            "by_severity": count_by_severity(result.findings),
            "by_priority": count_by_priority(result.findings),
            "incomplete": result.incomplete,
            "exit_code": code,
        },
        "findings": [_finding(f, rank, meta.fail_on) for rank, f in enumerate(result.findings, start=1)],
        "ignored": [
            {**_finding(item.finding, None, "none"), "reason": item.reason, "expires": item.expires}
            for item in result.ignored
        ],
        "unchecked": [
            {"dependency": _dependency(u.dependency), "reason": u.reason, "failed": u.failed}
            for u in result.unchecked
        ],
        "parse_issues": [
            {"source": i.source, "line": i.line, "message": i.message} for i in result.parse_issues
        ],
        "notes": list(result.notes) + (list(exploit.notes) if exploit else []),
    }


def render_json(result: ScanResult, meta: ReportMeta) -> str:
    return json.dumps(build_report(result, meta), indent=2, ensure_ascii=False)

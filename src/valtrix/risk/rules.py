"""Rule-based risk scoring: turn one finding into a 0-100 score with reasons.

The score is a plain sum of four factors, so every point can be explained:

    Severity      0-60   how bad it is if exploited (CVSS base score x 6)
    Exploitation  0-25   evidence that attackers use it (CISA KEV, EPSS)
    Exposure      0-8    how the package reaches the project (direct,
                         transitive, development only)
    Fix           0-7    whether a fixed version exists to upgrade to

When the database publishes no severity, an estimate is used instead and is
labelled as an estimate. Nothing here calls the network or guesses silently:
missing evidence adds no points and says so in the factor's detail.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from valtrix.databases.exploits import DISABLED, NOT_NEEDED, OK, UNAVAILABLE, ExploitData
from valtrix.models import Factor, Finding, Risk
from valtrix.risk.cvss import best_score, describe, label_for_score
from valtrix.risk.severity_model import Estimate

SEVERITY_MAX = 60
EXPLOITATION_MAX = 25
EXPOSURE_MAX = 8
FIX_POINTS = 7

# Used when only a label is published: a typical CVSS score for that label.
LABEL_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5}
UNKNOWN_SCORE = 5.5

FIX_NOW, FIX_SOON, PLAN, MONITOR = "fix now", "fix soon", "plan", "monitor"
THRESHOLDS = ((70, FIX_NOW), (50, FIX_SOON), (35, PLAN))


def priority_for(score: int) -> str:
    for minimum, name in THRESHOLDS:
        if score >= minimum:
            return name
    return MONITOR


def _percent(value: float) -> str:
    if value < 0.001:
        return "under 0.1%"
    return f"{value * 100:.1f}%"


def _severity(finding: Finding, estimate: Optional[Estimate]) -> Tuple[Factor, str, bool, Optional[float]]:
    vuln = finding.vulnerability
    if vuln.id.upper().startswith("MAL-"):
        detail = "Reported as a malicious package. Remove it and treat the machine as compromised"
        return Factor("Severity", SEVERITY_MAX, detail), "CRITICAL", False, None

    cvss = best_score(vuln.cvss)
    facts = describe(vuln.cvss)
    extra = f" ({', '.join(facts)})" if facts else ""

    if cvss is not None and cvss > 0:
        label = vuln.severity_label or label_for_score(cvss) or "LOW"
        detail = f"{label.capitalize()} severity, CVSS {cvss:.1f}{extra}"
        return Factor("Severity", round(cvss * 6), detail), label, False, cvss
    if vuln.severity_label in LABEL_SCORE:
        label = vuln.severity_label
        detail = f"{label.capitalize()} severity{extra}"
        return Factor("Severity", round(LABEL_SCORE[label] * 6), detail), label, False, None

    if estimate is None:
        detail = "No severity published, so it is scored as medium"
        return Factor("Severity", round(UNKNOWN_SCORE * 6), detail), "UNKNOWN", False, None

    # An estimate never reaches the top of the scale: it is a guess, not a rating.
    assumed = 3.5 + 4.5 * estimate.probability
    how = "the Valtrix model" if estimate.source == "model" else "keyword rules"
    detail = (f"No severity published. Estimated by {how}: "
              f"{estimate.probability:.0%} likely to be high or critical")
    if estimate.signals:
        detail += " (signals: " + ", ".join(estimate.signals) + ")"
    return Factor("Severity", round(assumed * 6), detail), estimate.label, True, None


def _exploitation(finding: Finding, data: Optional[ExploitData]) -> Factor:
    cves = [c.upper() for c in finding.vulnerability.cve_ids]
    if data is None or (data.epss_status == DISABLED and data.kev_status == DISABLED):
        return Factor("Exploitation", 0, "Exploitation evidence was not looked up")
    if not cves:
        return Factor("Exploitation", 0, "No CVE id, so there is no exploitation evidence to look up")

    for cve in cves:
        if cve in data.kev:
            detail = f"{cve} is in CISA's catalog of vulnerabilities known to be exploited"
            if data.kev[cve]:
                detail += ", and is used in ransomware attacks"
            return Factor("Exploitation", EXPLOITATION_MAX, detail)

    scored = [(data.epss[c][0], data.epss[c][1], c) for c in cves if c in data.epss]
    if scored:
        probability, percentile, cve = max(scored)
        points = 20 if probability >= 0.5 else 14 if probability >= 0.1 else 6 if probability >= 0.01 else 0
        detail = f"EPSS gives {cve} a {_percent(probability)} chance of being exploited in the next 30 days"
        if percentile:
            detail += f", higher than {percentile:.0%} of all CVEs"
        if data.kev_status == OK:
            detail += ". Not in CISA's known-exploited catalog"
        return Factor("Exploitation", points, detail)

    missing = [name for name, status in (("EPSS", data.epss_status), ("CISA KEV", data.kev_status))
               if status in (UNAVAILABLE, DISABLED, NOT_NEEDED)]
    if missing:
        return Factor("Exploitation", 0, f"Exploitation evidence is incomplete ({' and '.join(missing)} not available)")
    return Factor("Exploitation", 0, "No sign of exploitation: not in CISA's catalog and no EPSS score yet")


def _exposure(finding: Finding) -> Factor:
    dep = finding.dependency
    if dep.dev:
        return Factor("Exposure", 0, "Only used for development or testing, not shipped with the product")
    if dep.direct is False:
        if len(dep.path) > 1:
            depth = len(dep.path)
            points = 5 if depth == 2 else 3
            return Factor("Exposure", points, "Transitive dependency, pulled in by " + " > ".join(dep.path[:-1]))
        return Factor("Exposure", 5, "Transitive dependency, pulled in by another package")
    if dep.direct:
        return Factor("Exposure", EXPOSURE_MAX, "Direct dependency of the project")
    return Factor("Exposure", EXPOSURE_MAX, f"Listed in {dep.source or 'the project'}, so treated as a direct dependency")


def _fix(finding: Finding) -> Factor:
    if finding.fix:
        return Factor("Fix", FIX_POINTS, f"A fix exists: upgrade {finding.dependency.name} to {finding.fix}")
    if finding.vulnerability.fixed_versions:
        return Factor("Fix", 0, "Fixed versions are listed, but none is newer than the installed one")
    return Factor("Fix", 0, "No fixed version is listed. Look for a workaround or a replacement")


def score_finding(
    finding: Finding,
    exploit_data: Optional[ExploitData] = None,
    estimate: Optional[Estimate] = None,
) -> Risk:
    """Score one finding. `estimate` is only used when no severity is published."""
    severity, label, estimated, cvss = _severity(finding, estimate)
    factors: List[Factor] = [severity, _exploitation(finding, exploit_data), _exposure(finding), _fix(finding)]
    score = max(0, min(100, sum(f.points for f in factors)))
    return Risk(score, priority_for(score), tuple(factors), label, estimated, cvss)

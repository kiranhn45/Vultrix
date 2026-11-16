"""CVSS: compute the version 3 base score from a vector, and describe a vector in words.

The formula is the one in the CVSS v3.1 specification (section 7.1), including
its rounding rule. Version 4 vectors are understood well enough to describe
them, but their score needs a large lookup table and is not computed; callers
fall back to the published severity label.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def parse_vector(vector: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Split "CVSS:3.1/AV:N/..." into ("3.1", {"AV": "N", ...}). None if malformed."""
    if not isinstance(vector, str) or len(vector) > 300:
        return None
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:"):
        return None
    version = parts[0][5:]
    metrics: Dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or not key or not value or key in metrics:
            return None
        metrics[key.upper()] = value.upper()
    return version, metrics


def _round_up(value: float) -> float:
    """Round up to one decimal place, the way the CVSS 3.1 specification defines it."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Base score (0.0 to 10.0) for a CVSS 3.0 or 3.1 vector, or None if it is not one."""
    parsed = parse_vector(vector)
    if parsed is None or parsed[0] not in ("3.0", "3.1"):
        return None
    m = parsed[1]
    try:
        changed = {"U": False, "C": True}[m["S"]]
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _round_up(min(total, 10.0))


def label_for_score(score: float) -> Optional[str]:
    if score <= 0:
        return None
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def best_score(cvss: Sequence[Tuple[str, str]]) -> Optional[float]:
    """Highest computable base score among the published (type, vector) pairs."""
    scores = [s for s in (cvss3_base_score(vector) for _, vector in cvss) if s is not None]
    return max(scores) if scores else None


def describe(cvss: Sequence[Tuple[str, str]]) -> List[str]:
    """Plain-language facts from the first usable vector (version 3 or 4)."""
    for _, vector in cvss:
        parsed = parse_vector(vector)
        if parsed is None or not parsed[0].startswith(("3", "4")):
            continue
        m = parsed[1]
        facts: List[str] = []
        attack = {"N": "reachable over the network", "A": "needs access to the local network",
                  "L": "needs local access", "P": "needs physical access"}.get(m.get("AV", ""))
        if attack:
            facts.append(attack)
        login = {"N": "no login needed", "L": "needs a low-privilege login",
                 "H": "needs an administrator login"}.get(m.get("PR", ""))
        if login:
            facts.append(login)
        action = {"N": "no user action needed", "R": "needs a user to do something",
                  "P": "needs a user to do something", "A": "needs a user to do something"}.get(m.get("UI", ""))
        if action:
            facts.append(action)
        if m.get("AC") == "H":
            facts.append("hard to pull off")
        if facts:
            return facts
    return []

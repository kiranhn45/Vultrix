"""CVSS scoring, exploitation evidence, the risk rules and the severity model."""

import io
import json
import urllib.error

import pytest

from valtrix.databases.exploits import (
    DISABLED, OK, UNAVAILABLE, ExploitData, ExploitDataError, fetch_epss, fetch_kev, gather_exploit_data,
)
from valtrix.models import Dependency, Finding, ScanResult, Vulnerability
from valtrix.risk import prioritize, score_finding
from valtrix.risk.cvss import best_score, cvss3_base_score, describe, label_for_score, parse_vector
from valtrix.risk.rules import priority_for
from valtrix.risk.severity_model import (
    MODEL_PATH, Estimate, SeverityModel, default_model, estimate_severity, extract_features, keyword_estimate,
)

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# ----------------------------------------------------------------------- CVSS

# Published scores for well-known vulnerabilities (NVD).
@pytest.mark.parametrize("vector,expected", [
    (CRITICAL_VECTOR, 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),      # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),       # reflected XSS
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),       # Heartbleed
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),       # scope change alters the privilege weight
    ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_scores_match_published_values(vector, expected):
    assert cvss3_base_score(vector) == expected


@pytest.mark.parametrize("vector", [
    "", None, 5, "AV:N/AC:L", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CVSS:3.1/" + "A" * 400,
])
def test_cvss3_returns_none_for_anything_else(vector):
    assert cvss3_base_score(vector) is None


def test_cvss_helpers():
    assert [label_for_score(s) for s in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)] == [
        None, "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]
    assert best_score((("CVSS_V4", "CVSS:4.0/AV:N"), ("CVSS_V3", CRITICAL_VECTOR))) == 9.8
    assert best_score(()) is None
    assert describe((("CVSS_V3", CRITICAL_VECTOR),)) == [
        "reachable over the network", "no login needed", "no user action needed"]
    assert "needs local access" in describe((("CVSS_V4", "CVSS:4.0/AV:L/AC:H/PR:H/UI:A"),))
    assert parse_vector("CVSS:3.1/AV:N/AC")is None


# -------------------------------------------------------------- exploit data

class Opener:
    """Answers by matching a piece of the URL. Values are JSON-able objects or exceptions."""

    def __init__(self, routes):
        self.routes, self.urls = routes, []

    def open(self, request, timeout=None):
        self.urls.append(request.full_url)
        for piece, answer in self.routes.items():
            if piece in request.full_url:
                if isinstance(answer, BaseException):
                    raise answer
                return _Response(answer if isinstance(answer, bytes) else json.dumps(answer).encode())
        raise urllib.error.URLError("no route")


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


EPSS_OK = {"status": "OK", "data": [
    {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.999"},
    {"cve": "CVE-2000-0001", "epss": "7", "percentile": "0.1"},        # out of range: dropped
    {"cve": "CVE-1999-9999", "epss": "0.5"},                           # not asked for: dropped
    "junk",
]}
KEV_OK = {"vulnerabilities": [
    {"cveID": "CVE-2021-44228", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2022-0001", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": 5}, "junk",
]}


def test_epss_scores_are_validated():
    opener = Opener({"first.org": EPSS_OK})
    scores = fetch_epss(["cve-2021-44228", "CVE-2000-0001", "GHSA-not-a-cve", "CVE-2021-44228"], opener)
    assert scores == {"CVE-2021-44228": (0.97, 0.999)}
    assert opener.urls == ["https://api.first.org/data/v1/epss?cve=CVE-2000-0001,CVE-2021-44228"]


def test_epss_is_asked_in_batches():
    opener = Opener({"first.org": {"data": []}})
    fetch_epss([f"CVE-2024-{n:05d}" for n in range(200)], opener)
    assert len(opener.urls) == 3 and all(len(u) < 2000 for u in opener.urls)


def test_kev_falls_back_to_the_mirror():
    opener = Opener({"cisa.gov": urllib.error.URLError("blocked"), "githubusercontent": KEV_OK})
    assert fetch_kev(opener) == {"CVE-2021-44228": True, "CVE-2022-0001": False}
    assert len(opener.urls) == 3                 # cisa.gov tried twice, then the mirror


@pytest.mark.parametrize("answer", [b"not json", [1, 2], {"data": "x"}, urllib.error.URLError("down"),
                                    urllib.error.HTTPError("u", 500, "x", {}, io.BytesIO())])
def test_bad_answers_raise_a_clear_error(answer):
    with pytest.raises(ExploitDataError):
        fetch_epss(["CVE-2021-44228"], Opener({"first.org": answer}))


def test_gather_never_raises_and_records_what_is_missing():
    data = gather_exploit_data(["CVE-2021-44228"], Opener({"first.org": EPSS_OK}))
    assert data.epss_status == OK and data.kev_status == UNAVAILABLE
    assert data.epss and not data.kev and "known-exploited catalog" in data.notes[0]

    nothing = gather_exploit_data(["GHSA-only"], Opener({}))
    assert nothing.epss_status == "not needed" and nothing.notes == []


def test_only_https_sources(monkeypatch):
    from valtrix.databases import exploits
    monkeypatch.setattr(exploits, "EPSS_URL", "http://api.first.org/data/v1/epss")
    with pytest.raises(ExploitDataError, match="https"):
        fetch_epss(["CVE-2021-44228"], Opener({"first.org": EPSS_OK}))


# ---------------------------------------------------------------------- rules

def finding(severity="HIGH", cvss=(), aliases=(), fix="2.0", dep=None, vuln_id="GHSA-x", fixed=None, **text):
    dep = dep or Dependency("pkg", "1.0", "==1.0", (), None, "requirements.txt", 1)
    vuln = Vulnerability(id=vuln_id, severity_label=severity, cvss=tuple(cvss), aliases=tuple(aliases),
                         fixed_versions=tuple(fixed if fixed is not None else ([fix] if fix else [])), **text)
    return Finding(dep, vuln, fix)


def points(risk):
    return {f.name: f.points for f in risk.factors}


def test_score_is_the_sum_of_its_factors():
    risk = score_finding(finding(cvss=[("CVSS_V3", CRITICAL_VECTOR)], severity="CRITICAL"))
    assert points(risk) == {"Severity": 59, "Exploitation": 0, "Exposure": 8, "Fix": 7}
    assert risk.score == 74 and risk.priority == "fix now" and risk.cvss_score == 9.8
    assert "CVSS 9.8" in risk.factors[0].detail and "no login needed" in risk.factors[0].detail


def test_label_only_and_unknown_severity():
    assert points(score_finding(finding("MEDIUM")))["Severity"] == 33
    unknown = score_finding(finding(None))
    assert points(unknown)["Severity"] == 33 and unknown.severity == "UNKNOWN"
    assert "scored as medium" in unknown.factors[0].detail


def test_estimate_is_used_only_when_nothing_is_published_and_is_labelled():
    guess = Estimate(0.9, ("code execution",), "model")
    risk = score_finding(finding(None), estimate=guess)
    assert risk.estimated and risk.severity == "HIGH"
    assert "Estimated by the Valtrix model: 90%" in risk.factors[0].detail and "code execution" in risk.factors[0].detail
    assert points(risk)["Severity"] < 48          # an estimate never outranks a published HIGH
    published = score_finding(finding("LOW"), estimate=guess)
    assert not published.estimated and published.severity == "LOW"


def test_malware_is_always_top_severity():
    risk = score_finding(finding(None, vuln_id="MAL-2024-1", fix=None))
    assert points(risk)["Severity"] == 60 and "malicious package" in risk.factors[0].detail


def test_exploitation_evidence():
    f = finding(aliases=["CVE-2021-44228"])
    kev = ExploitData(kev={"CVE-2021-44228": True}, epss_status=OK, kev_status=OK)
    factor = score_finding(f, kev).factors[1]
    assert factor.points == 25 and "known to be exploited" in factor.detail and "ransomware" in factor.detail

    for probability, expected in [(0.9, 20), (0.2, 14), (0.02, 6), (0.001, 0)]:
        data = ExploitData(epss={"CVE-2021-44228": (probability, 0.9)}, epss_status=OK, kev_status=OK)
        factor = score_finding(f, data).factors[1]
        assert factor.points == expected and "EPSS" in factor.detail and "Not in CISA" in factor.detail

    assert "not looked up" in score_finding(f, None).factors[1].detail
    assert "not looked up" in score_finding(f, ExploitData()).factors[1].detail
    down = ExploitData(epss_status=UNAVAILABLE, kev_status=OK)
    assert "incomplete (EPSS not available)" in score_finding(f, down).factors[1].detail
    assert "No CVE id" in score_finding(finding(), kev).factors[1].detail
    clean = ExploitData(epss_status=OK, kev_status=OK)
    assert "No sign of exploitation" in score_finding(f, clean).factors[1].detail


def test_exposure():
    def dep(**kw):
        return Dependency("pkg", "1.0", "==1.0", (), None, "poetry.lock", 1, **kw)
    assert points(score_finding(finding(dep=dep(direct=True))))["Exposure"] == 8
    assert points(score_finding(finding(dep=dep())))["Exposure"] == 8              # unknown: assume direct
    assert points(score_finding(finding(dep=dep(direct=False, path=("a 1", "pkg 1.0")))))["Exposure"] == 5
    deep = score_finding(finding(dep=dep(direct=False, path=("a 1", "b 1", "pkg 1.0"))))
    assert points(deep)["Exposure"] == 3 and "pulled in by a 1 > b 1" in deep.factors[2].detail
    assert points(score_finding(finding(dep=dep(direct=True, dev=True))))["Exposure"] == 0


def test_fix_factor():
    assert points(score_finding(finding(fix="2.0")))["Fix"] == 7
    assert "No fixed version is listed" in score_finding(finding(fix=None)).factors[3].detail
    older = score_finding(finding(fix=None, fixed=["0.5"]))
    assert older.factors[3].points == 0 and "none is newer" in older.factors[3].detail


def test_priority_bands():
    assert [priority_for(s) for s in (100, 70, 69, 50, 49, 35, 34, 0)] == [
        "fix now", "fix now", "fix soon", "fix soon", "plan", "plan", "monitor", "monitor"]


def test_prioritize_orders_by_score_and_is_stable():
    medium_but_exploited = finding("MEDIUM", aliases=["CVE-2020-0001"], vuln_id="GHSA-exploited")
    high = finding("HIGH", vuln_id="GHSA-high")
    high_no_fix = finding("HIGH", vuln_id="GHSA-nofix", fix=None)
    result = ScanResult(findings=[high_no_fix, high, medium_but_exploited])
    data = ExploitData(kev={"CVE-2020-0001": False}, epss_status=OK, kev_status=OK)
    prioritize(result, data)
    assert [f.vulnerability.id for f in result.findings] == ["GHSA-exploited", "GHSA-high", "GHSA-nofix"]
    assert [f.risk.score for f in result.findings] == [73, 63, 56]   # being exploited outranks being worse on paper
    assert all(f.risk is not None for f in result.findings)
    again = [f.vulnerability.id for f in prioritize(result, data).findings]
    assert again == ["GHSA-exploited", "GHSA-high", "GHSA-nofix"]


# ---------------------------------------------------------------------- model

def test_feature_extraction():
    features = extract_features("Remote Code Execution in the parser", "An attacker can run code.", ["cwe-94"])
    assert {"remote", "code", "remote code", "code execution", "CWE-94"} <= features
    assert "the" not in features and "in" not in features
    assert extract_features("", "") == set()


def test_keyword_baseline():
    assert keyword_estimate(Vulnerability("X", summary="SQL injection in login")).probability == 0.8
    assert keyword_estimate(Vulnerability("X", summary="Reflected XSS")).probability == 0.3
    assert keyword_estimate(Vulnerability("X", summary="XSS leading to account takeover")).probability == 0.6
    assert keyword_estimate(Vulnerability("X")).probability == 0.5


def test_shipped_model_loads_and_behaves_sensibly():
    model = default_model()
    assert model is not None and len(model.weights) > 500
    rce = model.estimate(Vulnerability("X", summary="Remote code execution via unsafe deserialization",
                                       details="An attacker can execute arbitrary code on the server.", cwes=("CWE-94",)))
    xss = model.estimate(Vulnerability("X", summary="Reflected cross-site scripting in the search page",
                                       details="Open redirect and XSS with limited impact.", cwes=("CWE-79",)))
    assert rce.probability > 0.7 > 0.4 > xss.probability
    assert rce.signals and rce.source == "model" and rce.label == "HIGH" and xss.label == "MEDIUM"
    assert 0.0 < model.estimate(Vulnerability("X")).probability < 1.0


def test_shipped_model_beat_the_baseline_when_it_was_trained():
    """The model is only worth shipping if it beats the keyword rules on unseen data."""
    info = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    model, rules = info["evaluation"]["model"], info["evaluation"]["keyword_rules"]
    assert model["auc"] > rules["auc"] + 0.05 and model["accuracy"] > rules["accuracy"] + 0.05
    assert info["test"]["published_from"] >= info["training"]["published_to"]      # tested on newer data


@pytest.mark.parametrize("data", [
    None, [], {}, {"format": 2, "bias": 0, "weights": {}}, {"format": 1, "bias": "0", "weights": {}},
    {"format": 1, "bias": 0, "weights": []}, {"format": 1, "bias": 0, "weights": {"a": "1"}},
    {"format": 1, "bias": 0, "weights": {"a": float("nan")}}, {"format": 1, "bias": True, "weights": {}},
])
def test_damaged_model_files_are_rejected(data):
    with pytest.raises(ValueError):
        SeverityModel.from_dict(data)


def test_missing_model_falls_back_to_keywords(tmp_path):
    assert SeverityModel.load(tmp_path / "nope.json") is None
    (tmp_path / "bad.json").write_text("{broken")
    assert SeverityModel.load(tmp_path / "bad.json") is None
    vuln = Vulnerability("X", summary="SQL injection")
    assert estimate_severity(vuln, use_model=False).source == "keywords"


def test_prioritize_without_the_model_uses_keyword_rules():
    f = finding(None, summary="SQL injection in the login form")
    with_model = prioritize(ScanResult(findings=[f])).findings[0].risk
    without = prioritize(ScanResult(findings=[f]), use_model=False).findings[0].risk
    assert "the Valtrix model" in with_model.factors[0].detail
    assert "keyword rules" in without.factors[0].detail and without.estimated

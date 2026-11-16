"""Report formats: JSON, HTML, SARIF, and the settings that shape them."""

import datetime
import json
import re

import pytest

from valtrix.config import Config, ConfigError, IgnoreRule, apply_ignores, load_config, parse_config
from valtrix.databases.exploits import OK, ExploitData
from valtrix.models import Dependency, Finding, ParseIssue, ScanResult, Unchecked, Vulnerability
from valtrix.reports import ReportMeta, build_report, build_sarif, exit_code, render_html, render_json, render_scan
from valtrix.risk import prioritize

EVIL = '<script>alert(1)</script><img src=x onerror=alert(2)>"\'&'


def dep(name="django", version="3.2.0", **kw):
    return Dependency(name, version, f"=={version}", (), None, kw.pop("source", "requirements.txt"), kw.pop("line", 3), **kw)


def sample(extra_findings=()):
    django = dep()
    result = ScanResult(
        sources=["requirements.txt"],
        scanned=[django, dep("requests", "2.31.0")],
        findings=[
            Finding(django, Vulnerability("GHSA-aaaa", summary="SQL injection", severity_label="CRITICAL",
                                          aliases=("CVE-2022-0001",), fixed_versions=("3.2.13",),
                                          cvss=(("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
                                          references=("https://example.com/advisory",), cwes=("CWE-89",)), "3.2.13"),
            Finding(django, Vulnerability("PYSEC-cccc", summary="Something odd"), None),
            *extra_findings,
        ],
        unchecked=[Unchecked(dep("numpy", None), "version is not pinned", False)],
        parse_issues=[ParseIssue("requirements.txt", 9, "Could not parse requirement: ==oops")],
    )
    data = ExploitData(epss={"CVE-2022-0001": (0.4, 0.97)}, epss_status=OK, kev_status=OK)
    prioritize(result, data)
    return result, ReportMeta(target="/work/app", exploit_data=data, generated_at="2026-11-16T00:00:00Z")


# ----------------------------------------------------------------------- JSON

def test_json_report_structure():
    result, meta = sample()
    report = json.loads(render_json(result, meta))
    assert report["schema_version"] == 1 and report["tool"]["name"] == "valtrix"
    assert report["generated_at"] == "2026-11-16T00:00:00Z" and report["target"] == "/work/app"
    assert report["summary"] == {
        "dependencies": 3, "checked": 2, "vulnerable": 1, "findings": 2, "ignored": 0, "unchecked": 1,
        "by_severity": {"CRITICAL": 1, "UNKNOWN": 1},
        "by_priority": {"fix now": 1, "fix soon": 0, "plan": 1, "monitor": 0},
        "incomplete": False, "exit_code": 1,
    }
    first, second = report["findings"]
    assert first["rank"] == 1 and first["vulnerability"]["id"] == "GHSA-aaaa" and first["fix"] == "3.2.13"
    assert first["dependency"]["source"] == "requirements.txt" and first["dependency"]["line"] == 3
    assert first["vulnerability"]["cvss"][0]["score"] == 9.8 and first["vulnerability"]["cwes"] == ["CWE-89"]
    assert first["risk"]["score"] == sum(f["points"] for f in first["risk"]["factors"]) == 88
    assert [f["name"] for f in first["risk"]["factors"]] == ["Severity", "Exploitation", "Exposure", "Fix"]
    assert second["severity_estimated"] is True and second["vulnerability"]["severity"] is None
    assert report["unchecked"][0]["dependency"]["name"] == "numpy" and report["unchecked"][0]["failed"] is False
    assert report["parse_issues"] == [{"source": "requirements.txt", "line": 9, "message": "Could not parse requirement: ==oops"}]
    assert report["settings"]["exploit_data"] == {"epss": "ok", "kev": "ok"}
    assert report["settings"]["severity_model"]["evaluation"]["model"]["auc"] > 0.5


def test_json_report_for_an_empty_and_an_incomplete_scan():
    empty = build_report(ScanResult(), ReportMeta())
    assert empty["findings"] == [] and empty["summary"]["exit_code"] == 0
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", empty["generated_at"])
    broken = ScanResult(unchecked=[Unchecked(dep(), "lookup failed: down", True)])
    assert build_report(broken, ReportMeta())["summary"]["incomplete"] is True
    assert build_report(broken, ReportMeta())["summary"]["exit_code"] == 3


# ----------------------------------------------------------------------- HTML

def hostile():
    bad = Dependency("pkg" + EVIL, "1.0" + EVIL, "==1.0", (), None, "req" + EVIL + ".txt", 1,
                     path=("a" + EVIL, "b"), direct=False)
    vuln = Vulnerability("GHSA-" + EVIL, summary=EVIL, details=EVIL, aliases=("CVE-" + EVIL,),
                         references=("javascript:alert(1)", 'https://example.com/"><script>alert(3)</script>'),
                         fixed_versions=("2.0" + EVIL,))
    result = ScanResult(
        sources=["req" + EVIL], scanned=[bad], findings=[Finding(bad, vuln, "2.0" + EVIL)],
        unchecked=[Unchecked(bad, "reason " + EVIL, True)],
        parse_issues=[ParseIssue("f" + EVIL, 1, EVIL)], notes=[EVIL],
    )
    prioritize(result)
    apply_ignores(result, [])
    return result, ReportMeta(target="/tmp/" + EVIL)


def test_html_escapes_everything_from_outside():
    result, meta = hostile()
    result.ignored = []
    page = render_html(result, meta)
    assert "<script" not in page and "<img" not in page
    assert "onerror=alert" not in page.replace("onerror=alert(2)&gt;", "")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    # No attribute can be broken out of: every double quote from outside is escaped.
    for href in re.findall(r'href="([^"]*)"', page):
        assert href.startswith(("https://", "http://")) and "<" not in href
    assert "javascript:" not in "".join(re.findall(r'href="([^"]*)"', page))


def test_html_has_no_scripts_and_forbids_them():
    result, meta = sample()
    page = render_html(result, meta)
    assert page.startswith("<!doctype html>") and "<script" not in page.lower()
    assert "default-src 'none'" in page
    assert not re.search(r'(src|href)="(?!https://osv\.dev/|https://example\.com/)', page)   # loads nothing else
    assert "SQL injection" in page and "fix now" in page and "#1" in page
    assert "Not checked (1)" in page and "Lines that could not be used (1)" in page
    assert ">88<" in page


def test_html_wording_for_clean_incomplete_and_unchecked_scans():
    clean = ScanResult(sources=["requirements.txt"], scanned=[dep()])
    assert "No known vulnerabilities" in render_html(clean, ReportMeta())
    nothing = ScanResult(sources=["requirements.txt"], unchecked=[Unchecked(dep(), "lookup failed", True)])
    page = render_html(nothing, ReportMeta())
    assert "Nothing could be checked" in page and "scan is incomplete" in page
    assert "No known vulnerabilities" not in page


# ---------------------------------------------------------------------- SARIF

def test_sarif_structure():
    result, meta = sample()
    sarif = build_sarif(result, meta)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Valtrix"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "GHSA-aaaa" and rule["properties"]["security-severity"] == "9.8"
    assert rule["helpUri"] == "https://osv.dev/vulnerability/GHSA-aaaa"
    first = run["results"][0]
    assert first["ruleId"] == "GHSA-aaaa" and first["level"] == "error" and first["ruleIndex"] == 0
    location = first["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "requirements.txt" and location["region"]["startLine"] == 3
    assert "Upgrade to 3.2.13" in first["message"]["text"] and "Risk score 88/100" in first["message"]["text"]
    assert first["partialFingerprints"]["valtrix/v1"] == "PyPI/django@3.2.0/GHSA-aaaa"


def test_sarif_one_rule_per_advisory_and_valid_line_numbers():
    other = dep("django", "4.0.0", line=0, source="poetry.lock")
    result, meta = sample([Finding(other, Vulnerability("GHSA-aaaa", summary="SQL injection", severity_label="LOW"), None)])
    run = build_sarif(result, meta)["runs"][0]
    assert len(run["results"]) == 3 and len(run["tool"]["driver"]["rules"]) == 2
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])
    assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}


# ------------------------------------------------------------------- settings

def test_fail_on_levels():
    result, _ = sample()
    assert exit_code(result, "low") == 1 and exit_code(result, "critical") == 1 and exit_code(result, "none") == 0
    only_medium = ScanResult(findings=[Finding(dep(), Vulnerability("X", severity_label="MEDIUM"))])
    prioritize(only_medium)
    assert [exit_code(only_medium, level) for level in ("low", "medium", "high", "critical")] == [1, 1, 0, 0]
    unknown = ScanResult(findings=[Finding(dep(), Vulnerability("X"))])
    assert exit_code(unknown, "critical") == 1       # not scored: unknown severity is never assumed harmless
    incomplete = ScanResult(unchecked=[Unchecked(dep(), "x", True)])
    assert exit_code(incomplete, "none") == 3


def test_ignore_rules_move_findings_and_keep_them_visible():
    result, meta = sample()
    rules = [IgnoreRule("cve-2022-0001", "not reachable", package="Django", expires="2099-01-01"),
             IgnoreRule("PYSEC-cccc", "wrong package", package="flask")]
    apply_ignores(result, rules, today=datetime.date(2026, 11, 16))
    assert [f.vulnerability.id for f in result.findings] == ["PYSEC-cccc"]       # the package did not match
    assert result.ignored[0].finding.vulnerability.id == "GHSA-aaaa"             # matched through its alias
    text = render_scan(result, False, meta)
    assert "Ignored by the project's settings (1)" in text and "not reachable, until 2099-01-01" in text
    assert "not reachable" in render_html(result, meta)
    report = build_report(result, meta)
    assert report["ignored"][0]["reason"] == "not reachable" and report["summary"]["ignored"] == 1


def test_expired_ignore_rule_stops_working_and_says_so():
    result, _ = sample()
    apply_ignores(result, [IgnoreRule("GHSA-aaaa", "temporary", expires="2026-11-15")], today=datetime.date(2026, 11, 16))
    assert len(result.findings) == 2 and not result.ignored
    assert "expired on 2026-11-15" in result.notes[0]


def test_config_from_pyproject_and_dedicated_file(tmp_path):
    assert load_config(tmp_path) == Config()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.valtrix]\nfail-on = "HIGH"\nml = false\n[[tool.valtrix.ignore]]\nid = "GHSA-aaaa"\n'
        'reason = "accepted"\nexpires = 2027-01-31\n')
    config = load_config(tmp_path)
    assert config.fail_on == "high" and config.ml is False and config.exploit_data is True
    assert config.ignore == [IgnoreRule("GHSA-aaaa", "accepted", None, "2027-01-31")]
    assert config.source == "pyproject.toml [tool.valtrix]"
    (tmp_path / ".valtrix.toml").write_text('fail-on = "none"\n')
    assert load_config(tmp_path).fail_on == "none"                                # the dedicated file wins


@pytest.mark.parametrize("settings,message", [
    ({"fail-on": "severe"}, "fail-on"),
    ({"fail-on": 3}, "fail-on"),
    ({"ml": "yes"}, "true or false"),
    ({"surprise": 1}, "unknown setting"),
    ({"ignore": "GHSA-aaaa"}, "list of tables"),
    ({"ignore": ["GHSA-aaaa"]}, "table with"),
    ({"ignore": [{"id": "GHSA-aaaa"}]}, "reason"),
    ({"ignore": [{"id": "x y", "reason": "because"}]}, "needs an `id`"),
    ({"ignore": [{"id": "GHSA-aaaa", "reason": "because", "expires": "next week"}]}, "expires"),
    ({"ignore": [{"id": "GHSA-aaaa", "reason": "because", "expires": "2026-02-30"}]}, "expires"),
    ({"ignore": [{"id": "GHSA-aaaa", "reason": "because", "package": 5}]}, "package"),
])
def test_bad_settings_are_rejected_with_a_clear_message(settings, message):
    with pytest.raises(ConfigError, match=message):
        parse_config(settings, ".valtrix.toml")


def test_broken_settings_file_is_a_config_error(tmp_path):
    (tmp_path / ".valtrix.toml").write_text("fail-on = \n")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(tmp_path)

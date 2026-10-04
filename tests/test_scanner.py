import pytest

from valtrix.databases import OsvError
from valtrix.models import Dependency, Vulnerability, count_by_severity, severity_rank
from valtrix.parsers import RequirementsError
from valtrix.scanner import scan_dependencies, scan_project, suggest_upgrade
from valtrix.scanner import dependency_scanner as scanner_module


class FakeClient:
    """Answers per (name, version) from a table. Values may be lists or exceptions."""

    def __init__(self, table=None):
        self.table = table or {}
        self.calls = []

    def query(self, name, version):
        self.calls.append((name, version))
        answer = self.table.get((name, version), [])
        if isinstance(answer, BaseException):
            raise answer
        return answer


def dep(name, version=None, specifier=None, source="requirements.txt", line=1):
    if specifier is None:
        specifier = f"=={version}" if version else ""
    return Dependency(name, version, specifier, (), None, source, line)


def vuln(id, severity=None, fixed=()):
    return Vulnerability(id=id, severity_label=severity, fixed_versions=tuple(fixed))


# ---------------------------------------------------------- classification

def test_clean_vulnerable_and_unchecked_are_separated():
    deps = [
        dep("django", "3.2.0"),
        dep("requests", "2.31.0"),
        dep("numpy"),                                   # not pinned
        dep("django-ranged", None, ">=3.2,<4.0"),
        dep("mypkg", None, "@ https://example.com/x.zip"),
    ]
    client = FakeClient({("django", "3.2.0"): [vuln("GHSA-1", "HIGH", ["2.2.28", "3.2.13"])]})
    result = scan_dependencies(deps, client)

    assert [d.name for d in result.scanned] == ["django", "requests"]
    assert [f.vulnerability.id for f in result.findings] == ["GHSA-1"]
    reasons = {u.dependency.name: u.reason for u in result.unchecked}
    assert "not pinned" in reasons["numpy"]
    assert "not pinned" in reasons["django-ranged"]
    assert "direct URL" in reasons["mypkg"]
    assert not any(u.failed for u in result.unchecked)
    assert not result.incomplete
    assert client.calls == [("django", "3.2.0"), ("requests", "2.31.0")]   # unpinned never queried


def test_fix_matches_the_installed_release_line():
    client = FakeClient({("django", "3.2.0"): [vuln("GHSA-1", "HIGH", ["4.0.4", "2.2.28", "3.2.13"])]})
    result = scan_dependencies([dep("django", "3.2.0")], client)
    assert result.findings[0].fix == "3.2.13"


def test_finding_without_usable_fix():
    client = FakeClient({("old", "1.0"): [vuln("X-1", "LOW", [])]})
    assert scan_dependencies([dep("old", "1.0")], client).findings[0].fix is None


def test_findings_are_ordered_by_severity_then_name():
    client = FakeClient({
        ("b", "1"): [vuln("B-LOW", "LOW"), vuln("B-CRIT", "CRITICAL")],
        ("a", "1"): [vuln("A-UNK", None), vuln("A-HIGH", "HIGH")],
    })
    result = scan_dependencies([dep("a", "1"), dep("b", "1")], client)
    assert [f.vulnerability.id for f in result.findings] == ["B-CRIT", "A-HIGH", "B-LOW", "A-UNK"]


def test_same_pinned_dependency_from_two_files_is_checked_once():
    deps = [dep("flask", "3.0.0", source="a.txt"), dep("flask", "3.0.0", source="b.txt")]
    client = FakeClient()
    result = scan_dependencies(deps, client)
    assert len(client.calls) == 1 and len(result.scanned) == 1


def test_same_package_with_different_pins_is_checked_twice():
    client = FakeClient()
    scan_dependencies([dep("flask", "2.0.0"), dep("flask", "3.0.0")], client)
    assert client.calls == [("flask", "2.0.0"), ("flask", "3.0.0")]


def test_empty_input():
    result = scan_dependencies([], FakeClient())
    assert result.findings == [] and result.scanned == [] and not result.incomplete


# ---------------------------------------------------------------- failures

def test_one_failing_package_does_not_stop_the_scan():
    client = FakeClient({
        ("bad", "1.0"): OsvError("OSV rejected the request (HTTP 400)"),
        ("good", "1.0"): [vuln("G-1", "HIGH")],
    })
    result = scan_dependencies([dep("bad", "1.0"), dep("good", "1.0")], client)
    assert [f.vulnerability.id for f in result.findings] == ["G-1"]
    [failed] = result.unchecked
    assert failed.dependency.name == "bad" and failed.failed and "HTTP 400" in failed.reason
    assert result.incomplete


def test_invalid_value_is_reported_without_crashing():
    client = FakeClient({("weird", "1.0"): ValueError("invalid")})
    result = scan_dependencies([dep("weird", "1.0"), dep("ok", "1.0")], client)
    assert [d.name for d in result.scanned] == ["ok"]
    assert result.unchecked[0].failed is False


def test_stops_early_when_osv_is_unreachable():
    down = OsvError("Could not get an answer from OSV", unreachable=True)
    names = [f"pkg{i}" for i in range(10)]
    client = FakeClient({(n, "1.0"): down for n in names})
    result = scan_dependencies([dep(n, "1.0") for n in names], client)

    assert len(client.calls) == scanner_module.MAX_CONSECUTIVE_UNREACHABLE
    assert len(result.unchecked) == 10
    assert all(u.failed for u in result.unchecked)
    assert any("could not be reached" in u.reason for u in result.unchecked)
    assert result.incomplete


def test_success_resets_the_unreachable_counter():
    down = OsvError("down", unreachable=True)
    table = {("a", "1"): down, ("b", "1"): down, ("c", "1"): [], ("d", "1"): down, ("e", "1"): down}
    client = FakeClient(table)
    result = scan_dependencies([dep(n, "1") for n in "abcde"], client)
    assert len(client.calls) == 5          # never hit three failures in a row
    assert [d.name for d in result.scanned] == ["c"]


def test_rejected_requests_do_not_trip_the_breaker():
    rejected = OsvError("rejected", unreachable=False)
    names = [f"pkg{i}" for i in range(8)]
    client = FakeClient({(n, "1.0"): rejected for n in names})
    scan_dependencies([dep(n, "1.0") for n in names], client)
    assert len(client.calls) == 8


# ---------------------------------------------------------------- progress

def test_progress_reports_each_lookup():
    seen = []
    scan_dependencies([dep("a", "1"), dep("numpy"), dep("b", "1")], FakeClient(),
                      progress=lambda i, total, d: seen.append((i, total, d.name)))
    assert seen == [(1, 2, "a"), (2, 2, "b")]


# ----------------------------------------------------------------- helpers

def test_suggest_upgrade_takes_highest_fix_and_counts_unfixed():
    client = FakeClient({("django", "3.2.0"): [
        vuln("A", "HIGH", ["3.2.13"]), vuln("B", "HIGH", ["3.2.25"]), vuln("C", "LOW", []),
    ]})
    findings = scan_dependencies([dep("django", "3.2.0")], client).findings
    assert suggest_upgrade(findings) == ("3.2.25", 1)


def test_suggest_upgrade_compares_numerically():
    client = FakeClient({("d", "3.2.0"): [vuln("A", None, ["3.2.9"]), vuln("B", None, ["3.2.10"])]})
    assert suggest_upgrade(scan_dependencies([dep("d", "3.2.0")], client).findings)[0] == "3.2.10"


def test_suggest_upgrade_with_no_findings():
    assert suggest_upgrade([]) == (None, 0)


def test_count_by_severity_and_rank():
    client = FakeClient({("d", "1"): [vuln("A", "HIGH"), vuln("B", "HIGH"), vuln("C", None)]})
    counts = count_by_severity(scan_dependencies([dep("d", "1")], client).findings)
    assert counts == {"HIGH": 2, "UNKNOWN": 1}
    assert severity_rank("CRITICAL") < severity_rank("LOW") < severity_rank(None)


def test_result_helpers():
    client = FakeClient({("a", "1"): [vuln("A1", "HIGH"), vuln("A2", "LOW")], ("b", "1"): [vuln("B1", "LOW")]})
    result = scan_dependencies([dep("a", "1"), dep("b", "1"), dep("c", "1")], client)
    assert [d.name for d in result.vulnerable_dependencies] == ["a", "b"]
    assert len(result.findings_for(result.vulnerable_dependencies[0])) == 2


# --------------------------------------------------------------- scan_project

def test_scan_project_reads_requirements_and_includes(tmp_path):
    (tmp_path / "base.txt").write_text("requests==2.25.1\n")
    (tmp_path / "requirements.txt").write_text("-r base.txt\nflask==2.0.1\nnumpy\n==broken\n")
    client = FakeClient({("flask", "2.0.1"): [vuln("F-1", "MEDIUM", ["2.2.5"])]})
    result = scan_project(tmp_path, client)

    assert result.sources == ["base.txt", "requirements.txt"]
    assert sorted(d.name for d in result.scanned) == ["flask", "requests"]
    assert result.findings[0].fix == "2.2.5"
    assert [u.dependency.name for u in result.unchecked] == ["numpy"]
    assert len(result.parse_issues) == 1


def test_scan_project_without_requirements(tmp_path):
    client = FakeClient()
    result = scan_project(tmp_path, client)
    assert result.sources == [] and client.calls == []


def test_scan_project_unreadable_file_raises(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"\x80\x81\x82\xfa\xfb")
    with pytest.raises(RequirementsError):
        scan_project(tmp_path, FakeClient())


def test_upgrade_suggestion_for_real_django_shaped_data():
    fixes = [["3.2.13", "4.0.4"], ["3.2.25"], ["5.2.16", "6.0.7"], ["4.2.24", "5.1.12", "5.2.6"]]
    client = FakeClient({("django", "3.2.0"): [vuln(f"G-{i}", "HIGH", f) for i, f in enumerate(fixes)]})
    findings = scan_dependencies([dep("django", "3.2.0")], client).findings
    assert sorted(f.fix for f in findings) == ["3.2.13", "3.2.25", "4.2.24", "5.2.16"]
    assert suggest_upgrade(findings) == ("5.2.16", 0)

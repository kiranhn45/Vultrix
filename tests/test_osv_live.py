"""Live checks against the real OSV API.

Skipped by default. Run them yourself, with internet access, using:

    pytest -m live
"""

import pytest

from valtrix.databases import OsvClient

pytestmark = pytest.mark.live


def test_live_known_vulnerable_version_has_findings():
    vulns = OsvClient().query("django", "3.2.0")
    assert vulns, "expected OSV to know of vulnerabilities in django 3.2.0"
    assert all(v.id for v in vulns)
    assert any(v.fixed_versions for v in vulns)


def test_live_unknown_package_returns_empty_list():
    assert OsvClient().query("valtrix-no-such-package-xyz", "1.0.0") == []


def test_live_same_issue_is_not_listed_twice():
    vulns = OsvClient().query("django", "3.2.0")
    seen = {}
    for vuln in vulns:
        for ident in (vuln.id, *vuln.aliases):
            assert ident not in seen, f"{ident} appears in both {seen[ident]} and {vuln.id}"
        seen.update({ident: vuln.id for ident in (vuln.id, *vuln.aliases)})


def test_live_scan_picks_fixes_that_apply_to_the_installed_version():
    from valtrix.models import Dependency
    from valtrix.scanner import scan_dependencies, suggest_upgrade
    from valtrix.versions import parse_version

    django = Dependency("django", "3.2.0", "==3.2.0", (), None, "requirements.txt", 1)
    result = scan_dependencies([django], OsvClient())
    assert result.findings, "expected findings for django 3.2.0"
    assert not result.incomplete
    for finding in result.findings:
        if finding.fix:
            assert parse_version(finding.fix) > parse_version("3.2.0")
    assert any(f.fix and f.fix.startswith("3.2.") for f in result.findings)
    upgrade, _ = suggest_upgrade(result.findings)
    assert upgrade is not None

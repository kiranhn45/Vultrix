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

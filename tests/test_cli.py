import pytest

from valtrix import __version__
from valtrix import cli
from valtrix.cli import EXIT_BAD_INPUT, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK, main
from valtrix.databases import OsvError
from valtrix.models import Vulnerability


# ------------------------------------------------------------ test double

class FakeClient:
    """Stands in for OsvClient so no network is needed."""

    table = {}
    calls = []

    def query(self, name, version):
        FakeClient.calls.append((name, version))
        answer = FakeClient.table.get((name, version), [])
        if isinstance(answer, BaseException):
            raise answer
        return answer


@pytest.fixture
def fake_osv(monkeypatch):
    FakeClient.table, FakeClient.calls = {}, []
    monkeypatch.setattr(cli, "OsvClient", FakeClient)
    return FakeClient


def write_requirements(folder, text):
    (folder / "requirements.txt").write_text(text)


DJANGO_VULNS = [
    Vulnerability(id="GHSA-aaaa", summary="SQL\ninjection", severity_label="CRITICAL",
                  fixed_versions=("2.2.28", "3.2.13", "4.0.4")),
    Vulnerability(id="GHSA-bbbb", summary="Denial of service", severity_label="HIGH",
                  fixed_versions=("3.2.25",)),
    Vulnerability(id="PYSEC-cccc"),
]


# ---------------------------------------------------------------- basics

def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_OK
    out = capsys.readouterr().out
    assert "scan" in out and "lookup" in out and "Exit codes" in out


def test_scan_missing_path(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope")]) == EXIT_BAD_INPUT
    assert "does not exist" in capsys.readouterr().err


def test_scan_file_instead_of_directory(tmp_path, capsys):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.31.0\n")
    assert main(["scan", str(f)]) == EXIT_BAD_INPUT
    assert "not a directory" in capsys.readouterr().err


# ---------------------------------------------------------- scan --offline

def test_offline_directory_without_requirements(tmp_path, capsys):
    assert main(["scan", str(tmp_path), "--offline"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Target:" in out and "No requirements.txt found" in out


def test_offline_lists_dependencies_without_touching_osv(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "requests==2.31.0\nflask>=3.0\n# comment\n==broken\n")
    assert main(["scan", str(tmp_path), "--offline"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Found 2 dependencies" in out
    assert "requests" in out and "2.31.0" in out
    assert "flask" in out and "not pinned" in out
    assert "1 lines could not be used" in out and "requirements.txt:4" in out
    assert "OSV was not contacted" in out
    assert fake_osv.calls == []


def test_offline_unreadable_file(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_bytes(b"\x80\x81\x82\xfa\xfb")
    assert main(["scan", str(tmp_path), "--offline"]) == EXIT_BAD_INPUT
    assert "not valid" in capsys.readouterr().err


# ------------------------------------------------------------ scan (online)

def test_scan_reports_findings_and_exits_1(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "django==3.2.0\nrequests==2.31.0\n")
    fake_osv.table = {("django", "3.2.0"): DJANGO_VULNS}
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "Checked 2 of 2 dependencies" in out
    assert "1 dependency with known vulnerabilities (3 issues in total)" in out
    assert "django 3.2.0" in out
    assert "3 issues: 1 critical, 1 high, 1 unknown" in out
    assert "Upgrading to 3.2.25 or later" in out
    assert "1 issue with no known fix" in out
    assert "1 dependency with no known vulnerabilities" in out
    assert "Run with --details" in out
    assert "GHSA-aaaa" not in out          # summary only by default


def test_scan_details_lists_every_issue(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "django==3.2.0\n")
    fake_osv.table = {("django", "3.2.0"): DJANGO_VULNS}
    assert main(["scan", str(tmp_path), "--details"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "[CRITICAL] GHSA-aaaa  SQL injection  (fix: 3.2.13)" in out
    assert "[HIGH] GHSA-bbbb" in out and "(fix: 3.2.25)" in out
    assert "[UNKNOWN] PYSEC-cccc" in out and "no fix listed" in out
    assert "Run with --details" not in out


def test_scan_clean_project_exits_0(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "requests==2.31.0\n")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "No known vulnerabilities in the dependencies that were checked" in out
    assert "not that the code is guaranteed safe" in out


def test_unpinned_dependencies_are_reported_but_do_not_fail(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "requests==2.31.0\nflask>=3.0\nnumpy\n")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Checked 1 of 3 dependencies" in out
    assert "Not checked (2)" in out
    assert "flask  version is not pinned" in out and "requirements.txt:2" in out
    assert fake_osv.calls == [("requests", "2.31.0")]


def test_unreachable_osv_exits_3(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "a==1.0\nb==1.0\n")
    down = OsvError("Could not get an answer from OSV after 4 attempts", unreachable=True)
    fake_osv.table = {("a", "1.0"): down, ("b", "1.0"): down}
    assert main(["scan", str(tmp_path)]) == EXIT_INCOMPLETE
    captured = capsys.readouterr()
    assert "Not checked (2)" in captured.out and "lookup failed" in captured.out
    assert "scan is incomplete" in captured.err


def test_never_says_no_vulnerabilities_when_nothing_was_checked(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "a==1.0\nb==1.0\n")
    down = OsvError("Could not get an answer from OSV", unreachable=True)
    fake_osv.table = {("a", "1.0"): down, ("b", "1.0"): down}
    assert main(["scan", str(tmp_path)]) == EXIT_INCOMPLETE
    out = capsys.readouterr().out
    assert "Checked 0 of 2 dependencies" in out
    assert "Nothing could be checked" in out
    assert "No known vulnerabilities" not in out
    assert "guaranteed safe" not in out


def test_only_unpinned_dependencies_is_not_reported_as_clean(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "flask>=3.0\n")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Nothing could be checked" in out and "No known vulnerabilities" not in out


def test_empty_requirements_file(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "# nothing here\n")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "No dependencies were found" in out and "No known vulnerabilities" not in out


def test_findings_take_priority_over_incomplete(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "django==3.2.0\nbroken==1.0\n")
    fake_osv.table = {
        ("django", "3.2.0"): DJANGO_VULNS,
        ("broken", "1.0"): OsvError("OSV rejected the request (HTTP 400)"),
    }
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS
    assert "HTTP 400" in capsys.readouterr().out


def test_scan_reports_unusable_lines(tmp_path, capsys, fake_osv):
    write_requirements(tmp_path, "requests==2.31.0\n==oops\n")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "1 line could not be used" in out and "requirements.txt:2" in out


def test_scan_directory_without_requirements(tmp_path, capsys, fake_osv):
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    assert "No requirements.txt found" in capsys.readouterr().out
    assert fake_osv.calls == []


def test_scan_unreadable_requirements_file(tmp_path, capsys, fake_osv):
    (tmp_path / "requirements.txt").write_bytes(b"\x80\x81\x82\xfa\xfb")
    assert main(["scan", str(tmp_path)]) == EXIT_BAD_INPUT
    assert "not valid" in capsys.readouterr().err


def test_scan_follows_includes(tmp_path, capsys, fake_osv):
    (tmp_path / "base.txt").write_text("django==3.2.0\n")
    write_requirements(tmp_path, "-r base.txt\n")
    fake_osv.table = {("django", "3.2.0"): DJANGO_VULNS}
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS
    assert "Sources: base.txt, requirements.txt" in capsys.readouterr().out


# ----------------------------------------------------------------- lookup

def test_lookup_picks_the_fix_for_the_installed_version(fake_osv, capsys):
    fake_osv.table = {("django", "3.2.0"): [DJANGO_VULNS[0], DJANGO_VULNS[2]]}
    assert main(["lookup", "Django", "3.2.0"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert fake_osv.calls == [("django", "3.2.0")]
    assert "django 3.2.0 (PyPI)" in out
    assert "Found 2 known vulnerabilities" in out
    assert "GHSA-aaaa  [CRITICAL]" in out
    assert "SQL injection" in out
    assert "Fixed in: 3.2.13 (other release lines: 2.2.28, 4.0.4)" in out
    assert "PYSEC-cccc  [severity unknown]" in out and "No fixed version listed" in out
    assert "https://osv.dev/vulnerability/GHSA-aaaa" in out


def test_lookup_shows_aliases(fake_osv, capsys):
    fake_osv.table = {("requests", "2.25.1"): [
        Vulnerability(id="GHSA-x", aliases=("CVE-2023-1", "PYSEC-1"), fixed_versions=("2.31.0",))]}
    main(["lookup", "requests", "2.25.1"])
    out = capsys.readouterr().out
    assert "Also known as: CVE-2023-1, PYSEC-1" in out
    assert "Found 1 known vulnerability:" in out


def test_lookup_when_no_fix_applies_lists_all_fixed_versions_sorted(fake_osv, capsys):
    fake_osv.table = {("old", "5.0"): [Vulnerability(id="X-1", fixed_versions=("3.2.10", "3.2.9"))]}
    main(["lookup", "old", "5.0"])
    assert "Fixed in: 3.2.9, 3.2.10" in capsys.readouterr().out


def test_lookup_without_findings_is_careful_about_wording(fake_osv, capsys):
    assert main(["lookup", "requests", "2.31.0"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "No known vulnerabilities" in out
    assert "not that the package is guaranteed safe" in out


def test_lookup_reports_osv_failure_without_crashing(fake_osv, capsys):
    fake_osv.table = {("requests", "2.25.1"): OsvError("Could not get an answer from OSV after 4 attempts")}
    assert main(["lookup", "requests", "2.25.1"]) == EXIT_INCOMPLETE
    assert "after 4 attempts" in capsys.readouterr().err


@pytest.mark.parametrize("package,version", [("bad name", "1.0"), ("requests", "1.*"), ("requests", ">=1.0"), (".hidden", "1.0")])
def test_lookup_rejects_bad_input_before_any_request(fake_osv, capsys, package, version):
    assert main(["lookup", package, version]) == EXIT_BAD_INPUT
    assert fake_osv.calls == []
    assert "valtrix:" in capsys.readouterr().err


def test_lookup_requires_both_arguments(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["lookup", "requests"])
    assert exc.value.code == 2

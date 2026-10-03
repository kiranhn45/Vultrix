import pytest

from valtrix import __version__
from valtrix import cli
from valtrix.cli import EXIT_BAD_INPUT, EXIT_ERROR, EXIT_OK, main
from valtrix.databases import OsvError
from valtrix.models import Vulnerability


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_OK
    assert "scan" in capsys.readouterr().out


def test_scan_directory_without_requirements(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Target:" in out
    assert "No requirements.txt found" in out


def test_scan_lists_dependencies(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3.0\n# comment\n==broken\n"
    )
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Found 2 dependencies" in out
    assert "requests" in out and "2.31.0" in out
    assert "flask" in out and "not pinned" in out
    assert "1 lines could not be used" in out
    assert "requirements.txt:4" in out


def test_scan_unreadable_requirements_file(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_bytes(b"\x80\x81\x82\xfa\xfb")
    assert main(["scan", str(tmp_path)]) == EXIT_BAD_INPUT
    assert "not valid" in capsys.readouterr().err


def test_scan_missing_path(tmp_path, capsys):
    missing = tmp_path / "nope"
    assert main(["scan", str(missing)]) == EXIT_BAD_INPUT
    assert "does not exist" in capsys.readouterr().err


def test_scan_file_instead_of_directory(tmp_path, capsys):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.31.0\n")
    assert main(["scan", str(f)]) == EXIT_BAD_INPUT
    assert "not a directory" in capsys.readouterr().err


# ----------------------------------------------------------------- lookup

class FakeClient:
    """Stands in for OsvClient so no network is needed."""

    result = []
    error = None
    calls = []

    def query(self, name, version):
        FakeClient.calls.append((name, version))
        if FakeClient.error:
            raise FakeClient.error
        return FakeClient.result


@pytest.fixture
def fake_osv(monkeypatch):
    FakeClient.result, FakeClient.error, FakeClient.calls = [], None, []
    monkeypatch.setattr(cli, "OsvClient", FakeClient)
    return FakeClient


def test_lookup_prints_findings(fake_osv, capsys):
    fake_osv.result = [
        Vulnerability(
            id="GHSA-aaaa-bbbb-cccc",
            summary="Leaks\nheaders",
            aliases=("CVE-2023-32681",),
            severity_label="MEDIUM",
            fixed_versions=("2.31.0",),
        ),
        Vulnerability(id="PYSEC-1"),
    ]
    assert main(["lookup", "Requests", "2.25.1"]) == EXIT_OK
    out = capsys.readouterr().out
    assert fake_osv.calls == [("requests", "2.25.1")]
    assert "requests 2.25.1 (PyPI)" in out
    assert "Found 2 known vulnerabilities" in out
    assert "GHSA-aaaa-bbbb-cccc  [MEDIUM]" in out
    assert "CVE-2023-32681" in out
    assert "Leaks headers" in out
    assert "Fixed in: 2.31.0" in out
    assert "PYSEC-1  [severity unknown]" in out
    assert "No fixed version listed" in out
    assert "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc" in out


def test_lookup_singular_wording(fake_osv, capsys):
    fake_osv.result = [Vulnerability(id="PYSEC-1")]
    main(["lookup", "requests", "2.25.1"])
    assert "Found 1 known vulnerability:" in capsys.readouterr().out


def test_lookup_no_findings_is_careful_about_wording(fake_osv, capsys):
    assert main(["lookup", "requests", "2.31.0"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "No known vulnerabilities" in out
    assert "not that the package is guaranteed safe" in out


def test_lookup_reports_osv_failure_without_crashing(fake_osv, capsys):
    fake_osv.error = OsvError("Could not get an answer from OSV after 4 attempts")
    assert main(["lookup", "requests", "2.25.1"]) == EXIT_ERROR
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

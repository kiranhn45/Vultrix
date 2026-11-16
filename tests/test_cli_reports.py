"""Command-line behaviour added after Phase 4: formats, files, settings, graph, ecosystems."""

import json
import shutil
from pathlib import Path

import pytest

from valtrix import cli
from valtrix.cli import EXIT_BAD_INPUT, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK, main
from valtrix.databases import ExploitData, OsvError
from valtrix.models import Vulnerability

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class FakeClient:
    table = {}
    calls = []

    def query(self, name, version, ecosystem="PyPI"):
        FakeClient.calls.append((ecosystem, name, version))
        answer = FakeClient.table.get((name, version), [])
        if isinstance(answer, BaseException):
            raise answer
        return answer


@pytest.fixture
def osv(monkeypatch):
    FakeClient.table, FakeClient.calls = {}, []
    monkeypatch.setattr(cli, "OsvClient", FakeClient)
    return FakeClient


CRITICAL = Vulnerability("GHSA-crit", summary="Remote code execution", severity_label="CRITICAL",
                         aliases=("CVE-2024-0001",), fixed_versions=("3.2.13",))
MEDIUM = Vulnerability("GHSA-med", summary="Open redirect", severity_label="MEDIUM", fixed_versions=("3.2.5",))
NO_SEVERITY = Vulnerability("PYSEC-1", summary="SQL injection allows remote code execution")


def project(tmp_path, text="django==3.2.0\n"):
    (tmp_path / "requirements.txt").write_text(text)
    return str(tmp_path)


# -------------------------------------------------------------------- formats

def test_json_on_stdout_is_nothing_but_json(tmp_path, capsys, osv):
    osv.table = {("django", "3.2.0"): [MEDIUM, CRITICAL]}
    assert main(["scan", project(tmp_path), "--format", "json"]) == EXIT_FINDINGS
    report = json.loads(capsys.readouterr().out)
    assert [f["vulnerability"]["id"] for f in report["findings"]] == ["GHSA-crit", "GHSA-med"]
    assert report["summary"]["exit_code"] == 1 and report["target"] == str(tmp_path.resolve())


def test_json_report_for_a_folder_without_dependency_files(tmp_path, capsys, osv):
    assert main(["scan", str(tmp_path), "--format", "json"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["sources"] == []


def test_output_file_and_summary_on_screen(tmp_path, capsys, osv):
    osv.table = {("django", "3.2.0"): [CRITICAL]}
    target = tmp_path / "out" / "report.html"
    target.parent.mkdir()
    assert main(["scan", project(tmp_path), "--format", "html", "--output", str(target)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "Fix first" in out and f"Wrote the html report to {target}" in out and "<html" not in out
    page = target.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>") and "Remote code execution" in page


def test_sarif_and_text_files(tmp_path, capsys, osv):
    osv.table = {("django", "3.2.0"): [CRITICAL]}
    folder = project(tmp_path)
    assert main(["scan", folder, "--format", "sarif", "--output", str(tmp_path / "r.sarif")]) == EXIT_FINDINGS
    assert json.loads((tmp_path / "r.sarif").read_text())["runs"][0]["results"][0]["ruleId"] == "GHSA-crit"
    assert main(["scan", folder, "--output", str(tmp_path / "r.txt")]) == EXIT_FINDINGS
    text = (tmp_path / "r.txt").read_text()
    assert "Fix first" in text and "\x1b[" not in text


def test_unwritable_output_is_bad_input(tmp_path, capsys, osv):
    code = main(["scan", project(tmp_path), "--output", str(tmp_path / "missing" / "r.txt")])
    assert code == EXIT_BAD_INPUT and "could not write" in capsys.readouterr().err


# --------------------------------------------------------------- prioritizing

def test_details_show_why_each_issue_ranks_where_it_does(tmp_path, capsys, osv, monkeypatch):
    osv.table = {("django", "3.2.0"): [MEDIUM, CRITICAL, NO_SEVERITY]}
    seen = []

    def evidence(cves):
        seen.extend(cves)
        return ExploitData(kev={"CVE-2024-0001": False}, epss_status="ok", kev_status="ok")

    monkeypatch.setattr(cli, "gather_exploit_data", evidence)
    assert main(["scan", project(tmp_path), "--details"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert seen == ["CVE-2024-0001"]
    assert out.index("GHSA-crit\n") < out.index("PYSEC-1\n") < out.index("GHSA-med\n")
    assert "1. score  97  fix now" in out
    assert "+25  Exploitation: CVE-2024-0001 is in CISA's catalog" in out
    assert " +7  Fix: A fix exists: upgrade django to 3.2.13" in out
    assert "Estimated by the Valtrix model" in out
    assert "Priorities: 1 fix now" in out


def test_no_ml_and_no_exploit_data_flags(tmp_path, capsys, osv, monkeypatch):
    osv.table = {("django", "3.2.0"): [NO_SEVERITY]}
    monkeypatch.setattr(cli, "gather_exploit_data", lambda cves: pytest.fail("must not be called"))
    assert main(["scan", project(tmp_path), "--details", "--no-ml", "--no-exploit-data"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "Estimated by keyword rules" in out and "Exploitation evidence was not looked up" in out


def test_missing_exploit_data_is_mentioned_not_hidden(tmp_path, capsys, osv, monkeypatch):
    osv.table = {("django", "3.2.0"): [CRITICAL]}
    monkeypatch.setattr(cli, "gather_exploit_data", lambda cves: ExploitData(
        epss_status="unavailable", kev_status="unavailable", notes=["EPSS exploit-likelihood scores could not be fetched (down)."]))
    assert main(["scan", project(tmp_path)]) == EXIT_FINDINGS
    assert "Note: EPSS exploit-likelihood scores could not be fetched" in capsys.readouterr().out


# ------------------------------------------------------- fail-on and ignoring

def test_fail_on_threshold(tmp_path, capsys, osv):
    osv.table = {("django", "3.2.0"): [MEDIUM]}
    folder = project(tmp_path)
    assert main(["scan", folder, "--fail-on", "medium"]) == EXIT_FINDINGS
    assert main(["scan", folder, "--fail-on", "high"]) == EXIT_OK
    captured = capsys.readouterr()
    assert "GHSA-med" in captured.out and "below the --fail-on level (high)" in captured.err
    assert main(["scan", folder, "--fail-on", "none"]) == EXIT_OK


def test_incomplete_scan_still_exits_3_below_the_threshold(tmp_path, capsys, osv):
    osv.table = {("django", "3.2.0"): [MEDIUM], ("b", "1.0"): OsvError("OSV rejected the request (HTTP 400)")}
    assert main(["scan", project(tmp_path, "django==3.2.0\nb==1.0\n"), "--fail-on", "high"]) == EXIT_INCOMPLETE
    assert "scan is incomplete" in capsys.readouterr().err


def test_ignore_flag_and_settings_file(tmp_path, capsys, osv):
    osv.table = {("django", "3.2.0"): [MEDIUM, CRITICAL]}
    folder = project(tmp_path)
    assert main(["scan", folder, "--ignore", "CVE-2024-0001", "--ignore", "GHSA-med"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Ignored by the project's settings (2)" in out and "ignored on the command line" in out

    (tmp_path / ".valtrix.toml").write_text(
        'fail-on = "critical"\n[[ignore]]\nid = "GHSA-crit"\nreason = "admin site is not deployed"\n')
    assert main(["scan", folder]) == EXIT_OK                     # medium is below critical, critical is accepted
    assert "admin site is not deployed" in capsys.readouterr().out
    assert main(["scan", folder, "--fail-on", "low"]) == EXIT_FINDINGS       # the flag overrides the file
    assert main(["scan", folder, "--no-config"]) == EXIT_FINDINGS            # nothing in the project can hide findings
    assert "Ignored by" not in capsys.readouterr().out.split("Target:")[-1]


def test_bad_settings_and_bad_ignore_id_are_bad_input(tmp_path, capsys, osv):
    folder = project(tmp_path)
    assert main(["scan", folder, "--ignore", "not an id"]) == EXIT_BAD_INPUT
    (tmp_path / ".valtrix.toml").write_text('[[ignore]]\nid = "GHSA-crit"\n')
    assert main(["scan", folder]) == EXIT_BAD_INPUT
    assert "needs a `reason`" in capsys.readouterr().err
    assert osv.calls == []


# ----------------------------------------------------------------- ecosystems

def test_scan_covers_every_ecosystem_and_passes_it_to_osv(tmp_path, capsys, osv):
    for folder, name in [("node-app", "package-lock.json"), ("node-app", "package.json"),
                         ("rust-app", "Cargo.lock"), ("go-app", "go.mod")]:
        shutil.copy(EXAMPLES / folder / name, tmp_path / name)
    osv.table = {("qs", "6.7.0"): [Vulnerability("GHSA-qs", summary="Prototype pollution", severity_label="HIGH",
                                                 fixed_versions=("6.7.3", "6.2.4"))]}
    assert main(["scan", project(tmp_path), "--details"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert {eco for eco, _, _ in osv.calls} == {"PyPI", "npm", "crates.io", "Go"}
    assert ("Go", "github.com/gin-gonic/gin", "1.7.0") in osv.calls
    assert "qs 6.7.0  (npm, transitive)" in out and "Pulled in by: express 4.17.1" in out
    assert "(fix: 6.7.3)" in out
    assert " +5  Exposure: Transitive dependency, pulled in by express 4.17.1" in out


def test_dev_only_dependency_scores_lower(tmp_path, capsys, osv):
    shutil.copytree(EXAMPLES / "poetry-app", tmp_path / "app")
    same = Vulnerability("GHSA-same", summary="Bug", severity_label="HIGH", fixed_versions=("99.0",))
    osv.table = {("pyyaml", "5.3"): [same], ("flask", "2.0.1"): [same]}
    assert main(["scan", str(tmp_path / "app"), "--format", "json", "--no-config"]) == EXIT_FINDINGS
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert [(f["dependency"]["name"], f["risk"]["score"]) for f in findings] == [("flask", 63), ("pyyaml", 55)]
    assert findings[1]["dependency"]["dev"] is True


def test_example_settings_are_applied(capsys, osv):
    osv.table = {("requests", "2.25.1"): [Vulnerability("GHSA-9wx4-h78v-vm56", summary="x", severity_label="MEDIUM")]}
    assert main(["scan", str(EXAMPLES / "poetry-app")]) == EXIT_OK
    assert "we never call requests with verify=False, until 2099-01-01" in capsys.readouterr().out


def test_offline_lists_every_ecosystem(capsys, osv):
    assert main(["scan", str(EXAMPLES / "node-app"), "--offline"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Found 6 dependencies" in out and "[npm, transitive]" in out and "[npm, dev]" in out
    assert osv.calls == []


def test_broken_lock_file_is_bad_input(tmp_path, capsys, osv):
    (tmp_path / "Cargo.lock").write_text("[[package\n")
    assert main(["scan", str(tmp_path)]) == EXIT_BAD_INPUT
    assert "not valid TOML" in capsys.readouterr().err
    assert main(["scan", str(tmp_path), "--offline"]) == EXIT_BAD_INPUT
    assert main(["graph", str(tmp_path)]) == EXIT_BAD_INPUT


# ------------------------------------------------------ lookup, graph, model

def test_lookup_in_another_ecosystem(capsys, osv):
    osv.table = {("@scope/pkg", "1.0.0-rc.1"): [Vulnerability("GHSA-x", fixed_versions=("1.0.0", "0.9.5"))]}
    assert main(["lookup", "@scope/pkg", "1.0.0-rc.1", "--ecosystem", "npm"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert osv.calls == [("npm", "@scope/pkg", "1.0.0-rc.1")]
    assert "@scope/pkg 1.0.0-rc.1 (npm)" in out and "Fixed in: 1.0.0 (other release lines: 0.9.5)" in out
    assert main(["lookup", "@scope/pkg", "1.0.0"]) == EXIT_BAD_INPUT          # not a PyPI name


def test_graph_command(tmp_path, capsys):
    assert main(["graph", str(EXAMPLES / "poetry-app")]) == EXIT_OK
    out = capsys.readouterr().out
    assert "flask 2.0.1\n  click 8.1.3\n  jinja2 3.0.1\n    markupsafe 2.0.1" in out
    assert "3 direct dependencies, 6 pulled in by other packages." in out
    assert main(["graph", project(tmp_path)]) == EXIT_OK
    assert "do not record which package pulls in which" in capsys.readouterr().out
    assert main(["graph", str(tmp_path / "nope")]) == EXIT_BAD_INPUT
    (tmp_path / "empty").mkdir()
    assert main(["graph", str(tmp_path / "empty")]) == EXIT_OK
    assert "No dependency files found" in capsys.readouterr().out


def test_model_command(capsys):
    assert main(["model"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "always marked as an estimate" in out and "Keyword rules" in out and "never seen in training" in out

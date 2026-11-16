# Valtrix progress

Update this file at the end of every step. Paste it into a new chat to resume.

## Current phase
Version 1.0.0: all 11 phases built. Waiting for the live check on the user's machine
(`python scripts/check.py --live`), because the build sandbox could not reach api.osv.dev or api.first.org.

## Done
- Phase 1: repo layout, `pyproject.toml`, `valtrix` command, README, LICENSE, `.gitignore`
- Phase 2: `Dependency` model, `requirements.txt` parser (includes, encodings, limits), `valtrix scan` lists dependencies
- Phase 3:
  - `Vulnerability` model (`models/vulnerability.py`)
  - `OsvClient` (`databases/osv.py`), standard library `urllib` only: retries with backoff,
    Retry-After, timeouts, response size cap, page cap, https only, certificate failures
    not retried, in-memory cache, withdrawn advisories excluded
  - Server data treated as untrusted: types checked, terminal control characters stripped,
    text clipped, only http(s) links kept, GIT-range commit hashes never reported as versions
  - `valtrix lookup <package> <version>` command
  - Test suite blocks the network (`tests/conftest.py`); live tests are opt-in (`pytest -m live`)
  - Client tests were mutation-checked: 10 deliberate bugs, all caught
  - Live run found that OSV lists one issue several times (GHSA, PYSEC, CVE, BIT copies):
    django 3.2.0 returned 66 records for about 33 issues, and the PYSEC copies lacked severity.
    `merge_related()` (`models/vulnerability.py`) now merges records that share any identifier,
    keeps the richest record's ID, unions fields, and loses no identifier. Mutation-checked.
- Phase 4:
  - `valtrix/versions.py`: PEP 440 subset comparison, `choose_fix()`, `sort_versions()`.
    Cross-checked against the `packaging` library; real django fix lists are test cases.
  - `Finding` (one dependency + one vulnerability + the fix that applies), `Unchecked`, `ScanResult`
    (`models/finding.py`)
  - `scan_dependencies()` / `scan_project()` (`scanner/dependency_scanner.py`): a failing package never
    stops the scan; 3 unreachable failures in a row (network down, HTTP 401/403/407, repeated 5xx)
    stop it early and the rest are listed as not checked; duplicate pins are checked once
  - `valtrix scan` summarizes per dependency, `--details` lists every issue, `--offline` skips the network
  - Exit codes 0/1/2/3 (documented in README and `--help`)
  - A real run in a network-blocked sandbox found two bugs the fake-client tests missed:
    "No known vulnerabilities" was printed when nothing was checked, and HTTP 403 did not stop the scan
    early. Both fixed and tested.
  - Mutation-checked: 14 deliberate bugs. One survivor revealed dead logic in `choose_fix`; simplified.
- Phase 5 (reporting):
  - `reports/terminal.py`: pure functions that return text; `cli.py` only prints
  - `--format json` (`reports/json_report.py`, documented in `docs/json-report.md`, `schema_version` 1)
  - `--format html` (`reports/html_report.py`): one file, no scripts, strict Content-Security-Policy,
    every outside value escaped; tests inject markup through every field
  - `--format sarif` (`reports/sarif.py`) for GitHub code scanning
  - `--output FILE`; a machine-readable report on stdout is the only thing on stdout
- Phase 6 (more ecosystems): `parsers/` now reads `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`,
  `package-lock.json` (versions 1 to 3), `Cargo.lock`, `go.mod`, plus dev requirement files.
  `parsers/discover.py` finds them all. `Dependency` gained `ecosystem`, `direct`, `dev`, `path`.
  SemVer comparison (`versions.parse_semver`) for npm, crates.io and Go. `lookup --ecosystem`.
- Phase 7 (dependency graph): `models/graph.py`; lock-file parsers return edges; discovery fills in the
  shortest chain that pulls each package in and marks dev-only packages; `valtrix graph`
- Phase 8 (risk rules): `risk/cvss.py` (CVSS 3.x base score, checked against published scores),
  `databases/exploits.py` (EPSS and CISA KEV, optional, validated), `risk/rules.py`
  (score 0 to 100 = severity 60 + exploitation 25 + exposure 8 + fix 7). Documented in `docs/scoring.md`.
- Phase 9 (machine learning): `risk/severity_model.py` + `scripts/train_model.py`. Logistic regression in
  plain Python that estimates severity for advisories that publish none. Trained on 16,751 advisories,
  tested on the 4,188 newest: accuracy 65.7% / AUC 0.716, against 53.3% / 0.586 for the keyword-rule
  baseline. Settings were chosen on a validation slice, not the test set. `docs/severity-model.md`.
- Phase 10 (explainability): every score lists its four factors, their points and a sentence each, in all
  report formats; model estimates name the words that drove them; `valtrix model` shows the test results
- Phase 11 (developer experience and CI): `[tool.valtrix]` / `.valtrix.toml` settings (`config.py`),
  `--fail-on`, `--ignore`, ignore rules with a required reason and optional expiry, `--no-config`,
  GitHub Action (`action.yml`), pre-commit hook, CI workflow running the gate, `docs/ci.md`
- Verification beyond unit tests:
  - Full scans of every example against a stand-in OSV server built from OSV's own data exports
    (real advisories, real CVSS vectors) for all four ecosystems
  - One real request to the KEV catalog (1,781 entries; the cisa.gov -> mirror fallback worked), and a real
    EPSS failure, which degraded as designed
  - HTML report and `ui/index.html` opened in a browser, including a report file with injected markup
  - Mutation check: 26 deliberate bugs, 25 caught at first; a test was added for the survivor
- `ui/index.html` is now a report viewer: it opens a `--format json` report in the browser
- Phase gate: `python scripts/check.py` (see below)

## Decisions
- Name: Valtrix (working title was VulnScan)
- argparse and urllib: zero runtime dependencies
- Only exact `==` pins count as a known version; ranges and unpinned names have `version = None`
- Project files and server responses are untrusted input
- Includes may not leave the project folder
- A withdrawn OSV advisory is a retracted false alarm, so it is not reported
- Records sharing any identifier are one issue and are merged (found by the live check, not by mocks)
- A Finding is one (dependency, vulnerability) pair; that pair is what Phase 8 ranks
- The fix to show is the lowest listed fix above the installed version
- Unpinned dependencies are reported, never silently skipped, and do not fail the scan
- Never print "no vulnerabilities" unless at least one dependency was actually checked
- Exit codes: 0 clean, 1 findings, 2 bad input, 3 incomplete (findings take priority over incomplete)
- The gate captures command output in temp files, never pipes, closes stdin, and times out every command.
  A `git status` hung the gate on the user's Windows machine (suspected cause: a background git process
  kept the output pipe open). Reproduced the pattern and added regression tests (`tests/test_check_script.py`).
- Severity is stored as published (label and CVSS vector). Scores are computed in `risk/`, never stored.
- Python 3.11 is the minimum (3.9 and 3.10 are past end of life; `tomllib` keeps the zero-dependency rule)
- A lock file beats a declaration: `pyproject.toml` is only a dependency source when nothing pins versions
- The risk score is a plain sum of four factors so every point can be explained. No hidden weights.
- Missing evidence adds no points and is stated in the report; it is never treated as "not exploited"
- EPSS and KEV are optional: a failure there never makes the scan incomplete or changes the exit code
- ML has one narrow job: estimate severity when none is published. It is labelled as an estimate, capped
  below a published "high", and a test fails if the shipped model does not beat the keyword baseline.
  The model file is JSON read as data; nothing is unpickled or executed.
- Project settings are untrusted input: ignore rules need a reason, ignored findings stay in every report,
  `--no-config` switches the project's settings off
- Unknown severity always counts as reaching `--fail-on`
- `MAL-` (malware) advisories always get the top severity
- No automatic patching; a human reviews every fix.

## Next step
On a machine with normal internet access:

    python scripts/check.py --live

This runs the live tests that could not run in the sandbox: OSV for npm, Go and crates.io, and EPSS + KEV
for CVE-2021-44228. If one fails, the failure message says which service and why.

Ideas for after 1.0 (none started):
- An offline mode that scans against a downloaded OSV export
- Scanning subfolders (monorepos), `yarn.lock`, `pnpm-lock.yaml`, Maven and Gradle
- CVSS version 4 scores (needs the official lookup table)
- Publishing to PyPI

## Phase gate
Run after every phase, before committing:

    python scripts/check.py          # offline checks
    python scripts/check.py --live   # also checks the real OSV API (needs internet)

The gate must print GATE PASSED. Then walk this checklist:

- [ ] New code has tests, including failure cases (bad input, network down, malformed data)
- [ ] Anything from outside the program (files, server responses) is validated before use
- [ ] No secrets, no `.env`, no `.venv` committed
- [ ] If the phase uses the network, `--live` passed on a real machine
- [ ] README, this file, and the UI roadmap are up to date
- [ ] Committed with a message that says what the phase added

## Phase gate log
| Phase | Date | Result | Mode |
|---|---|---|---|
| Phase 1: project foundation | 2026-10-03 | 5 passed (user machine, Python 3.14) | offline only |
| Phase 2: dependency discovery | 2026-10-03 | 40 passed (sandbox) | offline only |
| Phase 3: OSV vulnerability database client | 2026-10-03 | 99 passed, 2 deselected (user machine, Python 3.14) | offline + live, passed. Committed ccd219c |
| Phase 3 fix: merge duplicate advisories | 2026-10-03 | 108 passed, 3 deselected (sandbox) | offline. Live re-check pending on user machine |
| Phase 4: the scanner | 2026-10-04 | 182 passed, 4 deselected (sandbox) | offline. Live check pending on user machine; gate hung at the git step on first run, fixed |
| Phases 5 to 11: reporting, ecosystems, graph, risk rules, ML, explainability, CI | 2026-11-16 | 321 passed, 6 deselected (sandbox, Python 3.13) | offline. Live check pending on user machine |

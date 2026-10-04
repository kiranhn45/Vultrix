# Valtrix progress

Update this file at the end of every step. Paste it into a new chat to resume.

## Current phase
Phase 4: the scanner. Built; waiting for the live check on the user's machine.

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
- Phase gate: `python scripts/check.py` (see below)
- UI mock-up in `ui/index.html` (sample data only; roadmap still shows Phase 2, update after the live check)

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
- Severity is stored as published (label and CVSS vector). Computing scores belongs to Phase 8.
- V1 is not AI. ML arrives in Phase 9, compared against a rule-based baseline.
- No automatic patching; a human reviews every fix.

## Next step
Phase 5: reporting.
- Move the terminal output out of `cli.py` into `reports/terminal.py` as pure functions that return text
- `--format json`: stable, documented structure (this becomes the CI interface)
- `--format html`: one self-contained file. Every value from OSV (summaries, ids, URLs) is untrusted and
  must be HTML-escaped; links limited to http(s). Add tests that try to inject markup.
- Include the version, scan time, sources, unchecked dependencies, and the incomplete flag in JSON/HTML
- `--output FILE` to write a report

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

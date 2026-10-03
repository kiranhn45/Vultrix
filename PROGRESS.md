# Valtrix progress

Update this file at the end of every step. Paste it into a new chat to resume.

## Current phase
Phase 3: OSV vulnerability database client. Built; waiting for the live check on the user's machine.

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
- Phase gate: `python scripts/check.py` (see below)
- UI mock-up in `ui/index.html` (sample data only; roadmap still shows Phase 2, update after the live check)

## Decisions
- Name: Valtrix (working title was VulnScan)
- argparse and urllib: zero runtime dependencies
- Only exact `==` pins count as a known version; ranges and unpinned names have `version = None`
- Project files and server responses are untrusted input
- Includes may not leave the project folder
- A withdrawn OSV advisory is a retracted false alarm, so it is not reported
- Severity is stored as published (label and CVSS vector). Computing scores belongs to Phase 8.
- V1 is not AI. ML arrives in Phase 9, compared against a rule-based baseline.
- No automatic patching; a human reviews every fix.

## Next step
Phase 4: the scanner. Combine parser and OSV client.
- `Finding` model: one Dependency plus its Vulnerabilities
- Scan every pinned dependency; report unpinned ones as "cannot check exactly"
- If OSV fails for one package, record the error for that package and continue
- `valtrix scan` prints findings and exits non-zero when vulnerabilities are found (needed for CI later)

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
| Phase 3: OSV vulnerability database client | 2026-10-03 | 99 passed, 2 deselected (sandbox) | offline only. Live check pending on user machine |

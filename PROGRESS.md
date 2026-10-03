# Valtrix progress

Update this file at the end of every step. Paste it into a new chat to resume.

## Current phase
Phase 2: dependency discovery. Complete.

## Done
- Phase 1: repo layout, `pyproject.toml`, `valtrix` command, README, LICENSE, `.gitignore`
- Phase 2:
  - `Dependency` model (`models/dependency.py`) with PEP 503 name normalization
  - `ParseResult` / `ParseIssue` (`models/parse_result.py`): the parser reports lines it
    could not use instead of silently dropping them
  - `requirements.txt` parser (`parsers/requirements.py`): comments, blank lines,
    `==` pins, ranges, unpinned names, extras, markers, `--hash`, line continuations,
    `-r` includes (cycle, depth, and outside-the-project guards), UTF-16 and BOM files
    (Windows PowerShell `pip freeze >`), file size limit
  - `valtrix scan <dir>` now lists the dependencies found in `requirements.txt`
  - 40 passing tests
- UI mock-up in `ui/index.html` (sample data only)

## Decisions
- Name: Valtrix (working title was VulnScan)
- argparse for the CLI for now, to keep dependencies at zero
- Only exact `==` pins count as a known version. Ranges and unpinned names have
  `version = None`, because vulnerability lookups need an exact version.
- Project files are untrusted input: parse as text only, never execute
- Includes may not leave the project folder (the scanner passes the project dir as `root`)
- V1 is not AI. ML arrives in Phase 9, compared against a rule-based baseline.
- No automatic patching; a human reviews every fix.

## Next step
Phase 3: OSV client.
- `Vulnerability` model in `src/valtrix/models/vulnerability.py`
- `OsvClient` in `src/valtrix/databases/osv.py`: query one package + version
- Handle network errors, timeouts, and retries without crashing
- Tests use mocked HTTP responses (no live network in tests)
- Standard library `urllib` or `requests`? Decide at the start of Phase 3.

## Suggested commits
1. `Add Dependency and ParseResult models`
2. `Add requirements.txt parser`
3. `Add parser tests`
4. `List parsed dependencies in scan command`

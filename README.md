# Valtrix

Scan a project's dependencies for known vulnerabilities, then work out which ones to fix first.

Valtrix reads your dependency files, checks every pinned package against the
[OSV](https://osv.dev) database, and ranks what it finds with a score you can read:
every point comes with the reason it was given.

- **Four ecosystems:** Python, npm, Rust and Go
- **Knows your dependency tree:** tells direct dependencies from transitive ones and shows what pulls each one in
- **Ranks, not just lists:** severity, real-world exploitation (CISA KEV, EPSS), exposure, and whether a fix exists
- **Explains itself:** no hidden weights; the score is a sum you can check
- **Reports for people and for CI:** terminal, HTML, JSON, SARIF
- **No runtime dependencies:** standard library only, Python 3.11+

## Install

```bash
pip install git+https://github.com/kiranhn45/Vultrix
```

For development:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
valtrix scan .                              # scan this folder (needs internet)
valtrix scan . --details                    # every issue, with the reasons behind its score
valtrix scan . --format html --output report.html
valtrix scan . --format json                # the stable interface for CI
valtrix scan . --fail-on high               # exit 1 only for high or critical findings
valtrix scan . --offline                    # only list the dependencies, no network
valtrix graph .                             # which package pulls in which
valtrix lookup requests 2.25.1              # check one package version
valtrix lookup lodash 4.17.20 --ecosystem npm
valtrix model                               # how the severity model was trained and tested
```

Try it on the examples: `valtrix scan examples/poetry-app --details`.

### What the output looks like

```
Fix first (top 5 of 8 issues, ranked by risk):

   1. score  74  fix now   pyyaml 5.3  GHSA-8q59-q68h-6hv4
      Improper Input Validation in PyYAML
      Why: Critical severity, CVSS 9.8 (reachable over the network, no login needed, no user action needed). ...
      A fix exists: upgrade pyyaml to 5.4.
```

With `--details`, each issue lists its four factors and the points each one added.

## Files it reads

| Ecosystem | Files | Knows direct from transitive |
|---|---|---|
| Python | `requirements.txt` (and `requirements-dev.txt`, `dev-requirements.txt`, `requirements-test.txt`) | no |
| Python | `poetry.lock`, `uv.lock` | yes, with the full tree |
| Python | `Pipfile.lock` | yes, when `Pipfile` is next to it |
| Python | `pyproject.toml` (when nothing above exists) | all direct |
| npm | `package-lock.json`, `npm-shrinkwrap.json` | yes, with the full tree |
| Rust | `Cargo.lock` | yes, with the full tree |
| Go | `go.mod` | yes (`// indirect`) |

Files are read from the folder you point at, not its subfolders. Only exact versions can
be checked; a dependency without one is listed as "Not checked", never silently skipped.

## How findings are ranked

A score from 0 to 100, the sum of four factors:

| Factor | Points | Source |
|---|---|---|
| Severity | 0 to 60 | CVSS base score, or the published label |
| Exploitation | 0 to 25 | CISA's Known Exploited Vulnerabilities catalog and EPSS |
| Exposure | 0 to 8 | direct, transitive, or development only |
| Fix | 0 to 7 | whether a fixed version exists |

70 or more is "fix now", 50 or more "fix soon", 35 or more "plan", otherwise "monitor".
Full details: [docs/scoring.md](docs/scoring.md).

When an advisory publishes no severity, a small model estimates it from the advisory
text. On advisories newer than its training data it is right about 66% of the time,
against 53% for keyword rules, so its output is always marked as an estimate and can
never outrank a published rating. See [docs/severity-model.md](docs/severity-model.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing found at or above `--fail-on`, and every lookup succeeded |
| 1 | Known vulnerabilities were found |
| 2 | Bad input (missing path, unreadable file, invalid name, version or settings) |
| 3 | The check could not be completed (OSV unreachable or a lookup failed) |

Dependencies without an exact version do not change the exit code.

## Settings

In `pyproject.toml` under `[tool.valtrix]`, or at the top level of `.valtrix.toml`:

```toml
[tool.valtrix]
fail-on = "high"

[[tool.valtrix.ignore]]
id = "GHSA-xxxx-xxxx-xxxx"
reason = "Only reachable from the admin site, which we do not deploy"
expires = "2027-03-01"
```

Ignored findings must have a reason and still appear in every report. Use `--no-config`
when scanning a project you do not trust.

## CI

A GitHub Action (with code-scanning upload), a pre-commit hook, and examples for other
systems are in [docs/ci.md](docs/ci.md). The JSON layout is in [docs/json-report.md](docs/json-report.md).

## What it does not do

- It does not know whether your code calls the vulnerable function.
- It never changes your files. A person reviews every upgrade.
- "No known vulnerabilities" means none are listed in OSV, not that the code is safe.

## Tests and the phase gate

```bash
pytest                           # offline tests (the network is blocked)
pytest -m live                   # real OSV API (needs internet)
python scripts/check.py          # full gate, run before every commit
python scripts/check.py --live   # also checks the real services
```

## Report viewer

`ui/index.html` is a standalone page. Open it in a browser, choose "Open a report", and
pick a file made with `valtrix scan . --format json --output report.json`. The file is
read in your browser and never uploaded.

## Project history

Built in 11 phases, each gated by tests: foundation, dependency discovery, OSV client,
scanner, reporting, more ecosystems, dependency graph, risk rules, machine learning,
explainability, developer experience. `PROGRESS.md` has the decisions and the gate log.

## License

MIT

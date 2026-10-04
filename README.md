# Valtrix

Scan a project's dependencies for known vulnerabilities, then work out which ones to fix first.

> Status: early development. Phases 1 to 4 are built. `valtrix scan` checks every pinned dependency in `requirements.txt` against OSV and `valtrix lookup` checks one package version.

## Install (development)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
valtrix --help
valtrix --version
valtrix scan .                    # check the project in this folder (needs internet)
valtrix scan . --details          # list every issue, not just a summary
valtrix scan . --offline          # only list the dependencies, no network
valtrix scan examples/messy --offline   # a deliberately messy example
valtrix lookup requests 2.25.1    # check one package version (needs internet)
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing vulnerable found and every lookup succeeded |
| 1 | Known vulnerabilities were found |
| 2 | Bad input (missing path, unreadable file, invalid name or version) |
| 3 | The check could not be completed (OSV unreachable or a lookup failed) |

Dependencies without an exact `==` pin cannot be checked precisely. They are listed
as "Not checked" and do not change the exit code.

## Tests and the phase gate

```bash
pytest                           # offline tests
pytest -m live                   # real OSV API (needs internet)
python scripts/check.py          # full phase gate, run before every commit
```

## Roadmap

1. Project foundation (done)
2. Dependency discovery (`requirements.txt` parser) (done)
3. OSV vulnerability database client (done)
4. Vulnerability scanner (done)
5. Reporting (terminal, JSON, HTML)
6. More ecosystems
7. Dependency graph (transitive dependencies)
8. Rule-based risk prioritization
9. Machine learning prioritization, compared against the rule baseline
10. Explainability
11. Developer experience and CI/CD

## Interface preview

`ui/index.html` is a standalone landing page and scan-preview mock-up. It uses sample data only and is not connected to the scanner yet.

## License

MIT

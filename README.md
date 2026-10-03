# Valtrix

Scan a project's dependencies for known vulnerabilities, then work out which ones to fix first.

> Status: early development. Phases 1 to 3 are built. `valtrix scan` lists the dependencies in `requirements.txt`, and `valtrix lookup` checks one package version against OSV. A full scan that combines the two arrives in Phase 4.

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
valtrix scan .
valtrix scan examples/messy   # a deliberately messy example
valtrix lookup requests 2.25.1   # needs internet
```

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
4. Vulnerability scanner
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

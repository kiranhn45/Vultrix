# Valtrix

Scan a project's dependencies for known vulnerabilities, then work out which ones to fix first.

> Status: early development. Phases 1 and 2 are complete: `valtrix scan` lists the dependencies in `requirements.txt`. Vulnerability lookup is not implemented yet.

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
```

## Tests

```bash
pytest
```

## Roadmap

1. Project foundation (done)
2. Dependency discovery (`requirements.txt` parser) (done)
3. OSV vulnerability database client
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

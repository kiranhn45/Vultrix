# The JSON report

`valtrix scan --format json` prints one JSON object. This is the stable interface
for CI and other tools.

- `schema_version` changes only when a field is removed or changes meaning.
- New fields may be added at any time. Ignore keys you do not know.
- With `--format json` and no `--output`, nothing else is written to standard output.

## Top level

| Field | Meaning |
|---|---|
| `schema_version` | `1` |
| `tool` | `{"name": "valtrix", "version": "..."}` |
| `generated_at` | UTC time, `2026-11-16T09:30:00Z` |
| `target` | The folder that was scanned |
| `sources` | Dependency files that were read |
| `settings` | `fail_on`, where the settings came from, the state of the EPSS and KEV lookups (`ok`, `unavailable`, `disabled`, `not needed`), and the severity model's test results |
| `summary` | Counts, `incomplete`, and the `exit_code` the command returned |
| `findings` | Open findings, most urgent first |
| `ignored` | Findings accepted by an ignore rule, with `reason` and `expires` |
| `unchecked` | Dependencies that were not checked, with `reason` and `failed` |
| `parse_issues` | Lines or entries that could not be used |
| `notes` | Things a reader should know, such as a source that could not be reached |

## A finding

```json
{
  "rank": 1,
  "dependency": {
    "name": "jinja2", "version": "3.0.1", "ecosystem": "PyPI", "specifier": "==3.0.1",
    "source": "poetry.lock", "line": 31,
    "direct": false, "dev": false, "path": ["flask 2.0.1", "jinja2 3.0.1"]
  },
  "vulnerability": {
    "id": "GHSA-h5c8-rqwp-cp95", "aliases": ["CVE-2024-22195"],
    "summary": "...", "severity": "MEDIUM",
    "cvss": [{"type": "CVSS_V3", "vector": "CVSS:3.1/...", "score": 5.4}],
    "cwes": ["CWE-79"], "fixed_versions": ["3.1.3"], "references": ["https://..."],
    "published": "...", "modified": "...", "url": "https://osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95"
  },
  "fix": "3.1.3",
  "severity": "MEDIUM",
  "severity_estimated": false,
  "fails_build": true,
  "risk": {
    "score": 44, "priority": "plan", "cvss_score": 5.4,
    "factors": [
      {"name": "Severity", "points": 32, "detail": "Medium severity, CVSS 5.4 (...)"},
      {"name": "Exploitation", "points": 0, "detail": "..."},
      {"name": "Exposure", "points": 5, "detail": "Transitive dependency, pulled in by flask 2.0.1"},
      {"name": "Fix", "points": 7, "detail": "A fix exists: upgrade jinja2 to 3.1.3"}
    ]
  }
}
```

- `direct` is `true`, `false`, or `null` when the file does not say.
- `vulnerability.severity` is what the database published (`null` if nothing).
  `severity` is what was used for scoring; `severity_estimated` says whether it is a guess.
- `cvss[].score` is `null` for vector versions Valtrix does not compute (version 4).
- `risk.score` always equals the sum of the factor points.
- `fails_build` says whether this finding reaches the `fail_on` level.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `fail_on`, and every lookup succeeded |
| 1 | At least one finding at or above `fail_on` |
| 2 | Bad input: missing path, unreadable file, invalid settings |
| 3 | The check could not be completed; findings take priority over this |

## Example: fail a build on anything rated "fix now"

```bash
valtrix scan . --format json --output valtrix.json --fail-on none
python -c "import json,sys; r=json.load(open('valtrix.json')); sys.exit(r['summary']['by_priority']['fix now'] > 0)"
```

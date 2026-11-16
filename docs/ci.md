# Using Valtrix in CI

## GitHub Actions, with results in the Security tab

```yaml
name: Dependency scan
on:
  pull_request:
  schedule:
    - cron: "17 5 * * 1"      # new advisories appear even when your code does not change

jobs:
  valtrix:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # needed to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: kiranhn45/Vultrix@main
        with:
          fail-on: high
```

The action installs Valtrix, scans the repository, uploads a SARIF file to GitHub code
scanning, and fails the job when a finding reaches `fail-on`. Inputs:

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Folder to scan |
| `fail-on` | (project settings, else `low`) | `none`, `low`, `medium`, `high` or `critical` |
| `upload-sarif` | `true` | Upload results to GitHub code scanning |
| `args` | | Extra arguments, for example `--no-exploit-data` |

## Any other CI system

```bash
pip install git+https://github.com/kiranhn45/Vultrix
valtrix scan . --fail-on high --format html --output valtrix-report.html
```

Keep `valtrix-report.html` as a build artifact. The exit code tells the pipeline what
happened: 0 clean, 1 findings at or above the level, 2 bad input, 3 could not finish.
Treat 3 as "try again", not as "clean".

## pre-commit

```yaml
repos:
  - repo: https://github.com/kiranhn45/Vultrix
    rev: main
    hooks:
      - id: valtrix
```

The hook runs only when a dependency file changes.

## Project settings

Put these in `pyproject.toml` under `[tool.valtrix]`, or at the top level of `.valtrix.toml`:

```toml
[tool.valtrix]
fail-on = "high"
exploit-data = true
ml = true

[[tool.valtrix.ignore]]
id = "GHSA-xxxx-xxxx-xxxx"
package = "django"                      # optional
reason = "Only reachable from the admin site, which we do not deploy"
expires = "2027-03-01"                  # optional; the finding returns after this day
```

An ignore rule must give a reason. Ignored findings stay visible in every report, and
an expired rule stops working with a note. When scanning a project you do not trust,
add `--no-config` so its own settings cannot hide anything.

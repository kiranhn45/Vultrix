# How Valtrix ranks findings

Every finding (one vulnerability in one dependency) gets a risk score from 0 to 100.
The score is a plain sum of four factors. Nothing is weighted in secret: the report
shows the points each factor added and a sentence explaining why.

| Factor | Points | What it measures |
|---|---|---|
| Severity | 0 to 60 | How bad it is if exploited |
| Exploitation | 0 to 25 | Evidence that attackers actually use it |
| Exposure | 0 to 8 | How the package reaches your project |
| Fix | 0 to 7 | Whether a fixed version exists |

## Severity (0 to 60)

- A published CVSS version 3 vector is scored with the official formula and multiplied by 6
  (CVSS 9.8 gives 59 points).
- If only a label is published, a typical score for that label is used:
  critical 9.5, high 8.0, medium 5.5, low 2.5.
- A malware report (`MAL-...`) always gets the full 60.
- If nothing is published, the severity is **estimated** (see [severity-model.md](severity-model.md)).
  An estimate is always marked as one, and is capped below a published "high" so a guess
  never outranks a rating.

## Exploitation (0 to 25)

| Evidence | Points |
|---|---|
| Listed in CISA's Known Exploited Vulnerabilities catalog | 25 |
| EPSS probability 50% or more | 20 |
| EPSS probability 10% or more | 14 |
| EPSS probability 1% or more | 6 |
| Below 1%, or no data | 0 |

EPSS (from FIRST.org) is the estimated chance a CVE is exploited in the next 30 days.
Both sources are keyed by CVE id, so an advisory without a CVE has no evidence to look up.
If a source cannot be reached, the scan still finishes and the report says the evidence
is missing. Use `--no-exploit-data` to skip these lookups.

## Exposure (0 to 8)

| Situation | Points |
|---|---|
| Direct dependency, or the file does not say (requirements.txt) | 8 |
| Transitive, pulled in by a direct dependency | 5 |
| Transitive, deeper than that | 3 |
| Only used for development or testing | 0 |

Direct or transitive comes from lock files (`poetry.lock`, `uv.lock`, `package-lock.json`,
`Cargo.lock`) and from `// indirect` in `go.mod`. `valtrix graph` shows the tree.

## Fix (0 to 7)

A finding you can fix today by upgrading ranks above one you cannot. Findings with no
fix are still reported; the detail suggests looking for a workaround or a replacement.

## Priority bands

| Score | Priority |
|---|---|
| 70 or more | fix now |
| 50 to 69 | fix soon |
| 35 to 49 | plan |
| below 35 | monitor |

## Worked example

`pyyaml 5.3`, advisory GHSA-8q59-q68h-6hv4, listed directly in `requirements.txt`:

    +59  Severity: Critical severity, CVSS 9.8 (reachable over the network, no login needed, no user action needed)
     +0  Exploitation: Exploitation evidence is incomplete (EPSS not available)
     +8  Exposure: Listed in requirements.txt, so treated as a direct dependency
     +7  Fix: A fix exists: upgrade pyyaml to 5.4
    = 74, fix now

## Limits

- The score ranks findings against each other. It is not a probability of being attacked.
- Valtrix does not know whether your code calls the vulnerable function.
- A person should review every upgrade. Valtrix never changes your files.

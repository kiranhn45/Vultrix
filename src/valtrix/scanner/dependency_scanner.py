"""The scanner: look up every pinned dependency and collect the findings.

One failing package never stops the scan. If OSV cannot be reached at all,
the scan stops early instead of waiting through retries for every remaining
package, and says which packages were not checked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, List, Optional, Sequence, Set, Tuple, Union

from valtrix.databases import OsvClient, OsvError
from valtrix.models import (
    Dependency,
    Finding,
    ParseIssue,
    ScanResult,
    Unchecked,
    severity_rank,
)
from valtrix.parsers import parse_requirements
from valtrix.versions import choose_fix, parse_version

# Stop after this many packages in a row fail because OSV is unreachable.
MAX_CONSECUTIVE_UNREACHABLE = 3

Progress = Callable[[int, int, Dependency], None]


def scan_dependencies(
    dependencies: Sequence[Dependency],
    client: OsvClient,
    progress: Optional[Progress] = None,
) -> ScanResult:
    """Check each dependency against OSV and return the combined result."""
    result = ScanResult()

    to_check: List[Dependency] = []
    seen: Set[Tuple[str, Optional[str], str]] = set()
    for dep in dependencies:
        key = (dep.name, dep.version, dep.specifier)
        if key in seen:
            continue
        seen.add(key)
        if dep.version is not None:
            to_check.append(dep)
        elif dep.specifier.startswith("@"):
            result.unchecked.append(Unchecked(dep, "points to a direct URL, so the version is unknown"))
        else:
            result.unchecked.append(Unchecked(dep, "version is not pinned with ==, so it cannot be checked exactly"))

    in_a_row = 0
    for index, dep in enumerate(to_check, start=1):
        if in_a_row >= MAX_CONSECUTIVE_UNREACHABLE:
            result.unchecked.append(
                Unchecked(dep, "not checked because OSV could not be reached", failed=True)
            )
            continue

        if progress is not None:
            progress(index, len(to_check), dep)
        try:
            vulns = client.query(dep.name, dep.version or "")
        except OsvError as exc:
            in_a_row = in_a_row + 1 if exc.unreachable else 0
            result.unchecked.append(Unchecked(dep, f"lookup failed: {exc}", failed=True))
            continue
        except ValueError:
            in_a_row = 0
            result.unchecked.append(Unchecked(dep, "name or version has a form the lookup cannot accept"))
            continue

        in_a_row = 0
        result.scanned.append(dep)
        for vuln in vulns:
            result.findings.append(Finding(dep, vuln, choose_fix(dep.version or "", vuln.fixed_versions)))

    result.findings.sort(
        key=lambda f: (
            severity_rank(f.vulnerability.severity_label),
            f.dependency.name,
            f.vulnerability.id,
        )
    )
    return result


def scan_project(
    root: Union[str, Path],
    client: OsvClient,
    progress: Optional[Progress] = None,
) -> ScanResult:
    """Scan a project folder. Currently reads requirements.txt only.

    Raises RequirementsError if requirements.txt exists but cannot be read.
    If there is no requirements.txt, the result has no sources.
    """
    folder = Path(root).resolve()
    requirements = folder / "requirements.txt"
    if not requirements.is_file():
        return ScanResult()

    parsed = parse_requirements(requirements, root=folder)
    result = scan_dependencies(parsed.dependencies, client, progress)
    result.sources = sorted({d.source for d in parsed.dependencies} | {"requirements.txt"})
    result.parse_issues = list(parsed.issues)
    return result


def suggest_upgrade(findings: Sequence[Finding]) -> Tuple[Optional[str], int]:
    """For one dependency's findings, return (version to upgrade to, issues with no fix).

    The version is the highest of the per-issue fixes, so upgrading to it
    should resolve every issue that has a known fix. It is a suggestion to
    check against the package's changelog, not a guarantee.
    """
    fixes = [f.fix for f in findings if f.fix]
    unfixed = sum(1 for f in findings if not f.fix)
    best: Optional[str] = None
    for text in fixes:
        parsed = parse_version(text)
        if parsed is not None and (best is None or parsed > parse_version(best)):  # type: ignore[arg-type]
            best = text
    return best, unfixed

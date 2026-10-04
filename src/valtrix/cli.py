"""Command-line interface for Valtrix.

    valtrix scan [path]              check a project's dependencies against OSV
    valtrix scan [path] --details    also list every issue
    valtrix scan [path] --offline    only list the dependencies; no network
    valtrix lookup <package> <ver>   check one package version

Exit codes (stable, so CI can rely on them):
    0  nothing vulnerable found and every lookup succeeded
    1  known vulnerabilities were found
    2  bad input (missing path, unreadable file, invalid name or version)
    3  the check could not be completed (OSV unreachable or a lookup failed)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Optional, Sequence

from valtrix import __version__
from valtrix.databases import OsvClient, OsvError
from valtrix.models import (
    SEVERITY_ORDER,
    Dependency,
    Finding,
    ScanResult,
    Vulnerability,
    count_by_severity,
    normalize_name,
)
from valtrix.parsers import RequirementsError, parse_requirements
from valtrix.scanner import scan_project, suggest_upgrade
from valtrix.versions import choose_fix, sort_versions

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BAD_INPUT = 2
EXIT_INCOMPLETE = 3

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,199}$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="valtrix",
        description="Scan a project's dependencies for known vulnerabilities "
        "and prioritize what to fix first.",
        epilog="Exit codes: 0 clean, 1 vulnerabilities found, 2 bad input, "
        "3 check could not be completed.",
    )
    parser.add_argument(
        "--version", action="version", version=f"valtrix {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    scan = subparsers.add_parser(
        "scan", help="scan a project directory for vulnerable dependencies"
    )
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="project directory to scan (default: current directory)",
    )
    scan.add_argument(
        "--details",
        action="store_true",
        help="list every issue, not just a summary per dependency",
    )
    scan.add_argument(
        "--offline",
        action="store_true",
        help="only list the dependencies found; do not contact OSV",
    )

    lookup = subparsers.add_parser(
        "lookup", help="check one package version against the OSV database"
    )
    lookup.add_argument("package", help="package name, e.g. requests")
    lookup.add_argument("version", help="exact version, e.g. 2.25.1")
    return parser


# ------------------------------------------------------------------- output

def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _describe(dep: Dependency) -> str:
    if dep.version:
        return dep.version
    return f"{dep.specifier or 'any version'} (not pinned)"


def _severity_summary(findings: Sequence[Finding]) -> str:
    counts = count_by_severity(findings)
    order = list(SEVERITY_ORDER) + ["UNKNOWN"]
    return ", ".join(f"{counts[label]} {label.lower()}" for label in order if label in counts)


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _print_scan(result: ScanResult, details: bool) -> None:
    checked = len(result.scanned)
    total = checked + len(result.unchecked)
    print(f"Sources: {', '.join(result.sources)}")
    print(f"\nChecked {checked} of {_plural(total, 'dependency', 'dependencies')} against OSV.")

    vulnerable = result.vulnerable_dependencies
    if vulnerable:
        issues = len(result.findings)
        print(
            f"\n{_plural(len(vulnerable), 'dependency', 'dependencies')} "
            f"with known vulnerabilities ({_plural(issues, 'issue')} in total):\n"
        )
        for dep in vulnerable:
            findings = result.findings_for(dep)
            print(f"  {dep.name} {dep.version}")
            print(f"    {_plural(len(findings), 'issue')}: {_severity_summary(findings)}")
            upgrade, unfixed = suggest_upgrade(findings)
            if upgrade:
                note = f" ({_plural(unfixed, 'issue')} with no known fix)" if unfixed else ""
                print(f"    Upgrading to {upgrade} or later resolves the issues that have a fix{note}")
            else:
                print("    No fixed version is listed for these issues")
            if details:
                for f in findings:
                    label = f.vulnerability.severity_label or "UNKNOWN"
                    fix = f"fix: {f.fix}" if f.fix else "no fix listed"
                    summary = _one_line(f.vulnerability.summary)
                    print(f"      [{label}] {f.vulnerability.id}  {summary}  ({fix})")
            print()
        if not details:
            print("Run with --details to list every issue.\n")
    elif total == 0:
        print("\nNo dependencies were found in these files.")
    elif checked == 0:
        print("\nNothing could be checked, so there is no result. See the list below.")
    else:
        print("\nNo known vulnerabilities in the dependencies that were checked.")

    clean = [d for d in result.scanned if d not in vulnerable]
    if clean and vulnerable:
        print(f"{_plural(len(clean), 'dependency', 'dependencies')} with no known vulnerabilities.\n")

    if result.unchecked:
        print(f"Not checked ({len(result.unchecked)}):")
        for item in result.unchecked:
            where = f"{item.dependency.source}:{item.dependency.line}"
            print(f"  {item.dependency.name}  {item.reason}  ({where})")
        print()

    if result.parse_issues:
        print(f"{_plural(len(result.parse_issues), 'line')} could not be used:")
        for issue in result.parse_issues:
            print(f"  {issue}")
        print()

    if checked:
        print("No known vulnerabilities means none are listed in OSV, not that the code is guaranteed safe.")


class _Progress:
    """A one-line progress indicator, shown only when stderr is a terminal."""

    def __init__(self) -> None:
        self.active = sys.stderr.isatty()

    def __call__(self, index: int, total: int, dep: Dependency) -> None:
        if self.active:
            sys.stderr.write(f"\r  Checking {index}/{total}: {dep.name} {dep.version}".ljust(70))
            sys.stderr.flush()

    def clear(self) -> None:
        if self.active:
            sys.stderr.write("\r" + " " * 70 + "\r")
            sys.stderr.flush()


# ----------------------------------------------------------------- commands

def _list_only(target: Path) -> int:
    requirements = target / "requirements.txt"
    if not requirements.is_file():
        print("No requirements.txt found. Other dependency files arrive in Phase 6.")
        return EXIT_OK
    try:
        result = parse_requirements(requirements, root=target)
    except RequirementsError as exc:
        print(f"valtrix: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    deps = result.dependencies
    print(f"\nFound {len(deps)} dependencies:")
    width = max((len(d.name) for d in deps), default=0)
    for dep in deps:
        print(f"  {dep.name.ljust(width)}  {_describe(dep)}")
    if result.issues:
        print(f"\n{len(result.issues)} lines could not be used:")
        for issue in result.issues:
            print(f"  {issue}")
    print("\nOffline mode: OSV was not contacted.")
    return EXIT_OK


def run_scan(path: str, details: bool = False, offline: bool = False) -> int:
    target = Path(path).resolve()

    if not target.exists():
        print(f"valtrix: path does not exist: {target}", file=sys.stderr)
        return EXIT_BAD_INPUT
    if not target.is_dir():
        print(f"valtrix: not a directory: {target}", file=sys.stderr)
        return EXIT_BAD_INPUT

    print(f"Valtrix {__version__}")
    print(f"Target: {target}")

    if offline:
        return _list_only(target)

    progress = _Progress()
    try:
        result = scan_project(target, OsvClient(), progress)
    except RequirementsError as exc:
        progress.clear()
        print(f"valtrix: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT
    progress.clear()

    if not result.sources:
        print("No requirements.txt found. Other dependency files arrive in Phase 6.")
        return EXIT_OK

    _print_scan(result, details)
    if result.findings:
        return EXIT_FINDINGS
    if result.incomplete:
        print("The scan is incomplete: some dependencies could not be checked (see above).", file=sys.stderr)
        return EXIT_INCOMPLETE
    return EXIT_OK


def _print_vulnerability(vuln: Vulnerability, installed: str) -> None:
    label = vuln.severity_label or "severity unknown"
    print(f"  {vuln.id}  [{label}]")
    extra_ids = [a for a in vuln.aliases if a != vuln.id]
    if extra_ids:
        print(f"    Also known as: {', '.join(extra_ids)}")
    if vuln.summary:
        print(f"    {_one_line(vuln.summary)}")
    if vuln.fixed_versions:
        fix = choose_fix(installed, vuln.fixed_versions)
        others = [v for v in sort_versions(vuln.fixed_versions) if v != fix]
        if fix and others:
            print(f"    Fixed in: {fix} (other release lines: {', '.join(others)})")
        elif fix:
            print(f"    Fixed in: {fix}")
        else:
            print(f"    Fixed in: {', '.join(sort_versions(vuln.fixed_versions))}")
    else:
        print("    No fixed version listed")
    print(f"    {vuln.osv_url}")


def run_lookup(package: str, version: str) -> int:
    if not _PACKAGE_NAME.match(package):
        print(f"valtrix: not a valid package name: {package!r}", file=sys.stderr)
        return EXIT_BAD_INPUT
    if not _VERSION.match(version):
        print(
            f"valtrix: not a valid exact version: {version!r} "
            "(use a single version such as 2.25.1)",
            file=sys.stderr,
        )
        return EXIT_BAD_INPUT

    name = normalize_name(package)
    try:
        vulns = OsvClient().query(name, version)
    except OsvError as exc:
        print(f"valtrix: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE

    print(f"{name} {version} (PyPI)")
    if not vulns:
        print("No known vulnerabilities found in OSV for this exact version.")
        print("That means none are known, not that the package is guaranteed safe.")
        return EXIT_OK

    print(f"Found {_plural(len(vulns), 'known vulnerability', 'known vulnerabilities')}:\n")
    for vuln in vulns:
        _print_vulnerability(vuln, version)
    return EXIT_FINDINGS


def _make_output_safe() -> None:
    """Never crash on a character the console cannot display (common on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    _make_output_safe()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args.path, details=args.details, offline=args.offline)
    if args.command == "lookup":
        return run_lookup(args.package, args.version)

    parser.print_help()
    return EXIT_OK

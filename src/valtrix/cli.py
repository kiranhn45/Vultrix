"""Command-line interface for Valtrix.

`scan` finds and parses the project's requirements.txt and lists the
dependencies. `lookup` checks one package version against OSV. Combining the
two into a full scan arrives in Phase 4.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Optional, Sequence

from valtrix import __version__
from valtrix.databases import OsvClient, OsvError
from valtrix.models import Dependency, Vulnerability, normalize_name
from valtrix.parsers import RequirementsError, parse_requirements

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_BAD_INPUT = 2

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,199}$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="valtrix",
        description="Scan a project's dependencies for known vulnerabilities "
        "and prioritize what to fix first.",
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

    lookup = subparsers.add_parser(
        "lookup", help="check one package version against the OSV database"
    )
    lookup.add_argument("package", help="package name, e.g. requests")
    lookup.add_argument("version", help="exact version, e.g. 2.25.1")
    return parser


def _describe(dep: Dependency) -> str:
    if dep.version:
        return dep.version
    return f"{dep.specifier or 'any version'} (not pinned)"


def run_scan(path: str) -> int:
    target = Path(path).resolve()

    if not target.exists():
        print(f"valtrix: path does not exist: {target}", file=sys.stderr)
        return EXIT_BAD_INPUT
    if not target.is_dir():
        print(f"valtrix: not a directory: {target}", file=sys.stderr)
        return EXIT_BAD_INPUT

    print(f"Valtrix {__version__}")
    print(f"Target: {target}")

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

    print("\nTo check one package, run: valtrix lookup <package> <version>")
    print("Checking every dependency in one scan arrives in Phase 4.")
    return EXIT_OK


def _print_vulnerability(vuln: Vulnerability) -> None:
    label = vuln.severity_label or "severity unknown"
    print(f"  {vuln.id}  [{label}]")
    extra_ids = [a for a in vuln.aliases if a != vuln.id]
    if extra_ids:
        print(f"    Also known as: {', '.join(extra_ids)}")
    if vuln.summary:
        print(f"    {' '.join(vuln.summary.split())}")
    if vuln.fixed_versions:
        print(f"    Fixed in: {', '.join(vuln.fixed_versions)}")
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
        return EXIT_ERROR

    print(f"{name} {version} (PyPI)")
    if not vulns:
        print("No known vulnerabilities found in OSV for this exact version.")
        print("That means none are known, not that the package is guaranteed safe.")
        return EXIT_OK

    noun = "vulnerability" if len(vulns) == 1 else "vulnerabilities"
    print(f"Found {len(vulns)} known {noun}:\n")
    for vuln in vulns:
        _print_vulnerability(vuln)
    return EXIT_OK


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
        return run_scan(args.path)
    if args.command == "lookup":
        return run_lookup(args.package, args.version)

    parser.print_help()
    return EXIT_OK

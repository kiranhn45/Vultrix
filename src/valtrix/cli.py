"""Command-line interface for Valtrix.

`scan` currently finds and parses the project's requirements.txt and lists
the dependencies. Vulnerability lookup arrives in Phases 3 and 4.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from valtrix import __version__
from valtrix.models import Dependency
from valtrix.parsers import RequirementsError, parse_requirements

EXIT_OK = 0
EXIT_BAD_INPUT = 2


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

    print("\nVulnerability lookup arrives in Phase 3.")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args.path)

    parser.print_help()
    return EXIT_OK

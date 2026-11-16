"""Command-line interface for Valtrix.

    valtrix scan [path]              check a project's dependencies and rank what to fix first
    valtrix scan [path] --details    also list every issue with the reasons for its score
    valtrix scan [path] --offline    only list the dependencies; no network
    valtrix scan [path] --format json|html|sarif [--output FILE]
    valtrix lookup <package> <ver>   check one package version
    valtrix graph [path]             show which package pulls in which
    valtrix model                    show how the severity model was trained and how it scored

Exit codes (stable, so CI can rely on them):
    0  nothing vulnerable found and every lookup succeeded
    1  known vulnerabilities were found (at or above --fail-on)
    2  bad input (missing path, unreadable file, invalid name, version or settings)
    3  the check could not be completed (OSV unreachable or a lookup failed)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from valtrix import __version__
from valtrix.config import FAIL_LEVELS, Config, ConfigError, IgnoreRule, apply_ignores, load_config
from valtrix.databases import ExploitData, OsvClient, OsvError, gather_exploit_data
from valtrix.models import CARGO, GO, NPM, PYPI, Dependency, normalize_name
from valtrix.parsers import SUPPORTED_FILES, ParseError, discover
from valtrix.reports import (
    EXIT_BAD_INPUT,
    EXIT_FINDINGS,
    EXIT_INCOMPLETE,
    EXIT_OK,
    FORMATS,
    ReportMeta,
    exit_code,
    render_dependency_list,
    render_graph,
    render_html,
    render_json,
    render_sarif,
    render_scan,
    render_vulnerability,
)
from valtrix.reports.common import plural
from valtrix.risk import default_model, prioritize
from valtrix.scanner import scan_project

__all__ = ["EXIT_BAD_INPUT", "EXIT_FINDINGS", "EXIT_INCOMPLETE", "EXIT_OK", "main"]

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_OTHER_NAME = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._~/-]{0,300}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,199}$")
_IGNORE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{2,99}$")
_ECOSYSTEMS = {"pypi": PYPI, "python": PYPI, "npm": NPM, "crates.io": CARGO, "cargo": CARGO,
               "rust": CARGO, "go": GO, "golang": GO}
_NO_FILES = "No dependency files found. Valtrix reads: " + ", ".join(SUPPORTED_FILES) + "."


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
        help="list every issue and the reasons behind its score",
    )
    scan.add_argument(
        "--offline",
        action="store_true",
        help="only list the dependencies found; do not contact OSV",
    )
    scan.add_argument(
        "--format", choices=FORMATS, default="text",
        help="report format (default: text). json is the stable interface for CI; "
        "sarif is for GitHub code scanning",
    )
    scan.add_argument(
        "--output", metavar="FILE",
        help="write the report to FILE instead of the screen",
    )
    scan.add_argument(
        "--fail-on", choices=FAIL_LEVELS, default=None,
        help="lowest severity that makes the scan exit 1 (default: low, meaning any finding). "
        "'none' never fails on findings",
    )
    scan.add_argument(
        "--ignore", metavar="ID", action="append", default=[],
        help="accept this advisory (GHSA, CVE or other id) for this run; may be repeated. "
        "Ignored findings are still listed",
    )
    scan.add_argument(
        "--no-exploit-data", action="store_true",
        help="do not look up exploitation evidence (EPSS and CISA KEV)",
    )
    scan.add_argument(
        "--no-ml", action="store_true",
        help="estimate missing severities with keyword rules instead of the trained model",
    )
    scan.add_argument(
        "--no-config", action="store_true",
        help="do not read settings from the project (.valtrix.toml or pyproject.toml)",
    )

    lookup = subparsers.add_parser(
        "lookup", help="check one package version against the OSV database"
    )
    lookup.add_argument("package", help="package name, e.g. requests")
    lookup.add_argument("version", help="exact version, e.g. 2.25.1")
    lookup.add_argument(
        "--ecosystem", default="pypi", choices=sorted(_ECOSYSTEMS),
        help="where the package comes from (default: pypi)",
    )

    graph = subparsers.add_parser(
        "graph", help="show which package pulls in which (needs a lock file)"
    )
    graph.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")

    subparsers.add_parser("model", help="show how the severity model was trained and tested")
    return parser


class _Progress:
    """A one-line progress indicator, shown only when stderr is a terminal."""

    def __init__(self) -> None:
        self.active = sys.stderr.isatty()

    def __call__(self, index: int, total: int, dep: Dependency) -> None:
        if self.active:
            sys.stderr.write(f"\r  Checking {index}/{total}: {dep.name} {dep.version}"[:78].ljust(78))
            sys.stderr.flush()

    def clear(self) -> None:
        if self.active:
            sys.stderr.write("\r" + " " * 78 + "\r")
            sys.stderr.flush()


def _fail(message: str) -> int:
    print(f"valtrix: {message}", file=sys.stderr)
    return EXIT_BAD_INPUT


def _project_folder(path: str) -> Optional[Path]:
    target = Path(path).resolve()
    if not target.exists():
        _fail(f"path does not exist: {target}")
        return None
    if not target.is_dir():
        _fail(f"not a directory: {target}")
        return None
    return target


def _use_color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


# ----------------------------------------------------------------- commands

def _list_only(target: Path) -> int:
    try:
        project = discover(target)
    except ParseError as exc:
        return _fail(str(exc))
    if not project.sources:
        print(_NO_FILES)
        return EXIT_OK
    print(render_dependency_list(project.dependencies, project.issues))
    return EXIT_OK


def run_scan(
    path: str,
    details: bool = False,
    offline: bool = False,
    fmt: str = "text",
    output: Optional[str] = None,
    fail_on: Optional[str] = None,
    ignore: Sequence[str] = (),
    exploit_data: bool = True,
    ml: bool = True,
    use_config: bool = True,
) -> int:
    target = _project_folder(path)
    if target is None:
        return EXIT_BAD_INPUT
    for ident in ignore:
        if not _IGNORE_ID.match(ident):
            return _fail(f"not a valid advisory id for --ignore: {ident!r}")

    try:
        config = load_config(target) if use_config else Config()
    except ConfigError as exc:
        return _fail(str(exc))

    # A machine-readable report on stdout must be the only thing on stdout.
    chatty = fmt == "text" or output is not None
    if chatty:
        print(f"Valtrix {__version__}")
        print(f"Target: {target}")

    if offline:
        return _list_only(target)

    progress = _Progress()
    try:
        result = scan_project(target, OsvClient(), progress)
    except ParseError as exc:
        progress.clear()
        return _fail(str(exc))
    progress.clear()

    if not result.sources and fmt == "text":
        print(_NO_FILES)
        return EXIT_OK

    cves = [cve for f in result.findings for cve in f.vulnerability.cve_ids]
    if exploit_data and config.exploit_data:
        evidence = gather_exploit_data(cves)
    else:
        evidence = ExploitData()
    prioritize(result, evidence, use_model=ml and config.ml)
    rules = list(config.ignore) + [IgnoreRule(i, "ignored on the command line") for i in ignore]
    apply_ignores(result, rules)

    level = fail_on or config.fail_on
    meta = ReportMeta(target=str(target), fail_on=level, exploit_data=evidence,
                      model_used=ml and config.ml, config_source=config.source)
    code = exit_code(result, level)

    text = render_scan(result, details, meta, color=_use_color() and output is None)
    if fmt == "text":
        report = text
    elif fmt == "json":
        report = render_json(result, meta)
    elif fmt == "html":
        report = render_html(result, meta)
    else:
        report = render_sarif(result, meta)

    if output is not None:
        try:
            Path(output).write_text(report + ("" if report.endswith("\n") else "\n"),
                                    encoding="utf-8", newline="\n")
        except OSError as exc:
            return _fail(f"could not write {output}: {exc.strerror or exc}")
        if fmt != "text":
            print(text)
        print(f"\nWrote the {fmt} report to {output}")
    else:
        print(report)

    if result.findings and code == EXIT_OK and level != "low":
        print(f"Findings are below the --fail-on level ({level}), so the exit code is 0.", file=sys.stderr)
    if result.incomplete and code != EXIT_FINDINGS:
        print("The scan is incomplete: some dependencies could not be checked (see above).", file=sys.stderr)
    return code


def run_lookup(package: str, version: str, ecosystem: str = PYPI) -> int:
    pattern = _PACKAGE_NAME if ecosystem == PYPI else _OTHER_NAME
    if not pattern.match(package):
        return _fail(f"not a valid package name: {package!r}")
    if not _VERSION.match(version):
        return _fail(
            f"not a valid exact version: {version!r} "
            "(use a single version such as 2.25.1)"
        )

    name = normalize_name(package) if ecosystem == PYPI else package
    try:
        client = OsvClient()
        vulns = client.query(name, version) if ecosystem == PYPI else client.query(name, version, ecosystem)
    except OsvError as exc:
        print(f"valtrix: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE

    print(f"{name} {version} ({ecosystem})")
    if not vulns:
        print("No known vulnerabilities found in OSV for this exact version.")
        print("That means none are known, not that the package is guaranteed safe.")
        return EXIT_OK

    print(f"Found {plural(len(vulns), 'known vulnerability', 'known vulnerabilities')}:\n")
    for vuln in vulns:
        print(render_vulnerability(vuln, version, ecosystem))
    return EXIT_FINDINGS


def run_graph(path: str) -> int:
    target = _project_folder(path)
    if target is None:
        return EXIT_BAD_INPUT
    try:
        project = discover(target)
    except ParseError as exc:
        return _fail(str(exc))
    if not project.sources:
        print(_NO_FILES)
        return EXIT_OK
    print(f"Sources: {', '.join(project.sources)}\n")
    if not project.graph.children:
        print("These files do not record which package pulls in which.")
        print("A lock file does: poetry.lock, uv.lock, package-lock.json or Cargo.lock.")
        return EXIT_OK
    print(render_graph(project.graph))
    direct = len(project.graph.roots)
    total = len(project.graph.nodes)
    print(f"\n{plural(direct, 'direct dependency', 'direct dependencies')}, "
          f"{total - direct} pulled in by other packages.")
    return EXIT_OK


def run_model() -> int:
    model = default_model()
    if model is None:
        print("The severity model file is missing or damaged, so keyword rules are used instead.")
        return EXIT_OK
    info = model.info
    training, test, evaluation = (info.get(k) or {} for k in ("training", "test", "evaluation"))
    print("Valtrix severity model")
    print("  Used only when an advisory publishes no severity. Its output is always marked as an estimate.")
    print(f"  Task:      {info.get('task')}")
    print(f"  Trained:   {info.get('trained_on')} on {training.get('advisories')} advisories "
          f"published {training.get('published_from')} to {training.get('published_to')}")
    print(f"  Tested:    {test.get('advisories')} newer advisories "
          f"({test.get('published_from')} to {test.get('published_to')}), never seen in training")
    print(f"  Features:  {len(model.weights)} words, word pairs and CWE ids\n")
    print(f"  {'':<16}{'accuracy':>10}{'AUC':>8}")
    for key, label in (("model", "This model"), ("keyword_rules", "Keyword rules"), ("always_medium", "Always medium")):
        row = evaluation.get(key) or {}
        print(f"  {label:<16}{row.get('accuracy', '-'):>10}{row.get('auc', '-'):>8}")
    print("\n  Retrain with scripts/train_model.py. See docs/severity-model.md.")
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
        return run_scan(
            args.path, details=args.details, offline=args.offline, fmt=args.format,
            output=args.output, fail_on=args.fail_on, ignore=args.ignore,
            exploit_data=not args.no_exploit_data, ml=not args.no_ml,
            use_config=not args.no_config,
        )
    if args.command == "lookup":
        return run_lookup(args.package, args.version, _ECOSYSTEMS[args.ecosystem])
    if args.command == "graph":
        return run_graph(args.path)
    if args.command == "model":
        return run_model()

    parser.print_help()
    return EXIT_OK

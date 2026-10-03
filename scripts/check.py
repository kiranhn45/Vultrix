#!/usr/bin/env python3
"""Phase gate: run this after every phase, before committing.

    python scripts/check.py          # everything that works offline
    python scripts/check.py --live   # also talk to the real OSV API

Exit code 0 means every check passed. Any FAIL exits 1. WARN lines are
reminders and do not fail the gate. Uses only the standard library.
"""

from __future__ import annotations

import argparse
import compileall
import datetime
import importlib
import os
import pkgutil
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "build", "dist"}

PASS, FAIL, WARN = "PASS", "FAIL", "WARN"
Result = Tuple[str, str]  # (status, detail)


# ------------------------------------------------------------------ helpers

def run(cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    return subprocess.run(
        cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, env=env,
    )


def tail(text: str, lines: int = 15) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def project_files() -> List[Path]:
    found = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        found.extend(Path(dirpath) / f for f in filenames)
    return found


# ------------------------------------------------------------------- checks

def check_python() -> Result:
    if sys.version_info < (3, 9):
        return FAIL, f"Python 3.9 or newer is required, found {sys.version.split()[0]}"
    return PASS, f"Python {sys.version.split()[0]}"


def check_compile() -> Result:
    ok = all(
        compileall.compile_dir(str(ROOT / d), quiet=1)
        for d in ("src", "tests", "scripts") if (ROOT / d).is_dir()
    )
    return (PASS, "all source files compile") if ok else (FAIL, "a file has a syntax error (see above)")


def check_imports() -> Result:
    try:
        package = importlib.import_module("valtrix")
    except ImportError as exc:
        return FAIL, f"cannot import valtrix ({exc}). Run: pip install -e \".[dev]\""
    names = ["valtrix"]
    for module in pkgutil.walk_packages(package.__path__, "valtrix."):
        names.append(module.name)
        try:
            importlib.import_module(module.name)
        except Exception as exc:  # any import-time failure is a problem
            return FAIL, f"importing {module.name} failed: {type(exc).__name__}: {exc}"
    return PASS, f"{len(names)} modules import cleanly"


def check_tests() -> Result:
    proc = run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    summary = tail(proc.stdout, 1)
    if proc.returncode != 0:
        return FAIL, tail(proc.stdout + proc.stderr, 25)
    if " passed" not in summary:
        return FAIL, f"no tests ran: {summary}"
    return PASS, summary


def check_cli() -> Result:
    cases = [
        (["--version"], 0, "valtrix"),
        (["--help"], 0, "scan"),
        (["lookup", "--help"], 0, "package"),
        (["scan", "examples"], 0, "Found"),
        (["scan", "examples/messy"], 0, "could not be used"),
        (["scan", "this-folder-does-not-exist"], 2, ""),
        (["lookup", "bad name", "1.0"], 2, ""),
    ]
    for args, want_code, want_text in cases:
        proc = run([sys.executable, "-m", "valtrix", *args], timeout=60)
        shown = "valtrix " + " ".join(args)
        if proc.returncode != want_code:
            return FAIL, f"`{shown}` exited {proc.returncode}, expected {want_code}\n{tail(proc.stdout + proc.stderr, 8)}"
        if want_text and want_text not in proc.stdout:
            return FAIL, f"`{shown}` output is missing {want_text!r}"
    return PASS, f"{len(cases)} command checks behave as expected"


def check_required_files() -> Result:
    required = ["README.md", "LICENSE", "PROGRESS.md", "pyproject.toml", ".gitignore",
                "src/valtrix/__init__.py", "tests/conftest.py", "scripts/check.py"]
    missing = [f for f in required if not (ROOT / f).is_file()]
    if missing:
        return FAIL, "missing: " + ", ".join(missing)
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8", errors="replace")
    lacking = [e for e in (".venv", ".env") if e not in gitignore]
    if lacking:
        return FAIL, ".gitignore must list: " + ", ".join(lacking)
    return PASS, "required files present, .gitignore protects .venv and .env"


def check_version_consistency() -> Result:
    match = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    if not match:
        return FAIL, "no version found in pyproject.toml"
    import valtrix
    if match.group(1) != valtrix.__version__:
        return FAIL, f"pyproject.toml says {match.group(1)} but valtrix.__version__ is {valtrix.__version__}"
    return PASS, f"version {valtrix.__version__} matches in both places"


_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("hard-coded credential", re.compile(r"""(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"][^'"\s]{12,}['"]""")),
]
_TEXT_SUFFIXES = {".py", ".md", ".txt", ".toml", ".cfg", ".ini", ".json", ".yml", ".yaml", ".html", ".js", ".env", ""}


def check_secrets() -> Result:
    this_file = Path(__file__).resolve()
    for path in project_files():
        if path.resolve() == this_file or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        if path.name.startswith(".env") and path.name != ".env.example":
            return FAIL, f"{path.relative_to(ROOT)} must not be inside the project (keep secrets out of the repo)"
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return FAIL, f"possible {label} in {path.relative_to(ROOT)}"
    return PASS, "no secrets or .env files found"


def check_progress_doc() -> Result:
    text = (ROOT / "PROGRESS.md").read_text(encoding="utf-8", errors="replace")
    for heading in ("## Current phase", "## Next step", "## Phase gate log"):
        if heading not in text:
            return FAIL, f"PROGRESS.md is missing the section {heading!r}"
    return PASS, "PROGRESS.md has current phase, next step, and gate log"


def check_git() -> Result:
    if shutil.which("git") is None:
        return WARN, "git is not installed"
    if not (ROOT / ".git").exists():
        return WARN, "not a git repository yet. Run: git init"
    tracked = run(["git", "ls-files"]).stdout.splitlines()
    bad = [f for f in tracked if f.startswith((".venv/", "venv/")) or Path(f).name.startswith(".env")]
    if bad:
        return FAIL, "these must not be committed: " + ", ".join(bad[:5])
    status = run(["git", "status", "--porcelain"]).stdout.strip()
    if status:
        return WARN, f"{len(status.splitlines())} uncommitted changes. Commit this phase once the gate passes"
    return PASS, "git is clean and nothing sensitive is tracked"


def check_live() -> Result:
    proc = run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-m", "live"], timeout=180)
    if proc.returncode != 0:
        return FAIL, tail(proc.stdout + proc.stderr, 25)
    return PASS, tail(proc.stdout, 1)


# --------------------------------------------------------------------- main

def current_phase() -> str:
    match = re.search(r"## Current phase\s*\n(.+)", (ROOT / "PROGRESS.md").read_text(encoding="utf-8", errors="replace"))
    if not match:
        return "unknown phase"
    return match.group(1).strip().split(". ")[0].rstrip(".")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Valtrix phase gate.")
    parser.add_argument("--live", action="store_true", help="also run tests that call the real OSV API")
    args = parser.parse_args()

    steps: List[Tuple[str, Callable[[], Result]]] = [
        ("Python version", check_python),
        ("Source compiles", check_compile),
        ("Modules import", check_imports),
        ("Test suite (offline)", check_tests),
        ("Command-line behavior", check_cli),
        ("Required files", check_required_files),
        ("Version consistency", check_version_consistency),
        ("Secrets scan", check_secrets),
        ("Progress notes", check_progress_doc),
        ("Git", check_git),
    ]
    if args.live:
        steps.append(("Live OSV check", check_live))

    print(f"Valtrix phase gate: {current_phase()}\n")
    failures = warnings = 0
    last_summary: Optional[str] = None
    for index, (label, func) in enumerate(steps, start=1):
        try:
            status, detail = func()
        except Exception as exc:  # a broken check must fail loudly, not crash silently
            status, detail = FAIL, f"the check itself crashed: {type(exc).__name__}: {exc}"
        failures += status == FAIL
        warnings += status == WARN
        first, *rest = detail.splitlines() or [""]
        print(f"[{status}] {index:>2}. {label}: {first}")
        for line in rest:
            print(f"          {line}")
        if label.startswith("Test suite") and status == PASS:
            last_summary = detail

    print()
    if failures:
        print(f"GATE FAILED: {failures} check(s) failed. Fix them before starting the next phase.")
        return 1
    note = f" ({warnings} reminder(s) above)" if warnings else ""
    print(f"GATE PASSED{note}.")
    when = datetime.date.today().isoformat()
    print("Add this row to the Phase gate log in PROGRESS.md:")
    print(f"| {current_phase()} | {when} | {last_summary or 'n/a'} | {'offline + live' if args.live else 'offline only'} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())

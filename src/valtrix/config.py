"""Project settings: `[tool.valtrix]` in pyproject.toml, or a `.valtrix.toml` file.

    [tool.valtrix]
    fail-on = "high"          # none, low, medium, high or critical
    exploit-data = true       # look up EPSS and CISA KEV
    ml = true                 # estimate missing severities with the model

    [[tool.valtrix.ignore]]
    id = "GHSA-xxxx-xxxx-xxxx"
    package = "django"        # optional: only for this package
    reason = "Only reachable from the admin site, which is not deployed"
    expires = "2027-03-01"    # optional: the finding comes back after this day

In `.valtrix.toml` the same keys sit at the top level. `.valtrix.toml` wins
when both exist.

The file belongs to the project being scanned, so it is untrusted input and
is validated strictly. An ignore entry must give a reason, and ignored
findings are still listed in every report, so nothing can be hidden quietly.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from valtrix.models import Finding, Ignored, ScanResult, normalize_name
from valtrix.parsers.common import ParseError, clean, read_toml

FAIL_LEVELS = ("none", "low", "medium", "high", "critical")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{2,99}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ConfigError(Exception):
    """The settings file is present but not usable."""


@dataclass(frozen=True)
class IgnoreRule:
    id: str
    reason: str
    package: Optional[str] = None
    expires: Optional[str] = None

    def expired(self, today: datetime.date) -> bool:
        return self.expires is not None and datetime.date.fromisoformat(self.expires) < today

    def matches(self, finding: Finding) -> bool:
        vuln = finding.vulnerability
        ids = {i.upper() for i in (vuln.id,) + vuln.aliases}
        if self.id.upper() not in ids:
            return False
        return self.package is None or normalize_name(self.package) == normalize_name(finding.dependency.name)


@dataclass
class Config:
    fail_on: str = "low"
    exploit_data: bool = True
    ml: bool = True
    ignore: List[IgnoreRule] = field(default_factory=list)
    source: Optional[str] = None


def _flag(settings: Dict[str, Any], key: str, default: bool, where: str) -> bool:
    value = settings.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}: `{key}` must be true or false")
    return value


def parse_config(settings: Dict[str, Any], where: str) -> Config:
    known = {"fail-on", "exploit-data", "ml", "ignore"}
    unknown = sorted(str(k) for k in settings if k not in known)
    if unknown:
        raise ConfigError(f"{where}: unknown setting {clean(unknown[0], 40)!r} (known: {', '.join(sorted(known))})")

    fail_on = settings.get("fail-on", "low")
    if not isinstance(fail_on, str) or fail_on.lower() not in FAIL_LEVELS:
        raise ConfigError(f"{where}: `fail-on` must be one of {', '.join(FAIL_LEVELS)}")

    rules: List[IgnoreRule] = []
    entries = settings.get("ignore", [])
    if not isinstance(entries, list):
        raise ConfigError(f"{where}: `ignore` must be a list of tables")
    for number, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: ignore entry {number} must be a table with `id` and `reason`")
        ident, reason = clean(entry.get("id"), 100), clean(entry.get("reason"), 300)
        if not _ID.match(ident):
            raise ConfigError(f"{where}: ignore entry {number} needs an `id` such as GHSA-xxxx-xxxx-xxxx or CVE-2024-12345")
        if len(reason) < 3:
            raise ConfigError(f"{where}: ignore entry {number} ({ident}) needs a `reason` saying why it is accepted")
        package = entry.get("package")
        if package is not None and not clean(package, 200):
            raise ConfigError(f"{where}: ignore entry {number} ({ident}) has an invalid `package`")
        expires = entry.get("expires")
        if isinstance(expires, (datetime.date, datetime.datetime)):
            expires = expires.isoformat()[:10]
        if expires is not None:
            try:
                if not isinstance(expires, str) or not _DATE.match(expires):
                    raise ValueError
                datetime.date.fromisoformat(expires)
            except ValueError:
                raise ConfigError(f"{where}: ignore entry {number} ({ident}) has an invalid `expires` date; use YYYY-MM-DD") from None
        rules.append(IgnoreRule(ident, reason, clean(package, 200) if package else None, expires))

    return Config(
        fail_on=fail_on.lower(),
        exploit_data=_flag(settings, "exploit-data", True, where),
        ml=_flag(settings, "ml", True, where),
        ignore=rules,
        source=where,
    )


def load_config(root: Union[str, Path]) -> Config:
    """Read the project's settings. Returns defaults if there are none."""
    folder = Path(root)
    try:
        dedicated = folder / ".valtrix.toml"
        if dedicated.is_file():
            return parse_config(read_toml(dedicated), ".valtrix.toml")
        pyproject = folder / "pyproject.toml"
        if pyproject.is_file():
            tool = read_toml(pyproject).get("tool")
            settings = tool.get("valtrix") if isinstance(tool, dict) else None
            if isinstance(settings, dict):
                return parse_config(settings, "pyproject.toml [tool.valtrix]")
    except ParseError as exc:
        raise ConfigError(str(exc)) from exc
    return Config()


def apply_ignores(result: ScanResult, rules: List[IgnoreRule],
                  today: Optional[datetime.date] = None) -> None:
    """Move accepted findings to `result.ignored`. Expired rules no longer apply."""
    today = today or datetime.date.today()
    active = [r for r in rules if not r.expired(today)]
    for rule in rules:
        if rule.expired(today):
            result.notes.append(f"The ignore rule for {rule.id} expired on {rule.expires}, so the finding is reported again.")
    if not active:
        return
    kept: List[Finding] = []
    for finding in result.findings:
        rule = next((r for r in active if r.matches(finding)), None)
        if rule is None:
            kept.append(finding)
        else:
            result.ignored.append(Ignored(finding, rule.reason, rule.expires))
    result.findings = kept

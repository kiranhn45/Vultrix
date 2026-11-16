"""Plain-text reports for the terminal. Pure functions: they return text and print nothing."""

from __future__ import annotations

from typing import List, Optional, Sequence

from valtrix.models import SEVERITY_ORDER, Dependency, Finding, ScanResult, Vulnerability, count_by_severity
from valtrix.models.graph import DependencyGraph, Node, node_label
from valtrix.reports.common import ReportMeta, count_by_priority, one_line, plural
from valtrix.scanner import suggest_upgrade
from valtrix.versions import choose_fix, sort_versions

TOP = 5
_COLORS = {"fix now": "1;31", "fix soon": "33", "plan": "36", "monitor": "2"}


def describe_dependency(dep: Dependency) -> str:
    if dep.version:
        return dep.version
    return f"{dep.specifier or 'any version'} (not pinned)"


def _severity_summary(findings: Sequence[Finding]) -> str:
    counts = count_by_severity(findings)
    order = list(SEVERITY_ORDER) + ["UNKNOWN"]
    return ", ".join(f"{counts[label]} {label.lower()}" for label in order if label in counts)


def _paint(text: str, priority: str, color: bool) -> str:
    return f"\x1b[{_COLORS[priority]}m{text}\x1b[0m" if color and priority in _COLORS else text


def _ranked(findings: Sequence[Finding], details: bool, color: bool) -> List[str]:
    shown = list(findings) if details else list(findings[:TOP])
    if len(shown) < len(findings):
        head = f"Fix first (top {len(shown)} of {plural(len(findings), 'issue')}, ranked by risk):"
    else:
        head = f"Fix first ({plural(len(findings), 'issue')}, ranked by risk):"
    lines = [head, ""]
    for rank, f in enumerate(shown, start=1):
        risk = f.risk
        assert risk is not None
        summary = one_line(f.vulnerability.summary) or "(no description)"
        tag = _paint(f"{risk.priority:<8}", risk.priority, color)
        lines.append(f"  {rank:>2}. score {risk.score:>3}  {tag}  {f.dependency.label}  {f.vulnerability.id}")
        lines.append(f"      {summary}")
        if details:
            for factor in risk.factors:
                lines.append(f"      {factor.points:>+3}  {factor.name}: {factor.detail}")
            lines.append(f"      {f.vulnerability.osv_url}")
        else:
            lines.append(f"      Why: {risk.factors[0].detail}. {risk.factors[1].detail}.")
            lines.append(f"      {risk.factors[3].detail}.")
        lines.append("")
    return lines


def render_scan(result: ScanResult, details: bool = False, meta: Optional[ReportMeta] = None,
                color: bool = False) -> str:
    """The full text report for a scan."""
    lines: List[str] = []
    out = lines.append
    checked = len(result.scanned)
    total = checked + len(result.unchecked)
    out(f"Sources: {', '.join(result.sources)}")
    out(f"\nChecked {checked} of {plural(total, 'dependency', 'dependencies')} against OSV.")

    vulnerable = result.vulnerable_dependencies
    if vulnerable:
        issues = len(result.findings)
        out(
            f"\n{plural(len(vulnerable), 'dependency', 'dependencies')} "
            f"with known vulnerabilities ({plural(issues, 'issue')} in total):\n"
        )
        for dep in vulnerable:
            findings = result.findings_for(dep)
            tags = [t for t, on in (("transitive", dep.direct is False), ("dev only", dep.dev)) if on]
            where = f"  ({dep.ecosystem}{', ' + ', '.join(tags) if tags else ''})" if tags or dep.ecosystem != "PyPI" else ""
            out(f"  {dep.name} {dep.version}{where}")
            out(f"    {plural(len(findings), 'issue')}: {_severity_summary(findings)}")
            upgrade, unfixed = suggest_upgrade(findings)
            if upgrade:
                note = f" ({plural(unfixed, 'issue')} with no known fix)" if unfixed else ""
                out(f"    Upgrading to {upgrade} or later resolves the issues that have a fix{note}")
            else:
                out("    No fixed version is listed for these issues")
            if len(dep.path) > 1:
                out(f"    Pulled in by: {' > '.join(dep.path[:-1])}")
            if details:
                for f in findings:
                    label = f.vulnerability.severity_label or "UNKNOWN"
                    fix = f"fix: {f.fix}" if f.fix else "no fix listed"
                    summary = one_line(f.vulnerability.summary)
                    out(f"      [{label}] {f.vulnerability.id}  {summary}  ({fix})")
            out("")

        if all(f.risk is not None for f in result.findings):
            lines.extend(_ranked(result.findings, details, color))
            counts = count_by_priority(result.findings)
            out("Priorities: " + ", ".join(f"{n} {name}" for name, n in counts.items() if n) + ".\n")
        if not details:
            out("Run with --details to list every issue.\n")
    elif total == 0:
        out("\nNo dependencies were found in these files.")
    elif checked == 0:
        out("\nNothing could be checked, so there is no result. See the list below.")
    else:
        out("\nNo known vulnerabilities in the dependencies that were checked.")

    clean = [d for d in result.scanned if d not in vulnerable]
    if clean and vulnerable:
        out(f"{plural(len(clean), 'dependency', 'dependencies')} with no known vulnerabilities.\n")

    if result.ignored:
        out(f"Ignored by the project's settings ({len(result.ignored)}):")
        for item in result.ignored:
            until = f", until {item.expires}" if item.expires else ""
            out(f"  {item.finding.vulnerability.id} in {item.finding.dependency.label}: {item.reason}{until}")
        out("")

    if result.unchecked:
        out(f"Not checked ({len(result.unchecked)}):")
        for item in result.unchecked:
            where = f"{item.dependency.source}:{item.dependency.line}"
            out(f"  {item.dependency.name}  {item.reason}  ({where})")
        out("")

    if result.parse_issues:
        out(f"{plural(len(result.parse_issues), 'line')} could not be used:")
        for issue in result.parse_issues:
            out(f"  {issue}")
        out("")

    notes = list(result.notes) + (list(meta.exploit_data.notes) if meta and meta.exploit_data else [])
    for note in notes:
        out(f"Note: {note}")
    if notes:
        out("")

    if checked:
        out("No known vulnerabilities means none are listed in OSV, not that the code is guaranteed safe.")
    return "\n".join(lines)


def render_dependency_list(deps: Sequence[Dependency], issues: Sequence[object]) -> str:
    """The `--offline` listing: what was found, without contacting anything."""
    lines = [f"\nFound {len(deps)} dependencies:"]
    width = max((len(d.name) for d in deps), default=0)
    for dep in deps:
        tags = [dep.ecosystem] if dep.ecosystem != "PyPI" else []
        if dep.direct is False:
            tags.append("transitive")
        if dep.dev:
            tags.append("dev")
        suffix = f"  [{', '.join(tags)}]" if tags else ""
        lines.append(f"  {dep.name.ljust(width)}  {describe_dependency(dep)}{suffix}")
    if issues:
        lines.append(f"\n{len(issues)} lines could not be used:")
        lines.extend(f"  {issue}" for issue in issues)
    lines.append("\nOffline mode: OSV was not contacted.")
    return "\n".join(lines)


def render_vulnerability(vuln: Vulnerability, installed: str, ecosystem: str = "PyPI") -> str:
    """One advisory, as shown by `valtrix lookup`."""
    label = vuln.severity_label or "severity unknown"
    lines = [f"  {vuln.id}  [{label}]"]
    extra_ids = [a for a in vuln.aliases if a != vuln.id]
    if extra_ids:
        lines.append(f"    Also known as: {', '.join(extra_ids)}")
    if vuln.summary:
        lines.append(f"    {one_line(vuln.summary)}")
    if vuln.fixed_versions:
        fix = choose_fix(installed, vuln.fixed_versions, ecosystem)
        ordered = sort_versions(vuln.fixed_versions, ecosystem)
        others = [v for v in ordered if v != fix]
        if fix and others:
            lines.append(f"    Fixed in: {fix} (other release lines: {', '.join(others)})")
        elif fix:
            lines.append(f"    Fixed in: {fix}")
        else:
            lines.append(f"    Fixed in: {', '.join(ordered)}")
    else:
        lines.append("    No fixed version listed")
    lines.append(f"    {vuln.osv_url}")
    return "\n".join(lines)


def render_graph(graph: DependencyGraph, max_depth: int = 12, max_lines: int = 2000) -> str:
    """The dependency tree, one package per line, indented under what pulls it in."""
    lines: List[str] = []
    expanded = set()

    def walk(node: Node, depth: int, trail: tuple) -> None:
        if len(lines) >= max_lines:
            return
        kids = graph.children.get(node, [])
        repeat = node in expanded and bool(kids)
        lines.append("  " * depth + node_label(node) + ("  (shown above)" if repeat else ""))
        if repeat or depth >= max_depth or node in trail:
            return
        expanded.add(node)
        for child in kids:
            walk(child, depth + 1, trail + (node,))

    for root in graph.roots:
        walk(root, 0, ())
    if len(lines) >= max_lines:
        lines.append(f"... stopped after {max_lines} lines")
    return "\n".join(lines)

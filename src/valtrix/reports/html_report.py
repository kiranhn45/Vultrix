"""The HTML report: one self-contained file, safe to open or attach anywhere.

Every value that came from outside (advisory text, ids, links, file names,
package names) is escaped before it is written. Links are only made for
http(s) addresses. The page has no scripts and loads nothing from the
network, and its Content-Security-Policy forbids both.
"""

from __future__ import annotations

from html import escape
from typing import List

from valtrix.models import PRIORITIES, Finding, ScanResult
from valtrix.reports.common import (
    ReportMeta,
    count_by_priority,
    effective_severity,
    exit_code,
    one_line,
    plural,
)
from valtrix.risk.rules import EXPLOITATION_MAX, EXPOSURE_MAX, FIX_POINTS, SEVERITY_MAX

_MAX = {"Severity": SEVERITY_MAX, "Exploitation": EXPLOITATION_MAX, "Exposure": EXPOSURE_MAX, "Fix": FIX_POINTS}

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#16191f;--dim:#5d6675;--line:#dfe3ea;--now:#c62828;--soon:#b26a00;
--plan:#1565c0;--mon:#5d6675;--ok:#1b7f4b;--bar:#d5dae3}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--ink:#e7eaf0;--dim:#98a2b3;--line:#2a303b;
--now:#ff6b6b;--soon:#ffb454;--plan:#6cb6ff;--mon:#98a2b3;--ok:#56d39b;--bar:#2f3643}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.15rem;margin:36px 0 12px}
.meta,.dim{color:var(--dim)}.meta{font-size:.875rem;overflow-wrap:anywhere}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:1.7rem;line-height:1.2}.card span{color:var(--dim);font-size:.85rem}
.banner{border-radius:10px;padding:12px 16px;margin:16px 0;border:1px solid var(--line);background:var(--card)}
.banner.bad{border-color:var(--now)}.banner.warn{border-color:var(--soon)}.banner.good{border-color:var(--ok)}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--mon);border-radius:10px;
padding:14px 16px;margin:12px 0}
.finding.p-fix-now{border-left-color:var(--now)}.finding.p-fix-soon{border-left-color:var(--soon)}
.finding.p-plan{border-left-color:var(--plan)}
.top{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:baseline}
.rank{color:var(--dim);font-variant-numeric:tabular-nums}.pkg{font-weight:650;overflow-wrap:anywhere}
.pill{font-size:.75rem;font-weight:650;border-radius:999px;padding:2px 9px;border:1px solid currentColor;white-space:nowrap}
.pill.p-fix-now{color:var(--now)}.pill.p-fix-soon{color:var(--soon)}.pill.p-plan{color:var(--plan)}.pill.p-monitor{color:var(--mon)}
.score{margin-left:auto;font-weight:700;font-variant-numeric:tabular-nums}
.sum{margin:6px 0 10px;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%}td,th{padding:4px 8px 4px 0;vertical-align:top;text-align:left}
th{color:var(--dim);font-weight:600;font-size:.85rem;white-space:nowrap;width:110px}
td.pts{font-variant-numeric:tabular-nums;white-space:nowrap;width:1%}td.detail{overflow-wrap:anywhere}
.bar{display:inline-block;width:64px;height:6px;border-radius:3px;background:var(--bar);vertical-align:middle;margin-right:6px}
.bar i{display:block;height:100%;border-radius:3px;background:var(--plan)}
.ids{font-size:.85rem;color:var(--dim);margin-top:8px;overflow-wrap:anywhere}
a{color:var(--plan)}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}
ul.plain{list-style:none;padding:0;margin:0}ul.plain li{padding:6px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
footer{margin-top:40px;color:var(--dim);font-size:.85rem}
"""


def _slug(priority: str) -> str:
    return "p-" + priority.replace(" ", "-")


def _link(url: str, text: str) -> str:
    if url.lower().startswith(("http://", "https://")):
        return f'<a href="{escape(url, quote=True)}" rel="noopener noreferrer">{escape(text)}</a>'
    return escape(text)


def _finding(rank: int, finding: Finding) -> str:
    vuln, dep, risk = finding.vulnerability, finding.dependency, finding.risk
    priority = risk.priority if risk else "monitor"
    severity = effective_severity(finding)
    if risk and risk.estimated:
        severity += " (estimated)"
    parts: List[str] = [f'<article class="finding {_slug(priority)}">', '<div class="top">']
    parts.append(f'<span class="rank">#{rank}</span>')
    parts.append(f'<span class="pkg">{escape(dep.label)}</span>')
    parts.append(f'<span class="pill {_slug(priority)}">{escape(priority)}</span>')
    parts.append(f'<span class="dim">{escape(severity.lower())} · {escape(dep.ecosystem)}</span>')
    if risk:
        parts.append(f'<span class="score" title="Risk score out of 100">{risk.score}</span>')
    parts.append("</div>")
    parts.append(f'<p class="sum">{escape(one_line(vuln.summary) or "No description published.")}</p>')
    if risk:
        parts.append("<table><tbody>")
        for factor in risk.factors:
            width = round(100 * factor.points / _MAX.get(factor.name, 100))
            parts.append(
                f"<tr><th>{escape(factor.name)}</th>"
                f'<td class="pts"><span class="bar"><i style="width:{max(0, min(100, width))}%"></i></span>+{factor.points}</td>'
                f'<td class="detail">{escape(factor.detail)}</td></tr>'
            )
        parts.append("</tbody></table>")
    ids = [_link(vuln.osv_url, vuln.id)] + [escape(a) for a in vuln.aliases[:8]]
    where = f"{dep.source}:{dep.line}" if dep.line else dep.source
    parts.append(f'<div class="ids">{" · ".join(ids)} · found in <code>{escape(where)}</code>')
    refs = [_link(url, f"reference {n}") for n, url in enumerate(vuln.references[:3], start=1)]
    if refs:
        parts.append(" · " + " · ".join(refs))
    parts.append("</div></article>")
    return "".join(parts)


def render_html(result: ScanResult, meta: ReportMeta) -> str:
    checked = len(result.scanned)
    total = checked + len(result.unchecked)
    code = exit_code(result, meta.fail_on)
    counts = count_by_priority(result.findings)
    notes = list(result.notes) + (list(meta.exploit_data.notes) if meta.exploit_data else [])

    body: List[str] = []
    add = body.append
    add("<h1>Valtrix dependency report</h1>")
    add(f'<p class="meta">{escape(meta.target)}<br>Generated {escape(meta.generated_at)} by Valtrix {escape(meta.version)}'
        f' · sources: {escape(", ".join(result.sources) or "none")}</p>')

    if result.findings and code == 1:
        add(f'<div class="banner bad"><b>{plural(len(result.findings), "known vulnerability", "known vulnerabilities")}</b> in '
            f'{plural(len(result.vulnerable_dependencies), "dependency", "dependencies")}. Most urgent first, below.</div>')
    elif result.findings:
        add(f'<div class="banner warn"><b>{plural(len(result.findings), "known vulnerability", "known vulnerabilities")}</b>, '
            f'all below the level this project fails on ({escape(meta.fail_on)}).</div>')
    elif checked == 0:
        add('<div class="banner warn"><b>Nothing could be checked</b>, so there is no result.</div>')
    else:
        add('<div class="banner good"><b>No known vulnerabilities</b> in the dependencies that were checked. '
            'That means none are listed in OSV, not that the code is guaranteed safe.</div>')
    if result.incomplete:
        add('<div class="banner warn"><b>The scan is incomplete.</b> Some dependencies could not be checked; see the list below.</div>')

    add('<div class="cards">')
    for value, label in [(f"{checked} / {total}", "dependencies checked"),
                         (len(result.vulnerable_dependencies), "vulnerable"),
                         (len(result.findings), "issues")] + [(counts[p], p) for p in PRIORITIES]:
        add(f'<div class="card"><b>{escape(str(value))}</b><span>{escape(label)}</span></div>')
    add("</div>")

    if result.findings:
        add("<h2>What to fix first</h2>")
        add('<p class="dim">The score (0 to 100) adds up four factors: how severe the issue is, evidence that it is '
            "being exploited, how the package reaches the project, and whether a fix exists.</p>")
        for rank, finding in enumerate(result.findings, start=1):
            add(_finding(rank, finding))

    if result.ignored:
        add(f"<h2>Ignored by the project's settings ({len(result.ignored)})</h2><ul class=\"plain\">")
        for item in result.ignored:
            until = f" (until {escape(item.expires)})" if item.expires else ""
            add(f"<li><code>{escape(item.finding.vulnerability.id)}</code> in {escape(item.finding.dependency.label)}: "
                f"{escape(item.reason)}{until}</li>")
        add("</ul>")

    if result.unchecked:
        add(f"<h2>Not checked ({len(result.unchecked)})</h2><ul class=\"plain\">")
        for item in result.unchecked:
            dep = item.dependency
            add(f"<li><b>{escape(dep.name)}</b>: {escape(item.reason)} "
                f'<span class="dim">({escape(dep.source)}:{dep.line})</span></li>')
        add("</ul>")

    if result.parse_issues:
        add(f"<h2>Lines that could not be used ({len(result.parse_issues)})</h2><ul class=\"plain\">")
        for issue in result.parse_issues:
            add(f"<li>{escape(str(issue))}</li>")
        add("</ul>")

    if notes:
        add('<h2>Notes</h2><ul class="plain">')
        for note in notes:
            add(f"<li>{escape(note)}</li>")
        add("</ul>")

    add("<footer>Vulnerability data from OSV (osv.dev). Exploitation evidence from FIRST EPSS and CISA KEV when available. "
        "A person should review every upgrade before it is applied.</footer>")

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        "<title>Valtrix dependency report</title>"
        f"<style>{_CSS}</style></head><body><main>{''.join(body)}</main></body></html>\n"
    )

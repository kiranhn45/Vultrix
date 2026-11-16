"""Report formats: terminal text, JSON, HTML and SARIF."""

from valtrix.reports.common import (
    EXIT_BAD_INPUT,
    EXIT_FINDINGS,
    EXIT_INCOMPLETE,
    EXIT_OK,
    ReportMeta,
    exit_code,
)
from valtrix.reports.html_report import render_html
from valtrix.reports.json_report import SCHEMA_VERSION, build_report, render_json
from valtrix.reports.sarif import build_sarif, render_sarif
from valtrix.reports.terminal import (
    render_dependency_list,
    render_graph,
    render_scan,
    render_vulnerability,
)

FORMATS = ("text", "json", "html", "sarif")

__all__ = [
    "EXIT_BAD_INPUT", "EXIT_FINDINGS", "EXIT_INCOMPLETE", "EXIT_OK", "FORMATS", "ReportMeta",
    "SCHEMA_VERSION", "build_report", "build_sarif", "exit_code", "render_dependency_list",
    "render_graph", "render_html", "render_json", "render_sarif", "render_scan",
    "render_vulnerability",
]

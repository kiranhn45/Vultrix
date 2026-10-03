import email.message
import io
import json
import ssl
import urllib.error

import pytest

from valtrix import __version__
from valtrix.databases import OsvClient, OsvError, parse_vulnerability
from valtrix.databases import osv as osv_module


# ------------------------------------------------------------- test doubles

class FakeResponse:
    def __init__(self, body):
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Plays back a script of responses/exceptions, then `repeat` forever."""

    def __init__(self, *script, repeat=None):
        self.script = list(script)
        self.repeat = repeat
        self.calls = []

    def open(self, request, timeout=None):
        self.calls.append((request, timeout))
        if len(self.calls) > 100:
            raise AssertionError("client made more than 100 requests: runaway loop")
        item = self.script.pop(0) if self.script else self.repeat
        if item is None:
            raise AssertionError("FakeOpener ran out of scripted responses")
        if isinstance(item, BaseException):
            raise item
        return item

    def sent(self, index=0):
        return json.loads(self.calls[index][0].data.decode())


def http_error(code, body=b"", retry_after=None):
    headers = email.message.Message()
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return urllib.error.HTTPError(
        "https://api.osv.dev/v1/query", code, "status", headers, io.BytesIO(body)
    )


def client(opener, **kwargs):
    sleeps = []
    c = OsvClient(opener=opener, sleep=sleeps.append, **kwargs)
    c.sleeps = sleeps
    return c


def record(**overrides):
    base = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Something is wrong",
        "details": "Longer explanation.",
        "aliases": ["CVE-2023-0001"],
        "published": "2023-05-01T00:00:00Z",
        "modified": "2023-06-01T00:00:00Z",
        "database_specific": {"severity": "MODERATE"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}
                ],
            }
        ],
    }
    base.update(overrides)
    return base


# ------------------------------------------------------------ record parsing

def test_parse_full_record():
    v = parse_vulnerability(record(), "requests")
    assert v.id == "GHSA-aaaa-bbbb-cccc"
    assert v.summary == "Something is wrong"
    assert v.aliases == ("CVE-2023-0001",)
    assert v.cve_ids == ("CVE-2023-0001",)
    assert v.severity_label == "MEDIUM"          # MODERATE is normalized
    assert v.cvss[0][0] == "CVSS_V3"
    assert v.fixed_versions == ("2.31.0",)
    assert v.has_fix
    assert v.references == ("https://example.com/advisory",)
    assert v.published == "2023-05-01T00:00:00Z"
    assert v.osv_url == "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"


def test_minimal_record():
    v = parse_vulnerability({"id": "PYSEC-2020-1"}, "requests")
    assert v.id == "PYSEC-2020-1"
    assert v.severity_label is None
    assert v.fixed_versions == () and not v.has_fix
    assert v.cvss == () and v.references == ()


def test_cve_id_can_be_the_primary_id():
    v = parse_vulnerability({"id": "CVE-2020-1234", "aliases": ["GHSA-x"]}, "requests")
    assert v.cve_ids == ("CVE-2020-1234",)


def test_withdrawn_record_is_excluded():
    assert parse_vulnerability(record(withdrawn="2023-07-01T00:00:00Z"), "requests") is None


def test_record_without_id_is_an_error():
    with pytest.raises(OsvError, match="no id"):
        parse_vulnerability({"summary": "x"}, "requests")


def test_non_dict_record_is_an_error():
    with pytest.raises(OsvError, match="unexpected format"):
        parse_vulnerability("nope", "requests")


def test_fixed_versions_ignore_other_packages_and_git_ranges():
    rec = record(
        affected=[
            {
                "package": {"name": "Requests", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "GIT", "events": [{"fixed": "deadbeefcafe"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]},
                ],
            },
            {
                "package": {"name": "other-package", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9.9"}]}],
            },
            {
                "package": {"name": "requests", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "8.8.8"}]}],
            },
        ]
    )
    assert parse_vulnerability(rec, "requests").fixed_versions == ("2.31.0",)


def test_severity_variants():
    assert parse_vulnerability(record(database_specific={"severity": "critical"}), "requests").severity_label == "CRITICAL"
    assert parse_vulnerability(record(database_specific={"severity": "weird"}), "requests").severity_label is None
    assert parse_vulnerability(record(database_specific=None), "requests").severity_label is None
    assert parse_vulnerability(record(severity=None), "requests").cvss == ()


def test_only_http_references_are_kept():
    rec = record(
        references=[
            {"url": "javascript:alert(1)"},
            {"url": "https://ok.example/a"},
            {"url": "https://ok.example/a"},
            {"url": "http://ok.example/b"},
            {"url": 42},
            "not-a-dict",
        ]
    )
    assert parse_vulnerability(rec, "requests").references == (
        "https://ok.example/a",
        "http://ok.example/b",
    )


def test_terminal_control_characters_are_stripped():
    rec = record(summary="\x1b[31mRED\x1b[0m alert\x07", details="line1\nline2")
    v = parse_vulnerability(rec, "requests")
    assert "\x1b" not in v.summary and "\x07" not in v.summary
    assert v.summary == "[31mRED[0m alert"
    assert v.details == "line1\nline2"


def test_long_text_is_clipped():
    v = parse_vulnerability(record(summary="x" * 10_000, details="y" * 100_000), "requests")
    assert len(v.summary) <= 500 and len(v.details) <= 5_000


def test_wrong_types_are_tolerated():
    rec = {"id": "X-1", "aliases": "oops", "affected": "oops", "references": 5, "severity": "oops"}
    v = parse_vulnerability(rec, "requests")
    assert v.aliases == () and v.fixed_versions == () and v.references == () and v.cvss == ()


# ------------------------------------------------------------- the request

def test_request_shape():
    opener = FakeOpener(FakeResponse({}))
    client(opener).query("Flask_SQLAlchemy", "3.0.0")
    request, timeout = opener.calls[0]
    assert request.full_url == "https://api.osv.dev/v1/query"
    assert request.get_method() == "POST"
    assert opener.sent() == {
        "package": {"name": "flask-sqlalchemy", "ecosystem": "PyPI"},
        "version": "3.0.0",
    }
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("User-agent") == f"valtrix/{__version__}"
    assert timeout == 15.0


def test_empty_object_means_no_vulnerabilities():
    assert client(FakeOpener(FakeResponse({}))).query("requests", "2.31.0") == []


def test_results_are_parsed():
    opener = FakeOpener(FakeResponse({"vulns": [record(), record(id="PYSEC-1", withdrawn="2024-01-01T00:00:00Z")]}))
    found = client(opener).query("requests", "2.25.1")
    assert [v.id for v in found] == ["GHSA-aaaa-bbbb-cccc"]


def test_pagination_collects_every_page_without_duplicates():
    opener = FakeOpener(
        FakeResponse({"vulns": [record(id="A-1"), record(id="A-2")], "next_page_token": "tok1"}),
        FakeResponse({"vulns": [record(id="A-2"), record(id="A-3")]}),
    )
    found = client(opener).query("requests", "2.25.1")
    assert [v.id for v in found] == ["A-1", "A-2", "A-3"]
    assert "page_token" not in opener.sent(0)
    assert opener.sent(1)["page_token"] == "tok1"


def test_endless_pagination_is_stopped():
    opener = FakeOpener(repeat=FakeResponse({"vulns": [], "next_page_token": "again"}))
    with pytest.raises(OsvError, match="pages of results"):
        client(opener).query("requests", "2.25.1")
    assert len(opener.calls) == osv_module.MAX_PAGES


def test_same_query_is_cached():
    opener = FakeOpener(FakeResponse({"vulns": [record()]}))
    c = client(opener)
    first = c.query("requests", "2.25.1")
    second = c.query("Requests", "2.25.1")
    assert first == second
    assert len(opener.calls) == 1


# ------------------------------------------------------- retries and failures

def test_temporary_server_error_is_retried_with_backoff():
    opener = FakeOpener(http_error(503), http_error(502), FakeResponse({}))
    c = client(opener, backoff=1.0)
    assert c.query("requests", "2.31.0") == []
    assert len(opener.calls) == 3
    assert c.sleeps == [1.0, 2.0]


def test_rate_limit_respects_retry_after():
    opener = FakeOpener(http_error(429, retry_after=3), FakeResponse({}))
    c = client(opener)
    c.query("requests", "2.31.0")
    assert c.sleeps == [3.0]


def test_retry_after_is_capped():
    opener = FakeOpener(http_error(429, retry_after=100000), FakeResponse({}))
    c = client(opener)
    c.query("requests", "2.31.0")
    assert c.sleeps == [osv_module.MAX_DELAY_SECONDS]


def test_gives_up_after_max_retries_with_clear_message():
    opener = FakeOpener(repeat=http_error(503))
    c = client(opener, max_retries=2)
    with pytest.raises(OsvError, match=r"after 3 attempts.*HTTP 503"):
        c.query("requests", "2.31.0")
    assert len(opener.calls) == 3
    assert len(c.sleeps) == 2


def test_bad_request_is_not_retried():
    opener = FakeOpener(http_error(400, body=b'{"code":3,"message":"Invalid version."}'))
    with pytest.raises(OsvError, match=r"HTTP 400.*Invalid version"):
        client(opener).query("requests", "2.31.0")
    assert len(opener.calls) == 1


def test_network_error_is_retried():
    opener = FakeOpener(urllib.error.URLError("connection refused"), FakeResponse({}))
    c = client(opener)
    assert c.query("requests", "2.31.0") == []
    assert len(opener.calls) == 2


def test_timeout_is_retried_and_reported():
    opener = FakeOpener(repeat=TimeoutError())
    with pytest.raises(OsvError, match="timed out"):
        client(opener, max_retries=1).query("requests", "2.31.0")
    assert len(opener.calls) == 2


def test_certificate_problem_is_not_retried():
    err = urllib.error.URLError(ssl.SSLCertVerificationError("bad cert"))
    opener = FakeOpener(err)
    with pytest.raises(OsvError, match="security certificate"):
        client(opener).query("requests", "2.31.0")
    assert len(opener.calls) == 1


def test_invalid_json_is_an_error():
    with pytest.raises(OsvError, match="not valid JSON"):
        client(FakeOpener(FakeResponse(b"<html>oops</html>"))).query("requests", "2.31.0")


def test_non_object_json_is_an_error():
    with pytest.raises(OsvError, match="unexpected format"):
        client(FakeOpener(FakeResponse(b"[1, 2, 3]"))).query("requests", "2.31.0")


def test_vulns_not_a_list_is_an_error():
    with pytest.raises(OsvError, match="unexpected format"):
        client(FakeOpener(FakeResponse({"vulns": "nope"}))).query("requests", "2.31.0")


def test_oversized_response_is_rejected(monkeypatch):
    monkeypatch.setattr(osv_module, "MAX_RESPONSE_BYTES", 50)
    with pytest.raises(OsvError, match="too large"):
        client(FakeOpener(FakeResponse(b"x" * 500))).query("requests", "2.31.0")


# ---------------------------------------------------------- argument checks

@pytest.mark.parametrize("name", ["", " ", "bad name", "../etc", "-leading", "a" * 300, None])
def test_invalid_names_are_rejected(name):
    with pytest.raises(ValueError):
        client(FakeOpener()).query(name, "1.0")


@pytest.mark.parametrize("version", ["", "1.0 beta", "1.*", "-1", "x" * 300, None])
def test_invalid_versions_are_rejected(version):
    with pytest.raises(ValueError):
        client(FakeOpener()).query("requests", version)


def test_invalid_ecosystem_is_rejected():
    with pytest.raises(ValueError):
        client(FakeOpener()).query("requests", "1.0", ecosystem="Py PI")


@pytest.mark.parametrize("url", ["http://api.osv.dev", "ftp://x", "api.osv.dev", ""])
def test_non_https_base_url_is_rejected(url):
    with pytest.raises(ValueError):
        OsvClient(base_url=url)

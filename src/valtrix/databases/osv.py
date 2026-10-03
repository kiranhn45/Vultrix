"""Client for the OSV vulnerability database (https://osv.dev).

Uses only the standard library. Everything the server sends back is treated
as untrusted: types are checked, text is cleaned of terminal control
characters and clipped, links are limited to http(s), and response size,
retries, and pagination are all bounded.

The tests never touch the network. Pass a fake `opener` to OsvClient to
simulate responses.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

from valtrix import __version__
from valtrix.models import Vulnerability, normalize_name

DEFAULT_BASE_URL = "https://api.osv.dev"
PYPI = "PyPI"

MAX_RESPONSE_BYTES = 10_000_000
MAX_PAGES = 20
MAX_DELAY_SECONDS = 30.0
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

_MAX_SUMMARY = 500
_MAX_DETAILS = 5_000
_MAX_ITEM = 300
_MAX_ITEMS = 50

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,199}$")
_ECOSYSTEM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,49}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

_SEVERITY_LABELS = {
    "LOW": "LOW",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


class OsvError(Exception):
    """OSV could not be queried or returned something unusable.

    The message is written for the person running Valtrix.
    """


# ------------------------------------------------------------ parsing records

def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return _CONTROL_CHARS.sub("", value).strip()[:limit]


def _text_tuple(value: Any, limit_items: int = _MAX_ITEMS) -> Tuple[str, ...]:
    out: List[str] = []
    if isinstance(value, list):
        for item in value:
            cleaned = _text(item, _MAX_ITEM)
            if cleaned and cleaned not in out:
                out.append(cleaned)
            if len(out) >= limit_items:
                break
    return tuple(out)


def _same_package(a: str, b: str, ecosystem: str) -> bool:
    if ecosystem.lower() == PYPI.lower():
        return normalize_name(a) == normalize_name(b)
    return a.lower() == b.lower()


def _fixed_versions(record: Mapping[str, Any], package: str, ecosystem: str) -> Tuple[str, ...]:
    fixed: List[str] = []
    affected = record.get("affected")
    if not isinstance(affected, list):
        return ()
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package")
        if not isinstance(pkg, dict):
            continue
        if _text(pkg.get("ecosystem"), 50).lower() != ecosystem.lower():
            continue
        if not _same_package(_text(pkg.get("name"), 200), package, ecosystem):
            continue
        ranges = entry.get("ranges")
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            # GIT ranges hold commit hashes, not versions, so they are skipped.
            if not isinstance(rng, dict) or rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            events = rng.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict):
                    version = _text(event.get("fixed"), _MAX_ITEM)
                    if version and version not in fixed:
                        fixed.append(version)
    return tuple(fixed[:_MAX_ITEMS])


def _references(record: Mapping[str, Any]) -> Tuple[str, ...]:
    urls: List[str] = []
    refs = record.get("references")
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            url = _text(ref.get("url"), 500)
            if url.lower().startswith(("http://", "https://")) and url not in urls:
                urls.append(url)
            if len(urls) >= _MAX_ITEMS:
                break
    return tuple(urls)


def _cvss(record: Mapping[str, Any]) -> Tuple[Tuple[str, str], ...]:
    pairs: List[Tuple[str, str]] = []
    severity = record.get("severity")
    if isinstance(severity, list):
        for item in severity:
            if isinstance(item, dict):
                kind, score = _text(item.get("type"), 20), _text(item.get("score"), 200)
                if kind and score:
                    pairs.append((kind, score))
    return tuple(pairs[:_MAX_ITEMS])


def _severity_label(record: Mapping[str, Any]) -> Optional[str]:
    specific = record.get("database_specific")
    if isinstance(specific, dict):
        label = _text(specific.get("severity"), 20).upper()
        return _SEVERITY_LABELS.get(label)
    return None


def parse_vulnerability(
    record: Any, package: str, ecosystem: str = PYPI
) -> Optional[Vulnerability]:
    """Convert one raw OSV record into a Vulnerability.

    Returns None for withdrawn advisories (the database has retracted them, so
    reporting them would be a false alarm). Raises OsvError if the record is
    not usable at all.
    """
    if not isinstance(record, dict):
        raise OsvError("OSV returned a vulnerability record in an unexpected format")
    vuln_id = _text(record.get("id"), 200)
    if not vuln_id:
        raise OsvError("OSV returned a vulnerability record with no id")
    if record.get("withdrawn"):
        return None

    return Vulnerability(
        id=vuln_id,
        summary=_text(record.get("summary"), _MAX_SUMMARY),
        details=_text(record.get("details"), _MAX_DETAILS),
        aliases=_text_tuple(record.get("aliases")),
        severity_label=_severity_label(record),
        cvss=_cvss(record),
        fixed_versions=_fixed_versions(record, package, ecosystem),
        references=_references(record),
        published=_text(record.get("published"), 40) or None,
        modified=_text(record.get("modified"), 40) or None,
    )


# ------------------------------------------------------------------- the client

class OsvClient:
    """Look up known vulnerabilities for a package version.

    base_url     Must be https.
    timeout      Seconds to wait for each request.
    max_retries  Extra attempts after a temporary failure (rate limit, server
                 error, network problem). Permanent errors are not retried.
    backoff      First retry delay in seconds; doubles each time (max 30).
    opener       Anything with `.open(request, timeout=...)`. Tests pass a fake.
    sleep        Function used to wait between retries. Tests pass a recorder.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 15.0,
        max_retries: int = 3,
        backoff: float = 1.0,
        opener: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme != "https" or not parts.netloc:
            raise ValueError("base_url must be an https URL")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self._backoff = backoff
        self._opener = opener if opener is not None else urllib.request.build_opener()
        self._sleep = sleep
        self._cache: Dict[Tuple[str, str, str], Tuple[Vulnerability, ...]] = {}

    def query(self, name: str, version: str, ecosystem: str = PYPI) -> List[Vulnerability]:
        """Return the known vulnerabilities affecting `name` at exactly `version`.

        An empty list means OSV knows of none for that exact version. It does
        not prove the package is safe.

        Raises ValueError for malformed arguments and OsvError if OSV cannot be
        reached or answers with something unusable.
        """
        if not isinstance(name, str) or not _NAME.match(name):
            raise ValueError(f"invalid package name: {name!r}")
        if not isinstance(version, str) or not _VERSION.match(version):
            raise ValueError(f"invalid version: {version!r}")
        if not isinstance(ecosystem, str) or not _ECOSYSTEM.match(ecosystem):
            raise ValueError(f"invalid ecosystem: {ecosystem!r}")

        if ecosystem.lower() == PYPI.lower():
            name = normalize_name(name)
        key = (ecosystem, name, version)
        if key in self._cache:
            return list(self._cache[key])

        payload: Dict[str, Any] = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }
        found: List[Vulnerability] = []
        seen: Set[str] = set()

        for _ in range(MAX_PAGES):
            body = self._post("/v1/query", payload)
            records = body.get("vulns")
            if records is None:
                records = []
            if not isinstance(records, list):
                raise OsvError("OSV returned a vulnerability list in an unexpected format")
            for record in records:
                vuln = parse_vulnerability(record, name, ecosystem)
                if vuln is not None and vuln.id not in seen:
                    seen.add(vuln.id)
                    found.append(vuln)

            token = body.get("next_page_token")
            if not token:
                break
            if not isinstance(token, str):
                raise OsvError("OSV returned an invalid page token")
            payload = {**payload, "page_token": token}
        else:
            raise OsvError(f"OSV returned more than {MAX_PAGES} pages of results; giving up")

        self._cache[key] = tuple(found)
        return found

    # ------------------------------------------------------------ HTTP details

    def _post(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        request = urllib.request.Request(
            self._base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"valtrix/{__version__}",
            },
        )
        attempts = self._max_retries + 1
        last_problem = "unknown error"

        for attempt in range(attempts):
            retry_after: Optional[float] = None
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
            except urllib.error.HTTPError as exc:
                try:
                    snippet = _text(exc.read(300).decode("utf-8", "replace"), 200)
                except Exception:
                    snippet = ""
                finally:
                    exc.close()
                if exc.code in RETRYABLE_STATUS:
                    last_problem = f"OSV returned HTTP {exc.code}"
                    retry_after = _parse_retry_after(exc.headers)
                else:
                    detail = f": {snippet}" if snippet else ""
                    raise OsvError(f"OSV rejected the request (HTTP {exc.code}){detail}") from exc
            except (OSError, http.client.HTTPException) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, ssl.SSLCertVerificationError):
                    raise OsvError(
                        "Could not verify OSV's security certificate, so the "
                        "connection was refused. Check your system clock, proxy, "
                        "or antivirus HTTPS scanning."
                    ) from exc
                last_problem = _describe(reason)
            else:
                return _decode(raw)

            if attempt < attempts - 1:
                delay = retry_after if retry_after is not None else self._backoff * (2 ** attempt)
                self._sleep(min(delay, MAX_DELAY_SECONDS))

        raise OsvError(
            f"Could not get an answer from OSV after {attempts} attempts ({last_problem}). "
            "Check your internet connection and try again."
        )


def _describe(reason: Any) -> str:
    if isinstance(reason, TimeoutError):
        return "the request timed out"
    text = str(reason).strip()
    return text or type(reason).__name__


def _parse_retry_after(headers: Any) -> Optional[float]:
    if headers is None:
        return None
    value = headers.get("Retry-After")
    if isinstance(value, str) and value.strip().isdigit():
        return float(value.strip())
    return None


def _decode(raw: bytes) -> Dict[str, Any]:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OsvError("OSV sent back a response that is too large to process")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise OsvError("OSV sent back a response that is not valid JSON") from exc
    if not isinstance(data, dict):
        raise OsvError("OSV sent back a response in an unexpected format")
    return data

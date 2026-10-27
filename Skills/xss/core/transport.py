"""
HTTP & Headless Browser transport layer for the XSS pipeline.

Provides a pooled, thread-safe `requests.Session` (with `curl` fallback),
automatic exponential backoff + jitter on 429/503 responses, raw HTTP header
parsing, and Playwright Chromium DOM rendering with sink/execution hooks.
"""
from __future__ import annotations

import re
import secrets
import subprocess
import time
import urllib.request
from typing import Any

from .constants import DEFAULT_UA, RENDER_HOOK_JS

try:
    import requests
    from requests.adapters import HTTPAdapter
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore[assignment]
    HTTPAdapter = None  # type: ignore[assignment,misc]

_HTTP_SESSION: Any = None
_HTTP_STATUS_RE = re.compile(r"HTTP/\S+\s+(\d+)")


def get_http_session() -> Any:
    """Return a shared `requests.Session` configured with connection pooling
    for both sequential probes and multi-threaded `--verify` waves."""
    global _HTTP_SESSION
    if _HTTP_SESSION is None and requests is not None:
        sess = requests.Session()
        sess.headers.update({"User-Agent": DEFAULT_UA})
        if HTTPAdapter is not None:
            adapter = HTTPAdapter(pool_connections=16, pool_maxsize=16)
            sess.mount("http://", adapter)
            sess.mount("https://", adapter)
        _HTTP_SESSION = sess
    return _HTTP_SESSION


def _backoff_sleep(attempt: int) -> None:
    delay = min(4.0, 0.3 * (2 ** attempt)) + (secrets.randbelow(200) / 1000.0)
    time.sleep(delay)


def parse_raw_http_response(raw: str) -> tuple[int, dict[str, str], str]:
    """Split `curl -i` output into `(status, headers_dict, body)`.
    Handles stacked HTTP header blocks (100-continue, redirects)."""
    status = 0
    headers: dict[str, str] = {}
    while raw.startswith("HTTP/"):
        _, _, rest = raw.partition("\n")
        m = _HTTP_STATUS_RE.match(raw)
        if m:
            status = int(m.group(1))
        head, sep, body = rest.partition("\r\n\r\n")
        if not sep:
            head, sep, body = rest.partition("\n\n")
        if not sep:
            break
        for hl in head.splitlines():
            k, _, v = hl.partition(":")
            if k.strip():
                headers[k.strip().lower()] = v.strip()
        raw = body
    return status, headers, raw


def _send_once(url: str, timeout: int = 10) -> tuple[str, str]:
    """Perform a single GET request preserving exact percent-encoding on the
    wire. Returns `(body, status_code_str)`."""
    sess = get_http_session()
    if sess is not None:
        try:
            req = requests.Request("GET", url)
            prep = sess.prepare_request(req)
            prep.url = url  # Preserve exact percent-encoding on the wire
            resp = sess.send(
                prep, verify=False, allow_redirects=False, timeout=timeout
            )
            return resp.text, str(resp.status_code)
        except Exception:
            pass
    try:
        result = subprocess.run(
            [
                "curl",
                "-s",
                "-k",
                "--max-time",
                str(timeout),
                "-A",
                DEFAULT_UA,
                "-w",
                "\n%{http_code}",
                url,
            ],
            capture_output=True,
            text=True,
        )
        body, sep, code = result.stdout.rpartition("\n")
        if not sep:
            return result.stdout, "000"
        return body, code.strip() or "000"
    except Exception as e:
        return f"[CURL_ERROR] {e}", "000"


def send_curl_meta(url: str, timeout: int = 10) -> tuple[str, str]:
    """Fetch `url` returning `(body, http_status)` with exponential backoff
    on transient 429/503 rate-limit responses."""
    body, status = _send_once(url, timeout=timeout)
    for attempt in range(3):
        if status not in ("429", "503"):
            break
        _backoff_sleep(attempt)
        body, status = _send_once(url, timeout=timeout)
    return body, status


def send_curl(url: str, timeout: int = 10) -> str:
    """Fetch `url` and return response body string."""
    return send_curl_meta(url, timeout=timeout)[0]


def send_verify_request(
    target_url: str, timeout: int = 15
) -> tuple[int, dict[str, str], str]:
    """Send a verification GET request preserving wire encoding and returning
    `(status_int, lowercase_headers_dict, body_str)`."""
    sess = get_http_session()
    if sess is not None:
        try:
            resp = None
            for attempt in range(4):
                req = requests.Request("GET", target_url)
                prep = sess.prepare_request(req)
                prep.url = target_url
                resp = sess.send(
                    prep, verify=False, allow_redirects=False, timeout=timeout
                )
                if resp.status_code not in (429, 503) or attempt == 3:
                    break
                _backoff_sleep(attempt)
            if resp is not None:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status_code, headers, resp.text
        except Exception:
            pass
    raw = subprocess.run(
        [
            "curl",
            "-s",
            "-k",
            "-i",
            "--max-time",
            str(timeout),
            "-A",
            DEFAULT_UA,
            target_url,
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 5,
    ).stdout
    return parse_raw_http_response(raw)


def fetch_url_with_base(url: str, timeout: int = 15) -> tuple[str, str]:
    """Fetch `url` following redirects (for surface discovery) and return
    `(decoded_body, final_url)`."""
    sess = get_http_session()
    if sess is not None:
        try:
            resp = sess.get(url, verify=False, timeout=timeout)
            return resp.text, str(resp.url or url)
        except Exception:
            pass
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", errors="replace")
        return body, r.url


def fetch_rendered(url: str, timeout_ms: int = 15000) -> tuple[str, dict[str, Any]]:
    """Render `url` in headless Chromium; return `(serialized_dom, meta)`.

    `meta = {"sinks": [[sink_name, raw_arg], ...], "fired": ["alert(1)", ...]}`
    Requires `playwright` + Chromium (`playwright install chromium`).
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.add_init_script(RENDER_HOOK_JS)
            page.goto(url, timeout=timeout_ms)
            page.wait_for_timeout(500)  # Let deferred/async sinks fire
            html = page.content()
            meta = page.evaluate(
                "({sinks: window.__sinks || [], fired: window.__fired || []})"
            )
        finally:
            browser.close()
    return html, meta

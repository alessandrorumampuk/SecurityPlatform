"""
HTTP & Headless Browser transport layer for the XSS pipeline.

Provides a pooled, thread-safe `requests.Session` (with `curl` fallback),
automatic exponential backoff + jitter on 429/503 responses, raw HTTP header
parsing, and Playwright Chromium DOM rendering with sink/execution hooks.
"""
from __future__ import annotations

import json
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any

from .constants import DEFAULT_UA, PLACEHOLDER, RENDER_HOOK_JS
from .types import RequestSpec

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


def expand_spec(
    spec: RequestSpec,
    payload: str,
    body_encode: str = "raw",
) -> tuple[str, str | None, dict[str, str]]:
    """Expand `spec` into `(url, data, headers)` with every `{xss_testing}`
    placeholder replaced by `payload`.

    Substitution rules:
      - URL: always percent-encoded (`urllib.parse.quote(safe="")`) — wire legality.
      - Body `data`: verbatim by default (curl `--data` semantics — the template
        is the wire byte); `body_encode="url"` applies the same quoting;
        `body_encode="json"` escapes the payload for embedding inside a JSON
        string literal (`json.dumps` minus the surrounding quotes).
      - Headers: verbatim.
    """
    url = spec.url.replace(PLACEHOLDER, urllib.parse.quote(payload, safe=""))
    data = spec.data
    if data is not None and PLACEHOLDER in data:
        if body_encode == "url":
            repl = urllib.parse.quote(payload, safe="")
        elif body_encode == "json":
            repl = json.dumps(payload)[1:-1]
        else:
            repl = payload
        data = data.replace(PLACEHOLDER, repl)
    headers = {
        k: v.replace(PLACEHOLDER, payload) for k, v in spec.headers.items()
    }
    return url, data, headers


def _send_once(
    url: str,
    timeout: int = 10,
    method: str = "GET",
    data: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Perform a single request preserving exact percent-encoding on the
    wire. Returns `(body, status_code_str)`."""
    sess = get_http_session()
    if sess is not None:
        try:
            req = requests.Request(method, url, data=data, headers=headers)
            prep = sess.prepare_request(req)
            prep.url = url  # Preserve exact percent-encoding on the wire
            resp = sess.send(
                prep, verify=False, allow_redirects=False, timeout=timeout
            )
            return resp.text, str(resp.status_code)
        except Exception:
            pass
    try:
        cmd = [
            "curl",
            "-s",
            "-k",
            "--max-time",
            str(timeout),
            "-A",
            DEFAULT_UA,
        ]
        for hk, hv in (headers or {}).items():
            cmd += ["-H", f"{hk}: {hv}"]
        if method.upper() == "HEAD":
            cmd.append("-I")
        elif method.upper() != "GET" or data is not None:
            cmd += ["-X", method.upper()]
        if data is not None:
            cmd += ["--data", data]
        cmd += ["-w", "\n%{http_code}", url]
        result = subprocess.run(cmd, capture_output=True, text=True)
        body, sep, code = result.stdout.rpartition("\n")
        if not sep:
            return result.stdout, "000"
        return body, code.strip() or "000"
    except Exception as e:
        return f"[CURL_ERROR] {e}", "000"


def send_spec(
    spec: RequestSpec,
    payload: str,
    timeout: int = 10,
    body_encode: str = "raw",
) -> tuple[str, str]:
    """Fill `spec` with `payload` and send it. Returns `(body, status_str)`."""
    url, data, headers = expand_spec(spec, payload, body_encode=body_encode)
    if spec.data is not None and data is not None:
        headers = dict(headers)
        headers.setdefault("Content-Type", spec.content_type)
    return send_curl_meta(
        url, timeout=timeout, method=spec.method, data=data, headers=headers
    )


def send_curl_meta(
    url: str,
    timeout: int = 10,
    method: str = "GET",
    data: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Fetch `url` returning `(body, http_status)` with exponential backoff
    on transient 429/503 rate-limit responses."""
    body, status = _send_once(
        url, timeout=timeout, method=method, data=data, headers=headers
    )
    for attempt in range(3):
        if status not in ("429", "503"):
            break
        _backoff_sleep(attempt)
        body, status = _send_once(
            url, timeout=timeout, method=method, data=data, headers=headers
        )
    return body, status


def send_curl(url: str, timeout: int = 10, **kw: Any) -> str:
    """Fetch `url` and return response body string."""
    return send_curl_meta(url, timeout=timeout, **kw)[0]


def send_verify_request(
    target_url: str,
    timeout: int = 15,
    method: str = "GET",
    data: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    """Send a verification request preserving wire encoding and returning
    `(status_int, lowercase_headers_dict, body_str)`."""
    sess = get_http_session()
    if sess is not None:
        try:
            resp = None
            for attempt in range(4):
                req = requests.Request(
                    method, target_url, data=data, headers=headers
                )
                prep = sess.prepare_request(req)
                prep.url = target_url
                resp = sess.send(
                    prep, verify=False, allow_redirects=False, timeout=timeout
                )
                if resp.status_code not in (429, 503) or attempt == 3:
                    break
                _backoff_sleep(attempt)
            if resp is not None:
                resp_headers = {
                    k.lower(): v for k, v in resp.headers.items()
                }
                return resp.status_code, resp_headers, resp.text
        except Exception:
            pass
    cmd = [
        "curl",
        "-s",
        "-k",
        "-i",
        "--max-time",
        str(timeout),
        "-A",
        DEFAULT_UA,
    ]
    for hk, hv in (headers or {}).items():
        cmd += ["-H", f"{hk}: {hv}"]
    if method.upper() == "HEAD":
        cmd.append("-I")
    elif method.upper() != "GET" or data is not None:
        cmd += ["-X", method.upper()]
    if data is not None:
        cmd += ["--data", data]
    cmd.append(target_url)
    raw = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout + 5,
    ).stdout
    return parse_raw_http_response(raw)


def send_verify_spec(
    spec: RequestSpec,
    payload: str,
    timeout: int = 15,
    body_encode: str = "raw",
) -> tuple[int, dict[str, str], str]:
    """Fill `spec` with `payload` and send it through `send_verify_request`,
    returning `(status_int, lowercase_headers_dict, body_str)`."""
    url, data, headers = expand_spec(spec, payload, body_encode=body_encode)
    if spec.data is not None and data is not None:
        headers = dict(headers)
        headers.setdefault("Content-Type", spec.content_type)
    return send_verify_request(
        url, timeout=timeout, method=spec.method, data=data, headers=headers
    )


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

#!/usr/bin/env python3
"""Probe a base URL for always-exposed sensitive paths (information disclosure).

This is the CLASS-B detector: files and endpoints that leak without needing
an error trigger -- .env, .git, actuator, phpinfo, backups, status pages.

For every path in the curated wordlist it records:
    - HTTP status (2xx = candidate leak, 401/403 = exists-but-protected)
    - content-type, body length, sha256
    - a truncated sample (first SAMPLE_BYTES) kept as evidence for
      check_leak.py -- full bodies are NOT stored

Result is saved as JSON next to the other skill logs via
``log_utils.new_log_path`` and consumed by ``check_leak.py``.

Usage:
    python3 probe_paths.py --url https://target.example
    python3 probe_paths.py --url https://target.example --delay 0.5 --out /tmp/p.json
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

SAMPLE_BYTES = 4096

# Curated disclosure wordlist, grouped by category.
PATHS = [
    # secrets / env / config
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old",
    "/.env.bak", "/env", "/env.js", "/config.php", "/wp-config.php",
    "/wp-config.php.bak", "/config.yml", "/config.json", "/settings.py",
    "/database.yml", "/secrets.yml", "/credentials.json", "/web.config",
    "/.htaccess", "/.htpasswd", "/.npmrc", "/.dockercfg", "/.aws/credentials",
    # version control
    "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore",
    "/.svn/entries", "/.hg/store/00manifest.i", "/.bzr/README", "/_git/HEAD",
    # backups / dumps
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip",
    "/config.php.bak", "/config.php~", "/index.php~", "/index.php.bak",
    # debug / profiling endpoints
    "/telescope", "/telescope/requests", "/_profiler", "/_profiler/empty/search/results",
    "/debug", "/_debug", "/console", "/phpinfo.php", "/phpinfo", "/info.php",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/actuator/mappings", "/actuator/configprops",
    "/_ignition/health-check", "/elmah.axd", "/debug/default/view",
    # status / monitoring
    "/server-status", "/server-info", "/nginx_status", "/status",
    "/health", "/metrics", "/prometheus",
    # API documentation / schema
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    # logs & misc
    "/storage/logs/laravel.log", "/logs/", "/log/", "/error.log",
    "/.DS_Store", "/crossdomain.xml", "/security.txt",
]


def probe(base: str, path: str, timeout: int = 10) -> dict:
    """GET base+path once; return a compact evidence record."""
    url = base.rstrip("/") + path
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                         allow_redirects=False, verify=False)
        return {
            "path": path,
            "status": r.status_code,
            "length": len(r.content),
            "content_type": r.headers.get("Content-Type", ""),
            "sample": (r.text or "")[:SAMPLE_BYTES],
            "sha256": hashlib.sha256(r.content).hexdigest(),
        }
    except Exception as e:
        return {"path": path, "status": 0, "error": str(e)[:120]}


def main() -> None:
    ap = argparse.ArgumentParser(description="Probe sensitive-path wordlist")
    ap.add_argument("--url", required=True, help="Base URL, e.g. https://target.example")
    ap.add_argument("--delay", type=float, default=0.3,
                    help="Seconds between requests (default 0.3)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--out", help="Output JSON path (default: log dir)")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()  # noqa
    base = args.url.rstrip("/")
    out = args.out or new_log_path("infoleak_probe", "json")

    results = []
    for path in PATHS:
        rec = probe(base, path, args.timeout)
        results.append(rec)
        mark = "◉" if 200 <= rec["status"] < 300 else ("▲" if rec["status"] in (401, 403) else "·")
        print(f"  {mark} {rec['status'] or 'ERR':>3} {path}")
        time.sleep(args.delay)

    payload = {
        "generated_by": "probe_paths.py",
        "target": base,
        "probed_at": datetime.now().isoformat(timespec="seconds"),
        "paths_tested": len(results),
        "hits": sum(1 for r in results if 200 <= r["status"] < 300),
        "results": results,
    }
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n💾 {out}")
    print(f"   {payload['hits']}/{len(results)} paths returned 2xx — run check_leak.py")


if __name__ == "__main__":
    main()

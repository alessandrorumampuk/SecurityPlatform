#!/usr/bin/env python3
"""
auto_hunt.py -- Automation mode for SecurityPlatform.

Unlike vvm.py there is no browser, no screenshot and no attack-surface
graph here: this orchestrator

    1. runs Skills/subdomain_finder/find_subdomains.py on the target's
       apex domain -> ONE JSON log holding every discovered subdomain,
    2. takes every host that resolves from that JSON (plus the submitted
       host itself) and
    3. runs the checked skill detectors on each host, bounded-parallel,
       until the list is exhausted.

Skills are subprocessed exactly like vvm.py does (same interpreter, the
skill dir as cwd) -- never imported -- and their own JSON/verdict output
decides findings. Progress is printed with vvm-style [skill] tags so
web.py can map lines to UI stages.

    python3 auto_hunt.py --url https://example.com --out auto.json
    python3 auto_hunt.py --url https://example.com --skills xss,csrf \
        --workers 3 --max-hosts 50

Local lab / authorized targets only.
"""
import argparse
import json
import re
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PLATFORM_DIR = Path(__file__).resolve().parent
SKILLS_DIR = PLATFORM_DIR / "Skills"
SKILL_LOG = PLATFORM_DIR / "log"
XSS_DIR = SKILLS_DIR / "xss"
INFOLEAK_DIR = SKILLS_DIR / "info_disclosure"
CSRF_DIR = SKILLS_DIR / "csrf"
BLH_DIR = SKILLS_DIR / "broken_link_hijacking"
DIRLIST_DIR = SKILLS_DIR / "directory_listing"
FINDER = SKILLS_DIR / "subdomain_finder" / "find_subdomains.py"

# Statuses meaning a BLH checker never actually evaluated the page
# (same convention as vvm.py / verify_tools.py).
_UNEVALUATED = {"CAPTCHA", "UNVERIFIABLE", "NoResponse", "Unknown"}

_BLH_CHECKERS = {"instagram.com": "instagram", "tiktok.com": "tiktok",
                 "youtube.com": "youtube", "youtu.be": "youtube",
                 "facebook.com": "facebook", "fb.com": "facebook"}

SKILL_IDS = ("xss", "info_disclosure", "csrf", "blh", "dirlist")

_PRINT_LOCK = threading.Lock()


def say(msg):
    with _PRINT_LOCK:
        print(msg, flush=True)


def _skill_run(script, *argv, timeout=180):
    """Run a skill script; return (combined_output, start_time, rc)."""
    t0 = time.time()
    try:
        p = subprocess.run(
            [sys.executable, str(script), *[str(a) for a in argv]],
            cwd=str(script.parent), capture_output=True, text=True,
            timeout=timeout, stdin=subprocess.DEVNULL)
        return (p.stdout or "") + (p.stderr or ""), t0, p.returncode
    except subprocess.TimeoutExpired:
        return f"[skill timeout after {timeout}s]", t0, 124
    except Exception as e:
        return f"[skill launch error: {e}]", t0, 1


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8",
                                               errors="replace"))
    except Exception:
        return None


def _log_since(prefix, t0):
    """Load newest SecurityPlatform/log/*-<prefix>.json written after t0."""
    newest, best = None, t0 - 1.5
    try:
        for f in SKILL_LOG.glob(f"*-{prefix}.json"):
            if f.stat().st_mtime >= best:
                newest, best = f, f.stat().st_mtime
    except OSError:
        return None
    if not newest:
        return None
    return _read_json(newest)


def _evaluated(res):
    st = str(res.get("status", ""))
    return st not in _UNEVALUATED and not st.startswith("Error")


# --------------------------------------------------------------------------
# Per-host skill chains (vvm.py hunt_* equivalents, minus the page graph --
# findings carry the host they came from instead of graph paths)
# --------------------------------------------------------------------------

def scan_infoleak(host, stem):
    """probe_paths + check_leak on the host origin."""
    origin = f"https://{host}"
    probe = stem + "-infoleak-probe.json"
    graded = stem + "-infoleak-findings.json"
    say(f"  [info_disclosure] probing {origin} (199 paths)...")
    _skill_run(INFOLEAK_DIR / "probe_paths.py",
               "--url", origin, "--out", probe, "--delay", "0.15",
               timeout=300)
    _skill_run(INFOLEAK_DIR / "check_leak.py",
               "--file", probe, "--out", graded, timeout=60)
    data = _read_json(graded)
    finds = []
    for f in (data or {}).get("findings", []):
        grade = f.get("grade", "")
        ev = " · ".join(f.get("evidence", [])[:4])
        secs = ", ".join(f.get("secrets_redacted", [])[:3])
        finds.append(dict(
            vuln="Information Disclosure",
            status="verified" if grade == "CONFIRMED" else "candidate",
            path=["page:" + origin],
            tool="info_disclosure",
            evidence=(f"GET {origin}{f.get('path')} -> {f.get('status')} "
                      f"[{grade}/{f.get('severity')}] {ev}"
                      + (f" secrets: {secs}" if secs else ""))))
    return finds


def scan_dirlist(host, stem):
    """directory_listing: probe listing-prone dirs, flag sensitive
    filenames (KTP/KK/NPWP/SIM/paspor/akta/BPJS/rekening/...) inside any
    open Index-of page."""
    origin = f"https://{host}"
    out = stem + "-dirlist.json"
    say(f"  [dirlist] probing {origin} for open directory listings...")
    _skill_run(DIRLIST_DIR / "directory_listing.py",
               "--url", origin, "--out", out, "--delay", "0.15",
               timeout=150)
    data = _read_json(out)
    finds = []
    for d in (data or {}).get("listings", []):
        sens = d.get("sensitive") or []
        sens_s = ", ".join(
            f"{s['name']} [{','.join(s['match'])}]" for s in sens[:5])
        finds.append(dict(
            vuln="Directory Listing",
            status="verified" if sens else "candidate",
            path=["page:" + origin],
            tool="dirlist",
            evidence=(f"{d.get('method', 'GET')} {d['url']} -> "
                      f"{d.get('status', 200)} Index-of "
                      f"({d.get('server') or 'server?'}); "
                      f"{d.get('file_count', 0)} entries"
                      + (f"; sensitive: {sens_s}" if sens_s else ""))))
    return finds


def scan_xss(host, stem, max_targets):
    """find_surface -> per-target payload/reflection/recommend chain."""
    origin = f"https://{host}"
    surf_j = stem + "-xss-surface.json"
    say("  [xss] discovering attack surface (skill find_surface.py)...")
    _skill_run(XSS_DIR / "find_surface.py", "--url", origin,
               "--out", surf_j, timeout=60)
    surf = _read_json(surf_j) or {}
    targets = [t["template"] for t in surf.get("targets", [])]

    finds = []
    for tpl in targets[:max_targets]:
        say(f"  [xss] pipeline on {tpl[:90]}")
        t0 = time.time()
        _skill_run(XSS_DIR / "send_payloads.py", "--url", tpl, "--probe2",
                   timeout=90)
        t_chk = time.time()
        _skill_run(XSS_DIR / "check_reflection.py", timeout=60)
        _skill_run(XSS_DIR / "check_reflection.py", "--keywords",
                   timeout=60)
        refl = _log_since("xss_reflection_analysis", t_chk)
        if not (refl or {}).get("results") or (refl or {}).get("dom_hint"):
            why = ("no server-side reflection"
                   if not (refl or {}).get("results")
                   else "location.* source -> DOM sink plumbing in page")
            say(f"    [xss] {why} -> render probe (DOM sinks)")
            _skill_run(XSS_DIR / "send_payloads.py", "--url", tpl,
                       "--probe2", "--render", timeout=150)
            _skill_run(XSS_DIR / "check_reflection.py", timeout=60)
            _skill_run(XSS_DIR / "check_reflection.py", "--keywords",
                       timeout=60)
        _skill_run(XSS_DIR / "recommend_payload.py", "--top", "3",
                   "--verify", "--url", tpl, timeout=240)
        rec = _log_since("xss_recommendation", t0)
        if not rec:
            continue
        for refl in rec.get("reflections", []):
            cands = refl.get("candidates", [])
            vers = refl.get("verification") or []
            param = urllib.parse.parse_qs(
                urllib.parse.urlsplit(tpl).query)
            pname = next((k for k, v in param.items()
                          if v and v[0] == "{xss_testing}"), "?")
            for v in vers:
                grade = v.get("confidence")
                if grade not in ("V", "R"):
                    continue
                finds.append(dict(
                    vuln="XSS",
                    status="verified" if grade == "V" else "candidate",
                    path=["page:" + origin, "param:" + pname],
                    tool="xss",
                    evidence=(f"[{grade}] {v.get('payload', '')} -- "
                              f"{(v.get('evidence') or '')[:110]}")))
            if not vers and cands:
                finds.append(dict(
                    vuln="XSS",
                    status="candidate",
                    path=["page:" + origin, "param:" + pname],
                    tool="xss",
                    evidence=(f"param {pname}: {len(cands)} unverified "
                              f"candidates, e.g. "
                              f"{cands[0].get('payload', '')[:80]}")))
    return finds


def scan_csrf(host, stem):
    """enumerate_forms -> check_csrf replay oracle."""
    origin = f"https://{host}"
    forms_j = stem + "-csrf-forms.json"
    finds_j = stem + "-csrf-findings.json"
    say("  [csrf] enumerating forms...")
    _skill_run(CSRF_DIR / "enumerate_forms.py",
               "--url", origin, "--out", forms_j, timeout=60)
    say("  [csrf] replay oracle (writes state on the target)")
    _skill_run(CSRF_DIR / "check_csrf.py",
               "--file", forms_j, "--out", finds_j, "--delay", "0.15",
               timeout=180)
    data = _read_json(finds_j)
    finds = []
    for f in (data or {}).get("findings", []):
        if f.get("grade") in ("DEFENDED", "SKIPPED"):
            continue
        finds.append(dict(
            vuln="CSRF",
            status="verified" if f.get("grade") == "CONFIRMED"
            else "candidate",
            path=["page:" + origin],
            tool="csrf",
            evidence=f"{f.get('action')} -- {f.get('evidence', '')}"))
    return finds


def scan_blh(host, stem, max_pages):
    """social_media_crawler mines social links on the host; findings
    are the discovered links themselves (no platform checkers run)."""
    origin = f"https://{host}/"
    crawl_j = stem + "-blh-social.json"
    say(f"  [blh] mining social links on {origin} "
        f"(max {max_pages} pages)...")
    _skill_run(BLH_DIR / "social_media_crawler.py",
               "--url", origin, "--max-pages", str(max_pages),
               "--no-enumerate", "--output", crawl_j, timeout=300)
    data = _read_json(crawl_j) or {}

    finds, done = [], set()
    for platform, entries in (data.get("social_media") or {}).items():
        for e in entries:
            url = e.get("url", "") if isinstance(e, dict) else str(e)
            if not url or url in done:
                continue
            done.add(url)
            finds.append(dict(
                vuln="Broken Link Hijacking", status="candidate",
                path=["page:" + origin], tool="broken_link_hijacking",
                evidence=f"{url} -- {platform} link found"))
    return finds


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def enumerate_subdomains(host, out_json):
    """Run find_subdomains.py; return (parsed_payload, log_tail)."""
    say("[subdomain] enumerating subdomains via find_subdomains.py "
        "(axfr + scrape + ct + mutation)...")
    argv = [sys.executable, "-u", str(FINDER),
            "--domain", host, "--apex", "--ct", "--no-probe",
            "--no-bruteforce",
            "--out", str(out_json)]
    try:
        p = subprocess.run(argv, cwd=str(FINDER.parent),
                           capture_output=True, text=True, timeout=900,
                           stdin=subprocess.DEVNULL)
        log = ((p.stdout or "") + (p.stderr or ""))[-3000:]
    except subprocess.TimeoutExpired:
        return None, "[subdomain finder timed out after 900s]"
    except Exception as e:
        return None, f"[subdomain finder launch error: {e}]"
    return _read_json(out_json), log


def main():
    ap = argparse.ArgumentParser(
        description="Automation mode: enumerate *.domain then run the "
                    "checked skill detectors on every resolving host. "
                    "No VVM browser/graph stage.")
    ap.add_argument("--url", required=True,
                    help="Target URL (apex is derived from its host)")
    ap.add_argument("--skills", default="",
                    help="Comma subset: xss, info_disclosure, csrf, blh, "
                         "dirlist (default: all five)")
    ap.add_argument("--workers", type=int, default=3,
                    help="Concurrent hosts being scanned (default 3)")
    ap.add_argument("--max-hosts", type=int, default=0,
                    help="Cap on hosts scanned (0 = all discovered)")
    ap.add_argument("--max-xss", type=int, default=3,
                    help="Max parameterized URLs per host for the xss "
                         "pipeline (default 3)")
    ap.add_argument("--blh-pages", type=int, default=8,
                    help="Pages social_media_crawler may visit per host "
                         "when mining social links (default 8)")
    ap.add_argument("--out", required=True, help="Aggregate results JSON")
    args = ap.parse_args()

    host = urllib.parse.urlsplit(args.url).hostname
    if not host:
        raise SystemExit(f"[!] cannot parse host from {args.url!r}")
    sel = [s.strip() for s in args.skills.split(",") if s.strip()]
    only = [s for s in sel if s in SKILL_IDS] or list(SKILL_IDS)
    bad = [s for s in sel if s not in SKILL_IDS]
    if bad:
        print(f"[!] unknown skill(s): {', '.join(bad)} "
              f"(valid: {', '.join(SKILL_IDS)})")

    out_path = Path(args.out).resolve()
    stem = str(out_path)[:-5] if str(out_path).endswith(".json") \
        else str(out_path)
    t0 = time.time()

    # -- blh-only fast path: social_media_crawler already enumerates
    #    subdomains itself via crt.sh, so find_subdomains would only
    #    duplicate the work. Run it once, as-is, on the start URL.
    if set(only) == {"blh"}:
        crawl_j = stem + "-blh-social.json"
        say(f"[auto] blh only -> crawler enumerates + mines {host} itself")

        def blh_partial(final=False):
            """Merge the crawler's own autosave into the aggregate JSON so
            the UI shows pages/links while the crawl is still running."""
            data = _read_json(crawl_j) or {}
            finds, seen = [], set()
            host_pages = {host: 0}
            for platform, entries in \
                    (data.get("social_media") or {}).items():
                for e in entries:
                    url = e.get("url", "") if isinstance(e, dict) else str(e)
                    on = (e.get("found_on") or []
                          if isinstance(e, dict) else [])
                    for p in on:
                        h = urllib.parse.urlsplit(p).hostname
                        if h:
                            host_pages[h] = host_pages.get(h, 0) + 1
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    h0 = (urllib.parse.urlsplit(on[0]).hostname
                          if on else host) or host
                    finds.append(dict(
                        vuln="Broken Link Hijacking", status="candidate",
                        path=["page:" + h0], tool="broken_link_hijacking",
                        host=h0,
                        evidence=f"{url} -- {platform} link found"))
            st = "done" if final else "running"
            targets = [{"host": h, "status": st, "verified": 0,
                        "findings": sum(1 for f in finds
                                        if f["host"] == h)}
                       for h in sorted(host_pages)]
            doc = {
                "generated_by": "auto_hunt.py", "url": args.url,
                "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "skills": only,
                "subdomains_discovered": len(host_pages) - 1,
                "hosts_scanned": len(targets),
                "pages_crawled": data.get("pages_crawled", 0),
                "elapsed_s": int(time.time() - t0),
                "targets": targets, "findings": finds,
                "blh_log": crawl_j}
            if not final:
                doc["partial"] = True
            out_path.write_text(json.dumps(doc, indent=2))
            return finds, targets

        blh_partial()   # placeholder targets=running, findings=[]

        # Poll the crawler's autosave file while it runs -- it writes every
        # 10 pages, so the UI gets a fresh snapshot without waiting for
        # the (potentially very long) full crawl to finish.
        proc = subprocess.Popen(
            [sys.executable, "-u",
             str(BLH_DIR / "social_media_crawler.py"),
             "--url", args.url, "--output", crawl_j],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            text=True)
        try:
            while proc.poll() is None:
                time.sleep(15)
                try:
                    blh_partial()
                except Exception:
                    pass
        except KeyboardInterrupt:
            proc.terminate()
            raise
        blh_partial(final=True)
        say(f"[auto] done -> {out_path} "
            f"(crawler finished, exit={proc.returncode})")
        return

    # -- Phase 1: subdomain_finder -> one JSON log -------------------------
    sub_json = stem + "-subdomains.json"
    payload, flog = enumerate_subdomains(host, sub_json)
    records = (payload or {}).get("subdomains") or []
    live = sorted({r["host"] for r in records
                   if r.get("resolves") and r.get("host")})
    hosts = [host] + [h for h in live if h != host]
    if args.max_hosts > 0:
        hosts = hosts[:args.max_hosts]
    say(f"[auto] {len(hosts)} resolving host(s) to scan "
        f"({len(records)} discovered); skills: {', '.join(only)}")
    if not hosts:
        out_path.write_text(json.dumps({
            "generated_by": "auto_hunt.py", "url": args.url,
            "subdomains_json": sub_json, "targets": [], "findings": [],
            "error": "subdomain finder produced no resolvable hosts",
            "finder_log": flog}, indent=2))
        return

    # -- Phase 2: every checked skill on every host ------------------------
    targets = [{"host": h, "status": "pending", "verified": 0,
                "findings": 0} for h in hosts]
    all_finds = []
    lock, done = threading.Lock(), [0]

    def write_partial():
        """Flush a live snapshot so the web UI can show hosts/findings
        while the scan is still running."""
        try:
            live, seen = [], set()
            for f in all_finds:
                k = (f.get("host"), f.get("vuln"), f.get("evidence"))
                if k in seen:
                    continue
                seen.add(k)
                live.append(f)
            out_path.write_text(json.dumps({
                "generated_by": "auto_hunt.py", "url": args.url,
                "partial": True, "skills": only,
                "subdomains_json": sub_json,
                "subdomains_discovered": len(records),
                "hosts_scanned": len(hosts),
                "targets": [dict(t) for t in targets],
                "findings": live}, indent=2))
        except Exception:
            pass

    def scan_host(idx, h):
        with lock:
            targets[idx]["status"] = "running"
        say(f"[auto] host {idx + 1}/{len(hosts)}: {h}")
        host_stem = f"{stem}-{idx:03d}"
        host_finds = []

        def flush(skill_finds):
            """Publish one skill's findings immediately -- the partial
            file refreshes per skill, not only per host."""
            for f in skill_finds:
                f["host"] = h
            host_finds.extend(skill_finds)
            with lock:
                all_finds.extend(skill_finds)
                targets[idx].update(
                    verified=sum(1 for f in host_finds
                                 if f["status"] == "verified"),
                    findings=len(host_finds))
                write_partial()

        try:
            if "info_disclosure" in only:
                flush(scan_infoleak(h, host_stem))
            if "dirlist" in only:
                flush(scan_dirlist(h, host_stem))
            if "xss" in only:
                flush(scan_xss(h, host_stem, args.max_xss))
            if "csrf" in only:
                flush(scan_csrf(h, host_stem))
            if "blh" in only:
                flush(scan_blh(h, host_stem, args.blh_pages))
        except Exception as e:
            say(f"  [auto] {h} scan error: {e}")
        ver = sum(1 for f in host_finds if f["status"] == "verified")
        with lock:
            targets[idx].update(status="done", verified=ver,
                                findings=len(host_finds))
            done[0] += 1
            say(f"[auto] {done[0]}/{len(hosts)} done -- {h} "
                f"({ver} verified, {len(host_finds)} total findings)")
            write_partial()

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        list(ex.map(lambda ih: scan_host(*ih), enumerate(hosts)))

    # dedupe across hosts by (host, vuln, evidence)
    uniq, seen = [], set()
    for f in all_finds:
        k = (f.get("host"), f.get("vuln"), f.get("evidence"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    uniq.sort(key=lambda f: (f.get("status") != "verified",
                             f.get("host") or ""))

    out_path.write_text(json.dumps({
        "generated_by": "auto_hunt.py",
        "url": args.url,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "skills": only,
        "subdomains_json": sub_json,
        "subdomains_discovered": len(records),
        "hosts_scanned": len(hosts),
        "elapsed_s": int(time.time() - t0),
        "targets": targets,
        "findings": uniq,
        "finder_log": flog[-2000:] if flog else "",
    }, indent=2))
    say(f"[auto] done -> {out_path} "
        f"({len(uniq)} findings over {len(hosts)} hosts)")


if __name__ == "__main__":
    main()

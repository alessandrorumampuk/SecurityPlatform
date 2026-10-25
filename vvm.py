#!/usr/bin/env python3
"""
VVM - Visual Vulnerability Mapping

Takes a URL, screenshots the page, and annotates visible UI elements as
potential vulnerability entry points, as described in the VVM + AVM + AI
white paper. For each annotated element it prints a table of possible
vulnerabilities.

Rule-based only. No AI calls, no requests beyond loading the page once.
Use only on sites you own or are authorized to test.

Usage:
    python3 vvm.py https://alessandrorumampuk.com/
    python3 vvm.py https://example.com -o out.png --report report.md
    python3 vvm.py https://example.com --hunt   # run the four skill detectors
"""

import argparse
import hashlib
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Rules: element selector signature -> (label, vulns)
# Scope is restricted to the four supported detector classes:
#   XSS, Information Disclosure, CSRF, Broken Link Hijacking.
# Elements outside that scope still get mapped (attack surface) but carry
# no vulnerability label (empty list).
# ---------------------------------------------------------------------------

RULES = [
    dict(kind="search",
         label="Search input",
         vulns=["XSS", "Information Disclosure"]),
    dict(kind="login",
         label="Login / password field",
         vulns=["CSRF", "Information Disclosure"]),
    dict(kind="file",
         label="File upload",
         vulns=["XSS"]),
    dict(kind="comment",
         label="Comment / text area",
         vulns=["XSS"]),
    dict(kind="form",
         label="Form",
         vulns=["CSRF"]),
    dict(kind="urlparam",
         label="URL parameter (page URL)",
         vulns=["XSS", "Information Disclosure"]),
    dict(kind="paramlink",
         label="Link with query parameters",
         vulns=["XSS", "Information Disclosure"]),
    dict(kind="sociallink",
         label="Social media link (BLH scope)",
         vulns=["Broken Link Hijacking"]),
    dict(kind="blanklink",
         label="target=_blank link",
         vulns=[]),
    dict(kind="iframe",
         label="iframe",
         vulns=[]),
    dict(kind="hidden",
         label="Hidden input",
         vulns=["CSRF"]),
    dict(kind="editable",
         label="Editable content",
         vulns=["XSS"]),
    dict(kind="weblink",
         label="Network (external link)",
         vulns=[]),
]

JS_COLLECT = r"""
() => {
    const seen = new Set();
    const els = [];
    const add = (el, kind, extra) => {
        const r = el.getBoundingClientRect();
        if (!r.width || !r.height || r.width < 8 || r.height < 8) return;
        const key = kind + '|' + Math.round(r.x) + '|' + Math.round(r.y) + '|' + Math.round(r.width);
        if (seen.has(key)) return;
        seen.add(key);
        const docTop = r.top + window.scrollY, docLeft = r.left + window.scrollX;
        if (docTop > 20000) return;  // cap absurdly tall pages
        els.push(Object.assign({ kind, x: docLeft, y: docTop, w: r.width, h: r.height,
                   desc: el.getAttribute('aria-label') || el.getAttribute('placeholder')
                      || el.getAttribute('name') || el.getAttribute('id')
                      || (el.textContent || '').trim().slice(0, 40)
                      || el.getAttribute('href') || '' }, extra || {}));
    };

    const fieldInfo = el => ({ pname: el.name || '',
        faction: el.form ? el.form.action : '',
        fmethod: el.form ? (el.form.method || 'get').toLowerCase() : '' });
    document.querySelectorAll('input').forEach(el => {
        const t = (el.type || 'text').toLowerCase();
        const hint = ((el.name||'') + ' ' + (el.id||'') + ' ' + (el.placeholder||'')).toLowerCase();
        const fi = fieldInfo(el);
        if (t === 'hidden')            add(el, 'hidden', fi);
        else if (t === 'password')     add(el, 'login', fi);
        else if (t === 'file')         add(el, 'file', fi);
        else if (t === 'search' || /search|cari|q\b/.test(hint)) add(el, 'search', fi);
        else if (/login|signin|user|email|pass/.test(hint))      add(el, 'login', fi);
        else                           add(el, 'form', fi);
    });
    document.querySelectorAll('textarea').forEach(el => add(el, 'comment', fieldInfo(el)));
    document.querySelectorAll('form').forEach(el => {
        const hasPwd = !!el.querySelector('input[type=password]');
        add(el, hasPwd ? 'login' : 'form', {
            action: el.action || '',
            method: (el.method || 'get').toLowerCase(),
            inputs: Array.from(el.querySelectorAll('input,textarea'))
                .filter(i => (i.type || 'text').toLowerCase() !== 'hidden')
                .map(i => i.name).filter(Boolean)
        });
    });
    document.querySelectorAll('iframe').forEach(el => add(el, 'iframe'));
    document.querySelectorAll('[contenteditable="true"]').forEach(el => add(el, 'editable'));

    const host = location.hostname;
    document.querySelectorAll('a[href]').forEach(el => {
        const href = el.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
        let u; try { u = new URL(href, location.href); } catch(e) { return; }
        const social = /(^|\.)((facebook|fb|instagram|twitter|x|youtube|youtu|tiktok|telegram|linkedin)\.(com|me|be|net|org)|t\.me)$/.test(u.hostname);
        const link = { href: u.href, hrefHost: u.hostname,
                       rel: el.getAttribute('rel') || '',
                       params: Array.from(u.searchParams.keys()) };
        if (u.search && u.search.length > 1)          add(el, 'paramlink', link);
        else if (u.hostname !== host)                  add(el, social ? 'sociallink' : 'weblink', link);
        if (el.target === '_blank')                    add(el, 'blanklink', link);
    });

    const pageParams = Array.from(new URL(location.href).searchParams.keys());
    return { els, url: location.href, pageParams,
             vh: window.innerHeight, scrollY: window.scrollY,
             height: document.documentElement.scrollHeight };
}
"""


def load_font(size):
    for p in ["/System/Library/Fonts/Helvetica.ttc",
              "/System/Library/Fonts/SFNSMono.ttf",
              "/Library/Fonts/Arial.ttf"]:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


def annotate(img, findings, el_vulns=None, show_all=False, banner=None):
    """Annotate the screenshot.

    Default: only elements tied to VERIFIED findings get a red box +
    "VERIFIED:" badge; verified findings with no on-page element (URL
    params, exposed paths) are listed in a banner strip on top.
    show_all=True restores the old behaviour (every mapped element boxed,
    candidates in gray).
    """
    img = img.convert("RGBA")
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    font = load_font(16)

    if banner:
        lines = ["VERIFIED VULNERABILITIES"] + banner
        bh = len(lines) * 20 + 12
        d.rectangle([0, 0, img.width, bh], fill=(140, 10, 10, 235))
        for i, ln in enumerate(lines):
            d.text((8, 6 + i * 20), ln, fill="white", font=font)

    # Same physical element can be mapped as several nodes (e.g. an anchor
    # that is both sociallink and blanklink) -- merge overlapping verified
    # boxes so one link gets one badge, not one badge per node kind.
    def _intersects(a, b):
        return not (a[2] < b[0] or a[0] > b[2] or a[3] < b[1] or a[1] > b[3])

    groups = []   # [box, set(vulns)]
    for i, f in enumerate(findings, 1):
        ver = (el_vulns or {}).get(i)
        if not ver:
            continue
        box = [f["x"], f["y"], f["x"] + f["w"], f["y"] + f["h"]]
        for g in groups:
            if _intersects(g[0], box):
                g[0] = [min(g[0][0], box[0]), min(g[0][1], box[1]),
                        max(g[0][2], box[2]), max(g[0][3], box[3])]
                g[1].update(ver)
                break
        else:
            groups.append([box, set(ver)])

    badge_rects = []

    def _overlaps(r):
        return any(_intersects(r, o) for o in badge_rects)

    def draw_verified(box, ver):
        pad = 4
        box = [box[0] - pad, box[1] - pad, box[2] + pad, box[3] + pad]
        d.rectangle(box, outline=(220, 40, 40, 255), width=3)
        d.rectangle(box, fill=(220, 40, 40, 30))
        label = "VERIFIED: " + ", ".join(sorted(ver))
        tb = d.textbbox((0, 0), label, font=font)
        bw, bh2 = tb[2] - tb[0] + 10, tb[3] - tb[1] + 8
        bx = box[0]
        slots = [max(0, box[1] - bh2 - 2)] + \
                [box[3] + 2 + k * (bh2 + 2) for k in range(4)]
        for by in slots:
            if not _overlaps([bx, by, bx + bw, by + bh2]):
                break
        d.rectangle([bx, by, bx + bw, by + bh2], fill=(220, 40, 40, 235))
        badge_rects.append([bx, by, bx + bw, by + bh2])
        d.text((bx + 5, by + 4), label, fill="white", font=font)

    for box, ver in groups:
        draw_verified(box, ver)

    if show_all:
        for f in findings:
            box = [f["x"], f["y"], f["x"] + f["w"], f["y"] + f["h"]]
            if any(_intersects(box, g[0]) for g in groups):
                continue
            d.rectangle(box, outline=(140, 140, 140, 255), width=1)
            label = ", ".join(f["rule"]["vulns"])
            tb = d.textbbox((0, 0), label, font=font)
            bw, bh2 = tb[2] - tb[0] + 10, tb[3] - tb[1] + 8
            bx, by = box[0], max(0, box[1] - bh2 - 2)
            d.rectangle([bx, by, bx + bw, by + bh2], fill=(140, 140, 140, 235))
            d.text((bx + 5, by + 4), label, fill="white", font=font)
    return Image.alpha_composite(img, overlay).convert("RGB")


def _resolve_path_els(graph, path):
    """Node ids in a finding path -> owning el indices (has_param /
    points_to resolution), so verified findings land on real elements."""
    edges = graph["edges"]
    owners = {}
    for e in edges:
        if e["type"] in ("has_param", "points_to"):
            owners.setdefault(e["dst"], []).append(e["src"])
    els = set()
    for nid in path:
        for cid in [nid] + owners.get(nid, []):
            if cid.startswith("el:"):
                els.add(int(cid.split(":")[1]))
    return els


def verified_element_vulns(graph):
    """el_index -> set of verified vuln names, resolved through paths."""
    el_v = {}
    for f in graph.get("findings", []):
        if f["status"] != "verified":
            continue
        for i in _resolve_path_els(graph, f.get("path", [])):
            el_v.setdefault(i, set()).add(f["vuln"])
    return el_v


def build_report(url, findings):
    lines = [f"# VVM Report", "", f"**URL:** {url}", "",
             "| # | Element | Possible vulnerabilities |",
             "|---|---|---|"]
    seen_rules = {}
    for i, f in enumerate(findings, 1):
        r = f["rule"]
        seen_rules[f["kind"]] = r
        desc = f' — "{f["desc"]}"' if f.get("desc") else ""
        lines.append(
            f"| {i} | {r['label']}{desc} | {', '.join(r['vulns'])} |")
    lines += ["", "_Use only on sites you own or are authorized to test._"]
    return "\n".join(lines)


def build_graph(data, findings, shot_name, rule_by_kind):
    """Assemble nodes+edges from collected elements.

    Nodes: Page, Element (with screenshot provenance), Domain, Endpoint,
    Parameter. Edges: hosts, points_to, submits_to, has_param, flows_to.
    """
    nodes, edges, seen = {}, [], set()

    def node(nid, **props):
        nodes.setdefault(nid, dict(id=nid, **props))

    def edge(src, dst, typ, **props):
        if (src, dst, typ) in seen:
            return
        seen.add((src, dst, typ))
        edges.append(dict(src=src, dst=dst, type=typ, **props))

    page_id = "page:" + data["url"]
    node(page_id, type="Page", url=data["url"])

    for i, f in enumerate(findings, 1):
        eid = f"el:{i}"
        node(eid, type="Element", kind=f["kind"], label=f["rule"]["label"],
             desc=f.get("desc", ""), vulns=f["rule"]["vulns"],
             prov=dict(screenshot=shot_name,
                       bbox=[f["x"], f["y"], f["w"], f["h"]]))
        edge(page_id, eid, "hosts")

        host = f.get("hrefHost")
        if host:
            did = "dom:" + host
            node(did, type="Domain", host=host)
            edge(eid, did, "points_to", href=f.get("href", ""))

        action = f.get("action")
        if action:
            base = action.split("?")[0]
            epid = "ep:" + base
            node(epid, type="Endpoint", url=base)
            edge(eid, epid, "submits_to")

        for pname in f.get("params") or []:
            pid = "param:" + pname
            node(pid, type="Parameter", name=pname,
                 vulns=rule_by_kind["paramlink"]["vulns"])
            edge(eid, pid, "has_param")
            if f.get("href"):
                base = f["href"].split("?")[0]
                epid = "ep:" + base
                node(epid, type="Endpoint", url=base)
                edge(pid, epid, "flows_to")

        # GET-form fields become URL params when submitted -- link the
        # element to its param node so findings resolve onto the field.
        field_names = list(f.get("inputs") or [])
        if f.get("pname"):
            field_names.append(f["pname"])
        is_get = (f.get("method") == "get"
                  or f.get("fmethod") == "get")
        if is_get:
            for pname in field_names:
                pid = "param:" + pname
                node(pid, type="Parameter", name=pname,
                     vulns=rule_by_kind["urlparam"]["vulns"])
                edge(eid, pid, "has_param")
                act = f.get("action") or f.get("faction")
                if act:
                    epid = "ep:" + act.split("?")[0]
                    node(epid, type="Endpoint", url=act.split("?")[0])
                    edge(pid, epid, "flows_to")

    for pname in data.get("pageParams") or []:
        pid = "param:" + pname
        node(pid, type="Parameter", name=pname,
             vulns=rule_by_kind["urlparam"]["vulns"])
        edge(page_id, pid, "has_param", via="page URL")

    return dict(meta=dict(url=data["url"], elements=len(findings)),
                nodes=list(nodes.values()), edges=edges)


SEC_HEADERS = ["content-security-policy", "x-frame-options",
               "strict-transport-security", "x-content-type-options",
               "referrer-policy", "permissions-policy"]


def _gnode(graph, nid, **props):
    for n in graph["nodes"]:
        if n["id"] == nid:
            return
    graph["nodes"].append(dict(id=nid, **props))


def _gedge(graph, src, dst, typ, **props):
    for e in graph["edges"]:
        if e["src"] == src and e["dst"] == dst and e["type"] == typ:
            return
    graph["edges"].append(dict(src=src, dst=dst, type=typ, **props))


def merge_passive(graph, passive):
    """Fold passive response facts (headers, TLS, cookies, DNS) into graph."""
    page = next(n for n in graph["nodes"] if n["type"] == "Page")
    hdrs = {k.lower(): v for k, v in (passive.get("headers") or {}).items()}
    page["http_status"] = passive.get("status")
    page["headers"] = {h: hdrs[h] for h in SEC_HEADERS if h in hdrs}
    page["missing_headers"] = [h for h in SEC_HEADERS if h not in hdrs]

    tls = passive.get("tls")
    if tls:
        cid = "cert:" + (tls.get("subjectName") or page["id"])
        _gnode(graph, cid, type="Certificate", **tls)
        _gedge(graph, page["id"], cid, "secured_by")

    for c in passive.get("cookies") or []:
        missing = []
        if not c.get("secure"):
            missing.append("Secure")
        if not c.get("httpOnly"):
            missing.append("HttpOnly")
        if c.get("sameSite") in (None, "", "None"):
            missing.append("SameSite")
        cid = "cookie:" + c["name"]
        _gnode(graph, cid, type="Cookie", name=c["name"],
               domain=c.get("domain"), missing_flags=missing)
        _gedge(graph, page["id"], cid, "sets_cookie")

    host = passive.get("host")
    if host:
        did = "dom:" + host
        _gnode(graph, did, type="Domain", host=host)
        _gedge(graph, page["id"], did, "hosted_on")
        for ip in passive.get("ips") or []:
            iid = "ip:" + ip
            _gnode(graph, iid, type="IP", addr=ip)
            _gedge(graph, did, iid, "resolves_to")


def dedupe_findings(finds):
    """Dedupe by (vuln, evidence), merging element paths."""
    uniq = {}
    for f in finds:
        k = (f["vuln"], f["evidence"])
        if k in uniq:
            uniq[k]["path"] += [x for x in f["path"]
                                if x not in uniq[k]["path"]]
        else:
            uniq[k] = f
    return list(uniq.values())


# ---------------------------------------------------------------------------
# Skill orchestration (--hunt)
#
# The four deterministic detectors under SecurityPlatform/Skills are run as
# subprocesses exactly as they would be from the CLI (same interpreter, the
# skill dir as cwd). Skills are never imported or modified -- vvm only
# consumes their JSON output and folds CONFIRMED/verified results into the
# graph findings. A skill result only upgrades to "verified" through the
# tool's own oracle: a DOM marker grade V, a CONFIRMED signature+format hit,
# or an evaluated not-found profile check.
# ---------------------------------------------------------------------------

PLATFORM_DIR = Path(__file__).resolve().parent
SKILLS_DIR = PLATFORM_DIR / "Skills"
SKILL_LOG = PLATFORM_DIR / "log"
XSS_DIR = SKILLS_DIR / "xss"
INFOLEAK_DIR = SKILLS_DIR / "info_disclosure"
CSRF_DIR = SKILLS_DIR / "csrf"
BLH_DIR = SKILLS_DIR / "broken_link_hijacking"
DIRLIST_DIR = SKILLS_DIR / "directory_listing"

# Statuses meaning a BLH checker never actually evaluated the page
# (same convention as verify_tools.py -- an error/captcha is not a
# not-found answer).
_UNEVALUATED = {"CAPTCHA", "UNVERIFIABLE", "NoResponse", "Unknown"}


def _skill_run(script, *argv, timeout=180):
    """Run a skill script; return (combined_output, start_time, returncode)."""
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


def _log_since(prefix, t0):
    """Load newest SecurityPlatform/log/*-<prefix>.json written after t0 (or None)."""
    newest, best = None, t0 - 1.5
    try:
        for f in SKILL_LOG.glob(f"*-{prefix}.json"):
            if f.stat().st_mtime >= best:
                newest, best = f, f.stat().st_mtime
    except OSError:
        return None
    if not newest:
        return None
    try:
        return json.loads(newest.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _evaluated(res):
    st = str(res.get("status", ""))
    return st not in _UNEVALUATED and not st.startswith("Error")


def hunt_infoleak(page_url, stem):
    """Run probe_paths + check_leak on the origin; trigger_errors on the
    page URL when it carries query params. Returns finding dicts."""
    u = urllib.parse.urlsplit(page_url)
    origin = f"{u.scheme}://{u.netloc}"
    finds = []

    probe = stem + "-infoleak-probe.json"
    graded = stem + "-infoleak-findings.json"
    print(f"  [info_disclosure] probing {origin} (199 paths)...")
    _skill_run(INFOLEAK_DIR / "probe_paths.py",
               "--url", origin, "--out", probe, "--delay", "0.15",
               timeout=300)
    _skill_run(INFOLEAK_DIR / "check_leak.py",
               "--file", probe, "--out", graded, timeout=60)
    data = _read_json(graded)
    for f in (data or {}).get("findings", []):
        grade = f.get("grade", "")
        ev = " · ".join(f.get("evidence", [])[:4])
        secs = ", ".join(f.get("secrets_redacted", [])[:3])
        finds.append(dict(
            vuln="Information Disclosure",
            status="verified" if grade == "CONFIRMED" else "candidate",
            path=["page:" + page_url],
            tool="info_disclosure",
            evidence=(f"GET {origin}{f.get('path')} -> {f.get('status')} "
                      f"[{grade}/{f.get('severity')}] {ev}"
                      + (f" secrets: {secs}" if secs else ""))))

    if u.query:
        errs = stem + "-infoleak-errors.json"
        print("  [info_disclosure] error-trigger probe on page params...")
        _skill_run(INFOLEAK_DIR / "trigger_errors.py",
                   "--url", page_url, "--out", errs, "--delay", "0.15",
                   timeout=120)
        edata = _read_json(errs)
        for f in (edata or {}).get("findings", []):
            grade = f.get("grade", "")
            sigs = ",".join(f.get("new_signatures", [])[:3])
            finds.append(dict(
                vuln="Information Disclosure",
                status="verified" if grade == "CONFIRMED" else "candidate",
                path=["page:" + page_url],
                tool="info_disclosure/trigger_errors",
                evidence=(f"{f.get('param')}={f.get('mutation')!r} -> "
                          f"HTTP {f.get('status')} [{grade}] {sigs}")))
    return finds


def hunt_dirlist(page_url, stem):
    """directory_listing skill: probe listing-prone dirs on the origin,
    flag sensitive filenames inside any open Index-of page."""
    u = urllib.parse.urlsplit(page_url)
    origin = f"{u.scheme}://{u.netloc}"
    out = stem + "-dirlist.json"
    print(f"  [dirlist] probing {origin} for open directory listings...")
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
            path=["page:" + page_url],
            tool="dirlist",
            evidence=(f"{d.get('method', 'GET')} {d['url']} -> "
                      f"{d.get('status', 200)} Index-of "
                      f"({d.get('server') or 'server?'}); "
                      f"{d.get('file_count', 0)} entries"
                      + (f"; sensitive: {sens_s}" if sens_s else ""))))
    return finds


def hunt_xss(page_url, stem, max_targets):
    """The xss skill owns the whole detection chain: find_surface.py
    discovers injectable params, then the existing pipeline
    (send_payloads -> check_reflection -> recommend_payload --verify)
    grades them. V-graded payloads become verified findings."""
    surf_j = stem + "-xss-surface.json"
    print("  [xss] discovering attack surface (skill find_surface.py)...")
    _skill_run(XSS_DIR / "find_surface.py", "--url", page_url,
               "--out", surf_j, timeout=60)
    surf = _read_json(surf_j) or {}
    targets = [t["template"] for t in surf.get("targets", [])]
    if surf.get("post_forms"):
        print(f"  [xss] {len(surf['post_forms'])} POST form(s) noted as "
              "stored-XSS surface (no stored oracle yet)")

    finds = []
    for tpl in targets[:max_targets]:
        print(f"  [xss] pipeline on {tpl[:90]}")
        t0 = time.time()
        _skill_run(XSS_DIR / "send_payloads.py", "--url", tpl, "--probe2",
                   timeout=90)
        t_chk = time.time()
        _skill_run(XSS_DIR / "check_reflection.py", timeout=60)
        _skill_run(XSS_DIR / "check_reflection.py", "--keywords", timeout=60)
        # DOM escalation: re-probe through a real browser when the marker
        # never reflected, OR when the response itself shows location.*
        # source -> DOM-sink plumbing (a reflected surface can coexist with
        # a DOM sink — the sink path never reaches the raw body). --verify
        # follows probe_mode from the analysis automatically.
        refl = _log_since("xss_reflection_analysis", t_chk)
        if not (refl or {}).get("results") or (refl or {}).get("dom_hint"):
            why = ("no server-side reflection"
                   if not (refl or {}).get("results")
                   else "location.* source -> DOM sink plumbing in page")
            print(f"    [xss] {why} -> render probe (DOM sinks)")
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
            for i, v in enumerate(vers):
                grade = v.get("confidence")
                if grade not in ("V", "R"):
                    continue
                finds.append(dict(
                    vuln="XSS",
                    status="verified" if grade == "V" else "candidate",
                    path=["page:" + page_url, "param:" + pname],
                    tool="xss",
                    evidence=(f"[{grade}] {v.get('payload', '')} -- "
                              f"{(v.get('evidence') or '')[:110]}")))
            if not vers and cands:
                finds.append(dict(
                    vuln="XSS",
                    status="candidate",
                    path=["page:" + page_url, "param:" + pname],
                    tool="xss",
                    evidence=(f"param {pname}: {len(cands)} unverified "
                              f"candidates, e.g. "
                              f"{cands[0].get('payload', '')[:80]}")))
    return finds


_BLH_CHECKERS = {"instagram.com": "instagram", "tiktok.com": "tiktok",
                 "youtube.com": "youtube", "youtu.be": "youtube",
                 "facebook.com": "facebook", "fb.com": "facebook"}


def hunt_blh(graph, page_url, stem):
    """Mine social links on the ONE target page via the
    social_media_crawler skill (single page: --max-pages 1, no crt.sh
    enumeration, no subdomain crawl). Findings are the discovered links
    themselves — no platform checkers are run."""
    crawl_j = stem + "-blh-social.json"
    print("  [blh] mining social links on the target page...")
    _skill_run(BLH_DIR / "social_media_crawler.py",
               "--url", page_url, "--max-pages", "1",
               "--no-subdomains", "--no-enumerate",
               "--output", crawl_j, timeout=300)
    data = _read_json(crawl_j) or {}

    # href -> graph edge so findings still annotate the page
    edge_by_href = {e.get("href", ""): e for e in graph["edges"]
                    if e["type"] == "points_to" and e.get("href")}

    finds = []
    done = set()
    for platform, entries in (data.get("social_media") or {}).items():
        for e in entries:
            href = e.get("url", "") if isinstance(e, dict) else str(e)
            if not href or href in done:
                continue
            done.add(href)
            e0 = edge_by_href.get(href)
            finds.append(dict(
                vuln="Broken Link Hijacking",
                status="candidate",
                path=[e0["src"], e0["dst"]] if e0
                     else ["page:" + page_url],
                tool="broken_link_hijacking",
                evidence=f"{href} -- {platform} link found on page"))
    return finds


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8",
                                               errors="replace"))
    except Exception:
        return None


def hunt_csrf(graph, page_url, stem, cookie):
    """Run the csrf skill: enumerate forms -> replay oracle.
    CONFIRMED grades become verified findings; DEFENDED/SKIPPED are
    dropped (not vulnerabilities)."""
    forms_j = stem + "-csrf-forms.json"
    finds_j = stem + "-csrf-findings.json"
    print("  [csrf] enumerating forms...")
    argv = ["--url", page_url, "--out", forms_j]
    if cookie:
        argv += ["--cookie", cookie]
    _skill_run(CSRF_DIR / "enumerate_forms.py", *argv, timeout=60)

    print("  [csrf] replay oracle (writes state on the target)")
    argv = ["--file", forms_j, "--out", finds_j, "--delay", "0.15"]
    if cookie:
        argv += ["--cookie", cookie]
    _skill_run(CSRF_DIR / "check_csrf.py", *argv, timeout=180)

    data = _read_json(finds_j)
    finds = []
    for f in (data or {}).get("findings", []):
        if f.get("grade") in ("DEFENDED", "SKIPPED"):
            continue
        # resolve the owning form element via submits_to -> ep:<action>
        epid = "ep:" + (f.get("action", "").split("?")[0])
        srcs = [e["src"] for e in graph["edges"]
                if e["type"] == "submits_to" and e["dst"] == epid]
        finds.append(dict(
            vuln="CSRF",
            status="verified" if f.get("grade") == "CONFIRMED" else "candidate",
            path=srcs or ["page:" + page_url],
            tool="csrf",
            evidence=f"{f.get('action')} -- {f.get('evidence', '')}"))
    return finds


SKILL_IDS = ("xss", "info_disclosure", "csrf", "blh", "dirlist")


def hunt_skills(graph, data, page_url, stem, max_xss, cookie="",
                only=None):
    """Run the selected skill tools; fold their results into findings."""
    if not SKILLS_DIR.is_dir():
        print(f"  [!] skills dir not found: {SKILLS_DIR}")
        return []
    only = set(only) if only else set(SKILL_IDS)
    finds = []
    if "info_disclosure" in only:
        finds += hunt_infoleak(page_url, stem)
    if "dirlist" in only:
        finds += hunt_dirlist(page_url, stem)
    if "xss" in only:
        finds += hunt_xss(page_url, stem, max_xss)
    if "csrf" in only:
        finds += hunt_csrf(graph, page_url, stem, cookie)
    if "blh" in only:
        finds += hunt_blh(graph, page_url, stem)
    return finds


def main():
    ap = argparse.ArgumentParser(description="Visual Vulnerability Mapping")
    ap.add_argument("url", help="Page URL to map")
    ap.add_argument("-o", "--output", default=None, help="Output PNG path")
    ap.add_argument("--report", default=None, help="Write AVM markdown report")
    ap.add_argument("--hunt", action="store_true",
                    help="Run the four Skills detectors (xss, "
                         "info_disclosure, csrf, broken_link_hijacking) "
                         "and fold their verified results into the "
                         "findings. All verdicts come from the skills.")
    ap.add_argument("--skills", default="",
                    help="Comma subset for --hunt: xss, info_disclosure, "
                         "csrf, blh, dirlist (default: all five)")
    ap.add_argument("--hunt-max-xss", type=int, default=3,
                    help="Max parameterized URLs to run the xss pipeline on "
                         "(default 3)")
    ap.add_argument("--show-candidates", action="store_true",
                    help="Also print unverified candidate findings "
                         "(default: verified only)")
    args = ap.parse_args()

    out = args.output or "vvm-" + hashlib.md5(args.url.encode()).hexdigest()[:8] + ".png"
    report_path = args.report or out.rsplit(".", 1)[0] + "-avm.md"

    with sync_playwright() as p:
        # Prefer a real installed Chrome (less detectable by CDN bot filters);
        # fall back to the bundled headless Chromium.
        try:
            browser = p.chromium.launch(headless=True, channel="chrome")
        except Exception:
            browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(
            viewport={"width": 1440, "height": 900},
            locale="id-ID",
            user_agent=("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/130.0.0.0 Safari/537.36"))
        ctx.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
        page = ctx.new_page()
        resp = None
        try:
            resp = page.goto(args.url, wait_until="networkidle", timeout=45000)
        except Exception:
            resp = page.goto(args.url, wait_until="load", timeout=30000)
        if resp is not None and resp.status >= 400:
            print(f"Warning: site returned HTTP {resp.status} "
                  "(possible bot block). Results may be empty.", file=sys.stderr)
        page.wait_for_timeout(1500)

        # Sites may scroll inside a nested element (e.g. a fixed .scroll-wrapper)
        # instead of document scroll. Detect the real scrollable height, then
        # grow the viewport so everything is laid out and capturable.
        total_h = page.evaluate("""() => {
            const el = document.scrollingElement;
            let h = el ? el.scrollHeight : document.body.scrollHeight;
            document.querySelectorAll('*').forEach(n => {
                if (n.scrollHeight > n.clientHeight + 10
                    && n.scrollHeight > h) h = n.scrollHeight;
            });
            return h;
        }""")
        page.set_viewport_size({"width": 1440,
                                "height": min(int(total_h) + 100, 12000)})
        page.wait_for_timeout(1200)

        data = page.evaluate(JS_COLLECT)

        # Passive collectors: everything observable from the single page
        # load -- response headers, TLS cert, cookies, page-host DNS.
        passive = dict(status=resp.status if resp else None,
                       headers=dict(resp.headers) if resp else {},
                       tls=None, cookies=ctx.cookies(),
                       host=urllib.parse.urlparse(data["url"]).hostname,
                       ips=[])
        if resp is not None:
            try:
                passive["tls"] = resp.security_details()
            except Exception:
                pass
        try:
            passive["ips"] = sorted({a[4][0] for a in
                                     socket.getaddrinfo(passive["host"], 443)})
        except (OSError, TypeError):
            pass

        shot = page.screenshot()

        # Build the graph while the browser is still open.
        rule_by_kind = {r["kind"]: r for r in RULES}
        findings = []
        for el in data["els"]:
            if el["kind"] in rule_by_kind:
                f = dict(el)
                f["rule"] = rule_by_kind[el["kind"]]
                findings.append(f)

        graph = build_graph(data, findings, out, rule_by_kind)
        merge_passive(graph, passive)
        browser.close()

    report = build_report(data["url"], findings)
    open(report_path, "w").write(report)
    print(report)

    graph_path = out.rsplit(".", 1)[0] + "-graph.json"
    graph["findings"] = []

    if args.hunt:
        print("\nSkill detectors (--hunt):")
        # session cookies from the real page load, so authenticated forms
        # are replayed in-context by the csrf oracle
        cookie_hdr = "; ".join(
            f"{c['name']}={c['value']}" for c in passive["cookies"])
        # absolute stem: skill subprocesses run with their own cwd, so a
        # relative sidecar path would land inside the skill directory
        stem = str(Path(graph_path[:-5]).resolve())
        sel = [s.strip() for s in args.skills.split(",") if s.strip()]
        bad = [s for s in sel if s not in SKILL_IDS]
        if bad:
            print(f"[!] unknown skill(s): {', '.join(bad)} "
                  f"(valid: {', '.join(SKILL_IDS)})")
        graph["findings"] += hunt_skills(
            graph, data, data["url"], stem, args.hunt_max_xss,
            cookie_hdr, only=[s for s in sel if s in SKILL_IDS] or None)
        graph["findings"] = dedupe_findings(graph["findings"])

    # Annotate AFTER findings are final: only verified findings mark the
    # page (red box + badge); unattached verified vulns go into a banner.
    el_vulns = verified_element_vulns(graph)
    banner = [fnd["vuln"] for fnd in graph["findings"]
              if fnd["status"] == "verified"
              and not _resolve_path_els(graph, fnd.get("path", []))]
    img = Image.open(__import__("io").BytesIO(shot))
    annotate(img, findings, el_vulns=el_vulns,
             show_all=args.show_candidates, banner=banner).save(out)

    open(graph_path, "w").write(json.dumps(graph, indent=2))
    verified = [f for f in graph["findings"] if f["status"] == "verified"]
    cand_n = len(graph["findings"]) - len(verified)
    if verified:
        print(f"\nVerified vulnerabilities ({len(verified)}):")
        for fnd in verified:
            tool = f"  [{fnd['tool']}]" if fnd.get("tool") else ""
            print(f"  {fnd['vuln']}: {fnd['evidence']}{tool}")
    else:
        print("\nNo verified vulnerabilities.")
    if args.show_candidates:
        for fnd in graph["findings"]:
            if fnd["status"] != "verified":
                tool = f"  [{fnd['tool']}]" if fnd.get("tool") else ""
                print(f"  [candidate] {fnd['vuln']}: {fnd['evidence']}{tool}")
    elif cand_n:
        print(f"  ({cand_n} candidate(s) kept in graph JSON only -- "
              f"pass --show-candidates to list)")

    print(f"\n{len(findings)} elements mapped -> {out}\nAVM table -> {report_path}\n"
          f"Graph -> {graph_path} ({len(graph['nodes'])} nodes, "
          f"{len(graph['edges'])} edges)")


if __name__ == "__main__":
    main()

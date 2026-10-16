#!/usr/bin/env python3
"""
VVM - Visual Vulnerability Mapping

Takes a URL, screenshots the page, and annotates visible UI elements as
potential vulnerability entry points, as described in the VVM + AVM + AI
white paper. For each annotated element it prints an AVM table:
Assumption -> Inversion -> Result.

Rule-based only. No AI calls, no requests beyond loading the page once.
Use only on sites you own or are authorized to test.

Usage:
    python3 vvm.py https://alessandrorumampuk.com/
    python3 vvm.py https://example.com -o out.png --report report.md
    python3 vvm.py https://example.com --check-links   # also probe external links (HEAD)
"""

import argparse
import hashlib
import sys
import urllib.parse

from playwright.sync_api import sync_playwright
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Rules: element selector signature -> (label, assumption, inversion, vulns)
# ---------------------------------------------------------------------------

RULES = [
    dict(kind="search",
         label="Search input",
         assumption="User types a plain keyword",
         inversion="User types code or a query fragment instead",
         vulns=["SQL Injection", "Reflected XSS", "SSTI", "NoSQL Injection"]),
    dict(kind="login",
         label="Login / password field",
         assumption="User submits only their own credentials",
         inversion="Attacker submits someone else's or enumerated credentials",
         vulns=["Account Takeover", "Brute Force", "Credential Stuffing", "Auth Bypass"]),
    dict(kind="file",
         label="File upload",
         assumption="Users upload safe file types",
         inversion="Attacker uploads a script or executable",
         vulns=["Unrestricted File Upload", "Stored XSS", "RCE via webshell"]),
    dict(kind="comment",
         label="Comment / text area",
         assumption="Comments are plain text",
         inversion="Comment contains executable markup",
         vulns=["Stored XSS", "HTML Injection"]),
    dict(kind="form",
         label="Form",
         assumption="Client-side validation is enforced server-side",
         inversion="Attacker submits raw requests bypassing the form",
         vulns=["Injection", "Mass Assignment", "CSRF"]),
    dict(kind="urlparam",
         label="URL parameter (page URL)",
         assumption="User only requests their own resources",
         inversion="User changes the parameter value",
         vulns=["IDOR", "Parameter Tampering", "Open Redirect"]),
    dict(kind="paramlink",
         label="Link with query parameters",
         assumption="Parameter values are trusted input",
         inversion="Attacker rewrites values in the URL",
         vulns=["IDOR", "Reflected XSS", "SQL Injection", "Open Redirect"]),
    dict(kind="sociallink",
         label="External / social link",
         assumption="Old links stay alive and owned",
         inversion="Target expires or is claimed by someone else",
         vulns=["Broken Link Hijacking", "Phishing redirect"]),
    dict(kind="blanklink",
         label="target=_blank link",
         assumption="Opened page is trusted",
         inversion="Opened page rewrites the original tab",
         vulns=["Reverse Tabnabbing"]),
    dict(kind="iframe",
         label="iframe",
         assumption="Embedded content is trusted",
         inversion="Embedded source is compromised or swapped",
         vulns=["Content Injection", "Clickjacking aid"]),
    dict(kind="hidden",
         label="Hidden input",
         assumption="Users never see or edit it",
         inversion="Attacker modifies it in the request",
         vulns=["Parameter Tampering", "Price/Privilege Manipulation"]),
    dict(kind="editable",
         label="Editable content",
         assumption="Rendered HTML came from safe source",
         inversion="Stored markup reaches this area unsanitized",
         vulns=["Stored XSS"]),
    dict(kind="weblink",
         label="Navigation link",
         assumption="Destination is fixed and safe",
         inversion="Destination is user-controlled elsewhere",
         vulns=["Open Redirect", "Broken Link Hijacking"]),
]

JS_COLLECT = r"""
() => {
    const seen = new Set();
    const els = [];
    const add = (el, kind) => {
        const r = el.getBoundingClientRect();
        if (!r.width || !r.height || r.width < 8 || r.height < 8) return;
        const key = kind + '|' + Math.round(r.x) + '|' + Math.round(r.y) + '|' + Math.round(r.width);
        if (seen.has(key)) return;
        seen.add(key);
        const docTop = r.top + window.scrollY, docLeft = r.left + window.scrollX;
        if (docTop > 20000) return;  // cap absurdly tall pages
        els.push({ kind, x: docLeft, y: docTop, w: r.width, h: r.height,
                   desc: el.getAttribute('aria-label') || el.getAttribute('placeholder')
                      || el.getAttribute('name') || el.getAttribute('id')
                      || (el.textContent || '').trim().slice(0, 40)
                      || el.getAttribute('href') || '' });
    };

    document.querySelectorAll('input').forEach(el => {
        const t = (el.type || 'text').toLowerCase();
        const hint = ((el.name||'') + ' ' + (el.id||'') + ' ' + (el.placeholder||'')).toLowerCase();
        if (t === 'hidden')            add(el, 'hidden');
        else if (t === 'password')     add(el, 'login');
        else if (t === 'file')         add(el, 'file');
        else if (t === 'search' || /search|cari|q\b/.test(hint)) add(el, 'search');
        else if (/login|signin|user|email|pass/.test(hint))      add(el, 'login');
        else                           add(el, 'form');
    });
    document.querySelectorAll('textarea').forEach(el => add(el, 'comment'));
    document.querySelectorAll('form').forEach(el => {
        const hasPwd = !!el.querySelector('input[type=password]');
        add(el, hasPwd ? 'login' : 'form');
    });
    document.querySelectorAll('iframe').forEach(el => add(el, 'iframe'));
    document.querySelectorAll('[contenteditable="true"]').forEach(el => add(el, 'editable'));

    const host = location.hostname;
    document.querySelectorAll('a[href]').forEach(el => {
        const href = el.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
        let u; try { u = new URL(href, location.href); } catch(e) { return; }
        const social = /(facebook|twitter|x\.com|instagram|linkedin|youtube|tiktok|github)\./.test(u.hostname);
        if (u.search && u.search.length > 1)          add(el, 'paramlink');
        else if (u.hostname !== host)                  add(el, social ? 'sociallink' : 'weblink');
        if (el.target === '_blank')                    add(el, 'blanklink');
    });

    return { els, url: location.href,
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


def annotate(img, findings):
    """Draw numbered red boxes; returns the annotated image."""
    img = img.convert("RGBA")
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    font = load_font(16)
    for i, f in enumerate(findings, 1):
        x, y, w, h = f["x"], f["y"], f["w"], f["h"]
        pad = 4
        box = [x - pad, y - pad, x + w + pad, y + h + pad]
        d.rectangle(box, outline=(220, 40, 40, 255), width=3)
        d.rectangle(box, fill=(220, 40, 40, 30))
        # numbered badge
        label = str(i)
        tb = d.textbbox((0, 0), label, font=font)
        bw, bh = tb[2] - tb[0] + 10, tb[3] - tb[1] + 8
        bx, by = box[0], max(0, box[1] - bh - 2)
        d.rectangle([bx, by, bx + bw, by + bh], fill=(220, 40, 40, 235))
        d.text((bx + 5, by + 4), label, fill="white", font=font)
    return Image.alpha_composite(img, overlay).convert("RGB")


def build_report(url, findings):
    lines = [f"# VVM Report", "", f"**URL:** {url}", "",
             "| # | Element | Assumption | Inversion | Possible vulnerabilities |",
             "|---|---|---|---|---|"]
    seen_rules = {}
    for i, f in enumerate(findings, 1):
        r = f["rule"]
        seen_rules[f["kind"]] = r
        desc = f' — "{f["desc"]}"' if f.get("desc") else ""
        lines.append(
            f"| {i} | {r['label']}{desc} | {r['assumption']} | {r['inversion']} "
            f"| {', '.join(r['vulns'])} |")
    lines += ["", "_Use only on sites you own or are authorized to test._"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Visual Vulnerability Mapping")
    ap.add_argument("url", help="Page URL to map")
    ap.add_argument("-o", "--output", default=None, help="Output PNG path")
    ap.add_argument("--report", default=None, help="Write AVM markdown report")
    ap.add_argument("--check-links", action="store_true",
                    help="HEAD-probe external links to flag dead ones")
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
        shot = page.screenshot()
        browser.close()

    rule_by_kind = {r["kind"]: r for r in RULES}
    findings = []
    for el in data["els"]:
        if el["kind"] in rule_by_kind:
            f = dict(el)
            f["rule"] = rule_by_kind[el["kind"]]
            findings.append(f)

    img = Image.open(__import__("io").BytesIO(shot))
    annotate(img, findings).save(out)

    report = build_report(data["url"], findings)
    open(report_path, "w").write(report)
    print(report)

    if args.check_links:
        import urllib.request
        print("\nExternal link probe (HEAD):")
        for f in findings:
            if f["kind"] in ("sociallink", "weblink", "blanklink") and f["desc"]:
                try:
                    req = urllib.request.Request(f["desc"], method="HEAD",
                                                 headers={"User-Agent": "Mozilla/5.0"})
                    code = urllib.request.urlopen(req, timeout=8).status
                    flag = "" if code < 400 else "  <-- DEAD?"
                    print(f"  {code} {f['desc'][:70]}{flag}")
                except Exception as e:
                    print(f"  ERR {f['desc'][:70]}  ({e})  <-- check")

    print(f"\n{len(findings)} elements mapped -> {out}\nAVM table -> {report_path}")


if __name__ == "__main__":
    main()

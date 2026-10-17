#!/usr/bin/env python3
import subprocess
import urllib.parse
import os
import re
import secrets
import string
import json
import argparse
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

MARKER_START = "testing1"
MARKER_END = "testing2"
SEPARATOR = "x"
PLACEHOLDER = "{xss_testing}"

CHARACTERS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("greater_than", ">"),
    ("less_than", "<"),
    ("slash", "/"),
    ("backslash", "\\"),
]

# Layer B/C probe (--probe2): keyword-level filters the 6-char probe cannot see
KEYWORDS = [
    ("parentheses", "()"),
    ("backtick", "`"),
    ("alert", "alert"),
    ("confirm", "confirm"),
    ("prompt", "prompt"),
    ("script_tag", "<script>"),
    ("javascript_proto", "javascript:"),
    ("onerror", "onerror"),
    # tag probes carry '>': a whole-tag stripper (<img[^>]*>) deletes
    # complete tags while letting the bare '<img' name through
    ("img_tag", "<img>"),
    ("entity_lt", "&lt;"),
    ("srcdoc", "srcdoc"),
    ("onload", "onload"),
    ("ontoggle", "ontoggle"),
    ("autofocus", "autofocus"),
    ("onfocus", "onfocus"),
    ("print", "print"),
    ("svg_tag", "<svg>"),
    ("details_tag", "<details>"),
    ("body_tag", "<body>"),
    ("iframe_tag", "<iframe>"),
    # junction probes: WAF signatures fire on combinations, not atoms
    ("call_alert", "alert(1)"),
    ("call_confirm", "confirm(1)"),
    ("call_prompt", "prompt(1)"),
    ("call_print", "print()"),
    ("tick_alert", "alert`1`"),
    ("tick_confirm", "confirm`1`"),
    ("tick_prompt", "prompt`1`"),
    ("pair_img_onerror", "img onerror"),
    ("pair_svg_onload", "svg onload"),
    ("pair_details_ontoggle", "details ontoggle"),
    ("pair_body_onload", "body onload"),
    ("pair_iframe_onload", "iframe onload"),
    ("close_script", "</script"),
    ("close_title", "</title"),
    # NOTE: no item may contain 'x' — it is the split separator.
    # "</textarea" deliberately omitted ("textarea" contains 'x').
    ("close_noscript", "</noscript"),
    ("close_style", "</style"),
    ("close_iframe", "</iframe"),
    ("js_break_squote", "'-alert(1)-"),
    ("js_break_dquote", "\"-alert(1)-"),
    ("proto_href", "href=javascript:"),
    # case-mutation probes: cheap WAFs sign lowercase only
    ("case_script", "ScRiPt"),
    ("case_onload", "OnLoAd"),
    ("case_proto", "JaVaScRiPt:"),
    # context-syntax probes for comment/template-literal escapes
    ("newline", "\n"),
    ("comment_close", "*/"),
    ("interp", "${"),
]


def random_tag_name():
    """3-letter random tag name for the generic tag-stripper probe.
    'x'/'X' are excluded — 'x' is the probe split separator."""
    alpha = [c for c in string.ascii_letters if c.lower() != "x"]
    return "".join(secrets.choice(alpha) for _ in range(3))


def keyword_items():
    """KEYWORDS plus one random junk tag (e.g. <xDh>). If even this unknown
    tag is removed, the filter is a generic tag-stripper and ANY deleted
    string — including this random one — can be nested inside blocked
    content as a splitter (case: xss tag removed.md)."""
    return KEYWORDS + [("rand_tag", f"<{random_tag_name()}>")]


def send_curl(url):
    try:
        result = subprocess.run(
            ["curl", "-s", "-k", "--max-time", "10", url],
            capture_output=True,
            text=True,
        )
        return result.stdout
    except Exception as e:
        return f"[CURL_ERROR] {e}"


def send_probe(target_url, items, vuln_name, kind):
    input_str = MARKER_START + SEPARATOR.join(v for _, v in items) + MARKER_END
    print(f"{kind}: {input_str}")
    encoded = urllib.parse.quote(input_str, safe="")
    url = target_url.replace(PLACEHOLDER, encoded)
    print(f"URL:   {url}")
    response = send_curl(url)
    print(f"Response length: {len(response)}")

    html_file = new_log_path(vuln_name, "html")
    with open(html_file, "w") as f:
        f.write(f"<!-- generated_by: send_payloads.py -->\n")
        f.write(f"<!-- generated_at: {datetime.now().isoformat()} -->\n")
        f.write(f"<!-- input_sent: {input_str} -->\n")
        f.write(f"<!-- separator: {SEPARATOR} -->\n")
        f.write(f"<!-- items_json: {json.dumps(items)} -->\n")
        f.write(f"<!-- {kind.lower()}_names: {SEPARATOR.join(n for n, _ in items)} -->\n")
        f.write(f"<!-- url: {url} -->\n")
        f.write(f"<!-- response_length: {len(response)} -->\n")
        f.write(response)
    print(f"Saved: {html_file}\n")


def isolate_probe(target_url):
    """Escalation probe: send each character alone (testing1<c>testing2).
    Used when the combined probe shows an anomaly (no marker back, all
    FAIL, or split collapse) to pinpoint which single char triggers the
    filter. No separator parsing needed — verdict = exact marker match."""
    print("Isolation mode: one request per character")
    results = []
    for name, char in CHARACTERS:
        probe = MARKER_START + char + MARKER_END
        url = target_url.replace(PLACEHOLDER, urllib.parse.quote(probe, safe=""))
        response = send_curl(url)
        reflected_ok = probe in response
        m = re.search(re.escape(MARKER_START) + r"(.{0,100}?)" + re.escape(MARKER_END),
                      response, re.DOTALL)
        got = m.group(1) if m else None
        # verdict: char untouched if exact probe reflected; transformed if
        # markers present but middle differs; rejected if markers absent
        if reflected_ok:
            verdict, status = "unchanged", 100
        elif got is not None:
            verdict, status = "transformed", 50
        else:
            verdict, status = "rejected", 0
        results.append({"character_name": name, "character": char,
                        "reflected": got, "verdict": verdict, "score": status})
        print(f"  {name:<15} {char!r:<6} -> {verdict} (got: {got!r})")

    out_file = new_log_path("xss_isolation", "json")
    with open(out_file, "w") as f:
        json.dump({
            "generated_by": "send_payloads.py --isolate",
            "generated_at": datetime.now().isoformat(),
            "url": target_url,
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"Saved: {out_file}\n")


def main():
    parser = argparse.ArgumentParser(description="Send XSS test payloads to a target URL")
    parser.add_argument("--url", required=True, help=f'Target URL with {PLACEHOLDER} placeholder (example: --url="https://example.com/search?q={PLACEHOLDER}")')
    parser.add_argument("--probe2", action="store_true",
                        help="also send the Layer B/C keyword-mask probe "
                             "(), `, alert, <script>, javascript:, onerror, <img "
                             "plus a random <xYz> junk tag (generic "
                             "tag-stripper detector) "
                             "(saved as *-xss_keywords.html)")
    parser.add_argument("--isolate", action="store_true",
                        help="escalation probe: send each character alone "
                             "testing1<c>testing2 to pinpoint which char trips "
                             "the filter (saved as *-xss_isolation.json)")
    args = parser.parse_args()

    target_url = args.url

    if PLACEHOLDER not in target_url:
        print(f"Error: URL must contain {PLACEHOLDER} placeholder")
        print(f'Example: --url="https://example.com/search?q={PLACEHOLDER}"')
        return

    if args.isolate:
        isolate_probe(target_url)
        return

    kw_items = keyword_items() if args.probe2 else []

    print("=" * 80)
    print("Send Payloads")
    print(f"Target: {target_url}")
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Characters: {', '.join(name for name, _ in CHARACTERS)}")
    if args.probe2:
        print(f"Keywords:  {', '.join(name for name, _ in kw_items)}")
    print("=" * 80)
    print()

    # Probe 1: character fingerprint (Layer A) -> *-xss.html
    send_probe(target_url, CHARACTERS, "xss", "Characters")

    # Probe 2: keyword fingerprint (Layer B/C) -> *-xss_keywords.html
    if args.probe2:
        send_probe(target_url, kw_items, "xss_keywords", "Keywords")


if __name__ == "__main__":
    main()

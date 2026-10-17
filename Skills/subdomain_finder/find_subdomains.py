#!/usr/bin/env python3
"""
find_subdomains.py -- subdomain discovery with ZERO third-party data APIs.

No crt.sh, no SecurityTrails, no passive-DNS providers. Every record is
discovered from first-party evidence only:

    1. AXFR      -- zone transfer from the target's OWN nameservers
                    (raw DNS wire protocol, no `dig` dependency)
    2. BRUTEFORCE-- resolve each wordlist name via the system resolver
                    (DNS protocol queries -- not a data API)
    3. SCRAPE    -- fetch the target's own HTML/JS and regex
                    ``*.domain`` references out of it
    4. MUTATION  -- env-prefix/suffix permutations on discovered names
                    (dev-, staging-, -api, ...) then resolve them

Wildcard DNS is detected up front (random labels) so wildcard answers are
flagged instead of silently inflating results.

Usage:
    python3 find_subdomains.py --domain example.com
    python3 find_subdomains.py --domain example.com --wordlist big.txt \
        --workers 60 --depth 1
    python3 find_subdomains.py --domain example.com --no-bruteforce   # axfr+scrape only

Output JSON is written to SecurityPlatform/log/*-subdomains.json via
log_utils (plus --out if given). Local lab / authorized targets only.
"""
import argparse
import json
import os
import random
import re
import socket
import string
import struct
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST = os.path.join(SKILL_DIR, "wordlists", "subdomains.txt")

QTYPE_A, QTYPE_NS, QTYPE_SOA, QTYPE_AXFR = 1, 2, 6, 252


# --------------------------------------------------------------------------
# Minimal DNS wire client (NS lookups + AXFR) -- stdlib sockets only
# --------------------------------------------------------------------------

def _enc_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _dec_name(msg: bytes, off: int):
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels, jumped = [], False
    end = off
    while True:
        ln = msg[off]
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            break
        if ln & 0xC0 == 0xC0:                      # compression pointer
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("utf-8", "replace"))
        off += ln
        if not jumped:
            end = off
    return ".".join(labels), end


def _build_query(name: str, qtype: int) -> bytes:
    hdr = struct.pack("!HHHHHH", random.randrange(0xFFFF), 0x0100, 1, 0, 0, 0)
    return hdr + _enc_name(name) + struct.pack("!HH", qtype, 1)


def _parse_rrs(msg: bytes):
    """Return list of {name,type,rdata_off,rdlen,ttl} from all sections."""
    if len(msg) < 12:
        return []
    qd, an, ns, ar = struct.unpack("!HHHH", msg[4:12])
    off = 12
    for _ in range(qd):
        _, off = _dec_name(msg, off)
        off += 4
    rrs = []
    for _ in range(an + ns + ar):
        try:
            name, off = _dec_name(msg, off)
            rtype, _, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            rrs.append({"name": name, "type": rtype, "ttl": ttl,
                        "rdata_off": off + 10, "rdlen": rdlen, "msg": msg})
            off += 10 + rdlen
        except (IndexError, struct.error):
            break
    return rrs


def _udp_query(name, qtype, server, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(_build_query(name, qtype), (server, 53))
        msg, _ = s.recvfrom(4096)
        return msg
    finally:
        s.close()


def ns_records(domain: str, resolver: str, timeout=5):
    """NS hostnames for `domain` via the resolver; UDP, TCP fallback on TC."""
    try:
        msg = _udp_query(domain, QTYPE_NS, resolver, timeout)
    except (socket.timeout, OSError):
        return []
    # truncated -> retry over TCP
    if len(msg) >= 4 and msg[2] & 0x02:
        try:
            s = socket.create_connection((resolver, 53), timeout)
            q = _build_query(domain, QTYPE_NS)
            s.sendall(struct.pack("!H", len(q)) + q)
            ln = struct.unpack("!H", _recv_exact(s, 2))[0]
            msg = _recv_exact(s, ln)
            s.close()
        except OSError:
            return []
    hosts = []
    for rr in _parse_rrs(msg):
        if rr["type"] == QTYPE_NS:
            h, _ = _dec_name(rr["msg"], rr["rdata_off"])
            if h:
                hosts.append(h.rstrip("."))
    return hosts


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def axfr(domain: str, ns_ip: str, timeout=10):
    """Attempt a zone transfer from one nameserver. Returns set of names.

    AXFR runs over TCP; the zone stream is one or more length-prefixed
    messages and ends when the second SOA record arrives (or EOF).
    """
    names, soa_seen = set(), 0
    try:
        s = socket.create_connection((ns_ip, 53), timeout)
        s.settimeout(timeout)
        q = _build_query(domain, QTYPE_AXFR)
        s.sendall(struct.pack("!H", len(q)) + q)
        while True:
            hdr = _recv_exact(s, 2)
            if len(hdr) < 2:
                break
            (mlen,) = struct.unpack("!H", hdr)
            msg = _recv_exact(s, mlen)
            if len(msg) < mlen:
                break
            for rr in _parse_rrs(msg):
                if rr["type"] == QTYPE_SOA:
                    soa_seen += 1
                n = rr["name"].rstrip(".").lower()
                if n == domain or n.endswith("." + domain):
                    names.add(n)
            if soa_seen >= 2:
                break
        s.close()
    except OSError:
        pass
    return names


# --------------------------------------------------------------------------
# Resolution + wildcard handling
# --------------------------------------------------------------------------

def resolve(host: str, timeout=4):
    """A/AAAA addresses via the system resolver. [] if the name is dead."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, socket.timeout, OSError):
        return []


def wildcard_ips(domain: str):
    """Resolve two random labels -- same answer twice means wildcard DNS."""
    ips = set()
    for _ in range(2):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits,
                                      k=16))
        ips.update(resolve(f"{rand}.{domain}"))
    return ips


# --------------------------------------------------------------------------
# Scraping: pull *.domain references out of the target's own HTML/JS
# --------------------------------------------------------------------------

class RefParser(HTMLParser):
    """Collect same-domain asset URLs (script src / link href) to fetch."""

    def __init__(self, base, domain):
        super().__init__(convert_charrefs=True)
        self.base, self.domain = base, domain
        self.assets = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        for key in ("src", "href", "action", "data"):
            v = d.get(key)
            if not v:
                continue
            u = urllib.parse.urljoin(self.base, v)
            h = urllib.parse.urlsplit(u).hostname or ""
            if h == self.domain or h.endswith("." + self.domain):
                self.assets.append(u)


def fetch(url: str, timeout=10, limit=1_500_000):
    """GET a page, return (final_url, text) or (url, None)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.url, r.read(limit).decode("utf-8", errors="replace")
    except Exception:
        return url, None


def scrape(domain: str, seeds, sub_re, max_pages=40):
    """Fetch seeds + their same-domain assets; regex subdomain refs."""
    found, pages = set(), []
    queue = list(seeds)
    seen = set()
    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        final, body = fetch(url)
        if body is None:
            continue
        pages.append(url)
        for m in sub_re.finditer(body):
            found.add(m.group(1).lower().rstrip("."))
        p = RefParser(final, domain)
        try:
            p.feed(body)
        except Exception:
            pass
        for a in p.assets:
            if a not in seen:
                queue.append(a)
    return found, pages


# --------------------------------------------------------------------------
# Mutations (altdns-style) on discovered first labels
# --------------------------------------------------------------------------

MUT_AFFIX = ["dev", "staging", "stg", "test", "uat", "qa", "beta", "alpha",
             "api", "v1", "v2", "internal", "int", "prod", "sandbox", "old",
             "backup", "bak", "new", "demo", "stage", "pre", "canary", "edge"]


def mutations(found_hosts, domain):
    """dev-www / www-dev style permutations on each discovered first label."""
    out = set()
    for h in found_hosts:
        first = h.split(".", 1)[0]
        if not first or first == h:
            continue
        for a in MUT_AFFIX:
            out.add(f"{a}-{first}.{domain}")
            out.add(f"{first}-{a}.{domain}")
    return out


# --------------------------------------------------------------------------
# HTTP probe (optional liveness/title evidence)
# --------------------------------------------------------------------------

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def probe_http(host: str, timeout=6):
    """One GET on https then http; status + <title> for evidence."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        final, body = fetch(url, timeout=timeout, limit=65536)
        if body is None:
            continue
        title = ""
        m = TITLE_RE.search(body)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        return {"scheme": scheme, "status": status, "title": title,
                "final": final}
    return {}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def normalize_domain(raw: str) -> str:
    """Accept 'example.com', 'https://example.com/path', trailing dot, etc."""
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urllib.parse.urlsplit(raw).hostname or raw
    raw = raw.split("/")[0].rstrip(".")
    if not re.fullmatch(r"([a-z0-9_-]+\.)+[a-z]{2,}", raw):
        raise SystemExit(f"[!] not a domain: {raw!r} (IPs/localhost not supported)")
    return raw


def system_resolver():
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except OSError:
        pass
    return "8.8.8.8"


def main():
    ap = argparse.ArgumentParser(
        description="Subdomain discovery via AXFR + wordlist DNS + target "
                    "scraping + mutation. No third-party data APIs.")
    ap.add_argument("--domain", required=True,
                    help="Apex domain (or URL) to enumerate")
    ap.add_argument("--wordlist", default=DEFAULT_WORDLIST)
    ap.add_argument("--resolver", help="DNS resolver IP "
                                       "(default: system resolver)")
    ap.add_argument("--workers", type=int, default=40)
    ap.add_argument("--depth", type=int, default=0,
                    help="0 = scrape apex/www only; 1 = also scrape each "
                         "discovered host's root page")
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--no-axfr", action="store_true")
    ap.add_argument("--no-bruteforce", action="store_true")
    ap.add_argument("--no-scrape", action="store_true")
    ap.add_argument("--no-mutate", action="store_true")
    ap.add_argument("--no-probe", action="store_true",
                    help="Skip the HTTP liveness/title probe")
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--out", help="Output JSON path (default: log dir)")
    args = ap.parse_args()

    domain = normalize_domain(args.domain)
    resolver = args.resolver or system_resolver()
    found = {}          # host -> {"ips": set, "sources": set}

    def add(host, source):
        host = host.strip(".").lower()
        if host == domain or not host.endswith("." + domain):
            return
        rec = found.setdefault(host, {"ips": set(), "sources": set()})
        rec["sources"].add(source)

    print(f"[subdomain] target={domain} resolver={resolver}")

    # -- 1. AXFR -------------------------------------------------------------
    if not args.no_axfr:
        ns_hosts = ns_records(domain, resolver)
        print(f"[subdomain] nameservers: {', '.join(ns_hosts) or 'none found'}")
        ns_ips = sorted({ip for ns in ns_hosts for ip in resolve(ns)})
        got = set()
        for ip in ns_ips:
            names = axfr(domain, ip, timeout=args.timeout)
            if names:
                print(f"[subdomain] AXFR {ip}: {len(names)} zone records!")
                got |= names
        if not got and ns_ips:
            print("[subdomain] AXFR refused on all nameservers (expected)")
        for n in got:
            add(n, "axfr")

    # -- wildcard detection ---------------------------------------------------
    wild = wildcard_ips(domain)
    if wild:
        print(f"[subdomain] wildcard DNS detected -> {sorted(wild)}")

    # -- 2. bruteforce --------------------------------------------------------
    if not args.no_bruteforce:
        try:
            words = [w.strip() for w in open(args.wordlist)
                     if w.strip() and not w.startswith("#")]
        except OSError as e:
            print(f"[!] wordlist: {e}")
            words = []
        print(f"[subdomain] bruteforce: {len(words)} names "
              f"({args.workers} workers)")
        cand = [f"{w}.{domain}" for w in words]
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            for host, ips in zip(cand, ex.map(resolve, cand)):
                if ips:
                    add(host, "bruteforce")
                    found[host]["ips"].update(ips)

    # -- 3. scrape ------------------------------------------------------------
    if not args.no_scrape:
        seeds = [f"https://{domain}/", f"http://{domain}/"]
        if resolve(f"www.{domain}"):
            seeds.insert(0, f"https://www.{domain}/")
        sub_re = re.compile(r"(?i)\b((?:[a-z0-9_-]+\.)+%s)\b"
                            % re.escape(domain))
        scraped, pages = scrape(domain, seeds, sub_re, args.max_pages)
        print(f"[subdomain] scraped {len(pages)} page/asset(s) "
              f"-> {len(scraped)} refs")
        for n in scraped:
            add(n, "scrape")
        # depth 1: scrape root pages of every scraped host
        if args.depth >= 1:
            extra_seeds = [f"https://{h}/" for h in scraped]
            more, pages2 = scrape(domain, extra_seeds, sub_re,
                                  args.max_pages)
            print(f"[subdomain] depth-1 scrape {len(pages2)} page(s) "
                  f"-> {len(more)} refs")
            for n in more:
                add(n, "scrape")

    # -- 4. mutations -----------------------------------------------------------
    if not args.no_mutate and found:
        muts = mutations(set(found), domain)
        print(f"[subdomain] mutations: {len(muts)} permutations")
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            for host, ips in zip(sorted(muts), ex.map(resolve, sorted(muts))):
                if ips:
                    add(host, "mutation")
                    found[host]["ips"].update(ips)

    # -- resolve every scraped/AXFR name not yet resolved ----------------------
    unresolved = [h for h, r in found.items() if not r["ips"]]
    if unresolved:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            for host, ips in zip(unresolved, ex.map(resolve, unresolved)):
                if ips:
                    found[host]["ips"].update(ips)

    # -- 5. HTTP probe ----------------------------------------------------------
    if not args.no_probe and found:
        print(f"[subdomain] probing HTTP(S) on {len(found)} host(s)...")
        with ThreadPoolExecutor(max_workers=min(args.workers, 20)) as ex:
            for host, http in zip(sorted(found),
                                  ex.map(probe_http, sorted(found))):
                found[host]["http"] = http

    # -- report -----------------------------------------------------------------
    records = []
    for host in sorted(found):
        rec = found[host]
        ips = sorted(rec["ips"])
        records.append({
            "host": host,
            "ips": ips,
            "resolves": bool(ips),
            "wildcard_match": bool(wild) and set(ips) <= wild,
            "sources": sorted(rec["sources"]),
            "http": rec.get("http", {}),
        })

    live = [r for r in records if r["resolves"]]
    payload = {
        "generated_by": "find_subdomains.py",
        "domain": domain,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "resolver": resolver,
        "wildcard_ips": sorted(wild),
        "total_found": len(records),
        "resolving": len(live),
        "subdomains": records,
    }
    out = args.out or new_log_path("subdomains", "json")
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"\n[+] {len(live)}/{len(records)} subdomains resolve:")
    for r in records:
        mark = "+" if r["resolves"] else " "
        wc = " [wildcard]" if r["wildcard_match"] else ""
        http = r.get("http") or {}
        extra = (f" | {http.get('scheme')}:{http.get('status')} "
                 f"{http.get('title', '')[:40]}") if http else ""
        print(f"  {mark} {r['host']:45} {','.join(r['sources']):18} "
              f"{','.join(r['ips'][:2])}{wc}{extra}")
    print(f"saved -> {out}")


if __name__ == "__main__":
    main()

# Subdomain Finder

Subdomain discovery with **zero third-party data APIs** — no crt.sh, no
SecurityTrails, no passive-DNS providers. Every record comes from
first-party evidence only.

## Techniques

| Stage | Source of truth | What it does |
|---|---|---|
| `axfr` | Target's own nameservers | Zone transfer over raw DNS/TCP (no `dig` dependency — pure socket wire protocol). Dumps the entire zone when a NS is misconfigured. |
| `bruteforce` | DNS protocol via system resolver | Resolves each bundled wordlist name (`wordlists/subdomains.txt`, ~330 entries). A DNS query is a protocol exchange, not a data API. |
| `scrape` | Target's own HTML/JS | Fetches apex/www pages + same-domain assets, regexes `*.domain` references. `--depth 1` also scrapes each discovered host. |
| `mutation` | Discovered names | env affixes (`dev-`, `-staging`, `api-`, …) permuted on each found first label, then resolved. |

## Usage

```bash
python3 find_subdomains.py --domain example.com

# fast recon only (axfr + scrape, no wordlist/mutations)
python3 find_subdomains.py --domain example.com --no-bruteforce --no-mutate

# bigger wordlist, more workers, deeper scrape
python3 find_subdomains.py --domain example.com \
    --wordlist /path/to/big.txt --workers 60 --depth 1

# DNS only, skip the HTTP liveness probe
python3 find_subdomains.py --domain example.com --no-probe
```

## Output

JSON to `SecurityPlatform/log/*-subdomains.json` (or `--out`):

```json
{"domain": "example.com",
 "wildcard_ips": [...],
 "subdomains": [{"host": "api.example.com",
                 "ips": ["1.2.3.4"],
                 "resolves": true,
                 "wildcard_match": false,
                 "sources": ["bruteforce", "scrape"],
                 "http": {"scheme": "https", "status": 200, "title": "..."}}]}
```

`wildcard_match: true` = the host resolves to the same IPs as random junk
labels — it exists at DNS level but may be a wildcard answer, not a real
vhost. `resolves: false` = referenced (AXFR/scrape) but no DNS record now —
still evidence worth keeping.

## Honest limits

- **No CT logs / passive DNS** → less coverage than subfinder/amass.
  Subdomains never linked from the site and not in the wordlist stay
  invisible. Trade-off accepted by design: everything here is
  first-party-verifiable.
- AXFR succeeds only on misconfigured nameservers (rare in 2025, common
  in labs — `zonetransfer.me` works for testing).
- Resolution uses the OS resolver (`/etc/resolv.conf` or `--resolver`);
  DNS queries still transit resolver infra — that's the DNS protocol
  itself, not a data-provider API.
- Bruteforce sends real DNS queries: noisy on the resolver, invisible to
  the target (queries go to the resolver, not the target's servers).
  The HTTP probe (`--probe`, on by default) does touch the target.

Local lab / authorized targets only.

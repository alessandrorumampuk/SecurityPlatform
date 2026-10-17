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
| `ct` (opt-in, `--ct`) | crt.sh certwatch | **Third-party.** Same database crt.sh serves: raw PostgreSQL wire client to `crt.sh:5432/certwatch` (guest), running crt.sh's own indexed query — `identities(certificate) @@ phraseto_tsquery(domain)` on the `c_identities` GIN index, names extracted via `x509_altnames`/`x509_commonname`. Falls back to `?q=%25.domain&output=json` when :5432 is filtered. Off by default so the tool stays zero-API. |

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

# add Certificate Transparency (crt.sh) — third-party, breaks zero-API mode
python3 find_subdomains.py --domain example.com --ct
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

- **CT coverage requires `--ct`** (crt.sh) — off by default to keep the
  zero-API guarantee. Without it there is no certificate-history
  visibility; that's the deliberate trade-off.
- Replicating crt.sh *without* crt.sh is not possible at scan time: CT
  logs (RFC 6962 `get-entries`) are append-only sequential streams with
  no per-domain index — crt.sh IS the index (built over years of
  continuous ingestion). `--ct` queries that same index; a self-hosted
  equivalent would be a standing ingestion service, not a tool.
- Wildcard certs (`*.foo.example.com`) prove the zone exists but reveal
  no concrete hostnames — reported as `ct_wildcard` source, never
  expanded into invented names.
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

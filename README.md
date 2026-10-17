# SecurityPlatform

Security tooling collection. Currently contains:

## tools/vvm — Visual Vulnerability Mapping

Implements the VVM + AVM teaching method (see `VVM_AVM_AI_White_Paper.pdf`):
annotates a webpage screenshot, marking UI elements as potential vulnerability
entry points (each box is tagged with its vulnerability type, not a number),
and produces an AVM table plus an attack-surface knowledge graph.

```bash
python3 tools/vvm/vvm.py https://example.com/
python3 tools/vvm/vvm.py https://example.com/ -o out.png --check-links
```

Outputs per run:

| File | Contents |
|---|---|
| `vvm-*.png` | Annotated screenshot — red boxes labelled with vulnerability types |
| `*-avm.md` | Table: element → possible vulnerabilities |
| `*-graph.json` | Nodes + edges + provenance (see below) |

Rule-based only, one page load per run. Use only on sites you own or are
authorized to test.

Dependencies: `playwright`, `Pillow`.

### Link classification

External links are split by destination:

- **Social media (BLH scope)** — facebook/fb.com, instagram, twitter.com,
  x.com, youtube/youtu.be, tiktok, telegram/t.me, linkedin →
  `Broken Link Hijacking, Phishing redirect`
- **Other external sites** — labelled `Network (external link)` →
  `Open Redirect` (never Broken Link Hijacking)

## Graph model (`-graph.json`)

Instead of a flat list of findings, the tool also emits a small
knowledge graph — an ontology of objects and typed relations, with
provenance on every element (screenshot file + bounding box).

**Nodes**

| Type | Key properties |
|---|---|
| `Page` | `url` |
| `Element` | `kind`, `label`, `desc`, `vulns`, `prov: {screenshot, bbox}` |
| `Domain` | `host` |
| `Endpoint` | `url` (query string stripped) |
| `Parameter` | `name`, `vulns` |

**Edges**

| Edge | Meaning |
|---|---|
| `Page -hosts-> Element` | element is present on the page |
| `Element -points_to-> Domain` | link targets that domain (stores `href`) |
| `Element -submits_to-> Endpoint` | form `action` target |
| `Element -has_param-> Parameter` | link/URL carries the parameter |
| `Parameter -flows_to-> Endpoint` | parameter reaches the endpoint |

Example chain produced automatically:

    el:24 ("b1 playstore") --has_param--> param:id --flows_to--> ep:play.google.com/store/apps/details
    el:2  (form b1Search)  --submits_to--> ep:beritasatu.com/
    el:12 (button facebook)--points_to---> dom:www.facebook.com      [Broken Link Hijacking]

## Concept — Gotham-style attack-surface analysis

The graph output is the first step toward a Palantir-Gotham-inspired
architecture for web attack-surface analysis:

```
┌─────────────────────────────────────────────────────────┐
│ 4. ANALYST + AI   Queries, verification, narrative       │
├─────────────────────────────────────────────────────────┤
│ 3. RULES          Findings = graph patterns, not labels  │
├─────────────────────────────────────────────────────────┤
│ 2. ONTOLOGY       Objects + Links + Provenance           │
├─────────────────────────────────────────────────────────┤
│ 1. COLLECTORS     DOM, headers, DNS, TLS, JS, links      │
└─────────────────────────────────────────────────────────┘
```

1. **Collectors** — passive fact-gatherers. Today: DOM via Playwright.
   Future: HTTP headers, cookies, TLS cert, DNS/crt.sh/Wayback, JS-bundle
   endpoints. Each normalizes raw data into the shared ontology.
2. **Ontology** — heterogeneous sources become the same objects:
   `Page`, `Element`, `Parameter`, `Endpoint`, `Domain`, `IP`, `Org`.
   Entity resolution merges duplicates (`www.x.com` vs `x.com`, a param
   appearing on five pages).
3. **Rules = graph patterns** — findings carry evidence, not guesses:
   `Link→Domain(expired)` is a *verified* Broken Link Hijack;
   `Input→flows_to→/search→reflects→Page` is reflected XSS *with a
   dataflow*. Attack chains emerge for free as graph traversals
   (`open redirect → OAuth callback → account takeover`).
4. **Analyst + AI** — deterministic foundation first. AVM
   (assumption → inversion) lives here as edge-level reasoning metadata;
   an optional LLM layer can query the graph in natural language
   without inventing findings.

**Passive collectors** (single page load, no extra requests):

- Response headers → `Page.headers` + `Page.missing_headers`
  (CSP, X-Frame-Options, HSTS, XCTO, Referrer-Policy, Permissions-Policy)
- TLS certificate (`secured_by` edge → `Certificate` node)
- Cookies (`sets_cookie` edge → `Cookie` nodes with `missing_flags`)
- Page-host DNS (`hosted_on` → `Domain` → `resolves_to` → `IP` nodes)

**`--check-links`** probes every `points_to` target (DNS NXDOMAIN +
HTTP GET with a browser UA -- HEAD is skipped since many servers answer
it wrong) and writes `target_status` / `dns` / `http` back onto
the graph — turning Broken Link Hijacking from "possible" into
*verified* (e.g. a social-profile link returning 404).

**`graph.findings`** — pattern queries over the graph:

| Pattern | Finding |
|---|---|
| `Element -points_to-> dead target` | Verified BLH (social links) / dead external link |
| `Param(redirect-ish) -flows_to-> external Endpoint` | Open Redirect / redirect-to-auth chain (ATO candidate) |
| `Page` missing XFO & CSP frame-ancestors | Clickjacking exposure |
| `Cookie` with missing flags | Cookie flag hardening (aggregated) |
| `Certificate` validTo < now | Expired TLS certificate (verified) |
| `blanklink` without `rel=noopener` | Reverse Tabnabbing |

Each finding carries `status` (`verified` | `candidate`), a `path` of
node ids through the graph, and `evidence`.

Still ahead:

- JS-bundle collector (API routes, hidden params, secrets patterns)
- crt.sh/Wayback subdomain + historical-endpoint collectors
- Natural-language query layer (LLM) over the graph

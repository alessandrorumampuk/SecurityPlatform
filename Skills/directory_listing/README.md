# directory_listing

Detect open directory indexes ("Index of /…") and flag sensitive
filenames inside them.

```
base URL ──► directory_listing.py ──► listings + sensitive files → *-dirlist.json
```

## Usage

```bash
python3 directory_listing.py --url https://target.example
python3 directory_listing.py --url https://target.example --delay 0.2 --out /tmp/dl.json
```

## What it does

1. Probes ~70 listing-prone directories (`/files/`, `/uploads/`,
   `/backup/`, `/downloads/`, `/documents/`, …)
2. Confirms a real autoindex page by signature (`Index of`,
   `Directory listing for`, `Parent Directory` + columns) — a plain 200
   is not enough, since SPA fallbacks and custom index pages also
   return 200
3. Parses every `<a href>` entry in the listing
4. Flags filenames matching sensitive-document keywords:
   - Indonesian identity/financial docs: `KTP`, `KK`, `NPWP`, `SIM`,
     `STNK`, `BPKB`, `BPJS`, `SKCK`, `paspor`, `akta`, `rekening`,
     `buku tabungan`, `kartu kredit`/`debit`, `ijazah`, `slip gaji`,
     `surat kuasa`, `mutasi rekening`, …
   - generic secrets: `backup`, `dump`, `database`, `password`,
     `id_rsa`, `.env`, `.pem`, …
   - short codes match as whole tokens (`sim` does not flag
     `simple.png`); phrases match as substrings, so
     `Alessandro KTP.png` still flags on `KTP`
5. Writes a JSON log with `listings[]` = {url, status, server banner,
   entries, sensitive[{name, match}]} — consumed by `vvm.py` and
   `auto_hunt.py` as `Directory Listing` findings (verified when a
   sensitive filename is present, candidate otherwise)

Local lab / authorized targets only.

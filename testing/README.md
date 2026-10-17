# VulnLab — Situs Uji yang Sengaja Rentan

> **PERINGATAN:** Aplikasi ini **sengaja dibuat tidak aman** sebagai target uji
> lokal untuk VVM dan latihan pengujian keamanan manual.
> **Jalankan hanya di `127.0.0.1`. Jangan pernah deploy atau ekspos ke jaringan.**

`app.py` adalah aplikasi web satu-file (Flask + SQLite in-memory) berisi enam
kelas kerentanan yang umum ditemui, dengan data dummy (3 user, 3 produk,
komentar tersimpan). Data hilang setiap kali server restart — by design.

## Menjalankan

```bash
cd SecurityPlatform/testing
python3 app.py          # atau: ../..../.venv/bin/python app.py
# -> http://127.0.0.1:8765
```

Kebutuhan: `flask` (sudah ada di `.venv` repo). Tidak ada setup DB — SQLite
in-memory di-seed otomatis saat start.

## Peta Kerentanan

| # | Kerentanan | Endpoint | Tingkat |
|---|---|---|---|
| 1 | Reflected + Stored XSS | `/search?q=`, `/comment` | High |
| 2 | SQL Injection (UNION + error-based) | `/product?id=` | Critical |
| 3 | IDOR | `/profile?id=` | High |
| 4 | Broken Access Control | `/admin`, `/admin/users.json` | Critical |
| 5 | OTP tanpa rate limit | `/otp`, `/api/verify-otp?code=` | High |
| 6 | Broken Link Hijacking | footer `/` (link sosial mati + domain kedaluwarsa) | Medium |

---

### 1. Cross-Site Scripting (XSS)

**Reflected** — `/search?q=` mencetak input mentah ke HTML:

```bash
curl "http://127.0.0.1:8765/search?q=<script>alert(1)</script>"
# payload tercetak utuh di respons -> tereksekusi di browser
```

**Stored** — `POST /comment` menyimpan komentar tanpa sanitasi; dirender mentah
di beranda untuk setiap pengunjung:

```bash
curl -X POST http://127.0.0.1:8765/comment \
     -d "author=x&body=<img src=x onerror=alert(document.cookie)>"
```

**Akar masalah:** output tidak di-escape (flask `Markup`/string concat),
tidak ada CSP. **Perbaikan:** auto-escape templating, `sanitize`, CSP header.

### 2. SQL Injection

`/product?id=` digabungkan langsung ke query (`f-string`):

```bash
# dump seluruh tabel products
curl "http://127.0.0.1:8765/product?id=-1%20OR%201=1"

# UNION-based: tiriskan tabel users (kolom harus sama jumlahnya: 4)
curl "http://127.0.0.1:8765/product?id=-1%20UNION%20SELECT%20id,username,password,email%20FROM%20users--"

# error-based: input non-numerik membocorkan pesan error DB
curl "http://127.0.0.1:8765/product?id=abc"   # -> "DB error: ..."
```

**Akar masalah:** string concatenation, bukan parameterized query.
**Perbaikan:** `execute("... WHERE id=?", (pid,))` + validasi tipe + sembunyikan
error DB dari response.

### 3. IDOR (Insecure Direct Object Reference)

`/profile?id=` memakai parameterized query (query-nya sendiri aman dari SQLi)
tetapi **tidak ada pemeriksaan kepemilikan/sesi sama sekali**:

```bash
curl "http://127.0.0.1:8765/profile?id=3"   # data admin: email, NIK, saldo
for i in 1 2 3; do curl -s "http://127.0.0.1:8765/profile?id=$i"; done
```

**Pelajaran penting:** query aman ≠ akses aman. **Perbaikan:** autentikasi +
otorisasi per-objek (`session user_id == profile id`), atau gunakan
identifier tak-dapat-ditebak (UUID) *plus* access check.

### 4. Broken Access Control

Dua varian:

```bash
curl http://127.0.0.1:8765/admin              # dashboard internal, 200 tanpa login
curl http://127.0.0.1:8765/admin/users.json   # dump semua user + password plaintext
```

Juga tersembunyi `/admin/notice` yang dirender via `<iframe>` di beranda —
konten internal bocor ke publik.

**Akar masalah:** route sensitif tanpa decorator auth; asumsi "tidak ada yang
tahu URL-nya" (security through obscurity). **Perbaikan:** middleware auth,
deny-by-default, hapus endpoint debug/export, jangan embed konten internal
di halaman publik.

### 5. OTP Tanpa Rate Limit

Login mengeluarkan OTP 4 digit (`/otp`, atau JSON `/api/verify-otp?code=`).
Tidak ada batas percobaan, lockout, expiry, maupun throttle:

```bash
# brute force 0000-9999 — ruang hanya 10.000 kombinasi
for i in $(seq 0 9999); do
  code=$(printf "%04d" $i)
  curl -s "http://127.0.0.1:8765/api/verify-otp?code=$code" | grep -q true \
    && echo "OTP = $code" && break
done
# terbukti: ~5.900 request = beberapa detik saja
```

**Perbaikan:** rate limit + counter percobaan + lockout (mis. 5× gagal →
blokir), expiry pendek, code ≥6 digit, binding ke sesi.

### 6. Broken Link Hijacking

Footer beranda punya tautan "resmi" yang sudah tidak hidup:

| Link | Status | Kenapa berbahaya |
|---|---|---|
| `twitter.com/vulnlab_id` | HTTP 404 | Handle tidak ada → siapa pun bisa klaim & menyamar jadi brand |
| `twitter.com/vulnlab_official_lama2022` | HTTP 404 | Sama — akun "lama" bebas didaftarkan ulang |
| `promo-vulnlab-2023-nonexistent-domain-987654.com` | NXDOMAIN | Domain tidak terdaftar → beli Rp 150rb = phishing atas nama brand |

**Perbaikan:** audit tautan eksternal berkala, hapus link akun lama,
rel="noopener" untuk `target=_blank`.

---

## Demo End-to-End dengan VVM

Dari direktori `tools/vvm/`:

```bash
python3 vvm.py http://127.0.0.1:8765/ -o vulnlab-scan.png --check-links
```

Yang VVM deteksi dari lab ini (hasil terukur):

| Temuan VVM | Melalui |
|---|---|
| Search input → SQLi/XSS/SSTI (kandidat) | RULES `search` |
| Param links `?id=` → IDOR/XSS/SQLi/Open Redirect | RULES `paramlink` |
| Form + hidden `role` → Injection/Parameter Tampering | RULES `form`, `hidden` |
| Comment textarea → Stored XSS | RULES `comment` |
| iframe `/admin/notice` → Content Injection | RULES `iframe` |
| Social links → BLH scope | RULES `sociallink` |
| **`twitter.com/vulnlab*` 404 → BLH TERVERIFIKASI** | `graph.findings` via `--check-links` |
| **promo domain NXDOMAIN → dead link TERVERIFIKASI** | `graph.findings` via `--check-links` |
| No XFO/CSP frame-ancestors → Clickjacking exposure | `analyze_graph` |
| `target=_blank` tanpa `rel=noopener` → Reverse Tabnabbing | `analyze_graph` |

Semuanya muncul di `*-graph.json` sebagai node `Page/Element/Domain/Endpoint`
dengan edge `hosts`, `points_to`, `has_param`, `flows_to` — dan tiap temuan
membawa `status` (`verified`/`candidate`), `path`, dan `evidence`.

Catatan: VVM adalah pemindai **pasif** — ia menandai *permukaan serangan*
(search box = calon injeksi), bukan membuktikan eksploit. Kolom "verified"
di graph hanya berarti *target link terbukti mati*, bukan kerentanan
tereksekusi. Verifikasi manual tetap dilakukan oleh analis — persis
pemisahan Gotham-style: mesin memetakan, manusia memutuskan.

## Struktur File

```
testing/
├── app.py       # aplikasi rentan (Flask, SQLite in-memory, port 8765)
└── README.md    # dokumen ini
```

## Hardening Checklist (untuk latihan remediasi)

- [ ] Escape semua output (`|e` di Jinja / autoescape) + CSP `default-src 'self'`
- [ ] Parameterized query di semua route; sembunyikan error DB
- [ ] Login session + ownership check di `/profile`
- [ ] Auth decorator di `/admin*`; hapus export plaintext password
- [ ] Rate limit + lockout + expiry di `/otp` & `/api/verify-otp`
- [ ] Hapus/tambah `rel="noopener noreferrer"` pada semua `target=_blank`
- [ ] Audit link eksternal — hapus akun/domain mati
- [ ] `X-Frame-Options: DENY` atau CSP `frame-ancestors 'none'`

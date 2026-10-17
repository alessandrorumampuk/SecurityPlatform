# VVM Report

**URL:** http://127.0.0.1:8765/

| # | Element | Possible vulnerabilities |
|---|---|---|
| 1 | Search input — "Cari berita atau produk..." | SQL Injection, Reflected XSS, SSTI, NoSQL Injection |
| 2 | Form — "Nama" | Injection, Mass Assignment, CSRF |
| 3 | Comment / text area — "Tulis komentar..." | Stored XSS, HTML Injection |
| 4 | Form — "Cari" | Injection, Mass Assignment, CSRF |
| 5 | Form — "Kirim" | Injection, Mass Assignment, CSRF |
| 6 | iframe | Content Injection, Clickjacking aid |
| 7 | Link with query parameters — "Profile" | IDOR, Reflected XSS, SQL Injection, Open Redirect |
| 8 | Link with query parameters — "Kaos VVM" | IDOR, Reflected XSS, SQL Injection, Open Redirect |
| 9 | Link with query parameters — "Sticker Pack" | IDOR, Reflected XSS, SQL Injection, Open Redirect |
| 10 | Link with query parameters — "Hoodie" | IDOR, Reflected XSS, SQL Injection, Open Redirect |
| 11 | Social media link (BLH scope) — "Twitter" | Broken Link Hijacking, Phishing redirect |
| 12 | target=_blank link — "Twitter" | Reverse Tabnabbing |
| 13 | Social media link (BLH scope) — "Instagram" | Broken Link Hijacking, Phishing redirect |
| 14 | target=_blank link — "Instagram" | Reverse Tabnabbing |
| 15 | Social media link (BLH scope) — "TikTok" | Broken Link Hijacking, Phishing redirect |
| 16 | target=_blank link — "TikTok" | Reverse Tabnabbing |
| 17 | Social media link (BLH scope) — "Telegram" | Broken Link Hijacking, Phishing redirect |
| 18 | target=_blank link — "Telegram" | Reverse Tabnabbing |
| 19 | Social media link (BLH scope) — "Twitter (lama)" | Broken Link Hijacking, Phishing redirect |
| 20 | target=_blank link — "Twitter (lama)" | Reverse Tabnabbing |
| 21 | Network (external link) — "Portal Promo 2023" | Open Redirect |
| 22 | target=_blank link — "Portal Promo 2023" | Reverse Tabnabbing |

_Use only on sites you own or are authorized to test._
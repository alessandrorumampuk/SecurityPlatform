# VVM Report

**URL:** http://127.0.0.1:8765/

| # | Element | Possible vulnerabilities |
|---|---|---|
| 1 | Search input — "Cari berita atau produk..." | XSS, Information Disclosure |
| 2 | Form — "Nama" | CSRF |
| 3 | Comment / text area — "Tulis komentar..." | XSS |
| 4 | Form — "Cari" | CSRF |
| 5 | Form — "Kirim" | CSRF |
| 6 | iframe |  |
| 7 | Link with query parameters — "Profile" | XSS, Information Disclosure |
| 8 | Link with query parameters — "Kaos VVM" | XSS, Information Disclosure |
| 9 | Link with query parameters — "Sticker Pack" | XSS, Information Disclosure |
| 10 | Link with query parameters — "Hoodie" | XSS, Information Disclosure |
| 11 | Social media link (BLH scope) — "Twitter" | Broken Link Hijacking |
| 12 | target=_blank link — "Twitter" |  |
| 13 | Social media link (BLH scope) — "Instagram" | Broken Link Hijacking |
| 14 | target=_blank link — "Instagram" |  |
| 15 | Social media link (BLH scope) — "TikTok" | Broken Link Hijacking |
| 16 | target=_blank link — "TikTok" |  |
| 17 | Social media link (BLH scope) — "Telegram" | Broken Link Hijacking |
| 18 | target=_blank link — "Telegram" |  |
| 19 | Social media link (BLH scope) — "Twitter (lama)" | Broken Link Hijacking |
| 20 | target=_blank link — "Twitter (lama)" |  |
| 21 | Network (external link) — "Portal Promo 2023" |  |
| 22 | target=_blank link — "Portal Promo 2023" |  |

_Use only on sites you own or are authorized to test._
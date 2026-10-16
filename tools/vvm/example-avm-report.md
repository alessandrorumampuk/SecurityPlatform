# VVM Report

**URL:** https://alessandrorumampuk.com/

| # | Element | Assumption | Inversion | Possible vulnerabilities |
|---|---|---|---|---|
| 1 | Navigation link — "business@alessandrorumampuk.com" | Destination is fixed and safe | Destination is user-controlled elsewhere | Open Redirect, Broken Link Hijacking |
| 2 | External / social link — "LinkedIn" | Old links stay alive and owned | Target expires or is claimed by someone else | Broken Link Hijacking, Phishing redirect |
| 3 | External / social link — "YouTube" | Old links stay alive and owned | Target expires or is claimed by someone else | Broken Link Hijacking, Phishing redirect |
| 4 | target=_blank link — "YouTube" | Opened page is trusted | Opened page rewrites the original tab | Reverse Tabnabbing |

_Use only on sites you own or are authorized to test._
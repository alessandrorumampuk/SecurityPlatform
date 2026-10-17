#!/usr/bin/env python3
"""
Self-test / sanity-check for the four open_*_playwright.py link-verification
tools (Facebook, Instagram, TikTok, YouTube).

For each platform, it checks:
  - 3 randomly generated usernames that do NOT exist (should report NOT FOUND)
  - 3 known-valid, real usernames (should report EXISTS)

Run this BEFORE trusting the results of a batch check against links produced
by social_media_crawler.py. If any platform fails here, its open_*_playwright.py
tool's detection logic needs fixing before the batch results can be trusted.

Usage:
    python3 verify_tools.py                 # test all 4 platforms
    python3 verify_tools.py --platform tiktok
    python3 verify_tools.py --retries 2      # retry a failed platform N times
                                              # (helps with TikTok/anti-bot flakiness)
"""

import argparse
import os
import sys
import json
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generate_random_username import generate_usernames  # noqa: E402
from log_utils import new_log_path  # noqa: E402

# Known-valid, real, large/official accounts that are extremely unlikely to
# ever be deleted - used as the "should exist" control group per platform.
KNOWN_VALID_USERNAMES = {
    "facebook": ["nike", "cocacola", "facebook"],
    "instagram": ["instagram", "cristiano", "nike"],
    "tiktok": ["tiktok", "khaby.lame", "nike"],
    "youtube": ["YouTube", "NASA", "nike"],
}

URL_FORMAT = {
    "facebook": "https://facebook.com/{u}",
    "instagram": "https://instagram.com/{u}",
    "tiktok": "https://tiktok.com/@{u}",
    "youtube": "https://youtube.com/@{u}",
}


def run_facebook(urls):
    from open_facebook_playwright import check_profiles
    return check_profiles(urls, headless=True)


def run_instagram(urls):
    from open_instagram_playwright import check_profiles
    return check_profiles(urls, headless=True)


def run_tiktok(urls):
    from open_tiktok_playwright import check_profiles
    return check_profiles(urls, headless=True)


def run_youtube(urls):
    from open_youtube_playwright import check_profiles
    return check_profiles(urls, headless=True)


RUNNERS = {
    "facebook": run_facebook,
    "instagram": run_instagram,
    "tiktok": run_tiktok,
    "youtube": run_youtube,
}


# Statuses meaning the checker could NOT evaluate the page (blocked, errored,
# ambiguous). Such results must not count as a pass in either direction -
# otherwise a fully-broken checker (always returning exists=False) would
# "pass" every fake-account control while actually seeing nothing.
UNEVALUATED = {"CAPTCHA", "UNVERIFIABLE", "NoResponse", "Unknown"}


def _evaluated(res: dict) -> bool:
    """True if the checker actually evaluated the page (vs blocked/errored)."""
    st = str(res.get("status", ""))
    return st not in UNEVALUATED and not st.startswith("Error")


def verify_platform(platform: str, fake_length: int = 16):
    """
    Run one verification pass for `platform`. Returns (passed: bool, details: list[str], raw_results: list[dict]).
    """
    fake_usernames = generate_usernames(count=3, length=fake_length)
    valid_usernames = KNOWN_VALID_USERNAMES[platform]

    fake_urls = [URL_FORMAT[platform].format(u=u) for u in fake_usernames]
    valid_urls = [URL_FORMAT[platform].format(u=u) for u in valid_usernames]

    print(f"\n{'#' * 70}")
    print(f"# VERIFYING: {platform.upper()}")
    print(f"# Fake (should NOT exist): {', '.join(fake_usernames)}")
    print(f"# Valid (should exist):    {', '.join(valid_usernames)}")
    print(f"{'#' * 70}")

    results = RUNNERS[platform](fake_urls + valid_urls)

    details = []
    raw_results = []
    passed = True

    for res in results[:3]:
        evaluated = _evaluated(res)
        ok = res["exists"] is False and evaluated
        note = "" if evaluated else f" [UNEVALUATED status={res.get('status')}]"
        details.append(f"  [{'PASS' if ok else 'FAIL'}] fake  '{res['username']}' -> exists={res['exists']} (expected False){note}")
        raw_results.append({"username": res["username"], "category": "fake", "expected": False, "actual": res["exists"], "status": res.get("status"), "passed": ok})
        passed = passed and ok

    for res in results[3:]:
        evaluated = _evaluated(res)
        ok = res["exists"] is True and evaluated
        note = "" if evaluated else f" [UNEVALUATED status={res.get('status')}]"
        details.append(f"  [{'PASS' if ok else 'FAIL'}] valid '{res['username']}' -> exists={res['exists']} (expected True){note}")
        raw_results.append({"username": res["username"], "category": "valid", "expected": True, "actual": res["exists"], "status": res.get("status"), "passed": ok})
        passed = passed and ok

    return passed, details, raw_results


def main():
    parser = argparse.ArgumentParser(description="Verify open_*_playwright.py tools before trusting batch results")
    parser.add_argument(
        "--platform", choices=list(RUNNERS.keys()), default=None,
        help="Only verify a single platform (default: verify all 4)"
    )
    parser.add_argument(
        "--retries", type=int, default=1,
        help="Retries for a failed platform before giving up (default: 1, helps with anti-bot flakiness)"
    )
    args = parser.parse_args()

    platforms = [args.platform] if args.platform else list(RUNNERS.keys())

    summary = {}
    full_report = {
        "generated_by": "verify_tools.py",
        "generated_at": datetime.now().isoformat(),
        "platforms_tested": platforms,
        "retries": args.retries,
        "platform_results": {},
    }
    for platform in platforms:
        attempt = 0
        passed, details, raw_results = verify_platform(platform)
        while not passed and attempt < args.retries:
            attempt += 1
            print(f"\n[RETRY {attempt}/{args.retries}] {platform} had failures, retrying once (anti-bot flakiness)...")
            passed, details, raw_results = verify_platform(platform)

        summary[platform] = passed
        full_report["platform_results"][platform] = {
            "passed": passed,
            "retries_used": attempt,
            "details": details,
            "raw_results": raw_results,
        }
        print(f"\n--- {platform.upper()} RESULT: {'PASS' if passed else 'FAIL'} ---")
        for line in details:
            print(line)

    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    all_passed = True
    for platform, passed in summary.items():
        print(f"  {platform:<12} {'[OK] PASS' if passed else '[FAIL] FAIL'}")
        all_passed = all_passed and passed
    print("=" * 70)

    full_report["all_passed"] = all_passed

    # Save verification report to centralized log (Single Source of Truth)
    out_file = new_log_path("broken_link_hijacking_verify", "json")
    with open(out_file, "w") as f:
        json.dump(full_report, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Verification report saved to: {out_file}")

    if all_passed:
        print("\nAll tools verified working correctly. Safe to trust batch check results.")
        sys.exit(0)
    else:
        print("\nOne or more tools failed verification. DO NOT trust batch check results")
        print("until the failing platform's detection logic is fixed.")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Playwright script to open TikTok profile(s), capture response,
and verify if the profile exists. Supports batch testing from a JSON file.
"""

import sys
import time
import json
import os
import argparse
import urllib.parse
from datetime import datetime
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import latest_log_path, new_log_path, generated_by_comment


def _check_single_tiktok_page(page, url: str, username: str, item: str) -> dict:
    """Navigate to `url` and classify whether the TikTok account exists."""
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
    except Exception as nav_err:
        # Anti-bot stalls can blow the 15s navigation budget while still
        # leaving a rendered (captcha/404/profile) page behind - read what
        # we have instead of discarding the attempt as a transport error.
        print(f"   [WARN] navigation incomplete for {username}: {str(nav_err)[:60]} - inspecting partial page")
        response = None

    # Brief wait for client-side rendering
    time.sleep(3)

    status_code = response.status if response else "NoResponse"
    try:
        page_title = page.title()
        page_content = page.content()
        # Use visible inner text instead of raw content to prevent matching localization javascript tags
        page_visible_text = page.inner_text("body")
    except Exception as read_err:
        return {"target": item, "username": username, "exists": False,
                "status": f"Error: {str(read_err)[:40]}"}

    # Check for Captcha / Anti-Bot Blocked page
    is_captcha = (
        "captcha" in page_content.lower() or
        "secsdk" in page_content.lower() or
        "verify" in page_content.lower() or
        page_title in ["", "TikTok - Make Your Day"]
    )

    # Check if it has real profile markers (followers, likes, or translation
    # equivalents). NOTE: "following"/"mengikuti" are intentionally excluded -
    # they're generic nav bar tab labels ("For You | Explore | Following")
    # present on EVERY TikTok page, including 404/nonexistent-account pages,
    # so they caused false "profile exists" positives.
    profile_markers = ["followers", "pengikut", "likes", "suka"]
    has_profile_markers = any(marker in page_visible_text.lower() for marker in profile_markers)

    # TikTok error signatures. Includes both straight (') and
    # typographic/curly (') apostrophe variants since TikTok's
    # rendered text uses the curly apostrophe (U+2019).
    error_keywords = [
        "Couldn't find this account",
        "Couldn\u2019t find this account",
        "Couldn't find this page",
        "Couldn\u2019t find this page",
        "Page not available"
    ]

    is_error_page = any(keyword.lower() in page_visible_text.lower() for keyword in error_keywords) or any(keyword.lower() in page_title.lower() for keyword in error_keywords)

    if is_captcha and not has_profile_markers:
        return {"target": item, "username": username, "exists": False, "status": "CAPTCHA"}
    elif status_code == 404 or is_error_page:
        print(f"   [FAIL] PROFILE DOES NOT EXIST: {username} (404 / Couldn't find this account)")
        return {"target": item, "username": username, "exists": False, "status": status_code}
    elif has_profile_markers:
        print(f"   [OK] PROFILE EXISTS: {username}!")
        return {"target": item, "username": username, "exists": True, "status": status_code}
    else:
        # Fallback: no error keywords, no profile markers, and no
        # captcha detected - we genuinely can't confirm existence.
        # Default to "does not exist" (fail-safe) instead of
        # assuming it exists, since false positives are far more
        # dangerous for link-hijacking detection than false
        # negatives (which just need a manual re-check).
        print(f"   [WARN] UNVERIFIABLE: {username} (ambiguous response, treating as not confirmed)")
        return {"target": item, "username": username, "exists": False, "status": "UNVERIFIABLE"}


def check_profiles(urls_or_usernames: list, headless: bool = False):
    """
    Check a batch of TikTok profiles/URLs and report if they exist.
    Reuses the same browser instance for efficiency.
    """
    print("=" * 70)
    print(f"Testing {len(urls_or_usernames)} TikTok link(s)...")
    print("=" * 70)
    print(f"Launching Playwright browser (headless={headless})...")
    
    results = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, channel="chrome", args=[] if headless else ["--start-maximized"])
        context = browser.new_context(
            no_viewport=True if not headless else False,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        
        for idx, item in enumerate(urls_or_usernames, 1):
            # Normalize target URL and username
            normalized_item = item.strip()
            if not normalized_item.startswith("http"):
                # Prepend https://
                if normalized_item.startswith("tiktok.com"):
                    url = "https://" + normalized_item
                else:
                    username = normalized_item.strip('@')
                    url = f"https://www.tiktok.com/@{username}"
            else:
                url = normalized_item
                
            # Extract username for display
            parsed = urllib.parse.urlparse(url)
            parts = [p for p in parsed.path.split('/') if p]
            username = "Unknown"
            for part in parts:
                if part.startswith('@'):
                    username = part
                    break
            if username == "Unknown" and parts:
                username = parts[0]
                
            print(f"\n[{idx}/{len(urls_or_usernames)}] Checking: {url}")
            
            outcome = None
            for attempt in range(2):  # 1 retry if blocked by anti-bot/captcha
                try:
                    outcome = _check_single_tiktok_page(page, url, username, item)
                    if outcome["status"] != "CAPTCHA":
                        break
                    if attempt == 0:
                        print(f"   [WARN] CAPTCHA detected for {username}, backing off and retrying once...")
                        time.sleep(6)
                except Exception as e:
                    error_str = str(e)
                    print(f"   [WARN] Error checking {url}: {error_str[:60]}...")
                    outcome = {"target": item, "username": username, "exists": False, "status": f"Error: {error_str[:40]}"}
                    break

            if outcome["status"] == "CAPTCHA":
                print(f"   [WARN] UNVERIFIABLE: {username} (Blocked by TikTok Anti-Bot/Captcha, after retry)")
            results.append(outcome)
                
            # Inter-request delay to prevent rate limits / anti-bot escalation
            if idx < len(urls_or_usernames):
                time.sleep(4)
                
        browser.close()
        
    # Print a beautiful summary table
    print("\n" + "=" * 70)
    print("TIKTOK BATCH CHECK SUMMARY")
    print("=" * 70)
    print(f"{'No.':<4} | {'Username/Target':<30} | {'Status':<15} | {'Code':<6}")
    print("-" * 70)
    
    for i, res in enumerate(results, 1):
        status_str = "[OK] EXISTS" if res["exists"] else "[FAIL] NOT FOUND"
        print(f"{i:<4} | {res['username'][:30]:<30} | {status_str:<15} | {res['status']:<6}")
        
    print("=" * 70 + "\n")
    return results


def load_tiktok_links_from_json(json_path: str) -> list:
    """Load tiktok URLs from crawler JSON output file"""
    if not os.path.exists(json_path):
        print(f"[ERROR] Error: File not found: {json_path}")
        sys.exit(1)
        
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Try direct JSON parsing first to avoid comment-stripping bugs on malformed URLs
        try:
            data = json.loads(content)
        except Exception:
            # Clean inline comments like // YouTube, Instagram if direct load fails
            import re
            cleaned_content = []
            for line in content.splitlines():
                # Strip single-line comments that are not part of http:// or https://
                line_cleaned = re.sub(r'(?<!https:)(?<!http:)//.*$', '', line)
                cleaned_content.append(line_cleaned)
            
            cleaned_json_str = '\n'.join(cleaned_content)
            data = json.loads(cleaned_json_str)
            
        # Try structured format under 'tiktok'
        tiktok_entries = data.get("social_media", {}).get("tiktok", [])
        
        urls = []
        for entry in tiktok_entries:
            if isinstance(entry, dict) and "url" in entry:
                urls.append(entry["url"])
            elif isinstance(entry, str):
                urls.append(entry)
                
        return urls
    except Exception as e:
        print(f"[ERROR] Error reading JSON: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Check if a TikTok profile or a list of profiles from JSON exists using Playwright"
    )
    parser.add_argument(
        "username",
        nargs="?",
        default=None,
        help="Single TikTok username or URL to check"
    )
    parser.add_argument(
        "--file", "-f",
        default=None,
        help="Path to JSON file containing TikTok links to batch check (default: latest Skills/log/*-broken_link_hijacking.json)"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run in headless mode"
    )
    
    args = parser.parse_args()
    
    # If a file is specified or default exists, batch check
    if args.file:
        json_path = args.file
    else:
        # Default: use the latest centralized log file (Single Source of Truth)
        default_json = latest_log_path("broken_link_hijacking", "json")
        if default_json and os.path.exists(default_json):
            json_path = default_json
        else:
            json_path = None
    
    if json_path:
        urls = load_tiktok_links_from_json(json_path)
        if not urls:
            print(f"[WARN] No TikTok links found in {json_path}.")
            return
        print(f"📄 Loading links from: {json_path}")
        # Default to headless for batch check
        results = check_profiles(urls, headless=True)
    elif args.username:
        results = check_profiles([args.username], headless=args.headless)
    else:
        # Default fallback to checking a known account
        results = check_profiles(["univterbuka"], headless=args.headless)

    # Save results to centralized log (Single Source of Truth)
    out_file = new_log_path("broken_link_hijacking_tiktok_verify", "json")
    with open(out_file, "w") as f:
        json.dump({
            "generated_by": "open_tiktok_playwright.py",
            "generated_at": datetime.now().isoformat(),
            "input_source": json_path or "cli",
            "total_checked": len(results),
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Results saved to: {out_file}")


if __name__ == "__main__":
    main()

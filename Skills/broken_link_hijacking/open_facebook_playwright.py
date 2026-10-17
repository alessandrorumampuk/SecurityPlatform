#!/usr/bin/env python3
"""
Playwright script to open Facebook profile(s)/link(s), capture response,
and verify if the page exists. Supports batch testing from a JSON file.

Uses a separate, isolated persistent Chrome profile (not your real/daily
Chrome profile) so checks are done as a logged-in Facebook user instead
of an anonymous bot - Facebook shows different content/privacy walls to
anonymous visitors, causing false positives/negatives.

NOTE: Chrome intentionally refuses remote-debugging automation (which
Playwright relies on) against its *default* user data directory, as a
security guardrail against exactly this kind of profile takeover. That's
why this script uses its own dedicated profile folder instead of your
real Chrome profile - log in there once and it's reused on every run.

On first run (or with --login), a visible browser window opens so you
can log into Facebook manually; the session is saved to disk under
PROFILE_DIR and reused (headless) on future runs.
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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(SCRIPT_DIR, ".browser_profile", "facebook")


def is_logged_in(page) -> bool:
    """Check if the current Facebook session is logged in."""
    try:
        page.goto("https://www.facebook.com/", wait_until="domcontentloaded", timeout=15000)
        time.sleep(2)
        text = page.inner_text("body").lower()
        login_markers = ["log in to facebook", "masuk facebook", "email atau nomor ponsel", "create new account"]
        return not any(marker in text for marker in login_markers)
    except Exception:
        return False


def ensure_login(force_login: bool = False):
    """
    Ensure PROFILE_DIR has a logged-in Facebook session.
    Opens a visible browser for manual login if needed, then closes it
    so the persistent profile can be reused by the caller.
    """
    os.makedirs(PROFILE_DIR, exist_ok=True)
    profile_is_new = not os.listdir(PROFILE_DIR)

    if not (profile_is_new or force_login):
        return

    print("=" * 70)
    print("Facebook login required (using a logged-in session avoids false")
    print("positives/negatives caused by anonymous/bot detection).")
    print("A browser window will open - please log into Facebook manually.")
    print("=" * 70)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            PROFILE_DIR,
            headless=False,
            channel="chrome",
            args=["--start-maximized"],
            no_viewport=True,
        )
        page = context.pages[0] if context.pages else context.new_page()
        page.goto("https://www.facebook.com/", wait_until="domcontentloaded", timeout=30000)

        print("\n>>> Log into Facebook in the opened browser window.")
        input(">>> Press ENTER here once you are logged in to continue...\n")

        if not is_logged_in(page):
            print("[WARN] Could not confirm login - continuing anyway with current session state.")
        else:
            print("[OK] Facebook session confirmed logged in. Session saved.")

        context.close()


def check_profiles(urls_or_usernames: list, headless: bool = False, force_login: bool = False):
    """
    Check a batch of Facebook profiles/URLs and report if they exist.
    Reuses the same browser instance (with a persistent logged-in
    profile) for efficiency and accuracy.
    """
    ensure_login(force_login=force_login)

    print("=" * 70)
    print(f"Testing {len(urls_or_usernames)} Facebook link(s)...")
    print("=" * 70)
    print(f"Launching Playwright browser (headless={headless}, using logged-in profile)...")
    
    results = []
    
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            PROFILE_DIR,
            headless=headless,
            channel="chrome",
            args=[] if headless else ["--start-maximized"],
            no_viewport=True if not headless else False,
        )
        page = context.pages[0] if context.pages else context.new_page()
        
        for idx, item in enumerate(urls_or_usernames, 1):
            # Normalize target URL and username
            normalized_item = item.strip()
            if not normalized_item.startswith("http"):
                # Prepend https://
                if normalized_item.startswith("facebook.com") or normalized_item.startswith("fb.com"):
                    url = "https://" + normalized_item
                else:
                    url = f"https://www.facebook.com/{normalized_item}"
            else:
                url = normalized_item
                
            # Extract username/name for display
            parsed = urllib.parse.urlparse(url)
            parts = [p for p in parsed.path.split('/') if p]
            username = "Unknown"
            if parts:
                username = parts[0]
                
            print(f"\n[{idx}/{len(urls_or_usernames)}] Checking: {url}")
            
            try:
                # Navigate with 15s timeout
                response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
                
                # Brief wait for client-side rendering
                time.sleep(3)
                
                status_code = response.status if response else "Unknown"
                page_title = page.title()
                
                # Use visible inner text instead of raw content to prevent matching localization javascript tags
                page_visible_text = page.inner_text("body")
                
                # Facebook error signatures and generic landing pages (indicating dead links/redirects to login)
                error_keywords = [
                    "This page isn't available",
                    "This content isn't available",
                    "This content isn't available right now",
                    "Sorry about that",
                    "Try searching for something else",
                    "Halaman ini tidak tersedia",
                    "Konten ini tidak tersedia",
                    "Halaman tidak ditemukan",
                    "Page not found",
                    "404 Not Found"
                ]
                
                # Check for generic login landing page (which Facebook redirects to for dead profiles)
                generic_login_keywords = [
                    "Explore the things you love",
                    "Jelajahi hal yang Anda sukai",
                    "Jelajahi hal yang anda sukai",
                    "Jelajahi hal-hal yang Anda sukai",
                    "Jelajahi hal-hal yang anda sukai",
                    "Log in to Facebook",
                    "Facebook – log in or sign up",
                    "Facebook - Masuk atau Daftar",
                    "Masuk Facebook",
                    "Email atau nomor ponsel",
                    "Lupa kata sandi?",
                    "Buat akun baru",
                    "Create new account",
                    "Forgotten password?"
                ]
                
                # A profile is dead if it has error keywords, OR if it loads the generic login page 
                # without showing any profile-specific indicators like "See more from" or "See more of"
                has_error_keyword = any(keyword.lower() in page_visible_text.lower() for keyword in error_keywords) or any(keyword.lower() in page_title.lower() for keyword in error_keywords)
                
                is_generic_login = any(keyword.lower() in page_visible_text.lower() for keyword in generic_login_keywords) or any(keyword.lower() in page_title.lower() for keyword in generic_login_keywords)
                has_profile_context = any(kw in page_visible_text.lower() for kw in ["see more from", "see more of", "lihat lebih banyak dari", "lihat postingan", "posts", "postingan"])
                
                # If it's a generic login page and doesn't contain profile context, it's considered non-existent
                is_dead_profile = has_error_keyword or (is_generic_login and not has_profile_context)
                
                if status_code == 404 or is_dead_profile:
                    print(f"   [FAIL] PAGE DOES NOT EXIST: {username} (404 / Page Not Available)")
                    results.append({"target": item, "username": username, "exists": False, "status": status_code})
                else:
                    print(f"   [OK] PAGE EXISTS: {username}!")
                    results.append({"target": item, "username": username, "exists": True, "status": status_code})
                    
            except Exception as e:
                error_str = str(e)
                print(f"   [WARN] Error checking {url}: {error_str[:60]}...")
                results.append({"target": item, "username": username, "exists": False, "status": f"Error: {error_str[:40]}"})
                
            # Inter-request delay to prevent rate limits
            if idx < len(urls_or_usernames):
                time.sleep(1.5)
                
        context.close()
        
    # Print a beautiful summary table
    print("\n" + "=" * 70)
    print("FACEBOOK BATCH CHECK SUMMARY")
    print("=" * 70)
    print(f"{'No.':<4} | {'Username/Target':<30} | {'Status':<15} | {'Code':<6}")
    print("-" * 70)
    
    for i, res in enumerate(results, 1):
        status_str = "[OK] EXISTS" if res["exists"] else "[FAIL] NOT FOUND"
        print(f"{i:<4} | {res['username'][:30]:<30} | {status_str:<15} | {res['status']:<6}")
        
    print("=" * 70 + "\n")
    return results


def load_facebook_links_from_json(json_path: str) -> list:
    """Load Facebook URLs from crawler JSON output file"""
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
            # Clean inline comments if direct load fails
            import re
            cleaned_content = []
            for line in content.splitlines():
                # Strip single-line comments that are not part of http:// or https://
                line_cleaned = re.sub(r'(?<!https:)(?<!http:)//.*$', '', line)
                cleaned_content.append(line_cleaned)
            
            cleaned_json_str = '\n'.join(cleaned_content)
            data = json.loads(cleaned_json_str)
            
        # Try structured format under 'facebook'
        facebook_entries = data.get("social_media", {}).get("facebook", [])
        
        urls = []
        for entry in facebook_entries:
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
        description="Check if a Facebook profile or a list of links from JSON exists using Playwright"
    )
    parser.add_argument(
        "username",
        nargs="?",
        default=None,
        help="Single Facebook profile username or URL to check"
    )
    parser.add_argument(
        "--file", "-f",
        default=None,
        help="Path to JSON file containing Facebook links to batch check (default: latest crawl in Skills/log/)"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run in headless mode"
    )
    parser.add_argument(
        "--login",
        action="store_true",
        default=False,
        help="Force opening a visible browser to (re)login to Facebook before checking"
    )
    
    args = parser.parse_args()
    
    # If a file is specified or default exists, batch check
    if args.file:
        json_path = args.file
    else:
        # Default: use the most recent crawl produced by social_media_crawler.py
        # in the centralized Skills/log/ Single Source of Truth
        json_path = latest_log_path("broken_link_hijacking", "json")
    
    if json_path:
        urls = load_facebook_links_from_json(json_path)
        if not urls:
            print(f"[WARN] No Facebook links found in {json_path}.")
            return
        print(f"📄 Loading links from: {json_path}")
        # Default to headless for batch check
        results = check_profiles(urls, headless=True, force_login=args.login)
    elif args.username:
        results = check_profiles([args.username], headless=args.headless, force_login=args.login)
    else:
        # Default fallback to checking a known profile
        results = check_profiles(["WolfsonCam"], headless=args.headless, force_login=args.login)

    # Save results to centralized log (Single Source of Truth)
    out_file = new_log_path("broken_link_hijacking_facebook_verify", "json")
    with open(out_file, "w") as f:
        json.dump({
            "generated_by": "open_facebook_playwright.py",
            "generated_at": datetime.now().isoformat(),
            "input_source": json_path or "cli",
            "total_checked": len(results),
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Results saved to: {out_file}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Playwright script to open Instagram profile(s), capture response,
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


def check_profiles(urls_or_usernames: list, headless: bool = False):
    """
    Check a batch of Instagram profiles/URLs and report if they exist.
    Reuses the same browser instance for efficiency.
    """
    print("=" * 70)
    print(f"Testing {len(urls_or_usernames)} Instagram link(s)...")
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
            if item.startswith("http"):
                url = item
                # Extract username from URL
                parsed = urllib.parse.urlparse(item)
                parts = [p for p in parsed.path.split('/') if p]
                username = parts[0] if parts else item
            else:
                username = item
                url = f"https://www.instagram.com/{username.strip('/')}/"
                
            print(f"\n[{idx}/{len(urls_or_usernames)}] Checking: {url}")
            
            try:
                # Navigate with 15s timeout
                response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
                
                # Brief wait for client-side rendering
                time.sleep(2.5)
                
                status_code = response.status if response else "Unknown"
                page_title = page.title()
                page_content = page.content()
                
                # Instagram error signatures
                error_keywords = [
                    "Sorry, this page isn't available",
                    "Maaf, halaman ini tidak tersedia",
                    "Page Not Found",
                    "Halaman Tidak Ditemukan",
                    "Profile isn't available",
                    "Profile not found"
                ]
                
                is_error_page = any(keyword.lower() in page_content.lower() for keyword in error_keywords) or any(keyword.lower() in page_title.lower() for keyword in error_keywords)
                
                if status_code == 404 or is_error_page:
                    print(f"   [FAIL] PROFILE DOES NOT EXIST: @{username} (404 / Page Not Available)")
                    results.append({"target": item, "username": username, "exists": False, "status": status_code})
                else:
                    print(f"   [OK] PROFILE EXISTS: @{username}!")
                    results.append({"target": item, "username": username, "exists": True, "status": status_code})
                    
            except Exception as e:
                error_str = str(e)
                print(f"   [WARN] Error checking {url}: {error_str[:60]}...")
                results.append({"target": item, "username": username, "exists": False, "status": f"Error: {error_str[:40]}"})
                
            # Inter-request delay to prevent rate limits
            if idx < len(urls_or_usernames):
                time.sleep(1)
                
        browser.close()
        
    # Print a beautiful summary table
    print("\n" + "=" * 70)
    print("INSTAGRAM BATCH CHECK SUMMARY")
    print("=" * 70)
    print(f"{'No.':<4} | {'Username/Target':<30} | {'Status':<15} | {'Code':<6}")
    print("-" * 70)
    
    for i, res in enumerate(results, 1):
        status_str = "[OK] EXISTS" if res["exists"] else "[FAIL] NOT FOUND"
        print(f"{i:<4} | {res['username'][:30]:<30} | {status_str:<15} | {res['status']:<6}")
        
    print("=" * 70 + "\n")
    return results


def load_instagram_links_from_json(json_path: str) -> list:
    """Load instagram URLs from crawler JSON output file"""
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
            
        # Try both structured formats
        instagram_entries = data.get("social_media", {}).get("instagram", [])
        
        urls = []
        for entry in instagram_entries:
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
        description="Check if an Instagram profile or a list of profiles from JSON exists using Playwright"
    )
    parser.add_argument(
        "username",
        nargs="?",
        default=None,
        help="Single Instagram username or URL to check"
    )
    parser.add_argument(
        "--file", "-f",
        default=None,
        help="Path to JSON file containing Instagram links to batch check (default: latest crawl in Skills/log/)"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run in headless mode (default for single check is non-headless, but default for file is headless)"
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
        urls = load_instagram_links_from_json(json_path)
        if not urls:
            print(f"[WARN] No Instagram links found in {json_path}.")
            return
        print(f"📄 Loading links from: {json_path}")
        # Default to headless for batch check unless explicitly overridden
        headless = args.headless or not sys.stdin.isatty()
        # You can force headless=True for batch if desired to be fast
        results = check_profiles(urls, headless=True)
    elif args.username:
        results = check_profiles([args.username], headless=args.headless)
    else:
        # Default fallback to checking alessandrorumampuk
        results = check_profiles(["alessandrorumampuk"], headless=args.headless)

    # Save results to centralized log (Single Source of Truth)
    out_file = new_log_path("broken_link_hijacking_instagram_verify", "json")
    with open(out_file, "w") as f:
        json.dump({
            "generated_by": "open_instagram_playwright.py",
            "generated_at": datetime.now().isoformat(),
            "input_source": json_path or "cli",
            "total_checked": len(results),
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Results saved to: {out_file}")


if __name__ == "__main__":
    main()

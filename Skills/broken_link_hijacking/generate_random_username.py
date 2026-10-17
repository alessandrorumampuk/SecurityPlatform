#!/usr/bin/env python3
"""
Generate random alphanumeric usernames that are (astronomically) unlikely
to correspond to a real social media account. Used to test the accuracy
of the open_*_playwright.py link-verification tools with known-nonexistent
usernames, alongside known-valid usernames.
"""

import argparse
import os
import sys
import json
import random
import string
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

# Hard character limit enforced regardless of --length requested.
# Chosen to stay within the shortest real platform limit (TikTok: 24 chars)
# while leaving room for an "@" or path prefix.
MAX_USERNAME_LENGTH = 20
MIN_USERNAME_LENGTH = 6

ALPHABET = string.ascii_lowercase + string.digits


def generate_username(length: int = 16) -> str:
    """Generate a single random username: starts with a letter, then alnum."""
    length = max(MIN_USERNAME_LENGTH, min(length, MAX_USERNAME_LENGTH))
    first = random.choice(string.ascii_lowercase)
    rest = "".join(random.choice(ALPHABET) for _ in range(length - 1))
    return first + rest


def generate_usernames(count: int = 3, length: int = 16) -> list:
    """Generate `count` unique random usernames."""
    usernames = set()
    while len(usernames) < count:
        usernames.add(generate_username(length))
    return list(usernames)


def main():
    parser = argparse.ArgumentParser(
        description="Generate random usernames for known-nonexistent-account testing"
    )
    parser.add_argument("--count", type=int, default=3, help="How many usernames to generate (default: 3)")
    parser.add_argument(
        "--length", type=int, default=16,
        help=f"Requested username length, clamped to [{MIN_USERNAME_LENGTH}, {MAX_USERNAME_LENGTH}] (default: 16)"
    )
    args = parser.parse_args()

    usernames = generate_usernames(args.count, args.length)
    for username in usernames:
        print(username)

    # Save generated usernames to centralized log (Single Source of Truth)
    out_file = new_log_path("broken_link_hijacking_usernames", "json")
    with open(out_file, "w") as f:
        json.dump({
            "generated_by": "generate_random_username.py",
            "generated_at": datetime.now().isoformat(),
            "count": len(usernames),
            "length": args.length,
            "usernames": usernames,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Saved to: {out_file}", file=sys.stderr)


if __name__ == "__main__":
    main()

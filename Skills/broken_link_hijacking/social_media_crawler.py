#!/usr/bin/env python3
"""
Social Media Link Crawler
Crawl website dan ekstrak semua link media sosial (Instagram, TikTok, YouTube, Facebook, LinkedIn)
"""

import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from typing import Set, Dict, List
import re
import json
import time
from collections import deque
import sys
import ssl
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_loader import load_env
from log_utils import new_log_path, generated_by_comment
load_env()

# Subdomain enumeration/extraction is delegated to the subdomain_finder
# skill (ct_subdomains = crt.sh certwatch Postgres + HTTP JSON fallback;
# extract_subdomains_from_html = in-page *.domain reference mining)
try:
    from subdomain_finder.find_subdomains import (
        ct_subdomains, extract_subdomains_from_html)
except ImportError:
    ct_subdomains = None
    extract_subdomains_from_html = None


class SocialMediaExtractor(HTMLParser):
    """HTML parser untuk ekstrak social media links dan internal links"""
    
    def __init__(self, base_url: str, current_page: str, html_content: str = None, root_domain: str = None, include_subdomains: bool = True):
        super().__init__()
        self.base_url = base_url
        self.current_page = current_page
        self.html_content = html_content
        self.root_domain = root_domain
        self.include_subdomains = include_subdomains
        self.links = set()
        self.social_media = {
            'instagram': [],
            'tiktok': [],
            'youtube': [],
            'facebook': [],
            'linkedin': [],
            'twitter': [],
            'telegram': []
        }
        # Track normalized URLs to avoid duplicates
        self.seen_urls = {
            'instagram': set(),
            'tiktok': set(),
            'youtube': set(),
            'facebook': set(),
            'linkedin': set(),
            'twitter': set(),
            'telegram': set()
        }
        
        # Regex patterns untuk detect social media URLs di mana saja
        self.social_media_patterns = {
            'instagram': [
                r'https?://(?:www\.)?instagram\.com/[^\s"\'<>]+',
                r'https?://(?:www\.)?instagr\.am/[^\s"\'<>]+',
                r'instagram\.com/[a-zA-Z0-9_.]+'
            ],
            'tiktok': [
                r'https?://(?:www\.)?tiktok\.com/[^\s"\'<>]+',
                r'https?://(?:vm\.)?tiktok\.com/[^\s"\'<>]+',
                r'tiktok\.com/@[a-zA-Z0-9_.]+'
            ],
            'youtube': [
                r'https?://(?:www\.)?youtube\.com/[^\s"\'<>]+',
                r'https?://youtu\.be/[^\s"\'<>]+',
                r'youtube\.com/(?:user|channel|c|@)[^\s"\'<>]+'
            ],
            'facebook': [
                r'https?://(?:www\.)?facebook\.com/[^\s"\'<>]+',
                r'https?://(?:www\.)?fb\.com/[^\s"\'<>]+',
                r'https?://(?:www\.)?fb\.me/[^\s"\'<>]+',
                r'facebook\.com/[a-zA-Z0-9_.]+'
            ],
            'linkedin': [
                r'https?://(?:www\.)?linkedin\.com/[^\s"\'<>]+',
                r'https?://(?:www\.)?lnkd\.in/[^\s"\'<>]+',
                r'linkedin\.com/(?:in|company|school)/[^\s"\'<>]+'
            ],
            'twitter': [
                r'https?://(?:www\.)?x\.com/[^\s"\'<>]+',
                r'https?://(?:www\.)?twitter\.com/[^\s"\'<>]+',
                r'https?://t\.co/[^\s"\'<>]+',
                r'x\.com/[a-zA-Z0-9_]+',
                r'twitter\.com/[a-zA-Z0-9_]+'
            ],
            'telegram': [
                r'https?://(?:www\.)?t\.me/[^\s"\'<>]+',
                r'https?://(?:www\.)?telegram\.me/[^\s"\'<>]+',
                r'https?://(?:www\.)?telegram\.dog/[^\s"\'<>]+',
                r't\.me/[a-zA-Z0-9_]+',
                r'telegram\.me/[a-zA-Z0-9_]+'
            ]
        }
    
    def handle_starttag(self, tag, attrs):
        """Handle HTML tags"""
        if tag == 'a':
            for attr, value in attrs:
                if attr == 'href' and value:
                    # Normalize URL
                    full_url = urllib.parse.urljoin(self.base_url, value)
                    
                    # Check if it's a social media link
                    self._check_social_media(full_url, self.current_page)
                    
                    # Add to links if it's same domain
                    if self._is_same_domain(full_url):
                        self.links.add(full_url)
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing http/https difference and trailing slashes"""
        # Convert to lowercase
        normalized = url.lower()
        # Remove protocol (http:// or https://)
        normalized = re.sub(r'^https?://', '', normalized)
        # Remove www.
        normalized = normalized.replace('www.', '')
        # Remove trailing slash
        normalized = normalized.rstrip('/')
        # Remove query parameters for social media links (except important ones)
        if '?' in normalized:
            base, query = normalized.split('?', 1)
            # Keep only important query params
            if 'instagram.com' in base or 'facebook.com' in base or 'linkedin.com' in base:
                # Remove tracking parameters
                normalized = base
        return normalized
    
    def _check_social_media(self, url: str, found_on: str):
        """Check if URL is a social media link (hostname-suffix match)"""
        normalized = self._normalize_url(url)
        try:
            host = urllib.parse.urlparse(url.lower()).netloc
            host = host.split('@')[-1].split(':')[0]  # strip auth and port
            host = host[4:] if host.startswith('www.') else host
        except Exception:
            return
        if not host:
            return

        def _is(*domains):
            return any(host == d or host.endswith('.' + d) for d in domains)

        # Instagram
        if _is('instagram.com', 'instagr.am'):
            if normalized not in self.seen_urls['instagram']:
                self.seen_urls['instagram'].add(normalized)
                self.social_media['instagram'].append({'url': url, 'found_on': found_on})
        
        # TikTok
        elif _is('tiktok.com', 'tiktok.link'):
            if normalized not in self.seen_urls['tiktok']:
                self.seen_urls['tiktok'].add(normalized)
                self.social_media['tiktok'].append({'url': url, 'found_on': found_on})
        
        # YouTube
        elif _is('youtube.com', 'youtu.be'):
            if normalized not in self.seen_urls['youtube']:
                self.seen_urls['youtube'].add(normalized)
                self.social_media['youtube'].append({'url': url, 'found_on': found_on})
        
        # Facebook
        elif _is('facebook.com', 'fb.com', 'fb.me'):
            if normalized not in self.seen_urls['facebook']:
                self.seen_urls['facebook'].add(normalized)
                self.social_media['facebook'].append({'url': url, 'found_on': found_on})
        
        # LinkedIn
        elif _is('linkedin.com', 'lnkd.in'):
            if normalized not in self.seen_urls['linkedin']:
                self.seen_urls['linkedin'].add(normalized)
                self.social_media['linkedin'].append({'url': url, 'found_on': found_on})
        
        # Twitter / X
        elif _is('twitter.com', 'x.com', 't.co'):
            if normalized not in self.seen_urls['twitter']:
                self.seen_urls['twitter'].add(normalized)
                self.social_media['twitter'].append({'url': url, 'found_on': found_on})
        
        # Telegram
        elif _is('t.me', 'telegram.me', 'telegram.dog'):
            if normalized not in self.seen_urls['telegram']:
                self.seen_urls['telegram'].add(normalized)
                self.social_media['telegram'].append({'url': url, 'found_on': found_on})
    
    def extract_from_html_content(self):
        """Extract social media links from raw HTML content using regex"""
        if not self.html_content:
            return
        
        for platform, patterns in self.social_media_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, self.html_content, re.IGNORECASE)
                for match in matches:
                    url = match.group(0)
                    
                    # Normalize URL
                    if not url.startswith('http'):
                        url = 'https://' + url
                    
                    # Clean up URL (remove trailing quotes, brackets, backslashes, etc)
                    url = re.sub(r'["\'>\)\]\\]+$', '', url)
                    
                    # Check if not already added using normalized URL
                    normalized = self._normalize_url(url)
                    if normalized not in self.seen_urls[platform]:
                        self.seen_urls[platform].add(normalized)
                        self.social_media[platform].append({
                            'url': url,
                            'found_on': self.current_page
                        })
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is from same domain or subdomain"""
        try:
            url_domain = urllib.parse.urlparse(url).netloc
            
            # Remove www. for comparison
            url_domain = url_domain.replace('www.', '')
            
            if self.include_subdomains and self.root_domain:
                # Allow subdomains: check if url_domain ends with root_domain
                return url_domain == self.root_domain or url_domain.endswith('.' + self.root_domain)
            else:
                # Only exact domain match
                base_domain = urllib.parse.urlparse(self.base_url).netloc.replace('www.', '')
                return url_domain == base_domain
        except:
            return False


class SocialMediaCrawler:
    """Web crawler untuk ekstrak social media links"""
    
    def __init__(self, start_url: str, max_pages: int = None, delay: float = 0.3, auto_save_interval: int = 10, include_subdomains: bool = True, enumerate_subdomains: bool = True):
        """
        Initialize crawler
        
        Args:
            start_url: Starting URL to crawl
            max_pages: Maximum pages to crawl (None = unlimited, crawl until queue empty)
            delay: Delay between requests in seconds (default: 0.3)
            auto_save_interval: Auto-save every N pages (0 = disable)
            include_subdomains: Include subdomains of the same domain
            enumerate_subdomains: Enumerate subdomains via Certificate Transparency before crawling
        """
        self.start_url = start_url
        self.max_pages = max_pages
        self.delay = delay
        self.auto_save_interval = auto_save_interval
        self.include_subdomains = include_subdomains
        self.enumerate_subdomains = enumerate_subdomains
        
        # Parse base URL
        parsed = urllib.parse.urlparse(start_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Extract root domain (e.g., gorontalokota.go.id from www.gorontalokota.go.id)
        self.root_domain = self._extract_root_domain(parsed.netloc)
        
        # State
        self.visited = set()
        
        # Priority queue system:
        # 1. Main domain pages (highest priority)
        # 2. Subdomain pages (medium priority)
        # 3. Regular pages from main domain (low priority)
        # 4. Regular pages from subdomains (lowest priority)
        self.to_visit = deque()  # Main queue
        self.subdomain_queue = deque()  # Queue for subdomains (priority)
        self.regular_pages_main = deque()  # Regular pages from main domain
        self.regular_pages_subdomain = deque()  # Regular pages from subdomains
        
        # Add common pages that usually have social media links
        common_paths = [
            start_url,
            f"{self.base_url}/contact",
            f"{self.base_url}/about",
            f"{self.base_url}/about-us",
            f"{self.base_url}/kontak",
            f"{self.base_url}/tentang",
            f"{self.base_url}/profil",
            f"{self.base_url}/profile",
        ]
        # Start with main domain common pages
        for path in common_paths:
            self.to_visit.append(path)
        
        self.social_media = {
            'instagram': [],
            'tiktok': [],
            'youtube': [],
            'facebook': [],
            'linkedin': [],
            'twitter': [],
            'telegram': []
        }
        
        # Track normalized URLs globally to avoid duplicates across all pages
        self.seen_urls = {
            'instagram': set(),
            'tiktok': set(),
            'youtube': set(),
            'facebook': set(),
            'linkedin': set(),
            'twitter': set(),
            'telegram': set()
        }
        
        # Stats
        self.pages_crawled = 0
        self.errors = []
        self.subdomains_found = set()  # Track unique subdomains
    
    def _extract_root_domain(self, netloc: str) -> str:
        """Extract root domain from netloc"""
        # Remove www.
        domain = netloc.replace('www.', '')
        
        # For domains like subdomain.example.com, extract example.com
        # For domains like example.co.id, keep the full domain
        parts = domain.split('.')
        
        # If domain has more than 2 parts and last part is common TLD
        if len(parts) >= 3 and parts[-2] in ['co', 'ac', 'gov', 'go', 'or', 'ne', 'com', 'net', 'org']:
            # Keep last 3 parts (e.g., gorontalokota.go.id)
            return '.'.join(parts[-3:])
        elif len(parts) >= 2:
            # Keep last 2 parts (e.g., example.com)
            return '.'.join(parts[-2:])
        else:
            return domain
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is from same domain or subdomain"""
        try:
            url_domain = urllib.parse.urlparse(url).netloc
            
            # Remove www. for comparison
            url_domain = url_domain.replace('www.', '')
            
            if self.include_subdomains:
                # Allow subdomains: check if url_domain ends with root_domain
                # e.g., ppid.gorontalokota.go.id matches gorontalokota.go.id
                return url_domain == self.root_domain or url_domain.endswith('.' + self.root_domain)
            else:
                # Only exact domain match
                base_domain = urllib.parse.urlparse(self.base_url).netloc.replace('www.', '')
                return url_domain == base_domain
        except:
            return False
    
    def _enumerate_subdomains_crtsh(self) -> Set[str]:
        """Enumerate subdomains using Certificate Transparency (crt.sh).

        Delegated to subdomain_finder.find_subdomains.ct_subdomains, which
        queries crt.sh's certwatch Postgres index directly and falls back
        to the HTTP JSON endpoint. Returns plain hostnames plus wildcard
        zone bases (a '*.x.domain' cert is evidence the zone exists).
        """
        print(f"\n🔍 Enumerating subdomains via Certificate Transparency (crt.sh)...")

        if ct_subdomains is None:
            print(f"   ⚠️  subdomain_finder.find_subdomains is not importable")
            print(f"   Continuing with regular crawling...")
            return set()

        try:
            names, wildcard_zones, _raw_count = ct_subdomains(self.root_domain, timeout=60)
            subdomains = set(names) | set(wildcard_zones)

            print(f"   ✅ Found {len(subdomains)} unique subdomains from Certificate Transparency")

            # Display subdomains without adding to queue yet
            for subdomain in sorted(subdomains):
                self.subdomains_found.add(subdomain)
                # Display without www. prefix for cleaner output
                display_name = subdomain.replace('www.', '')
                print(f"      - {display_name}")

            return subdomains

        except Exception as e:
            print(f"   ⚠️  Failed to enumerate subdomains: {str(e)}")
            print(f"   Continuing with regular crawling...")
            return set()
    
    def _scan_enumerated_subdomains(self, subdomains: Set[str], output_file: str, last_save_count: int, start_time: float) -> int:
        """Scan all enumerated subdomains for social media links and other subdomain links"""
        print(f"\n📡 Scanning {len(subdomains)} enumerated subdomains...")
        
        for subdomain in sorted(subdomains):
            subdomain_url = f"https://{subdomain}"
            
            # Skip if already visited
            if subdomain_url in self.visited:
                continue
            
            # Check max_pages limit
            if self.max_pages and self.pages_crawled >= self.max_pages:
                print(f"\n✅ Reached max pages limit ({self.max_pages})")
                break
            
            # Skip non-HTTP(S) URLs
            if not subdomain_url.startswith(('http://', 'https://')):
                continue
            
            # Skip files
            if self._is_file_url(subdomain_url):
                continue
            
            # Crawl the subdomain homepage
            print(f"[{self.pages_crawled + 1}] Scanning enumerated subdomain: {subdomain_url[:80]}...")
            self._crawl_page(subdomain_url)
            
            # Auto-save check
            if self.auto_save_interval > 0 and (self.pages_crawled - last_save_count) >= self.auto_save_interval:
                total_queue = len(self.to_visit) + len(self.subdomain_queue) + len(self.regular_pages_main) + len(self.regular_pages_subdomain)
                print(f"\n💾 Auto-saving results (crawled {self.pages_crawled} pages)...")
                self.save_results(output_file, silent=True)
                last_save_count = self.pages_crawled
                print(f"   Queue remaining: {total_queue} pages")
                print(f"     - Main domain: {len(self.to_visit)} pages")
                print(f"     - Subdomains: {len(self.subdomain_queue)} pages")
                print(f"     - Regular (main): {len(self.regular_pages_main)} pages")
                print(f"     - Regular (subdomain): {len(self.regular_pages_subdomain)} pages")
                print(f"   Elapsed time: {self._format_time(time.time() - start_time)}\n")
            
            # Delay
            time.sleep(self.delay)
        
        return last_save_count
    
    def crawl(self, output_file: str = 'social_media_links.json'):
        """Start crawling"""
        print(f"🕷️  Starting crawler on: {self.start_url}")
        print(f"   Root domain: {self.root_domain}")
        if self.max_pages:
            print(f"   Max pages: {self.max_pages}")
        else:
            print(f"   Max pages: Unlimited (crawl until queue empty)")
        print(f"   Delay: {self.delay}s")
        print(f"   Include subdomains: {'Yes' if self.include_subdomains else 'No'}")
        if self.auto_save_interval > 0:
            print(f"   Auto-save: Every {self.auto_save_interval} pages")
        
        # Step 1: Enumerate subdomains first if enabled
        enumerated_subdomains = set()
        if self.enumerate_subdomains and self.include_subdomains:
            enumerated_subdomains = self._enumerate_subdomains_crtsh()
        
        print()
        start_time = time.time()
        last_save_count = 0
        
        # Step 2: Scan main domain homepage first
        print(f"\n📡 Scanning main domain homepage...")
        while self.to_visit:
            # Check max_pages limit if set
            if self.max_pages and self.pages_crawled >= self.max_pages:
                break
            
            url = self.to_visit.popleft()
            
            # Skip if already visited
            if url in self.visited:
                continue
            
            # Skip non-HTTP(S) URLs
            if not url.startswith(('http://', 'https://')):
                continue
            
            # Skip files
            if self._is_file_url(url):
                continue
            
            # Crawl page
            print(f"[{self.pages_crawled + 1}] Crawling main domain: {url[:80]}...")
            self._crawl_page(url)
            
            # Auto-save periodically
            if self.auto_save_interval > 0 and (self.pages_crawled - last_save_count) >= self.auto_save_interval:
                total_queue = len(self.to_visit) + len(self.subdomain_queue) + len(self.regular_pages_main) + len(self.regular_pages_subdomain)
                print(f"\n💾 Auto-saving results (crawled {self.pages_crawled} pages)...")
                self.save_results(output_file, silent=True)
                last_save_count = self.pages_crawled
                print(f"   Queue remaining: {total_queue} pages")
                print(f"     - Main domain: {len(self.to_visit)} pages")
                print(f"     - Subdomains: {len(self.subdomain_queue)} pages")
                print(f"     - Regular (main): {len(self.regular_pages_main)} pages")
                print(f"     - Regular (subdomain): {len(self.regular_pages_subdomain)} pages")
                print(f"   Elapsed time: {self._format_time(time.time() - start_time)}\n")
            
            # Delay
            time.sleep(self.delay)
        
        # Step 3: Scan all enumerated subdomains
        if enumerated_subdomains:
            last_save_count = self._scan_enumerated_subdomains(
                enumerated_subdomains, output_file, last_save_count, start_time
            )
        
        # Step 4: Now crawl regular pages (subdomain queue, then regular main, then regular subdomain)
        print(f"\n📄 Scanning regular pages...")
        while self.subdomain_queue or self.regular_pages_main or self.regular_pages_subdomain:
            # Check max_pages limit if set
            if self.max_pages and self.pages_crawled >= self.max_pages:
                break
            
            # Priority order:
            # 1. Subdomains discovered during scanning (subdomain_queue)
            # 2. Then regular pages from main domain (regular_pages_main)
            # 3. Finally regular pages from subdomains (regular_pages_subdomain)
            if self.subdomain_queue:
                url = self.subdomain_queue.popleft()
            elif self.regular_pages_main:
                url = self.regular_pages_main.popleft()
            elif self.regular_pages_subdomain:
                url = self.regular_pages_subdomain.popleft()
            else:
                break
            
            # Skip if already visited
            if url in self.visited:
                continue
            
            # Skip non-HTTP(S) URLs
            if not url.startswith(('http://', 'https://')):
                continue
            
            # Skip files
            if self._is_file_url(url):
                continue
            
            # Crawl page
            self._crawl_page(url)
            
            # Auto-save periodically
            if self.auto_save_interval > 0 and (self.pages_crawled - last_save_count) >= self.auto_save_interval:
                total_queue = len(self.to_visit) + len(self.subdomain_queue) + len(self.regular_pages_main) + len(self.regular_pages_subdomain)
                print(f"\n💾 Auto-saving results (crawled {self.pages_crawled} pages)...")
                self.save_results(output_file, silent=True)
                last_save_count = self.pages_crawled
                print(f"   Queue remaining: {total_queue} pages")
                print(f"     - Main domain: {len(self.to_visit)} pages")
                print(f"     - Subdomains: {len(self.subdomain_queue)} pages")
                print(f"     - Regular (main): {len(self.regular_pages_main)} pages")
                print(f"     - Regular (subdomain): {len(self.regular_pages_subdomain)} pages")
                print(f"   Elapsed time: {self._format_time(time.time() - start_time)}\n")
            
            # Delay
            time.sleep(self.delay)
        
        elapsed = time.time() - start_time
        
        # Calculate statistics
        total_social_links = sum(len(set(e['url'] for e in entries)) for entries in self.social_media.values())
        
        total_queue = len(self.to_visit) + len(self.subdomain_queue) + len(self.regular_pages_main) + len(self.regular_pages_subdomain)
        
        print(f"\n\n✅ Crawling completed!")
        print(f"   Pages crawled: {self.pages_crawled}")
        print(f"   Subdomains discovered: {len(self.subdomains_found)}")
        print(f"   Pages in queue (not visited): {total_queue}")
        
        # Count unique social media links
        unique_links = set()
        for platform, entries in self.social_media.items():
            for entry in entries:
                unique_links.add(entry['url'])
        
        print(f"   Social media links found: {len(unique_links)}")
        print(f"   Errors: {len(self.errors)}")
        print(f"   Total time: {elapsed:.1f}s")
        if self.pages_crawled > 0:
            print(f"   Average: {elapsed/self.pages_crawled:.2f}s per page")
        
        if total_queue > 0:
            if self.max_pages:
                print(f"\n⚠️  Note: {total_queue} pages were not visited (reached max_pages limit)")
            else:
                print(f"\n⚠️  Note: {total_queue} pages were not visited (errors or skipped)")
        
        self._print_results()

    def _extract_subdomain_urls_from_html(self, html: str) -> Set[str]:
        """Find <label>.<root_domain> references in raw page HTML.

        Extraction itself lives in find_subdomains.extract_subdomains_from_html
        (single implementation); this only wraps hostnames as https:// URLs
        and drops already-visited roots.
        """
        if extract_subdomains_from_html is None:
            return set()
        hosts = extract_subdomains_from_html(html, self.root_domain)
        return {f"https://{h}" for h in hosts
                if f"https://{h}" not in self.visited}

    def _queue_discovered_subdomains(self, subdomain_urls: Set[str]):
        """Track discovered subdomains and push their roots to subdomain_queue."""
        if not subdomain_urls:
            return

        print(f"   Found {len(subdomain_urls)} subdomain(s) in content")
        for subdomain_url in subdomain_urls:
            subdomain = urllib.parse.urlparse(subdomain_url).netloc.replace('www.', '')
            self.subdomains_found.add(subdomain)
            if subdomain_url not in self.visited and subdomain_url not in self.subdomain_queue:
                self.subdomain_queue.append(subdomain_url)

    def _enqueue_discovered_links(self, links: Set[str]):
        """Sort same-site links into the crawl queues by domain priority."""
        base_domain = urllib.parse.urlparse(self.base_url).netloc.replace('www.', '')

        for link in links:
            # Skip if already in any queue
            if link in self.to_visit or link in self.subdomain_queue or link in self.regular_pages_main or link in self.regular_pages_subdomain:
                continue

            link_domain = urllib.parse.urlparse(link).netloc.replace('www.', '')

            if link_domain == base_domain:
                # Regular page from main domain
                self.regular_pages_main.append(link)
            else:
                # Link is from a subdomain. If the path is root or very
                # short, treat it as a subdomain home page (high priority)
                parsed_link = urllib.parse.urlparse(link)
                path = parsed_link.path.strip('/')

                if not path or path in ['index.html', 'index.php', 'home', '']:
                    self.subdomains_found.add(link_domain)
                    self.subdomain_queue.append(link)
                else:
                    # Regular page from subdomain - lowest priority
                    self.regular_pages_subdomain.append(link)

    def _crawl_page(self, url: str):
        """Crawl single page"""
        try:
            self.visited.add(url)
            self.pages_crawled += 1
            
            total_queue = len(self.to_visit) + len(self.subdomain_queue) + len(self.regular_pages_main) + len(self.regular_pages_subdomain)
            
            if self.max_pages:
                print(f"[{self.pages_crawled}/{self.max_pages}] Crawling: {url[:80]}...")
            else:
                print(f"[{self.pages_crawled}] (Queue: {total_queue}) Crawling: {url[:80]}...")
            
            # Fetch page with redirect handling and cookies
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'
            }
            req = urllib.request.Request(url, headers=headers)
            
            # Create opener with cookie jar and redirect handler
            # Create SSL context that doesn't verify certificates (for websites with invalid SSL)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            cookie_jar = urllib.request.HTTPCookieProcessor()
            https_handler = urllib.request.HTTPSHandler(context=ssl_context)
            opener = urllib.request.build_opener(
                cookie_jar,
                https_handler,
                urllib.request.HTTPRedirectHandler
            )
            
            with opener.open(req, timeout=15) as response:
                # Get final URL after redirects
                final_url = response.geturl()
                if final_url != url:
                    print(f"   Redirected to: {final_url[:60]}...")
                    # Update visited with final URL
                    self.visited.add(final_url)
                
                # Only process HTML
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    return
                
                html = response.read().decode('utf-8', errors='ignore')
            
            # Parse HTML with current page URL
            parser = SocialMediaExtractor(self.base_url, url, html, self.root_domain, self.include_subdomains)
            parser.feed(html)
            
            # Debug: Show HTML info
            print(f"   DEBUG: HTML length: {len(html)} chars")
            print(f"   DEBUG: Found {len(parser.links)} internal links on page")
            
            # Check if website uses JavaScript rendering
            if len(parser.links) == 0 and ('__next' in html or 'react' in html.lower() or 'vue' in html.lower() or 'angular' in html.lower()):
                print(f"   ⚠️  Website may use JavaScript rendering (React/Next.js/Vue/Angular)")
            
            # Also extract from raw HTML using regex
            parser.extract_from_html_content()
            
            # Debug: Check what was extracted
            total_extracted = sum(len(entries) for entries in parser.social_media.values())
            print(f"   DEBUG: Extracted {total_extracted} social media links via regex")
            
            # Debug: Check if HTML contains social media keywords
            html_lower = html.lower()
            social_keywords = ['instagram', 'facebook', 'youtube', 'tiktok', 'linkedin']
            found_keywords = [kw for kw in social_keywords if kw in html_lower]
            if found_keywords:
                print(f"   DEBUG: HTML contains keywords: {', '.join(found_keywords)}")
                
                # Save HTML for debugging if keywords found but no links extracted
                if not any(parser.social_media.values()):
                    debug_file = f"debug_html_{self.pages_crawled}.html"
                    with open(debug_file, 'w', encoding='utf-8') as f:
                        f.write(html)
                    print(f"   DEBUG: Saved HTML to {debug_file} for inspection")
            else:
                print(f"   DEBUG: No social media keywords found in HTML")
            
            # Merge social media links with global deduplication
            found_any = False
            for platform, entries in parser.social_media.items():
                new_entries = 0
                for entry in entries:
                    # Normalize URL to check for duplicates
                    normalized = self._normalize_url(entry['url'])
                    if normalized not in self.seen_urls[platform]:
                        self.seen_urls[platform].add(normalized)
                        self.social_media[platform].append(entry)
                        new_entries += 1
                
                if new_entries > 0:
                    print(f"   Found {new_entries} new {platform} link(s)")
                    found_any = True
            
            if not found_any:
                print(f"   No social media links found (continuing to next page...)")
            
            # Extract subdomains from HTML content and queue their roots
            subdomain_urls = self._extract_subdomain_urls_from_html(html)
            self._queue_discovered_subdomains(subdomain_urls)

            # Add new links to appropriate queue based on domain
            new_links = parser.links - self.visited
            if new_links:
                print(f"   Added {len(new_links)} new page(s) to queue")
            self._enqueue_discovered_links(new_links)
            
        except urllib.error.HTTPError as e:
            # Handle redirects manually (307, 301, 302, etc)
            if e.code in [301, 302, 303, 307, 308]:
                redirect_url = e.headers.get('Location')
                if redirect_url:
                    # Make it absolute URL
                    redirect_url = urllib.parse.urljoin(url, redirect_url)
                    print(f"   Following redirect to: {redirect_url[:60]}...")
                    
                    # Add to queue if not visited (add to front of main queue for immediate processing)
                    if redirect_url not in self.visited:
                        if redirect_url not in self.to_visit:
                            self.to_visit.appendleft(redirect_url)  # Add to front of queue
                    
                    # Don't count this as an error
                    self.pages_crawled -= 1  # Decrement since we didn't actually crawl
                    return
                else:
                    # No Location header - try to read HTML body from error response
                    # Some websites (like ut.ac.id) return 307 with HTML content but no Location
                    try:
                        html = e.read().decode('utf-8', errors='ignore')
                        if html and len(html) > 100:  # Valid HTML content
                            print(f"   ⚠️  HTTP {e.code} without Location header - processing HTML body")
                            
                            # Parse HTML with current page URL
                            parser = SocialMediaExtractor(self.base_url, url, html, self.root_domain, self.include_subdomains)
                            parser.feed(html)
                            
                            # Debug: Show HTML info
                            print(f"   DEBUG: HTML length: {len(html)} chars")
                            print(f"   DEBUG: Found {len(parser.links)} internal links on page")
                            
                            # Extract from raw HTML using regex
                            parser.extract_from_html_content()
                            
                            # Debug: Check what was extracted
                            total_extracted = sum(len(entries) for entries in parser.social_media.values())
                            print(f"   DEBUG: Extracted {total_extracted} social media links via regex")
                            
                            # Merge social media links with global deduplication
                            found_any = False
                            for platform, entries in parser.social_media.items():
                                new_entries = 0
                                for entry in entries:
                                    normalized = self._normalize_url(entry['url'])
                                    if normalized not in self.seen_urls[platform]:
                                        self.seen_urls[platform].add(normalized)
                                        self.social_media[platform].append(entry)
                                        new_entries += 1
                                
                                if new_entries > 0:
                                    print(f"   Found {new_entries} new {platform} link(s)")
                                    found_any = True
                            
                            if not found_any:
                                print(f"   No social media links found (continuing to next page...)")
                            
                            # Extract subdomains and queue new links
                            subdomain_urls = self._extract_subdomain_urls_from_html(html)
                            self._queue_discovered_subdomains(subdomain_urls)

                            new_links = parser.links - self.visited
                            if new_links:
                                print(f"   Added {len(new_links)} new page(s) to queue")
                            self._enqueue_discovered_links(new_links)

                            return  # Successfully processed
                    except Exception as parse_error:
                        print(f"   ⚠️  Failed to parse HTML from {e.code} response: {parse_error}")
            
            error_msg = f"HTTP {e.code} - {url}"
            self.errors.append(error_msg)
            if e.code not in [404, 403]:  # Don't print common errors
                print(f"   ⚠️  {error_msg}")
        
        except urllib.error.URLError as e:
            error_msg = f"URL Error - {url}: {e.reason}"
            self.errors.append(error_msg)
            print(f"   ⚠️  {error_msg}")
        
        except Exception as e:
            error_msg = f"Error - {url}: {str(e)}"
            self.errors.append(error_msg)
            print(f"   ⚠️  {error_msg}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing http/https difference and trailing slashes"""
        # Convert to lowercase
        normalized = url.lower()
        # Remove protocol (http:// or https://)
        normalized = re.sub(r'^https?://', '', normalized)
        # Remove www.
        normalized = normalized.replace('www.', '')
        # Remove trailing slash
        normalized = normalized.rstrip('/')
        # Remove query parameters for social media links (except important ones)
        if '?' in normalized:
            base, query = normalized.split('?', 1)
            # Keep only important query params
            if 'instagram.com' in base or 'facebook.com' in base or 'linkedin.com' in base:
                # Remove tracking parameters
                normalized = base
        return normalized
    
    def _is_file_url(self, url: str) -> bool:
        """Check if URL points to a file"""
        file_extensions = [
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.tar', '.gz', '.jpg', '.jpeg', '.png', '.gif',
            '.mp4', '.mp3', '.avi', '.mov', '.css', '.js', '.xml', '.json'
        ]
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in file_extensions)
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds to human-readable time"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    def _print_results(self):
        """Print crawling results"""
        print("\n" + "="*80)
        print("SOCIAL MEDIA LINKS FOUND")
        print("="*80 + "\n")
        
        total = 0
        for platform, entries in self.social_media.items():
            if entries:
                # Deduplicate by URL
                unique_entries = {}
                for entry in entries:
                    url = entry['url']
                    if url not in unique_entries:
                        unique_entries[url] = []
                    unique_entries[url].append(entry['found_on'])
                
                print(f"📱 {platform.upper()} ({len(unique_entries)} unique link(s)):")
                for url, sources in sorted(unique_entries.items()):
                    print(f"   • {url}")
                    print(f"     Found on {len(sources)} page(s):")
                    for source in sources[:3]:  # Show first 3 sources
                        print(f"       - {source}")
                    if len(sources) > 3:
                        print(f"       ... and {len(sources) - 3} more page(s)")
                print()
                total += len(unique_entries)
        
        if total == 0:
            print("No social media links found.")
        
        print("="*80)
        print(f"Total: {total} unique social media link(s)")
        print("="*80)
    
    def save_results(self, output_file: str = 'social_media_links.json', silent: bool = False):
        """Save results to JSON file"""
        from datetime import datetime
        
        # Deduplicate and organize by URL
        social_media_organized = {}
        for platform, entries in self.social_media.items():
            unique_entries = {}
            for entry in entries:
                url = entry['url']
                if url not in unique_entries:
                    unique_entries[url] = {
                        'url': url,
                        'found_on': []
                    }
                if entry['found_on'] not in unique_entries[url]['found_on']:
                    unique_entries[url]['found_on'].append(entry['found_on'])
            social_media_organized[platform] = sorted(list(unique_entries.values()), key=lambda x: x['url'])
        
        results = {
            'generated_by': 'social_media_crawler.py',
            'start_url': self.start_url,
            'crawled_at': datetime.now().isoformat(),
            'pages_crawled': self.pages_crawled,
            'total_links': sum(len(links) for links in social_media_organized.values()),
            'social_media': social_media_organized,
            'errors': self.errors[:100]  # Save first 100 errors
        }
        
        # Write with compact format for social media entries
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('{\n')
            f.write(f'  "generated_by": "{results["generated_by"]}",\n')
            f.write(f'  "start_url": "{results["start_url"]}",\n')
            f.write(f'  "crawled_at": "{results["crawled_at"]}",\n')
            f.write(f'  "pages_crawled": {results["pages_crawled"]},\n')
            f.write(f'  "total_links": {results["total_links"]},\n')
            f.write('  "social_media": {\n')
            
            platforms = list(social_media_organized.keys())
            for i, platform in enumerate(platforms):
                entries = social_media_organized[platform]
                f.write(f'    "{platform}": [')
                if entries:
                    f.write('\n')
                    for j, entry in enumerate(entries):
                        entry_json = json.dumps(entry, ensure_ascii=False)
                        if j < len(entries) - 1:
                            f.write(f'      {entry_json},\n')
                        else:
                            f.write(f'      {entry_json}\n')
                    f.write('    ]')
                else:
                    f.write(']')
                
                if i < len(platforms) - 1:
                    f.write(',\n')
                else:
                    f.write('\n')
            
            f.write('  },\n')
            f.write('  "errors": ')
            f.write(json.dumps(results['errors'], ensure_ascii=False))
            f.write('\n}\n')
        
        if not silent:
            print(f"\n💾 Results saved to: {output_file}")
        
        # Also save as text file
        text_file = output_file.replace('.json', '.txt')
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(f"{generated_by_comment('social_media_crawler.py')}\n")
            f.write(f"Social Media Links from {self.start_url}\n")
            f.write(f"Pages crawled: {self.pages_crawled}\n")
            f.write("="*80 + "\n\n")
            
            for platform, entries in self.social_media.items():
                # Deduplicate by URL
                unique_entries = {}
                for entry in entries:
                    url = entry['url']
                    if url not in unique_entries:
                        unique_entries[url] = []
                    if entry['found_on'] not in unique_entries[url]:
                        unique_entries[url].append(entry['found_on'])
                
                if unique_entries:
                    f.write(f"{platform.upper()} ({len(unique_entries)} unique link(s)):\n")
                    for url, sources in sorted(unique_entries.items()):
                        f.write(f"  {url}\n")
                        f.write(f"    Found on {len(sources)} page(s):\n")
                        for source in sources:
                            f.write(f"      - {source}\n")
                        f.write("\n")
                    f.write("\n")
        
        if not silent:
            print(f"💾 Text version saved to: {text_file}")


def main():
    """Main function"""
    import argparse
    import os
    
    parser = argparse.ArgumentParser(
        description='Crawl website and extract social media links'
    )
    parser.add_argument(
        '--url',
        default=os.environ.get('CRAWLER_DEFAULT_URL', 'https://www.tudelft.nl'),
        help='Starting URL to crawl (default: from .env CRAWLER_DEFAULT_URL)'
    )
    parser.add_argument(
        '--max-pages',
        type=int,
        default=None,
        help='Maximum number of pages to crawl (default: None = unlimited)'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=0.3,
        help='Delay between requests in seconds (default: 0.3)'
    )
    parser.add_argument(
        '--output',
        default=None,
        help='Output file path (default: auto-save to root directory)'
    )
    parser.add_argument(
        '--auto-save',
        type=int,
        default=10,
        help='Auto-save interval in pages (default: 10, 0 = disable)'
    )
    parser.add_argument(
        '--no-subdomains',
        action='store_true',
        help='Disable subdomain crawling (only crawl exact domain)'
    )
    parser.add_argument(
        '--no-enumerate',
        action='store_true',
        help='Disable subdomain enumeration via Certificate Transparency'
    )
    
    args = parser.parse_args()
    
    # Determine output file path
    if args.output is None:
        # Save to the centralized Skills/log/ Single Source of Truth,
        # named yyyymmdd-hhmmss-broken_link_hijacking.json
        output_file = new_log_path("broken_link_hijacking", "json")
    else:
        output_file = args.output
        
    # Check if output file exists and append counter if it does to avoid conflicts
    if os.path.exists(output_file):
        base, ext = os.path.splitext(output_file)
        counter = 1
        while os.path.exists(f"{base}_{counter}{ext}"):
            counter += 1
        output_file = f"{base}_{counter}{ext}"
        print(f"⚠️  File {os.path.basename(base)}{ext} already exists. Using non-conflicting filename: {os.path.basename(output_file)}")
    
    # Create crawler
    crawler = SocialMediaCrawler(
        start_url=args.url,
        max_pages=args.max_pages,
        delay=args.delay,
        auto_save_interval=args.auto_save,
        include_subdomains=not args.no_subdomains,
        enumerate_subdomains=not args.no_enumerate
    )
    
    # Start crawling
    try:
        crawler.crawl(output_file=output_file)
        crawler.save_results(output_file)
    except KeyboardInterrupt:
        print("\n\n⚠️  Crawling interrupted by user")
        print(f"   Pages crawled so far: {crawler.pages_crawled}")
        crawler._print_results()
        crawler.save_results(output_file)
        sys.exit(0)


if __name__ == '__main__':
    main()

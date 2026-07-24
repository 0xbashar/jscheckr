"""
Advanced web crawler for JavaScript file discovery
Supports both static HTML parsing and dynamic Playwright-based crawling
"""

import asyncio
import re
from typing import List, Set, Dict
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

class JSCrawler:
    """Intelligent crawler for discovering JavaScript files"""
    
    def __init__(self, urls: List[str], use_playwright: bool = False, 
                 threads: int = 5, depth: int = 2):
        self.start_urls = urls
        self.use_playwright = use_playwright
        self.threads = threads
        self.max_depth = depth
        self.visited_urls: Set[str] = set()
        self.js_files: Set[str] = set()
        self.session = None
        
        # JavaScript file patterns
        self.js_patterns = [
            r'\.js$',
            r'\.mjs$',
            r'\.jsx$',
            r'\.es6$',
            r'\.es$',
            r'bundle.*\.js',
            r'chunk.*\.js',
            r'vendor.*\.js',
        ]
        
    async def crawl(self) -> List[str]:
        """Main crawling method"""
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Crawl each starting URL
            tasks = []
            for url in self.start_urls:
                tasks.append(self._crawl_url(url, depth=0))
            
            await asyncio.gather(*tasks)
            
            # If Playwright is enabled, do dynamic crawling
            if self.use_playwright:
                await self._crawl_dynamic()
        
        return list(self.js_files)
    
    async def _crawl_url(self, url: str, depth: int):
        """Crawl a single URL recursively"""
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            async with self.session.get(url, timeout=30) as response:
                if response.status != 200:
                    return
                
                content_type = response.headers.get('Content-Type', '')
                
                # If it's JavaScript, add to list
                if 'javascript' in content_type or url.endswith(('.js', '.mjs')):
                    self.js_files.add(url)
                    return
                
                # Parse HTML for script tags and links
                html = await response.text()
                await self._extract_js_from_html(html, url)
                
        except Exception as e:
            logger.debug(f"Error crawling {url}: {str(e)}")
    
    async def _extract_js_from_html(self, html: str, base_url: str):
        """Extract JavaScript URLs from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find script tags
        for script in soup.find_all('script', src=True):
            js_url = urljoin(base_url, script['src'])
            if self._is_js_file(js_url):
                self.js_files.add(js_url)
        
        # Find links to JS files
        for link in soup.find_all(['a', 'link'], href=True):
            href = urljoin(base_url, link['href'])
            if self._is_js_file(href):
                self.js_files.add(href)
        
        # Extract from inline scripts and data attributes
        patterns = [
            r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']',
            r'(?:import|require)\s*\(?["\']([^"\']+\.js[^"\']*)["\']',
            r'loadScript\(["\']([^"\']+)["\']\)',
            r'\.(?:getScript|load)\(["\']([^"\']+)["\']\)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                js_url = urljoin(base_url, match.group(1))
                if self._is_js_file(js_url):
                    self.js_files.add(js_url)
    
    async def _crawl_dynamic(self):
        """Use Playwright for dynamic JavaScript loading"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not installed. Install with: pip install playwright")
            return
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # Intercept network requests
            async def handle_request(request):
                url = request.url
                if self._is_js_file(url):
                    self.js_files.add(url)
            
            page.on('request', handle_request)
            
            # Visit each URL
            for url in self.start_urls:
                try:
                    await page.goto(url, wait_until='networkidle', timeout=30000)
                    # Scroll to trigger lazy loading
                    await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                    await asyncio.sleep(2)
                except Exception as e:
                    logger.debug(f"Playwright error for {url}: {str(e)}")
            
            await browser.close()
    
    def _is_js_file(self, url: str) -> bool:
        """Check if URL points to a JavaScript file"""
        if not url or 'javascript:void' in url:
            return False
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        return any(re.search(pattern, path) for pattern in self.js_patterns)

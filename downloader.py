"""
Asynchronous JavaScript file downloader with retry logic
"""

import asyncio
import aiohttp
import os
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse
import hashlib
import logging

logger = logging.getLogger(__name__)

class JSDownloader:
    """Downloads JavaScript files with concurrent connections"""
    
    def __init__(self, output_dir: str = './downloads', max_concurrent: int = 10):
        self.output_dir = Path(output_dir) / 'js_files'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
    async def download_batch(self, urls: List[str]) -> List[str]:
        """Download multiple files concurrently"""
        downloaded_files = []
        
        async with aiohttp.ClientSession() as session:
            tasks = [self._download_file(session, url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, str):
                    downloaded_files.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Download failed: {str(result)}")
        
        return downloaded_files
    
    async def _download_file(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Download a single file"""
        async with self.semaphore:
            try:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        content = await response.read()
                        
                        # Generate filename from URL
                        filename = self._generate_filename(url, content)
                        filepath = self.output_dir / filename
                        
                        # Save file
                        with open(filepath, 'wb') as f:
                            f.write(content)
                        
                        logger.debug(f"Downloaded: {url} -> {filename}")
                        return str(filepath)
                    else:
                        logger.warning(f"Failed to download {url}: HTTP {response.status}")
                        return None
                        
            except asyncio.TimeoutError:
                logger.warning(f"Timeout downloading {url}")
                return None
            except Exception as e:
                logger.error(f"Error downloading {url}: {str(e)}")
                return None
    
    def _generate_filename(self, url: str, content: bytes) -> str:
        """Generate unique filename from URL"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Get original filename
        original_name = os.path.basename(path) if path else 'index.js'
        if not original_name.endswith('.js'):
            original_name += '.js'
        
        # Add hash to avoid collisions
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        name, ext = os.path.splitext(original_name)
        
        # Sanitize filename
        safe_name = "".join(c for c in name if c.isalnum() or c in '._-')
        
        return f"{safe_name}_{url_hash}{ext}"

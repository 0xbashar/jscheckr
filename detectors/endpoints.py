"""
API endpoint and URL extractor
"""

import re
from typing import List, Dict
from urllib.parse import urlparse

class EndpointDetector:
    """Detects API endpoints and URLs in JavaScript"""
    
    def __init__(self):
        self.patterns = {
            'API Endpoint': [
                r'(?:fetch|axios|request|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                r'(?:api|base)?[Uu][Rr][Ll]\s*[:=]\s*["\']([^"\']+)["\']',
                r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                r'(?:endpoint|url|href|src|path)\s*[:=]\s*["\']([^"\']+)["\']',
            ],
            'WebSocket': [
                r'(?:ws|wss):\/\/[^\s"\']+',
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            ],
            'GraphQL': [
                r'(?:graphql|gql)\s*[:=]\s*["\']([^"\']+)["\']',
                r'\/graphql[^\s"\']*',
            ],
            'Internal Path': [
                r'(?:\/[a-zA-Z0-9_\-\/]+){2,}',
            ]
        }
    
    def detect(self, content: str, file_path: str) -> List[Dict]:
        """Extract endpoints from JavaScript content"""
        findings = []
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    url = match.group(1) if match.lastindex else match.group(0)
                    
                    # Clean and validate URL
                    url = self._clean_url(url)
                    if not url:
                        continue
                    
                    line_num = content[:match.start()].count('\n') + 1
                    
                    findings.append({
                        'type': category,
                        'value': url,
                        'file': file_path,
                        'line': line_num,
                        'method': self._detect_http_method(content, match.start()),
                        'description': f'Found {category}: {url}'
                    })
        
        return findings
    
    def _clean_url(self, url: str) -> str:
        """Clean and validate URL"""
        url = url.strip().strip("'\"")
        
        # Remove template literals
        url = re.sub(r'\${[^}]+}', 'param', url)
        
        # Check if it looks like a URL or path
        if url.startswith(('http://', 'https://', 'ws://', 'wss://', '/')):
            return url
        
        return url if len(url) > 3 else None
    
    def _detect_http_method(self, content: str, position: int) -> str:
        """Detect HTTP method from context"""
        context = content[max(0, position-100):position]
        
        if re.search(r'\bfetch\b', context):
            return 'GET'
        if re.search(r'\.post\s*\(', context):
            return 'POST'
        if re.search(r'\.put\s*\(', context):
            return 'PUT'
        if re.search(r'\.delete\s*\(', context):
            return 'DELETE'
        if re.search(r'\.patch\s*\(', context):
            return 'PATCH'
        
        return 'GET'

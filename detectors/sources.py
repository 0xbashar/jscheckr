"""
DOM XSS source detector
"""

import re
from typing import List, Dict

class SourceDetector:
    """Detects DOM XSS sources (user-controllable inputs)"""
    
    def __init__(self):
        self.sources = [
            # URL sources
            'window.location',
            'window.location.href',
            'window.location.search',
            'window.location.hash',
            'window.location.pathname',
            'location.href',
            'location.search',
            'location.hash',
            'location.pathname',
            'document.URL',
            'document.documentURI',
            'document.baseURI',
            
            # Navigation sources
            'window.name',
            'history.pushState',
            'history.replaceState',
            
            # Storage sources
            'localStorage.getItem',
            'sessionStorage.getItem',
            'document.cookie',
            
            # Messaging sources
            'postMessage',
            'onmessage',
            
            # DOM sources
            'document.referrer',
            'window.open',
            
            # Form inputs
            'input.value',
            'textarea.value',
            'select.value',
            
            # jQuery sources
            '$(location)',
            '$(window)',
            '$.getUrlParam',
        ]
    
    def detect(self, content: str, file_path: str) -> List[Dict]:
        """Detect DOM XSS sources"""
        findings = []
        
        for source in self.sources:
            # Escape special regex characters
            pattern = re.escape(source)
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                findings.append({
                    'type': 'DOM XSS Source',
                    'value': source,
                    'file': file_path,
                    'line': line_num,
                    'severity': 'MEDIUM',
                    'description': f'Potential DOM XSS source: {source}'
                })
        
        return findings

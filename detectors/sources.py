"""
Enhanced DOM XSS source detector with context-aware false positive reduction
"""

import re
from typing import List, Dict, Optional

class SourceDetector:
    """Detects DOM XSS sources with intelligent false positive reduction"""
    
    def __init__(self):
        self.sources = {
            'CRITICAL': [
                'location.href',
                'location.search', 
                'location.hash',
                'document.referrer',
                'window.name',
            ],
            'HIGH': [
                'location.pathname',
                'document.URL',
                'document.documentURI',
                'document.baseURI',
                'postMessage',
            ],
            'MEDIUM': [
                'localStorage.getItem',
                'sessionStorage.getItem',
                'document.cookie',
                'URLSearchParams',
            ],
            'LOW': [
                'history.pushState',
                'history.replaceState',
                'input.value',
                'textarea.value',
                'select.value',
            ]
        }
        
        # Safe usage patterns
        self.safe_patterns = [
            (r'console\.(?:log|debug|warn|error)\([^)]*location', 'Debug logging'),
            (r'if\s*\([^)]*location', 'Condition check'),
            (r'(?:typeof|instanceof)\s+[\w.]+location', 'Type checking'),
            (r'\/\/.*location', 'Comment'),
            (r'test|spec|mock|stub|spy', 'Test code'),
            (r'switch\s*\([^)]*location', 'Switch statement'),
            (r'case\s+[\w.]+location', 'Case statement'),
        ]
        
        # Dangerous usage patterns (true positives)
        self.dangerous_patterns = [
            # Direct assignment to DOM
            (r'\.innerHTML\s*=\s*.*location', 'innerHTML from location', 'CRITICAL'),
            (r'eval\s*\(.*location', 'eval with location', 'CRITICAL'),
            (r'Function\s*\(.*location', 'Function constructor with location', 'CRITICAL'),
            
            # Dangerous assignments
            (r'document\.write\s*\(.*location', 'document.write with location', 'HIGH'),
            (r'\.outerHTML\s*=\s*.*location', 'outerHTML from location', 'HIGH'),
            (r'insertAdjacentHTML\s*\(.*location', 'insertAdjacentHTML with location', 'HIGH'),
            
            # URL manipulation
            (r'location\.(?:href|replace|assign)\s*[=\(].*location', 'URL redirect with location', 'MEDIUM'),
            (r'window\.open\s*\(.*location', 'window.open with location', 'MEDIUM'),
        ]
    
    def detect(self, content: str, file_path: str) -> List[Dict]:
        """Detect DOM XSS sources with context analysis"""
        findings = []
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if self._is_comment_only(line):
                continue
            
            # Check for dangerous combinations first
            dangerous = self._check_dangerous_combinations(line, line_num, file_path, content)
            if dangerous:
                findings.extend(dangerous)
                continue
            
            # Then check individual sources
            source_findings = self._analyze_sources(line, line_num, file_path, content)
            findings.extend(source_findings)
        
        return findings
    
    def _is_comment_only(self, line: str) -> bool:
        """Check if line is only a comment"""
        stripped = line.strip()
        return (stripped.startswith('//') or 
                stripped.startswith('/*') or 
                stripped.startswith('*') or
                stripped.startswith('#'))
    
    def _check_dangerous_combinations(self, line: str, line_num: int, 
                                     file_path: str, content: str) -> List[Dict]:
        """Check for dangerous source-sink combinations"""
        findings = []
        
        for pattern, description, severity in self.dangerous_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Extract the actual source
                source_match = re.search(r'(?:location\.[a-zA-Z]+|document\.referrer|window\.name|document\.URL)', line)
                source = source_match.group(0) if source_match else 'unknown'
                
                findings.append({
                    'type': 'DOM XSS Source',
                    'value': source,
                    'file': file_path,
                    'line': line_num,
                    'severity': severity,
                    'context': line.strip()[:100],
                    'confidence': 'HIGH',
                    'description': f'[{severity}] Dangerous: {description}'
                })
        
        return findings
    
    def _analyze_sources(self, line: str, line_num: int, file_path: str, 
                        content: str) -> List[Dict]:
        """Analyze individual source appearances"""
        findings = []
        
        for severity, sources in self.sources.items():
            for source in sources:
                if source not in line:
                    continue
                
                # Check if it's a safe usage
                if self._is_safe_source_usage(line, source):
                    continue
                
                # Determine if this source is actually used dangerously
                usage_context = self._get_usage_context(line_num, content, source)
                
                if usage_context['risk_level'] != 'SAFE':
                    findings.append({
                        'type': 'DOM XSS Source',
                        'value': source,
                        'file': file_path,
                        'line': line_num,
                        'severity': severity,
                        'context': line.strip()[:100],
                        'confidence': usage_context['confidence'],
                        'description': usage_context['description']
                    })
        
        return findings
    
    def _is_safe_source_usage(self, line: str, source: str) -> bool:
        """Check if source usage appears safe"""
        
        # Check safe patterns
        for pattern, reason in self.safe_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        # Check if source is being compared or logged
        safe_keywords = ['if', 'switch', 'case', 'console.log', 'console.debug', 
                        'typeof', 'instanceof', '==', '===', '!=']
        
        for keyword in safe_keywords:
            if keyword in line and source in line:
                # Make sure it's not an assignment
                if not re.search(r'=\s*[^=]', line.split(source)[0] if source in line else ''):
                    return True
        
        # Check if it's just reading the value
        if re.search(rf'(?:var|let|const|return)\s+\w+\s*=\s*[\w.]*{re.escape(source)}', line):
            return False  # Variable assignment could be dangerous
        
        return False
    
    def _get_usage_context(self, line_num: int, content: str, source: str) -> Dict:
        """Analyze how the source is being used"""
        lines = content.split('\n')
        
        # Get surrounding context
        start = max(0, line_num - 5)
        end = min(len(lines), line_num + 5)
        context = '\n'.join(lines[start:end])
        
        # Check for dangerous usage in context
        if re.search(rf'\.innerHTML\s*=', context):
            return {
                'risk_level': 'HIGH',
                'confidence': 'HIGH',
                'description': f'Source {source} used near innerHTML assignment'
            }
        
        if re.search(r'eval|Function\(', context):
            return {
                'risk_level': 'CRITICAL',
                'confidence': 'HIGH',
                'description': f'Source {source} used near eval/Function'
            }
        
        if re.search(r'document\.write', context):
            return {
                'risk_level': 'HIGH',
                'confidence': 'MEDIUM',
                'description': f'Source {source} used near document.write'
            }
        
        # Check for URL manipulation
        if re.search(rf'(?:location\.href|location\.replace|window\.open)\s*[=(]', context):
            return {
                'risk_level': 'MEDIUM',
                'confidence': 'MEDIUM',
                'description': f'Source {source} used in URL manipulation'
            }
        
        # Check for storage or cookie operations
        if re.search(r'(?:localStorage|sessionStorage)\.setItem', context):
            return {
                'risk_level': 'LOW',
                'confidence': 'LOW',
                'description': f'Source {source} stored in browser storage'
            }
        
        return {
            'risk_level': 'SAFE',
            'confidence': 'LOW',
            'description': f'Source {source} found but appears safely used'
        }

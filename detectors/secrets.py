"""
Secret and API key detector using regex patterns
"""

import re
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class SecretDetector:
    """Detects secrets, API keys, and tokens in JavaScript"""
    
    def __init__(self):
        self.patterns = {
            'AWS Access Key': r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
            'AWS Secret Key': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'GitHub Token': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}',
            'GitHub OAuth': r'gho_[A-Za-z0-9]{36}',
            'Slack Token': r'xox[baprs]-[0-9A-Za-z\-]+',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
            'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'Generic API Key': r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+["\']([A-Za-z0-9+/=_-]{20,})["\']',
            'Private Key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            'JWT Token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'Generic Token': r'(?i)(?:token|secret|password|auth)["\s:=]+["\']([A-Za-z0-9+/=_-]{10,})["\']',
            'Firebase': r'(?i)firebase\.initializeApp\(\{[^}]*apiKey:\s*["\']([A-Za-z0-9_\-]+)["\']',
            'Twilio': r'sk[0-9a-fA-F]{32}',
            'Mailgun': r'key-[0-9a-fA-F]{32}',
            'Stripe': r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
        }
        
        self.false_positive_patterns = [
            r'example',
            r'test',
            r'xxx',
            r'placeholder',
            r'your[-_]?(?:api[-_]?)?key',
            r'<your',
        ]
    
    def detect(self, content: str, file_path: str) -> List[Dict]:
        """Detect secrets in JavaScript content"""
        findings = []
        
        for secret_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            
            for match in matches:
                value = match.group(0)
                
                # Apply false positive filters
                if self._is_false_positive(value, content, match.start()):
                    continue
                
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                findings.append({
                    'type': secret_type,
                    'value': value,
                    'file': file_path,
                    'line': line_num,
                    'severity': 'HIGH',
                    'description': f'Found {secret_type}'
                })
        
        return findings
    
    def _is_false_positive(self, value: str, content: str, position: int) -> bool:
        """Check if finding is likely a false positive"""
        # Check value against false positive patterns
        for fp_pattern in self.false_positive_patterns:
            if re.search(fp_pattern, value, re.IGNORECASE):
                return True
        
        # Check surrounding context (50 chars before)
        start = max(0, position - 50)
        context = content[start:position].lower()
        
        fp_context = ['example', 'test', 'sample', 'dummy', 'placeholder']
        if any(word in context for word in fp_context):
            return True
        
        return False

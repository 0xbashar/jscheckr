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
    
    # Add these methods to the SecretDetector class:

def _is_false_positive(self, value: str, content: str, position: int) -> bool:
    """Enhanced false positive detection"""
    
    # Check if it's in a test file
    if self._is_test_file(content):
        return True
    
    # Check if it's a known placeholder or example
    known_false_positives = [
        'AKIAIOSFODNN7EXAMPLE',
        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'your-api-key',
        'your_api_key',
        'YOUR_API_KEY',
        'example',
        'sample',
        'test',
        'dummy',
        'xxxx',
        '000000',
        'abcdef',
    ]
    
    value_lower = value.lower()
    if any(fp in value_lower for fp in known_false_positives):
        return True
    
    # Check surrounding context
    context_start = max(0, position - 100)
    context_end = min(len(content), position + len(value) + 100)
    context = content[context_start:context_end].lower()
    
    # False positive indicators in context
    fp_indicators = [
        'example',
        'documentation',
        'placeholder',
        'sample',
        'template',
        'boilerplate',
        'xxxxx',
        'todo',
        'fixme',
        'your-key',
        'your_token',
        'your_secret',
    ]
    
    if any(indicator in context for indicator in fp_indicators):
        return True
    
    # Check if it's in a comment
    line_start = content.rfind('\n', 0, position) + 1
    current_line = content[line_start:content.find('\n', position)]
    
    if current_line.strip().startswith(('//', '/*', '*', '#', '<!--')):
        return True
    
    # Check if it's in a console.log or debug statement
    if re.search(r'console\.(?:log|debug|warn|error|info)', current_line):
        return True
    
    # Check if the value looks like a hash (hex characters only)
    if re.match(r'^[0-9a-fA-F]{32,}$', value):
        # This might be a hash, not a key
        return True
    
    # Check if it's in a variable name (not a value)
    if re.search(rf'(?:var|let|const|function)\s+\w*{re.escape(value)}\w*\s*=', current_line):
        return True
    
    return False

def _is_test_file(self, content: str) -> bool:
    """Check if the file appears to be a test file"""
    test_indicators = [
        r'describe\(', r'it\(', r'test\(', r'expect\(', r'assert\.',
        r'jest\.', r'mocha\.', r'chai\.', r'sinon\.',
        r'\.spec\.', r'\.test\.', r'__tests__',
    ]
    
    # Check first 1000 characters for test indicators
    header = content[:1000]
    return any(re.search(pattern, header) for pattern in test_indicators)

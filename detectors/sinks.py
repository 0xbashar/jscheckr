"""
Enhanced DOM XSS sink detector with context-aware false positive reduction
"""

import re
from typing import List, Dict, Tuple, Optional

class SinkDetector:
    """Detects DOM XSS sinks with context-aware analysis"""
    
    def __init__(self):
        self.sinks = {
            'CRITICAL': [
                'eval',
                'Function',
                'setTimeout',
                'setInterval',
                'setImmediate',
                'execScript',
            ],
            'HIGH': [
                'innerHTML',
                'outerHTML',
                'insertAdjacentHTML',
                'document.write',
                'document.writeln',
            ],
            'MEDIUM': [
                'document.cookie',
                'location.href',
                'location.replace',
                'location.assign',
                'window.open',
            ],
            'LOW': [
                'jQuery.html',
                'jQuery.append',
                'jQuery.prepend',
                'jQuery.after',
                'jQuery.before',
                'jQuery.replaceWith',
            ]
        }
        
        # Patterns that indicate safe usage (false positives)
        self.safe_patterns = [
            # Assignment of static/constant values
            (r'\.innerHTML\s*=\s*["\'][^"\'${}]*["\']\s*;', 'Static string assignment'),
            (r'\.innerHTML\s*=\s*`[^${}]*`\s*;', 'Static template literal'),
            
            # Sanitized content
            (r'\.innerHTML\s*=\s*(?:DOMPurify|sanitize|escape)\(', 'Content sanitization'),
            (r'\.innerHTML\s*=\s*[\w.]+\.textContent', 'Safe textContent transfer'),
            
            # Framework-specific safe usage
            (r'React\.createElement|React\.render', 'React safe rendering'),
            (r'\.innerHTML\s*=\s*["\']\s*["\']', 'Empty string assignment'),
            
            # Comparison/checking (not assignment)
            (r'if\s*\([^)]*\.innerHTML', 'innerHTML in condition'),
            (r'console\.(?:log|debug)\([^)]*\.innerHTML', 'Debug logging'),
            (r'(?:typeof|instanceof)\s+[\w.]+\.innerHTML', 'Type checking'),
            
            # Getting innerHTML value
            (r'(?:var|let|const)\s+\w+\s*=\s*[\w.]+\.innerHTML', 'Reading innerHTML value'),
            (r'return\s+[\w.]+\.innerHTML', 'Returning innerHTML value'),
            
            # DOM manipulation libraries with XSS protection
            (r'\.innerHTML\s*=\s*(?:ReactDOMServer|Vue\.compile|angular\.element)', 'Framework safe usage'),
            
            # Assignment from safe sources
            (r'\.innerHTML\s*=\s*(?:document\.querySelector|getElementById)\([^)]+\)\.(?:textContent|innerText)', 'Safe DOM transfer'),
        ]
        
        # Patterns that indicate dangerous usage (true positives)
        self.dangerous_patterns = [
            # Direct user input
            (r'\.innerHTML\s*=\s*(?:location|window\.location|document\.URL|document\.referrer)', 'URL-based XSS', 'CRITICAL'),
            (r'\.innerHTML\s*=\s*(?:localStorage|sessionStorage)\.getItem', 'Storage-based XSS', 'HIGH'),
            (r'\.innerHTML\s*=\s*(?:document\.cookie|window\.name)', 'Cookie/Window XSS', 'HIGH'),
            
            # URL parameters
            (r'\.innerHTML\s*=\s*(?:URLSearchParams|URL\([^)]+\)\.searchParams)\.get', 'URL param XSS', 'HIGH'),
            
            # AJAX/fetch responses
            (r'\.innerHTML\s*=\s*(?:this\.responseText|response\.data|response\.body)', 'AJAX response XSS', 'MEDIUM'),
            
            # Variable concatenation with user input
            (r'\.innerHTML\s*=\s*[\w.]+\s*\+\s*[\w.]+', 'Variable concatenation', 'MEDIUM'),
            (r'\.innerHTML\s*=\s*`[^`]*\$\{[^}]*location[^}]*\}[^`]*`', 'Template with location', 'HIGH'),
            
            # PostMessage data
            (r'\.innerHTML\s*=\s*(?:event|e|message)\.data', 'PostMessage XSS', 'HIGH'),
            
            # Function calls that might return user input
            (r'\.innerHTML\s*=\s*\w+\(', 'Dynamic function result', 'LOW'),
        ]
        
    def detect(self, content: str, file_path: str) -> List[Dict]:
        """Detect DOM XSS sinks with intelligent false positive reduction"""
        findings = []
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and strings
            if self._is_comment_or_string_only(line):
                continue
            
            # Check for dangerous patterns first
            dangerous_found = self._check_dangerous_patterns(line, line_num, file_path)
            if dangerous_found:
                findings.extend(dangerous_found)
                continue
            
            # Then check for sinks with context
            sink_findings = self._analyze_sinks_in_line(line, line_num, file_path, content, lines)
            findings.extend(sink_findings)
        
        # Cross-line analysis for multi-line patterns
        multi_line_findings = self._analyze_multi_line(content, lines, file_path)
        findings.extend(multi_line_findings)
        
        return findings
    
    def _is_comment_or_string_only(self, line: str) -> bool:
        """Check if line is only comment or string literal"""
        stripped = line.strip()
        
        # Single line comments
        if stripped.startswith('//') or stripped.startswith('#'):
            return True
        
        # Multi-line comment start/end
        if stripped.startswith('/*') or stripped.startswith('*'):
            return True
        
        # Console.log or debug statements
        if re.match(r'console\.(?:log|debug|info|warn|error)\(', stripped):
            return True
        
        return False
    
    def _check_dangerous_patterns(self, line: str, line_num: int, file_path: str) -> List[Dict]:
        """Check for clearly dangerous patterns"""
        findings = []
        
        for pattern, description, severity in self.dangerous_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Extract the actual sink
                sink_match = re.search(r'(\.innerHTML|\.outerHTML|document\.write|eval)', line)
                sink = sink_match.group(1) if sink_match else 'unknown'
                
                findings.append({
                    'type': 'DOM XSS Sink',
                    'value': sink,
                    'file': file_path,
                    'line': line_num,
                    'severity': severity,
                    'context': line.strip()[:100],
                    'confidence': 'HIGH',
                    'description': f'[{severity}] {description}: {line.strip()[:100]}'
                })
        
        return findings
    
    def _analyze_sinks_in_line(self, line: str, line_num: int, file_path: str, 
                              full_content: str, all_lines: List[str]) -> List[Dict]:
        """Analyze sinks with full context"""
        findings = []
        
        for severity, sinks in self.sinks.items():
            for sink in sinks:
                # Check if sink is present
                if sink not in line:
                    continue
                
                # Skip if it's a safe pattern
                if self._is_safe_usage(line, line_num, full_content):
                    continue
                
                # Get surrounding context
                context_start = max(0, line_num - 2)
                context_end = min(len(all_lines), line_num + 2)
                context_lines = all_lines[context_start:context_end]
                context = '\n'.join(context_lines)
                
                # Determine confidence based on usage
                confidence = self._determine_confidence(line, context)
                
                if confidence != 'SAFE':
                    findings.append({
                        'type': 'DOM XSS Sink',
                        'value': sink,
                        'file': file_path,
                        'line': line_num,
                        'severity': severity,
                        'context': line.strip()[:100],
                        'confidence': confidence,
                        'description': f'[{severity}] {self._get_description(sink, line)}'
                    })
        
        return findings
    
    def _is_safe_usage(self, line: str, line_num: int, full_content: str) -> bool:
        """Determine if sink usage appears safe"""
        
        # Check safe patterns
        for pattern, reason in self.safe_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        # Check for sanitization functions in the same scope
        if self._has_sanitization_in_scope(line_num, full_content):
            return True
        
        # Check if it's a test file
        if self._is_test_context(full_content):
            return True
        
        return False
    
    def _has_sanitization_in_scope(self, line_num: int, content: str) -> bool:
        """Check if there's sanitization nearby"""
        # Look for common sanitization patterns within reasonable distance
        lines = content.split('\n')
        start = max(0, line_num - 20)
        end = min(len(lines), line_num + 5)
        
        scope_content = '\n'.join(lines[start:end])
        
        sanitization_patterns = [
            r'DOMPurify\.sanitize',
            r'\.sanitize\(',
            r'\.escape\(',
            r'htmlspecialchars',
            r'createTextNode',
            r'textContent\s*=',
            r'innerText\s*=',
            r'\.replace\(/</g',
            r'encodeURIComponent',
        ]
        
        return any(re.search(pattern, scope_content) for pattern in sanitization_patterns)
    
    def _is_test_context(self, content: str) -> bool:
        """Check if code appears to be test code"""
        test_indicators = [
            r'(?:describe|it|test|expect|assert)\s*\(',
            r'\.spec\.(?:js|ts|jsx|tsx)',
            r'\.test\.(?:js|ts|jsx|tsx)',
            r'mocha|jest|jasmine|qunit',
            r'mock|stub|spy',
        ]
        
        # Check first 500 chars for test context
        header = content[:500].lower()
        return any(re.search(pattern, header, re.IGNORECASE) for pattern in test_indicators)
    
    def _determine_confidence(self, line: str, context: str) -> str:
        """Determine confidence level of finding"""
        
        # High confidence patterns
        high_confidence = [
            r'\.innerHTML\s*=\s*[\w.]+\[[\'"]?\w+[\'"]?\]',  # Dynamic property access
            r'\.innerHTML\s*=\s*[^"\'`;]+\+',  # Concatenation with variables
            r'\.innerHTML\s*=\s*`[^`]*\$\{',  # Template literals with expressions
            r'eval\s*\(\s*[^"\']',  # Eval with non-literal
            r'Function\s*\(\s*[^"\']',  # Function constructor with non-literal
        ]
        
        # Medium confidence patterns
        medium_confidence = [
            r'\.innerHTML\s*=\s*\w+\s*\+\s*\w+',  # Simple concatenation
            r'document\.write\s*\(',  # Any document.write
        ]
        
        # Check high confidence first
        for pattern in high_confidence:
            if re.search(pattern, line, re.IGNORECASE):
                return 'HIGH'
        
        # Check medium confidence
        for pattern in medium_confidence:
            if re.search(pattern, line, re.IGNORECASE):
                return 'MEDIUM'
        
        # Check for assignment vs reading
        if 'innerHTML =' in line or 'innerHTML=' in line:
            return 'LOW'
        
        return 'SAFE'
    
    def _get_description(self, sink: str, line: str) -> str:
        """Generate human-readable description"""
        descriptions = {
            'eval': 'Potentially dangerous eval() with dynamic content',
            'Function': 'Dynamic function constructor usage',
            'innerHTML': 'innerHTML assignment detected',
            'outerHTML': 'outerHTML modification detected',
            'document.write': 'Document write operation detected',
            'document.writeln': 'Document write line operation detected',
        }
        
        base = descriptions.get(sink, f'Usage of {sink}')
        
        # Add specific details based on context
        if 'location' in line:
            base += ' (user-controllable URL)'
        elif 'cookie' in line:
            base += ' (cookie manipulation)'
        elif 'localStorage' in line or 'sessionStorage' in line:
            base += ' (storage-based data)'
        elif 'response' in line or 'fetch' in line:
            base += ' (network response)'
        
        return base
    
    def _analyze_multi_line(self, content: str, lines: List[str], file_path: str) -> List[Dict]:
        """Analyze multi-line patterns that might be dangerous"""
        findings = []
        
        # Look for innerHTML with variable assignment across lines
        pattern = r'(\w+)\s*=\s*[\w.]+\s*\+\s*[\w.]+\s*;[\s\S]{0,100}?\.innerHTML\s*=\s*\1\s*;'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'type': 'DOM XSS Sink',
                'value': 'innerHTML',
                'file': file_path,
                'line': line_num,
                'severity': 'MEDIUM',
                'context': match.group()[:100],
                'confidence': 'MEDIUM',
                'description': 'Multi-line variable used in innerHTML assignment'
            })
        
        return findings

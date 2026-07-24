"""
DOM XSS sink detector
"""

import re
from typing import List, Dict

class SinkDetector:
    """Detects DOM XSS sinks (dangerous output methods)"""
    
    def __init__(self):
        self.sinks = {
            'CRITICAL': [
                'eval(',
                'Function(',
                'setTimeout(',
                'setInterval(',
                'setImmediate(',
                'execScript(',
            ],
            'HIGH': [
                'document.write(',
                'document.writeln(',
                'innerHTML',
                'outerHTML',
                'insertAdjacentHTML',
                'onevent',
            ],
            'MEDIUM': [
                'document.cookie',
                'location.href',
                'location.replace(',
                'location.assign(',
                'window.open(',
            ],
            'LOW': [
                'jQuery.html(',
                'jQuery.append(',
                'jQuery.prepend(',
                'jQuery.after(',
                'jQuery.before(',
                'jQuery.replaceWith(',
                'jQuery.wrap(',
                'jQuery.wrapInner(',
            ]
        }
    
    def detect(self, content: str, file_path: str) -> List[Dict]:
        """Detect DOM XSS sinks"""
        findings = []
        
        for severity, sinks in self.sinks.items():
            for sink in sinks:
                # Escape special regex characters
                pattern = re.escape(sink)
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Get surrounding context
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 30)
                    context = content[start:end].strip()
                    
                    findings.append({
                        'type': 'DOM XSS Sink',
                        'value': sink,
                        'file': file_path,
                        'line': line_num,
                        'severity': severity,
                        'context': context,
                        'description': f'[{severity}] Potential DOM XSS sink: {sink}'
                    })
        
        return findings

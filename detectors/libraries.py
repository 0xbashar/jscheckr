"""
JavaScript library and framework detector
"""

import re
from typing import List, Dict

class LibraryDetector:
    """Detects JavaScript libraries and their versions"""
    
    def __init__(self):
        self.signatures = {
            'jQuery': [
                (r'jQuery\s+v([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
                (r'jquery[.-]?([0-9]+\.[0-9]+\.[0-9]+)\.min\.js', 'filename'),
            ],
            'React': [
                (r'React\s+v([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
                (r'react[.-]?([0-9]+\.[0-9]+\.[0-9]+)', 'filename'),
            ],
            'Angular': [
                (r'@angular\/core@([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
                (r'angular[.-]?([0-9]+\.[0-9]+\.[0-9]+)\.min\.js', 'filename'),
            ],
            'Vue.js': [
                (r'Vue\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
                (r'vue[.-]?([0-9]+\.[0-9]+\.[0-9]+)', 'filename'),
            ],
            'Bootstrap': [
                (r'Bootstrap\s+v?([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
                (r'bootstrap[.-]?([0-9]+\.[0-9]+\.[0-9]+)', 'filename'),
            ],
            'Lodash': [
                (r'lodash\s+v?([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
                (r'lodash[.-]?([0-9]+\.[0-9]+\.[0-9]+)', 'filename'),
            ],
            'Axios': [
                (r'axios\s+v?([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
            ],
            'D3.js': [
                (r'd3\s+v?([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
            ],
            'Three.js': [
                (r'THREE\.REVISION\s*=\s*["\']?([0-9]+)["\']?', 'revision'),
            ],
            'Moment.js': [
                (r'moment\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', 'version'),
            ],
        }
    
    def detect(self, content: str, file_path: str) -> List[Dict]:
        """Detect libraries in JavaScript content"""
        findings = []
        detected_libs = set()
        
        for lib_name, patterns in self.signatures.items():
            if lib_name in detected_libs:
                continue
                
            for pattern, pattern_type in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else 'unknown'
                    
                    findings.append({
                        'type': 'Library',
                        'value': f'{lib_name} v{version}',
                        'file': file_path,
                        'line': content[:match.start()].count('\n') + 1,
                        'library': lib_name,
                        'version': version,
                        'description': f'Detected {lib_name} version {version}'
                    })
                    
                    detected_libs.add(lib_name)
                    break
        
        return findings

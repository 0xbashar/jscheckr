"""
HTML report generator for JSHunter
"""

import json
from typing import Dict, List
from pathlib import Path
import os

class HTMLReporter:
    """Generates interactive HTML reports"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / 'templates'
        
    def generate(self, results: Dict, output_path: str):
        """Generate HTML report"""
        html_content = self._build_html(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _build_html(self, results: Dict) -> str:
        """Build complete HTML report"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSHunter Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        
        .summary-card h3 {{
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}
        
        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            color: #764ba2;
        }}
        
        .findings {{
            padding: 30px;
        }}
        
        .finding-section {{
            margin-bottom: 30px;
        }}
        
        .finding-section h2 {{
            color: #667eea;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            margin-bottom: 20px;
        }}
        
        .finding-item {{
            background: #f8f9fa;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
            transition: transform 0.2s;
        }}
        
        .finding-item:hover {{
            transform: translateX(5px);
        }}
        
        .finding-item.critical {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        
        .finding-item.high {{
            border-left-color: #fd7e14;
            background: #fff8f0;
        }}
        
        .finding-item.medium {{
            border-left-color: #ffc107;
            background: #fffef0;
        }}
        
        .finding-item .type {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        
        .finding-item .detail {{
            color: #666;
            font-size: 0.9em;
            word-break: break-all;
        }}
        
        .finding-item .meta {{
            color: #999;
            font-size: 0.8em;
            margin-top: 5px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 5px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }}
        
        .severity-critical {{
            background: #dc3545;
        }}
        
        .severity-high {{
            background: #fd7e14;
        }}
        
        .severity-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .severity-low {{
            background: #28a745;
        }}
        
        .chart-container {{
            padding: 30px;
            background: white;
        }}
        
        .bar-chart {{
            display: flex;
            align-items: flex-end;
            justify-content: space-around;
            height: 200px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 15px;
        }}
        
        .bar {{
            width: 60px;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
            border-radius: 5px 5px 0 0;
            position: relative;
            transition: all 0.3s;
        }}
        
        .bar:hover {{
            transform: scaleY(1.1);
            filter: brightness(1.1);
        }}
        
        .bar-label {{
            text-align: center;
            margin-top: 10px;
            font-size: 0.9em;
            color: #666;
        }}
        
        .bar-value {{
            position: absolute;
            top: -25px;
            left: 50%;
            transform: translateX(-50%);
            font-weight: bold;
            color: #667eea;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
        }}
        
        @media (max-width: 768px) {{
            .summary {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 1.8em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 JSHunter Analysis Report</h1>
            <p>Advanced JavaScript Security Analysis</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>🔑 Secrets</h3>
                <div class="number">{len(results.get('secrets', []))}</div>
            </div>
            <div class="summary-card">
                <h3>🔗 Endpoints</h3>
                <div class="number">{len(results.get('endpoints', []))}</div>
            </div>
            <div class="summary-card">
                <h3>📚 Libraries</h3>
                <div class="number">{len(results.get('libraries', []))}</div>
            </div>
            <div class="summary-card">
                <h3>⚠️ DOM XSS</h3>
                <div class="number">{len(results.get('dom_xss', []))}</div>
            </div>
        </div>
        
        {self._generate_chart_section(results)}
        
        <div class="findings">
            {self._generate_findings_section(results)}
        </div>
        
        <div class="footer">
            <p>Generated by JSHunter v1.0.0 | Advanced JavaScript Security Analysis Tool</p>
            <p>Report generated on {self._get_timestamp()}</p>
        </div>
    </div>
</body>
</html>'''
    
    def _generate_chart_section(self, results: Dict) -> str:
        """Generate chart visualization"""
        counts = {
            'Secrets': len(results.get('secrets', [])),
            'Endpoints': len(results.get('endpoints', [])),
            'Libraries': len(results.get('libraries', [])),
            'DOM XSS': len(results.get('dom_xss', [])),
            'Sources': len(results.get('sources', [])),
            'Sinks': len(results.get('sinks', []))
        }
        
        max_count = max(counts.values()) if counts.values() else 1
        
        bars = ''
        for label, count in counts.items():
            height = (count / max_count * 150) if max_count > 0 else 0
            bars += f'''
            <div style="text-align: center;">
                <div class="bar" style="height: {max(height, 5)}px;">
                    <div class="bar-value">{count}</div>
                </div>
                <div class="bar-label">{label}</div>
            </div>'''
        
        return f'''
        <div class="chart-container">
            <h2 style="color: #667eea; margin-bottom: 20px;">📊 Findings Distribution</h2>
            <div class="bar-chart">
                {bars}
            </div>
        </div>'''
    
    def _generate_findings_section(self, results: Dict) -> str:
        """Generate detailed findings sections"""
        sections = ''
        
        categories = [
            ('🔑 Secrets Found', 'secrets', 'CRITICAL'),
            ('🔗 Endpoints Discovered', 'endpoints', 'MEDIUM'),
            ('📚 Libraries Detected', 'libraries', 'LOW'),
            ('⚠️ DOM XSS Risks', 'dom_xss', 'HIGH'),
            ('📥 Sources Detected', 'sources', 'MEDIUM'),
            ('📤 Sinks Detected', 'sinks', 'HIGH')
        ]
        
        for title, key, default_severity in categories:
            findings = results.get(key, [])
            if findings:
                sections += f'<div class="finding-section"><h2>{title}</h2>'
                
                for finding in findings:
                    severity = finding.get('severity', default_severity).upper()
                    severity_class = f'severity-{severity.lower()}'
                    
                    sections += f'''
                    <div class="finding-item {severity.lower()}">
                        <div class="type">
                            <span class="severity-badge {severity_class}">{severity}</span>
                            {finding.get('type', 'Unknown')}
                        </div>
                        <div class="detail">{finding.get('value', finding.get('description', ''))}</div>
                        <div class="meta">
                            📄 {finding.get('file', 'Unknown')} 
                            {f"| 📍 Line {finding.get('line', 'N/A')}" if finding.get('line') else ""}
                        </div>
                    </div>'''
                
                sections += '</div>'
        
        return sections if sections else '<p style="text-align: center; color: #666;">No findings to display</p>'
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

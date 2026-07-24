#!/usr/bin/env python3
"""
JSHunter - Advanced JavaScript Security Analysis Tool
AST-based analysis for DOM XSS, secrets, endpoints, and library detection
"""

import argparse
import asyncio
import sys
import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import colorama
from colorama import Fore, Style, init

from crawler import JSCrawler
from downloader import JSDownloader
from beautifier import JSBeautifier
from detectors.secrets import SecretDetector
from detectors.endpoints import EndpointDetector
from detectors.libraries import LibraryDetector
from detectors.sources import SourceDetector
from detectors.sinks import SinkDetector
from report.html import HTMLReporter
from utils import setup_logging, validate_url, ensure_directory

# Initialize colorama
init(autoreset=True)

class JSHunter:
    """Main JSHunter application class"""
    
    def __init__(self, args):
        self.args = args
        self.target_urls = []
        self.js_files = []
        self.analysis_results = {
            'secrets': [],
            'endpoints': [],
            'libraries': [],
            'dom_xss': [],
            'sources': [],
            'sinks': []
        }
        self.logger = setup_logging(args.verbose)
        
    def banner(self):
        """Display ASCII banner"""
        banner_text = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   {Fore.YELLOW}██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗{Fore.CYAN} ║
║   {Fore.YELLOW}██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗{Fore.CYAN}║
║   {Fore.YELLOW}██║███████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝{Fore.CYAN}║
║   {Fore.YELLOW}██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗{Fore.CYAN}║
║   {Fore.YELLOW}██║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║{Fore.CYAN}║
║   {Fore.YELLOW}╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Fore.CYAN}║
║                                                          ║
║   {Fore.GREEN}Advanced JavaScript Security Analysis Tool v1.0{Fore.CYAN}        ║
║   {Fore.WHITE}AST-based • DOM XSS • Secrets • Endpoints • Libraries{Fore.CYAN}    ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner_text)
        
    async def run(self):
        """Main execution flow"""
        self.banner()
        
        try:
            # Phase 1: Crawl and collect JavaScript files
            self.logger.info(f"{Fore.BLUE}[*] Phase 1: Crawling and collecting JavaScript files{Style.RESET_ALL}")
            crawler = JSCrawler(
                self.target_urls,
                use_playwright=self.args.playwright,
                threads=self.args.threads,
                depth=self.args.depth
            )
            self.js_files = await crawler.crawl()
            
            if not self.js_files:
                self.logger.warning(f"{Fore.YELLOW}[!] No JavaScript files found{Style.RESET_ALL}")
                return
            
            self.logger.info(f"{Fore.GREEN}[+] Found {len(self.js_files)} JavaScript files{Style.RESET_ALL}")
            
            # Phase 2: Download JavaScript files
            self.logger.info(f"{Fore.BLUE}[*] Phase 2: Downloading JavaScript files{Style.RESET_ALL}")
            downloader = JSDownloader(self.args.output_dir)
            downloaded_files = await downloader.download_batch(self.js_files)
            
            # Phase 3: Beautify JavaScript
            if not self.args.no_beautify:
                self.logger.info(f"{Fore.BLUE}[*] Phase 3: Beautifying JavaScript{Style.RESET_ALL}")
                beautifier = JSBeautifier()
                beautified_files = beautifier.beautify_batch(downloaded_files)
            else:
                beautified_files = downloaded_files
            
            # Phase 4: AST Analysis
            self.logger.info(f"{Fore.BLUE}[*] Phase 4: AST Analysis{Style.RESET_ALL}")
            await self._run_ast_analysis(beautified_files)
            
            # Phase 5: Pattern-based Detection
            self.logger.info(f"{Fore.BLUE}[*] Phase 5: Pattern-based Detection{Style.RESET_ALL}")
            self._run_pattern_detection(downloaded_files)
            
            # Phase 6: Generate Reports
            self.logger.info(f"{Fore.BLUE}[*] Phase 6: Generating Reports{Style.RESET_ALL}")
            self._generate_reports()
            
            # Display summary
            self._display_summary()
            
        except KeyboardInterrupt:
            self.logger.warning(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    
    async def _run_ast_analysis(self, js_files: List[str]):
        """Run AST-based analysis using Node.js"""
        analyzer_path = Path(__file__).parent / 'ast' / 'analyzer.js'
        
        if not analyzer_path.exists():
            self.logger.warning(f"{Fore.YELLOW}[!] AST analyzer not found, skipping AST analysis{Style.RESET_ALL}")
            return
        
        for js_file in js_files:
            try:
                # Call Node.js AST analyzer
                proc = await asyncio.create_subprocess_exec(
                    'node', str(analyzer_path), js_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                
                if proc.returncode == 0:
                    results = json.loads(stdout)
                    
                    # Process DOM XSS findings
                    if 'dom_xss' in results:
                        self.analysis_results['dom_xss'].extend(results['dom_xss'])
                    
                    # Process taint analysis results
                    if 'taint_flows' in results:
                        for flow in results['taint_flows']:
                            self.analysis_results['sources'].append(flow['source'])
                            self.analysis_results['sinks'].append(flow['sink'])
                else:
                    self.logger.debug(f"AST analysis failed for {js_file}: {stderr.decode()}")
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing {js_file}: {str(e)}")
    
    def _run_pattern_detection(self, js_files: List[str]):
        """Run regex and pattern-based detection"""
        # Initialize detectors
        secret_detector = SecretDetector()
        endpoint_detector = EndpointDetector()
        library_detector = LibraryDetector()
        source_detector = SourceDetector()
        sink_detector = SinkDetector()
        
        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Detect secrets
                secrets = secret_detector.detect(content, js_file)
                self.analysis_results['secrets'].extend(secrets)
                
                # Detect endpoints
                endpoints = endpoint_detector.detect(content, js_file)
                self.analysis_results['endpoints'].extend(endpoints)
                
                # Detect libraries
                libraries = library_detector.detect(content, js_file)
                self.analysis_results['libraries'].extend(libraries)
                
                # Detect sources and sinks
                sources = source_detector.detect(content, js_file)
                sinks = sink_detector.detect(content, js_file)
                self.analysis_results['sources'].extend(sources)
                self.analysis_results['sinks'].extend(sinks)
                
            except Exception as e:
                self.logger.debug(f"Error analyzing {js_file}: {str(e)}")
    
    def _generate_reports(self):
        """Generate output reports in various formats"""
        ensure_directory(self.args.output_dir)
        
        # JSON Report
        if 'json' in self.args.report_format or 'all' in self.args.report_format:
            json_path = os.path.join(self.args.output_dir, 'jshunter_report.json')
            with open(json_path, 'w') as f:
                json.dump(self.analysis_results, f, indent=2)
            self.logger.info(f"{Fore.GREEN}[+] JSON report saved to {json_path}{Style.RESET_ALL}")
        
        # HTML Report
        if 'html' in self.args.report_format or 'all' in self.args.report_format:
            reporter = HTMLReporter()
            html_path = os.path.join(self.args.output_dir, 'jshunter_report.html')
            reporter.generate(self.analysis_results, html_path)
            self.logger.info(f"{Fore.GREEN}[+] HTML report saved to {html_path}{Style.RESET_ALL}")
        
        # SARIF Report
        if 'sarif' in self.args.report_format or 'all' in self.args.report_format:
            sarif_path = os.path.join(self.args.output_dir, 'jshunter_report.sarif')
            self._generate_sarif(sarif_path)
            self.logger.info(f"{Fore.GREEN}[+] SARIF report saved to {sarif_path}{Style.RESET_ALL}")
    
    def _generate_sarif(self, output_path: str):
        """Generate SARIF format report"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "JSHunter",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/jshunter/jshunter"
                    }
                },
                "results": []
            }]
        }
        
        # Add findings as SARIF results
        for category, findings in self.analysis_results.items():
            for finding in findings:
                result = {
                    "ruleId": f"JSHunter/{category}",
                    "level": "warning",
                    "message": {
                        "text": finding.get('description', f'{category} finding')
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('file', 'unknown')
                            },
                            "region": {
                                "startLine": finding.get('line', 1),
                                "startColumn": finding.get('column', 1)
                            }
                        }
                    }]
                }
                sarif['runs'][0]['results'].append(result)
        
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)
    
    def _display_summary(self):
        """Display analysis summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}📊 ANALYSIS SUMMARY")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Count findings
        total_secrets = len(self.analysis_results['secrets'])
        total_endpoints = len(self.analysis_results['endpoints'])
        total_libraries = len(self.analysis_results['libraries'])
        total_dom_xss = len(self.analysis_results['dom_xss'])
        
        print(f"{Fore.GREEN}🔑 Secrets Found: {Fore.WHITE}{total_secrets}")
        print(f"{Fore.GREEN}🔗 Endpoints Found: {Fore.WHITE}{total_endpoints}")
        print(f"{Fore.GREEN}📚 Libraries Detected: {Fore.WHITE}{total_libraries}")
        print(f"{Fore.GREEN}⚠️  DOM XSS Risks: {Fore.WHITE}{total_dom_xss}")
        
        if total_secrets > 0:
            print(f"\n{Fore.YELLOW}🔴 CRITICAL FINDINGS:")
            for secret in self.analysis_results['secrets'][:5]:
                print(f"  {Fore.RED}• {secret['type']}: {Fore.WHITE}{secret['value'][:50]}... "
                      f"{Fore.CYAN}({secret['file']})")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='JSHunter - Advanced JavaScript Security Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  jshunter -u https://example.com
  jshunter -f urls.txt --playwright
  jshunter -u https://example.com --report-format html,json,sarif
  jshunter -f urls.txt -t 10 -d 3 -o ./output
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-u', '--url', help='Target URL to analyze')
    input_group.add_argument('-f', '--file', help='File containing URLs (one per line)')
    
    # Analysis options
    parser.add_argument('-o', '--output-dir', default='./jshunter_output',
                       help='Output directory (default: ./jshunter_output)')
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
    parser.add_argument('-d', '--depth', type=int, default=2,
                       help='Crawl depth (default: 2)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    
    # Feature flags
    parser.add_argument('--playwright', action='store_true',
                       help='Use Playwright for dynamic JavaScript loading')
    parser.add_argument('--no-beautify', action='store_true',
                       help='Skip JavaScript beautification')
    parser.add_argument('--source-maps', action='store_true',
                       help='Attempt to download and parse source maps')
    
    # Report options
    parser.add_argument('--report-format', nargs='+', 
                       default=['html'],
                       choices=['html', 'json', 'sarif', 'all'],
                       help='Report formats (default: html)')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress banner and non-error output')
    parser.add_argument('--version', action='version', version='JSHunter v1.0.0')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    
    # Parse URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    
    # Validate URLs
    valid_urls = [url for url in urls if validate_url(url)]
    if not valid_urls:
        print(f"{Fore.RED}[!] No valid URLs provided{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create and run JSHunter
    hunter = JSHunter(args)
    hunter.target_urls = valid_urls
    
    # Run async main
    asyncio.run(hunter.run())

if __name__ == '__main__':
    main()

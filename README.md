# JSHunter - Advanced JavaScript Security Analysis Tool

JSHunter is a professional-grade JavaScript security analysis tool that performs AST-based analysis to detect DOM XSS vulnerabilities, secrets, API endpoints, and library versions in JavaScript files.

## Features

- 🔍 **AST-based Analysis**: Deep JavaScript analysis using Babel parser
- ⚡ **DOM XSS Detection**: Source-to-sink tracking for DOM-based XSS
- 🔑 **Secret Detection**: Find API keys, tokens, and credentials
- 🔗 **Endpoint Extraction**: Discover API endpoints and URLs
- 📚 **Library Detection**: Identify JavaScript libraries and versions
- 🎭 **Dynamic Analysis**: Playwright support for SPAs
- 📊 **Multiple Reports**: HTML, JSON, and SARIF formats
- 🚀 **Multi-threaded**: Fast concurrent crawling and analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/jshunter/jshunter.git
cd jshunter

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies for AST analysis
cd ast && npm install

# Install Playwright browsers (optional)
playwright install chromium

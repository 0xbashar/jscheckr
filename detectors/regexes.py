"""
Additional regex patterns for detection
"""

# Common JavaScript patterns
JS_PATTERNS = {
    'event_handlers': r'on(?:click|load|error|mouseover|keypress|submit)\s*=',
    'inline_eval': r'(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?:[\w.]+|["\'])',
    'dom_manipulation': r'(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=',
    'url_redirection': r'(?:location\.(?:href|replace|assign)|window\.open)\s*[=\(]',
    'storage_access': r'(?:localStorage|sessionStorage)\.(?:get|set)Item\(',
    'cookie_access': r'document\.cookie\s*=',
}

# Common JavaScript anti-patterns
ANTI_PATTERNS = {
    'debug_enabled': r'(?:debug|debugger)\s*=\s*true',
    'console_log': r'console\.log\s*\([^)]*password[^)]*\)',
    'hardcoded_ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
}

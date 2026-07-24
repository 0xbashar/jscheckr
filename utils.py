"""
Utility functions for JSHunter
"""

import re
import logging
import sys
from urllib.parse import urlparse
from pathlib import Path
from colorama import Fore, Style

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger('jshunter')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    formatter = logging.Formatter(
        '%(message)s'
    )
    handler.setFormatter(formatter)
    
    # Remove existing handlers
    logger.handlers = []
    logger.addHandler(handler)
    
    return logger

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def ensure_directory(path: str):
    """Create directory if it doesn't exist"""
    Path(path).mkdir(parents=True, exist_ok=True)

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem operations"""
    # Remove path separators and null bytes
    filename = filename.replace('/', '_').replace('\\', '_').replace('\0', '')
    # Remove or replace other potentially dangerous characters
    filename = re.sub(r'[<>:"|?*]', '_', filename)
    return filename

class ColorLogger:
    """Colored logging utility"""
    
    COLORS = {
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'DEBUG': Fore.CYAN
    }
    
    @staticmethod
    def format_message(level: str, message: str) -> str:
        color = ColorLogger.COLORS.get(level, Fore.WHITE)
        return f"{color}{message}{Style.RESET_ALL}"

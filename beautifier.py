"""
JavaScript beautifier for making minified code readable
"""

import subprocess
import os
from pathlib import Path
from typing import List
import logging

logger = logging.getLogger(__name__)

class JSBeautifier:
    """Beautifies JavaScript files using js-beautify"""
    
    def __init__(self, indent_size: int = 2):
        self.indent_size = indent_size
        self.output_dir = None
        
    def beautify_batch(self, file_paths: List[str]) -> List[str]:
        """Beautify multiple files"""
        self.output_dir = Path(file_paths[0]).parent.parent / 'beautified'
        self.output_dir.mkdir(exist_ok=True)
        
        beautified_files = []
        
        for file_path in file_paths:
            try:
                beautified_path = self.beautify_file(file_path)
                if beautified_path:
                    beautified_files.append(beautified_path)
            except Exception as e:
                logger.error(f"Error beautifying {file_path}: {str(e)}")
                # If beautification fails, use original file
                beautified_files.append(file_path)
        
        return beautified_files
    
    def beautify_file(self, file_path: str) -> str:
        """Beautify a single JavaScript file"""
        input_path = Path(file_path)
        output_path = self.output_dir / f"{input_path.stem}_beautified{input_path.suffix}"
        
        # Try using js-beautify if available
        try:
            import jsbeautifier
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            opts = jsbeautifier.default_options()
            opts.indent_size = self.indent_size
            opts.indent_char = ' '
            opts.preserve_newlines = True
            opts.max_preserve_newlines = 2
            opts.space_in_empty_paren = True
            
            beautified = jsbeautifier.beautify(content, opts)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(beautified)
            
            return str(output_path)
            
        except ImportError:
            # Fallback to command-line beautifier
            try:
                subprocess.run(
                    ['js-beautify', '-o', str(output_path), file_path],
                    check=True,
                    capture_output=True
                )
                return str(output_path)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.warning("js-beautify not available, using original files")
                return file_path

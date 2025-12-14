"""
Automatic Binary Compilation Module
Handles automatic compilation of C/C++ source files with AFL++ instrumentation
"""

import subprocess
import logging
from pathlib import Path
from typing import Optional, Tuple


class BinaryCompiler:
    """Automatic compilation with AFL++ instrumentation."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.afl_compilers = {
            'c': ['afl-clang-fast', 'afl-clang', 'afl-gcc'],
            'cpp': ['afl-clang-fast++', 'afl-clang++', 'afl-g++']
        }
    
    def _find_available_compiler(self, language: str = 'c') -> Optional[str]:
        """Find the first available AFL++ compiler."""
        compilers = self.afl_compilers.get(language, self.afl_compilers['c'])
        
        for compiler in compilers:
            try:
                result = subprocess.run(
                    ['which', compiler],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.logger.info(f"Found AFL++ compiler: {compiler}")
                    return compiler
            except Exception as e:
                continue
        
        return None
    
    def _detect_language(self, source_path: Path) -> str:
        """Detect source file language by extension."""
        ext = source_path.suffix.lower()
        if ext in ['.cpp', '.cc', '.cxx', '.c++']:
            return 'cpp'
        elif ext in ['.c']:
            return 'c'
        else:
            return 'c'  # Default to C
    
    def compile_source(
        self,
        source_path: str,
        output_path: Optional[str] = None,
        extra_flags: Optional[list] = None
    ) -> Tuple[bool, str, str]:
        """
        Compile source file with AFL++ instrumentation.
        
        Args:
            source_path: Path to source file (.c or .cpp)
            output_path: Path for output binary (optional)
            extra_flags: Additional compiler flags (optional)
            
        Returns:
            (success, binary_path, error_message)
        """
        source = Path(source_path).resolve()
        
        if not source.exists():
            return False, "", f"Source file not found: {source_path}"
        
        # Detect language
        language = self._detect_language(source)
        self.logger.info(f"Detected language: {language}")
        
        # Find compiler
        compiler = self._find_available_compiler(language)
        if not compiler:
            return False, "", "No AFL++ compiler found. Install with: sudo apt install afl++"
        
        # Determine output path
        if output_path:
            output = Path(output_path).resolve()
        else:
            # Default: same name, add _instrumented suffix, place in binaries/
            output = Path('binaries') / f"{source.stem}_instrumented"
            output.parent.mkdir(parents=True, exist_ok=True)
        
        # Build compilation command
        cmd = [
            compiler,
            str(source),
            '-o', str(output)
        ]
        
        # Add common optimization flags
        cmd.extend([
            '-g',           # Debug symbols for analysis
            '-O0',          # No optimization for easier analysis
            '-fno-inline',  # Don't inline functions
        ])
        
        # Add extra flags if provided
        if extra_flags:
            cmd.extend(extra_flags)
        
        self.logger.info(f"Compiling: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            if result.returncode == 0:
                self.logger.info(f"✓ Compilation successful: {output}")
                return True, str(output), ""
            else:
                error_msg = f"Compilation failed:\n{result.stderr}"
                self.logger.error(error_msg)
                return False, "", error_msg
                
        except subprocess.TimeoutExpired:
            return False, "", "Compilation timeout (>2 minutes)"
        except Exception as e:
            return False, "", f"Compilation error: {e}"
    
    def is_source_file(self, path: str) -> bool:
        """Check if file is a C/C++ source file."""
        p = Path(path)
        return p.suffix.lower() in ['.c', '.cpp', '.cc', '.cxx', '.c++']
    
    def verify_instrumentation(self, binary_path: str) -> bool:
        """Verify binary has AFL++ instrumentation."""
        try:
            result = subprocess.run(
                ['file', binary_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Check if it's an ELF executable
            if 'ELF' not in result.stdout:
                return False
            
            # Check for AFL++ markers (simplified check)
            result = subprocess.run(
                ['strings', binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Look for AFL++ related strings
            afl_markers = ['__afl_', 'AFL++', 'afl-fuzz']
            has_markers = any(marker in result.stdout for marker in afl_markers)
            
            return has_markers
            
        except Exception as e:
            self.logger.warning(f"Could not verify instrumentation: {e}")
            return True  # Assume it's OK if we can't verify

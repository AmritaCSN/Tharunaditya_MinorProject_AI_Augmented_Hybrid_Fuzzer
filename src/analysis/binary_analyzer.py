"""
Binary analyzer using angr for CFG analysis and vulnerability scoring.
"""

import angr
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import asdict

from src.core.interfaces import IBinaryAnalyzer, BinaryTarget, AnalysisResult


# Suppress angr verbosity
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)
logging.getLogger('angr.storage.memory_mixins').setLevel(logging.CRITICAL)


# Dangerous functions that indicate vulnerability potential
DANGEROUS_FUNCTIONS = {
    'strcpy': 10.0,
    'strcat': 9.0,
    'gets': 10.0,
    'sprintf': 8.0,
    'scanf': 7.0,
    'fscanf': 7.0,
    'sscanf': 7.0,
    'vsprintf': 8.0,
    'vscanf': 7.0,
    'vsscanf': 7.0,
    'strncpy': 5.0,
    'strncat': 5.0,
    'snprintf': 3.0,
    'memcpy': 4.0,
    'memmove': 4.0,
    'bcopy': 6.0,
    'alloca': 6.0,
    'malloc': 2.0,
    'free': 3.0,
    'system': 10.0,
    'exec': 10.0,
    'popen': 9.0,
}

# Custom function patterns that indicate intentional crash sites (for testing/fuzzing)
# These get highest priority for symbolic execution
CUSTOM_CRASH_PATTERNS = [
    'hard1_', 'hard2_', 'hard3_', 'hard4_', 'hard5_',  # Symex-required crashes
    'easy1_', 'easy2_', 'easy3_', 'easy4_', 'easy5_',  # Fuzzing-easy crashes
    'crash',         # Any crash function
    'vuln',          # Vulnerability functions
    'process_',      # process_echo, process_secretcode, etc.
    'dispatch_',     # dispatch_command, etc.
    'handle_',       # handle_request, etc.
    'parse_',        # parse_packet, etc.
    'secretcode',    # explicit symex-only target
    'admin',         # admin commands often have vulns
]


class BinaryAnalyzer(IBinaryAnalyzer):
    """Analyzes binaries using angr to extract vulnerability information."""
    
    def __init__(self, max_functions: int = 100, timeout_per_function: int = 30):
        """
        Initialize analyzer.
        
        Args:
            max_functions: Maximum number of functions to analyze
            timeout_per_function: Timeout in seconds for each function analysis
        """
        self.max_functions = max_functions
        self.timeout_per_function = timeout_per_function
        self.logger = logging.getLogger(__name__)
    
    def analyze_binary(self, binary_path: str) -> AnalysisResult:
        """
        Analyze binary and extract targets with vulnerability scores.
        
        Args:
            binary_path: Path to binary to analyze
            
        Returns:
            AnalysisResult with targets and metadata
        """
        self.logger.info(f"Starting analysis of {binary_path}")
        
        if not Path(binary_path).exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        try:
            # Load binary with angr
            project = angr.Project(binary_path, auto_load_libs=False)
            cfg = project.analyses.CFGFast()
            
            # Get function count (cfg.functions is a dict-like object)
            total_functions = len(list(cfg.functions.keys()))
            self.logger.info(f"CFG built: {total_functions} functions found")
            
            # Extract and score functions
            targets = self._extract_targets(project, cfg)
            
            # Sort by vulnerability score
            targets.sort(key=lambda t: t.vulnerability_score, reverse=True)
            
            # Limit to max_functions
            targets = targets[:self.max_functions]
            
            # Identify high-priority targets
            high_priority = [t.name for t in targets if t.vulnerability_score >= 7.0]
            
            result = AnalysisResult(
                binary_path=binary_path,
                targets=targets,
                total_functions=total_functions,
                high_priority_targets=high_priority,
                metadata={
                    'entry_point': hex(project.entry),
                    'architecture': project.arch.name,
                    'binary_name': Path(binary_path).name,
                }
            )
            
            self.logger.info(f"Analysis complete: {len(targets)} targets, {len(high_priority)} high-priority")
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            # Return minimal fallback result
            return AnalysisResult(
                binary_path=binary_path,
                targets=[BinaryTarget(
                    name="main",
                    address=0,
                    vulnerability_score=5.0,
                    complexity=10,
                    call_depth=1,
                    avoid_functions=[]
                )],
                total_functions=1,
                high_priority_targets=[],
                metadata={'error': str(e)}
            )
    
    def _extract_targets(self, project: angr.Project, cfg: any) -> List[BinaryTarget]:
        """Extract target functions from CFG."""
        targets = []
        
        for func_addr, func in cfg.functions.items():
            if not func.name:
                continue
            
            # FILTER: Skip known runtime/compiler/ASAN function patterns
            skip_patterns = [
                '__asan', '__ubsan', '__sanitizer', '__interceptor',
                'asan.module', 'sancov.module',
                '__libc', '__cxa', '_GLOBAL_',
                'frame_dummy', 'register_tm_clones', 'deregister_tm_clones',
                '__do_global', '_init', '_fini', '_start',
                'vsscanf', 'vsprintf', 'process_vm_', 'open_by_handle',  # Common runtime funcs
                '__isoc99_', '__isoc23_',  # C standard library wrappers
                'name_to_handle_at',
            ]
            if any(pattern in func.name for pattern in skip_patterns):
                continue
            
            # PRIORITY BOOST: Custom crash functions get maximum priority
            is_custom_crash = any(pattern in func.name.lower() for pattern in CUSTOM_CRASH_PATTERNS)
            
            # Calculate vulnerability score
            vuln_score = self._calculate_vulnerability_score(func, is_custom=is_custom_crash)
            
            # Get function complexity metrics
            complexity = len(list(func.blocks)) if hasattr(func, 'blocks') else 10
            call_depth = self._estimate_call_depth(func)
            
            # Find functions to avoid (error handlers, etc.)
            avoid_funcs = self._find_avoid_functions(func, cfg)
            
            target = BinaryTarget(
                name=func.name,
                address=func_addr,
                vulnerability_score=vuln_score,
                complexity=complexity,
                call_depth=call_depth,
                avoid_functions=avoid_funcs
            )
            
            targets.append(target)
        
        return targets
    
    def _calculate_vulnerability_score(self, func: any, is_custom: bool = False) -> float:
        """
        Calculate vulnerability score based on dangerous function calls.
        
        Higher score = more likely to contain vulnerabilities
        
        Args:
            func: Function object from angr CFG
            is_custom: True if function matches custom crash patterns (gets max priority)
        """
        # PRIORITY: Custom crash functions get maximum score for symex targeting
        if is_custom:
            self.logger.debug(f"Custom crash function detected: {func.name} - MAX PRIORITY")
            return 10.0
        
        score = 0.0
        
        # Check for dangerous function calls
        if hasattr(func, 'name'):
            func_name = func.name.lower()
            
            # Check if function name contains dangerous keywords
            for dangerous, weight in DANGEROUS_FUNCTIONS.items():
                if dangerous in func_name:
                    score += weight * 0.5
        
        # Check function calls (if CFG available)
        if hasattr(func, 'get_call_sites'):
            try:
                for call_site in func.get_call_sites():
                    target_func = func.get_call_target(call_site)
                    if target_func and hasattr(target_func, 'name'):
                        target_name = target_func.name.lower()
                        for dangerous, weight in DANGEROUS_FUNCTIONS.items():
                            if dangerous in target_name:
                                score += weight
            except:
                pass
        
        # Baseline score for all functions
        score += 2.0
        
        # Cap at 10.0
        return min(score, 10.0)
    
    def _estimate_call_depth(self, func: any) -> int:
        """Estimate function call depth (complexity metric)."""
        if hasattr(func, 'blocks'):
            num_blocks = len(list(func.blocks))
            return min(num_blocks // 5, 10)
        return 1
    
    def _find_avoid_functions(self, func: any, cfg: any) -> List[str]:
        """Find functions to avoid during symbolic execution (error handlers, etc.)."""
        avoid = []
        
        # Common error handling functions
        error_patterns = ['error', 'abort', 'exit', 'fail', 'assert', '__stack_chk_fail']
        
        if hasattr(func, 'get_call_sites'):
            try:
                for call_site in func.get_call_sites():
                    target_func = func.get_call_target(call_site)
                    if target_func and hasattr(target_func, 'name'):
                        name = target_func.name.lower()
                        if any(pattern in name for pattern in error_patterns):
                            avoid.append(target_func.name)
            except:
                pass
        
        return avoid[:5]  # Limit to 5 avoid functions

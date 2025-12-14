"""
Target Configuration Generator
Generates fuzzing target configurations from binary analysis results
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from pathlib import Path

from src.core.interfaces import AnalysisResult, BinaryTarget


@dataclass
class FuzzingTarget:
    """Single fuzzing target with full configuration."""
    name: str
    address: str
    priority: float
    target_type: str  # 'function', 'basic_block', 'path'
    avoid_addresses: List[str]
    symbolic_hooks: List[str]
    timeout: int
    max_states: int
    description: str
    semantic_tags: List[str] = field(default_factory=list)
    risk_breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class BinaryConfig:
    """Complete fuzzing configuration for a binary."""
    binary_path: str
    binary_name: str
    architecture: str
    entry_point: str
    targets: List[FuzzingTarget]
    global_hooks: List[str]
    seed_generation_hints: List[str]
    resource_limits: Dict[str, Any]
    metadata: Dict[str, Any]


class TargetConfigGenerator:
    """
    Generate fuzzing configurations from binary analysis.
    
    Features:
    - Skip CRT/runtime functions (not useful fuzz targets)
    - Identify error handlers to avoid
    - Semantic tagging (buffer_overflow, format_string, etc.)
    - Resource limits per target
    - Seed generation hints
    """
    
    # CRT and runtime functions to skip
    CRT_SKIP_PATTERNS = [
        '__tmainCRTStartup', '__mainCRTStartup', '_mainCRTStartup',
        '__pei386_runtime_relocator', '_gnu_exception_handler',
        '__mingw_TLScallback', '__mingw_', '_mingw_', '__CRT', '_CRT',
        'mark_section_writable', '__security_', '_security_', '__SEH_',
        'atexit', '_atexit', '__dyn_tls_', '_configthreadlocale',
        'pre_c_init', 'pre_cpp_init', '__main', '_start', '__start',
        'crtStartup', '__scrt_', '_fpreset', '__getmainargs',
        '__set_app_type', '__p_', '__lconv_init', '_setargv',
        '_setenvp', '_get_initial_narrow_environment'
    ]
    
    # Error handling functions to avoid in symbolic execution
    AVOID_PATTERNS = [
        'exit', 'abort', '_exit', 'quit',
        'error', 'err', 'fatal', 'panic',
        'exception', 'throw', 'raise',
        '__stack_chk_fail', '__fortify_fail',
        'perror', 'warn', 'errx', 'warnx'
    ]
    
    # Semantic tags for vulnerability types
    SEMANTIC_TAGS = {
        'strcpy': ['buffer_overflow', 'unsafe_string'],
        'strcat': ['buffer_overflow', 'unsafe_string'],
        'gets': ['buffer_overflow', 'unsafe_input'],
        'sprintf': ['buffer_overflow', 'format_string'],
        'scanf': ['format_string', 'unsafe_input'],
        'fscanf': ['format_string', 'unsafe_input'],
        'sscanf': ['format_string', 'unsafe_input'],
        'vsprintf': ['buffer_overflow', 'format_string'],
        'memcpy': ['buffer_overflow', 'memory_corruption'],
        'malloc': ['heap_corruption', 'memory_management'],
        'free': ['heap_corruption', 'use_after_free'],
        'system': ['command_injection', 'code_execution'],
        'exec': ['command_injection', 'code_execution'],
        'popen': ['command_injection', 'code_execution']
    }
    
    def __init__(self):
        """Initialize target config generator."""
        self.logger = logging.getLogger(__name__)
        
        # Default resource limits
        self.default_limits = {
            'max_memory_mb': 2048,
            'max_time_per_target': 300,
            'max_states_per_target': 100,
            'max_symbolic_depth': 50,
            'max_concurrent_states': 10
        }
    
    def generate_config(self, analysis_result: AnalysisResult) -> BinaryConfig:
        """
        Generate complete binary configuration from analysis result.
        
        Args:
            analysis_result: Binary analysis result
            
        Returns:
            BinaryConfig with filtered and enhanced targets
        """
        self.logger.info(f"Generating config for {analysis_result.binary_path}")
        
        # Filter out CRT/runtime functions
        filtered_targets = self._filter_targets(analysis_result.targets)
        self.logger.info(f"Filtered {len(analysis_result.targets)} -> {len(filtered_targets)} targets")
        
        # Convert to fuzzing targets with full configuration
        fuzzing_targets = []
        for target in filtered_targets:
            fuzzing_target = self._create_fuzzing_target(target, analysis_result)
            fuzzing_targets.append(fuzzing_target)
        
        # Generate seed hints
        seed_hints = self._generate_seed_hints(fuzzing_targets)
        
        # Create binary config
        binary_name = Path(analysis_result.binary_path).name
        
        config = BinaryConfig(
            binary_path=analysis_result.binary_path,
            binary_name=binary_name,
            architecture=analysis_result.metadata.get('architecture', 'unknown'),
            entry_point=analysis_result.metadata.get('entry_point', '0x0'),
            targets=fuzzing_targets,
            global_hooks=[],  # Can be populated with common hooks
            seed_generation_hints=seed_hints,
            resource_limits=self.default_limits.copy(),
            metadata=analysis_result.metadata
        )
        
        self.logger.info(f"Generated config with {len(fuzzing_targets)} targets, {len(seed_hints)} seed hints")
        return config
    
    def _filter_targets(self, targets: List[BinaryTarget]) -> List[BinaryTarget]:
        """Filter out CRT/runtime functions."""
        filtered = []
        
        for target in targets:
            # Skip if matches CRT pattern
            if any(pattern in target.name for pattern in self.CRT_SKIP_PATTERNS):
                self.logger.debug(f"Skipping CRT function: {target.name}")
                continue
            
            # Skip if name starts with underscore (likely internal)
            if target.name.startswith('_') and not target.name.startswith('__'):
                self.logger.debug(f"Skipping internal function: {target.name}")
                continue
            
            filtered.append(target)
        
        return filtered
    
    def _create_fuzzing_target(self, target: BinaryTarget, analysis_result: AnalysisResult) -> FuzzingTarget:
        """Create fuzzing target with full configuration."""
        # Get semantic tags
        tags = self._get_semantic_tags(target.name)
        
        # Build risk breakdown
        risk_breakdown = self._calculate_risk_breakdown(target, tags)
        
        # Get avoid addresses
        avoid_addrs = self._get_avoid_addresses(target)
        
        # Generate description
        description = self._generate_description(target, tags)
        
        # Calculate timeout and max states based on complexity
        timeout = min(300, 30 + target.complexity * 5)
        max_states = min(200, 50 + target.complexity * 2)
        
        return FuzzingTarget(
            name=target.name,
            address=hex(target.address),
            priority=target.vulnerability_score,
            target_type='function',
            avoid_addresses=avoid_addrs,
            symbolic_hooks=[],
            timeout=timeout,
            max_states=max_states,
            description=description,
            semantic_tags=tags,
            risk_breakdown=risk_breakdown
        )
    
    def _get_semantic_tags(self, function_name: str) -> List[str]:
        """Get semantic vulnerability tags for function."""
        tags = []
        name_lower = function_name.lower()
        
        for func_pattern, func_tags in self.SEMANTIC_TAGS.items():
            if func_pattern in name_lower:
                tags.extend(func_tags)
        
        # Remove duplicates
        return list(set(tags))
    
    def _calculate_risk_breakdown(self, target: BinaryTarget, tags: List[str]) -> Dict[str, float]:
        """Calculate detailed risk breakdown."""
        breakdown = {
            'base_score': min(target.vulnerability_score, 5.0),
            'complexity_factor': min(target.complexity / 20.0, 3.0),
            'call_depth_factor': min(target.call_depth / 5.0, 2.0),
            'semantic_boost': len(tags) * 0.5
        }
        
        breakdown['total'] = sum(breakdown.values())
        return breakdown
    
    def _get_avoid_addresses(self, target: BinaryTarget) -> List[str]:
        """Get addresses to avoid during symbolic execution."""
        # Use avoid_functions from target, convert to hex addresses
        # In practice, these would be resolved to actual addresses
        return [f"avoid_{func}" for func in target.avoid_functions[:5]]
    
    def _generate_description(self, target: BinaryTarget, tags: List[str]) -> str:
        """Generate human-readable target description."""
        parts = [f"Function: {target.name}"]
        
        if tags:
            parts.append(f"Vulnerabilities: {', '.join(tags)}")
        
        parts.append(f"Complexity: {target.complexity} blocks")
        parts.append(f"Priority: {target.vulnerability_score:.1f}/10.0")
        
        return " | ".join(parts)
    
    def _generate_seed_hints(self, targets: List[FuzzingTarget]) -> List[str]:
        """Generate seed generation hints from targets."""
        hints = set()
        
        for target in targets:
            for tag in target.semantic_tags:
                if 'buffer_overflow' in tag:
                    hints.add('long_strings')
                    hints.add('boundary_values')
                elif 'format_string' in tag:
                    hints.add('format_specifiers')
                elif 'command_injection' in tag:
                    hints.add('shell_metacharacters')
                elif 'integer_overflow' in tag:
                    hints.add('integer_boundaries')
        
        return list(hints)
    
    def save_config(self, config: BinaryConfig, output_path: str) -> None:
        """Save config to JSON file."""
        import json
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(asdict(config), f, indent=2)
        
        self.logger.info(f"Saved config to {output_path}")

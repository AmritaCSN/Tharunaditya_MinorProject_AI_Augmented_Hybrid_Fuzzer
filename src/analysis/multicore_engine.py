"""
Multi-Core Binary Analysis Engine
Parallel binary analysis with resource monitoring
"""

import logging
import time
import psutil
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.core.interfaces import IBinaryAnalyzer, AnalysisResult, BinaryTarget


@dataclass
class SystemResources:
    """System resource snapshot."""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    available_memory_mb: float
    cpu_count: int
    active_threads: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'cpu_percent': self.cpu_percent,
            'memory_percent': self.memory_percent,
            'memory_mb': self.memory_mb,
            'available_memory_mb': self.available_memory_mb,
            'cpu_count': self.cpu_count,
            'active_threads': self.active_threads
        }


@dataclass
class AnalysisPerformance:
    """Performance metrics for analysis."""
    total_time: float
    binaries_analyzed: int
    functions_found: int
    avg_time_per_binary: float
    peak_memory_mb: float
    peak_cpu_percent: float
    threads_used: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_time': self.total_time,
            'binaries_analyzed': self.binaries_analyzed,
            'functions_found': self.functions_found,
            'avg_time_per_binary': self.avg_time_per_binary,
            'peak_memory_mb': self.peak_memory_mb,
            'peak_cpu_percent': self.peak_cpu_percent,
            'threads_used': self.threads_used
        }


class ResourceMonitor:
    """
    Monitor system resources during analysis.
    
    Features:
    - Real-time CPU/memory tracking
    - Peak resource usage
    - Resource history
    """
    
    def __init__(self):
        """Initialize resource monitor."""
        self.logger = logging.getLogger(__name__)
        self.history: List[SystemResources] = []
        
        # Get initial resources
        self.initial_cpu = psutil.cpu_percent(interval=0.1)
        self.initial_memory = psutil.virtual_memory().percent
        
        # Track peaks
        self.peak_cpu = 0.0
        self.peak_memory_mb = 0.0
    
    def snapshot(self) -> SystemResources:
        """Take system resource snapshot."""
        mem = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        snapshot = SystemResources(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_percent=mem.percent,
            memory_mb=mem.used / (1024 * 1024),
            available_memory_mb=mem.available / (1024 * 1024),
            cpu_count=psutil.cpu_count(logical=True),
            active_threads=len(psutil.Process().threads())
        )
        
        # Update peaks
        self.peak_cpu = max(self.peak_cpu, cpu_percent)
        self.peak_memory_mb = max(self.peak_memory_mb, snapshot.memory_mb)
        
        self.history.append(snapshot)
        return snapshot
    
    def get_current(self) -> SystemResources:
        """Get current system resources."""
        return self.snapshot()
    
    def get_average(self) -> Optional[SystemResources]:
        """Get average resources from history."""
        if not self.history:
            return None
        
        avg_cpu = sum(s.cpu_percent for s in self.history) / len(self.history)
        avg_memory = sum(s.memory_percent for s in self.history) / len(self.history)
        avg_memory_mb = sum(s.memory_mb for s in self.history) / len(self.history)
        
        return SystemResources(
            timestamp=time.time(),
            cpu_percent=avg_cpu,
            memory_percent=avg_memory,
            memory_mb=avg_memory_mb,
            available_memory_mb=self.history[-1].available_memory_mb,
            cpu_count=self.history[-1].cpu_count,
            active_threads=self.history[-1].active_threads
        )
    
    def is_high_load(self) -> bool:
        """Check if system is under high load."""
        current = self.get_current()
        return current.cpu_percent > 95.0 or current.memory_percent > 90.0


class MultiCoreAnalysisEngine:
    """
    Parallel binary analysis engine.
    
    Features:
    - ThreadPoolExecutor for I/O-bound analysis
    - Auto-detect optimal thread count
    - Resource monitoring
    - Progress tracking
    """
    
    def __init__(self, analyzer: IBinaryAnalyzer, config: Dict[str, Any]):
        """
        Initialize multi-core engine.
        
        Args:
            analyzer: Binary analyzer instance
            config: Configuration dictionary
        """
        self.analyzer = analyzer
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Resource monitoring
        self.monitor = ResourceMonitor()
        
        # Get thread count
        multicore_config = config.get('multicore', {})
        self.max_workers = multicore_config.get('max_workers')
        
        if self.max_workers is None:
            # Auto-detect: 75% of logical cores
            cpu_count = psutil.cpu_count(logical=True)
            self.max_workers = min(15, max(1, cpu_count - 2))
        
        self.logger.info(f"Using {self.max_workers} worker threads for analysis")
        
        # Performance tracking
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.results: List[AnalysisResult] = []
    
    def analyze_binary(self, binary_path: str) -> AnalysisResult:
        """
        Analyze single binary (delegates to wrapped analyzer).
        
        Args:
            binary_path: Path to binary
            
        Returns:
            AnalysisResult
        """
        self.logger.info(f"Analyzing {binary_path}")
        self.start_time = time.time()
        
        # Monitor resources before
        before = self.monitor.snapshot()
        
        # Analyze
        try:
            result = self.analyzer.analyze_binary(binary_path)
            self.results.append(result)
        except Exception as e:
            self.logger.error(f"Analysis failed for {binary_path}: {e}")
            # Return empty result with all required fields
            result = AnalysisResult(
                binary_path=binary_path,
                targets=[],
                total_functions=0,
                high_priority_targets=[],
                metadata={'error': str(e)}
            )
        
        # Monitor resources after
        after = self.monitor.snapshot()
        
        self.end_time = time.time()
        
        self.logger.info(
            f"Analysis complete: {len(result.targets)} targets found "
            f"(CPU: {after.cpu_percent:.1f}%, Memory: {after.memory_mb:.0f}MB)"
        )
        
        return result
    
    def analyze_multiple(self, binary_paths: List[str]) -> List[AnalysisResult]:
        """
        Analyze multiple binaries in parallel.
        
        Args:
            binary_paths: List of binary paths
            
        Returns:
            List of AnalysisResults
        """
        self.logger.info(f"Analyzing {len(binary_paths)} binaries with {self.max_workers} threads")
        self.start_time = time.time()
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(self._analyze_single, path): path
                for path in binary_paths
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.results.append(result)
                    
                    # Log progress
                    self.logger.info(
                        f"[{len(results)}/{len(binary_paths)}] Completed {path}: "
                        f"{len(result.targets)} targets"
                    )
                except Exception as e:
                    self.logger.error(f"Failed to analyze {path}: {e}")
                    # Add empty result
                    results.append(AnalysisResult(
                        binary_path=path,
                        targets=[],
                        metadata={'error': str(e)}
                    ))
        
        self.end_time = time.time()
        
        # Log summary
        total_targets = sum(len(r.targets) for r in results)
        elapsed = self.end_time - self.start_time
        self.logger.info(
            f"Parallel analysis complete: {len(results)} binaries, "
            f"{total_targets} targets, {elapsed:.1f}s"
        )
        
        return results
    
    def _analyze_single(self, binary_path: str) -> AnalysisResult:
        """Analyze single binary with resource monitoring."""
        # Take snapshot before
        before = self.monitor.snapshot()
        
        try:
            result = self.analyzer.analyze_binary(binary_path)
        except Exception as e:
            self.logger.error(f"Analysis error for {binary_path}: {e}")
            result = AnalysisResult(
                binary_path=binary_path,
                targets=[],
                total_functions=0,
                high_priority_targets=[],
                metadata={'error': str(e)}
            )
        
        # Take snapshot after
        after = self.monitor.snapshot()
        
        return result
    
    def get_performance_report(self) -> AnalysisPerformance:
        """Get performance report."""
        if self.start_time is None or self.end_time is None:
            raise RuntimeError("No analysis has been performed yet")
        
        total_time = self.end_time - self.start_time
        binaries_analyzed = len(self.results)
        functions_found = sum(len(r.targets) for r in self.results)
        
        avg_time = total_time / binaries_analyzed if binaries_analyzed > 0 else 0.0
        
        return AnalysisPerformance(
            total_time=total_time,
            binaries_analyzed=binaries_analyzed,
            functions_found=functions_found,
            avg_time_per_binary=avg_time,
            peak_memory_mb=self.monitor.peak_memory_mb,
            peak_cpu_percent=self.monitor.peak_cpu,
            threads_used=self.max_workers
        )
    
    def save_report(self, output_path: str) -> None:
        """Save performance report to JSON."""
        import json
        
        report = self.get_performance_report()
        
        # Add resource history
        full_report = {
            'performance': report.to_dict(),
            'resource_history': [s.to_dict() for s in self.monitor.history],
            'average_resources': self.monitor.get_average().to_dict() if self.monitor.history else None
        }
        
        with open(output_path, 'w') as f:
            json.dump(full_report, f, indent=2)
        
        self.logger.info(f"Saved performance report to {output_path}")

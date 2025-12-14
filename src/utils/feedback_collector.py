"""
Enhanced Feedback Collector for AFL++ Statistics
Provides historical tracking, trend analysis, and resource correlation
"""

import os
import json
import time
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class FuzzingSnapshot:
    """Single point-in-time fuzzing statistics."""
    timestamp: float
    datetime_str: str
    session_runtime: float
    
    # AFL++ core metrics
    execs_done: int
    execs_per_sec: float
    paths_total: int
    paths_found: int
    crashes_total: int
    unique_crashes: int
    unique_hangs: int
    
    # Resource metrics
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    estimated_watts: float
    
    # Derived metrics
    crashes_per_hour: float
    paths_per_hour: float
    coverage_estimate: float
    
    # RL action tracking
    action_taken: str = "UNKNOWN"  # Current RL action (FUZZING, SYMBOLIC_EXECUTION)


class FeedbackCollector:
    """
    Enhanced AFL++ feedback collector with historical tracking.
    
    Features:
    - Historical data storage for trend analysis
    - Resource utilization tracking (CPU, memory)
    - Derived performance metrics
    - JSONL logging for post-campaign analysis
    """
    
    def __init__(self, afl_output_dir: str, log_file: Optional[str] = None):
        """
        Initialize feedback collector.
        
        Args:
            afl_output_dir: AFL++ output directory
            log_file: Optional JSONL log file path
        """
        self.afl_output_dir = Path(afl_output_dir)
        self.stats_file = self.afl_output_dir / "default" / "fuzzer_stats"
        
        # Logging
        self.log_file = Path(log_file) if log_file else self.afl_output_dir / "enhanced_metrics.jsonl"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Session tracking
        self.session_start_time = time.time()
        self.history: List[FuzzingSnapshot] = []
        
        # Last known state for delta calculations
        self.last_snapshot: Optional[FuzzingSnapshot] = None
        
        # Performance tracking
        self.first_crash_time: Optional[float] = None
        self.crash_timeline: List[Dict[str, Any]] = []
        
        # Adaptive stuck detection tracking
        self.last_path_count: int = 0
        self.execs_at_last_path: int = 0
    
    def get_stats(self, action_taken: str = "UNKNOWN", estimated_watts: float = 0.0) -> Dict[str, Any]:
        """
        Get current fuzzing statistics with enhancements.
        
        Args:
            action_taken: Current RL action being executed (for tracking)
            estimated_watts: Current power consumption estimate
        
        Returns:
            Dict with comprehensive metrics, or empty dict if stats unavailable
        """
        # Read AFL++ stats
        afl_stats = self._read_afl_stats()
        if not afl_stats:
            return {}
        
        # Get resource metrics
        resource_metrics = self._get_resource_metrics()
        
        # Create snapshot
        current_time = time.time()
        session_runtime = current_time - self.session_start_time
        
        snapshot = FuzzingSnapshot(
            timestamp=current_time,
            datetime_str=datetime.fromtimestamp(current_time).isoformat(),
            session_runtime=session_runtime,
            execs_done=afl_stats.get('execs_done', 0),
            execs_per_sec=afl_stats.get('execs_per_sec', 0.0),
            paths_total=afl_stats.get('corpus_count', 0),  # AFL++ v4.x uses corpus_count
            paths_found=afl_stats.get('corpus_found', 0),  # AFL++ v4.x field
            crashes_total=afl_stats.get('saved_crashes', 0),
            unique_crashes=afl_stats.get('saved_crashes', 0),  # Same as crashes_total in AFL++ v4.x
            unique_hangs=afl_stats.get('saved_hangs', 0),
            cpu_percent=resource_metrics['cpu_percent'],
            memory_percent=resource_metrics['memory_percent'],
            memory_mb=resource_metrics['memory_mb'],
            estimated_watts=estimated_watts,
            crashes_per_hour=self._calculate_rate(afl_stats.get('saved_crashes', 0), session_runtime),
            paths_per_hour=self._calculate_rate(afl_stats.get('corpus_found', 0), session_runtime),
            coverage_estimate=self._coverage_from_stats(afl_stats),
            action_taken=action_taken  # Track current RL action
        )
        
        # Track crash events
        if snapshot.crashes_total > 0 and self.first_crash_time is None:
            self.first_crash_time = current_time
        
        if self.last_snapshot and snapshot.crashes_total > self.last_snapshot.crashes_total:
            self.crash_timeline.append({
                'time': current_time - self.session_start_time,
                'total_crashes': snapshot.crashes_total,
                'timestamp': current_time
            })
        
        # Store snapshot
        self.history.append(snapshot)
        self.last_snapshot = snapshot
        
        # Log to JSONL
        self._log_snapshot(snapshot)
        
        # Return as dict with additional context
        stats_dict = asdict(snapshot)
        stats_dict.update({
            'time_to_first_crash': (self.first_crash_time - self.session_start_time) if self.first_crash_time else None,
            'total_snapshots': len(self.history),
            'crash_events': len(self.crash_timeline)
        })
        
        return stats_dict
    
    def get_trends(self, window_size: int = 10) -> Dict[str, Any]:
        """
        Get trend analysis over recent snapshots.
        
        Args:
            window_size: Number of recent snapshots to analyze
            
        Returns:
            Dict with trend data
        """
        if len(self.history) < 2:
            return {}
        
        recent = self.history[-window_size:]
        
        return {
            'avg_execs_per_sec': sum(s.execs_per_sec for s in recent) / len(recent),
            'avg_cpu_percent': sum(s.cpu_percent for s in recent) / len(recent),
            'avg_memory_percent': sum(s.memory_percent for s in recent) / len(recent),
            'paths_growth_rate': self._calculate_growth_rate([s.paths_total for s in recent]),
            'crash_growth_rate': self._calculate_growth_rate([s.crashes_total for s in recent]),
            'window_size': len(recent)
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get campaign summary statistics.
        
        Returns:
            Dict with summary metrics
        """
        if not self.history:
            return {}
        
        latest = self.history[-1]
        peak_cpu = max((s.cpu_percent for s in self.history), default=0.0)
        peak_mem_mb = max((s.memory_mb for s in self.history), default=0.0)
        
        return {
            'duration_seconds': latest.session_runtime,
            'total_executions': latest.execs_done,
            'total_paths': latest.paths_total,
            'total_crashes': latest.crashes_total,
            'unique_crashes': latest.unique_crashes,
            'avg_exec_speed': sum(s.execs_per_sec for s in self.history) / len(self.history),
            'time_to_first_crash': (self.first_crash_time - self.session_start_time) if self.first_crash_time else None,
            'snapshots_collected': len(self.history),
            'crashes_per_hour': latest.crashes_per_hour,
            'paths_per_hour': latest.paths_per_hour,
            'coverage_percentage': latest.coverage_estimate,
            'peak_cpu_percent': peak_cpu,
            'peak_memory_mb': peak_mem_mb
        }
    
    def _read_afl_stats(self) -> Dict[str, Any]:
        """Read AFL++ fuzzer_stats file."""
        if not self.stats_file.exists():
            return {}
        
        stats = {}
        try:
            with open(self.stats_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if ':' not in line:
                        continue
                    
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Parse relevant metrics
                    if key in ['execs_done', 'paths_total', 'paths_found', 'saved_crashes',
                               'unique_crashes', 'unique_hangs', 'corpus_count']:
                        try:
                            stats[key] = int(value)
                        except ValueError:
                            stats[key] = 0
                    elif key in ['execs_per_sec', 'bitmap_cvg']:
                        try:
                            # Handle percentage signs if present
                            clean_value = value.replace('%', '')
                            stats[key] = float(clean_value)
                        except ValueError:
                            stats[key] = 0.0
        except Exception as e:
            print(f"[FeedbackCollector] Error reading AFL++ stats: {e}")
            return {}
        
        return stats

    def _coverage_from_stats(self, stats: Dict[str, Any]) -> float:
        """Prefer AFL++ bitmap_cvg when available; fall back to heuristic."""
        bitmap = stats.get('bitmap_cvg')
        if isinstance(bitmap, (int, float)) and bitmap > 0:
            return min(100.0, float(bitmap))
        return self._estimate_coverage(stats.get('corpus_count', 0))
    
    def _get_resource_metrics(self) -> Dict[str, float]:
        """Get current system resource utilization."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_mb': memory.used / (1024 * 1024)
            }
        except Exception:
            return {
                'cpu_percent': 0.0,
                'memory_percent': 0.0,
                'memory_mb': 0.0
            }
    
    def _calculate_rate(self, count: int, duration_seconds: float) -> float:
        """Calculate per-hour rate."""
        if duration_seconds <= 0:
            return 0.0
        hours = duration_seconds / 3600.0
        return count / hours if hours > 0 else 0.0
    
    def _estimate_coverage(self, paths: int) -> float:
        """Estimate coverage percentage (simplified heuristic)."""
        # Rough heuristic: logarithmic growth
        # Assumes ~1000 paths = ~50% coverage
        if paths == 0:
            return 0.0
        import math
        coverage = min(100.0, (math.log10(paths + 1) / math.log10(1000)) * 50.0)
        return coverage
    
    def _calculate_growth_rate(self, values: List[int]) -> float:
        """Calculate growth rate (change per snapshot)."""
        if len(values) < 2:
            return 0.0
        
        total_change = values[-1] - values[0]
        return total_change / (len(values) - 1)
    
    def _log_snapshot(self, snapshot: FuzzingSnapshot) -> None:
        """Log snapshot to JSONL file."""
        try:
            with open(self.log_file, 'a') as f:
                json.dump(asdict(snapshot), f)
                f.write('\n')
        except Exception as e:
            print(f"[FeedbackCollector] Error logging snapshot: {e}")
    
    def is_fuzzer_stuck(self, lookback_window: int = 10, stuck_threshold_seconds: float = 120.0) -> bool:
        """
        Detect if fuzzer is stuck (no new paths for extended period).
        TIME-BASED approach (simple, works for initial implementation).
        
        Args:
            lookback_window: Number of recent snapshots to check
            stuck_threshold_seconds: Time without new paths = stuck
        
        Returns:
            True if fuzzer stuck (should trigger symex), False otherwise
        """
        if len(self.history) < 2:
            return False  # Not enough data
        
        # Get recent snapshots
        recent = self.history[-lookback_window:]
        
        if len(recent) < 2:
            return False
        
        # Check if paths_total hasn't changed in recent window
        first_paths = recent[0].paths_total
        last_paths = recent[-1].paths_total
        
        if last_paths > first_paths:
            # New paths found recently - NOT stuck
            return False
        
        # No new paths - check how long we've been stuck
        time_stuck = recent[-1].timestamp - recent[0].timestamp
        
        is_stuck = time_stuck >= stuck_threshold_seconds
        
        if is_stuck:
            print(f"[STUCK DETECTION] Fuzzer stuck for {time_stuck:.0f}s (threshold: {stuck_threshold_seconds:.0f}s)")
            print(f"                  No new paths: {first_paths} → {last_paths}")
        
        return is_stuck
    
    def get_stuck_metrics(self, current_input_size: int = 64) -> tuple[bool, int, int]:
        """
        Get detailed stuck metrics for decision making.
        Returns: (is_stuck, execs_since_last_path, threshold)
        """
        if len(self.history) < 2:
            return False, 0, 0
        
        current_snapshot = self.history[-1]
        current_paths = current_snapshot.paths_total
        current_execs = current_snapshot.execs_done
        
        # Update tracking when new path is found
        if current_paths > self.last_path_count:
            self.last_path_count = current_paths
            self.execs_at_last_path = current_execs
            return False, 0, current_input_size * 40
        
        # Calculate executions since last path discovery
        execs_since_last_path = current_execs - self.execs_at_last_path
        
        # Adaptive threshold: proportional to input complexity
        # LOWERED from *160 to *40 to find the "sweet spot" for hybrid fuzzing
        # 256 bytes * 40 = 10,240 execs (~2 seconds at 5k/sec)
        threshold_execs = current_input_size * 40
        
        is_stuck = execs_since_last_path >= threshold_execs
        
        return is_stuck, execs_since_last_path, threshold_execs

    def is_fuzzer_stuck_adaptive(self, current_input_size: int = 64) -> bool:
        """
        Adaptive stuck detection: no new coverage for input_size * 40 executions.
        EXEC-BASED approach (more robust than time-based).
        
        This is the preferred method as it adapts to execution speed and input complexity.
        
        Args:
            current_input_size: Average size of inputs in bytes (default 64)
        
        Returns:
            True if fuzzer stuck per adaptive heuristic, False otherwise
        """
        is_stuck, execs_since, threshold = self.get_stuck_metrics(current_input_size)
        
        if is_stuck:
            print(f"[FUZZER STUCK] No new paths for {execs_since:,} executions")
            print(f"                Threshold: {threshold:,} (input_size={current_input_size} bytes)")
            print(f"                Current: {self.last_path_count} paths")
        
        return is_stuck
    
    def get_last_interesting_seed(self, output_dir: str) -> Optional[bytes]:
        """
        Get the most recent interesting test case from AFL++ queue.
        
        This seed will be used for selective symex to unstick the fuzzer.
        
        Args:
            output_dir: AFL++ output directory
        
        Returns:
            Content of most recent queue file, or None
        """
        try:
            queue_dir = Path(output_dir) / "default" / "queue"
            if not queue_dir.exists():
                return None
            
            # Get all queue files sorted by modification time
            queue_files = sorted(
                queue_dir.glob("id:*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True  # Most recent first
            )
            
            if not queue_files:
                return None
            
            # Return content of most recent file
            with open(queue_files[0], 'rb') as f:
                content = f.read()
            
            print(f"[STUCK DETECTION] Last interesting seed: {queue_files[0].name} ({len(content)} bytes)")
            return content
            
        except Exception as e:
            print(f"[STUCK DETECTION] Error getting last seed: {e}")
            return None
    
    def get_execs_since_last_path(self) -> int:
        """
        Get number of executions since last path discovery.
        Critical metric for RL observations and adaptive stuck detection.
        
        Returns:
            Number of executions without finding new paths
        """
        if len(self.history) < 2:
            return 0
        
        current_snapshot = self.history[-1]
        current_execs = current_snapshot.execs_done
        
        # Return cached calculation
        return current_execs - self.execs_at_last_path

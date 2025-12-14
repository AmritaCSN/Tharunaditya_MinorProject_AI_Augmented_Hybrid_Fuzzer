"""
Resource Controller
CPU/RAM throttling and resource allocation management
"""

import logging
import time
import psutil
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ResourceLimits:
    """Resource limits configuration."""
    max_cpu_percent: float = 90.0
    max_memory_percent: float = 85.0
    max_memory_mb: Optional[int] = None
    cooldown_seconds: int = 5
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'max_cpu_percent': self.max_cpu_percent,
            'max_memory_percent': self.max_memory_percent,
            'max_memory_mb': self.max_memory_mb,
            'cooldown_seconds': self.cooldown_seconds
        }


@dataclass
class ResourceAllocation:
    """Resource allocation for different tasks."""
    fuzzing_percent: float = 60.0
    symbolic_exec_percent: float = 25.0
    analysis_percent: float = 15.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'fuzzing_percent': self.fuzzing_percent,
            'symbolic_exec_percent': self.symbolic_exec_percent,
            'analysis_percent': self.analysis_percent
        }


class ResourceController:
    """
    Control system resource usage.
    
    Features:
    - CPU throttling (max 90% usage)
    - Memory throttling (max 85% usage)
    - Auto-rebalancing allocation
    - Cooldown periods
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize resource controller.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Extract limits from config
        resource_config = config.get('resources', {})
        
        self.limits = ResourceLimits(
            max_cpu_percent=resource_config.get('max_cpu_percent', 90.0),
            max_memory_percent=resource_config.get('max_memory_percent', 85.0),
            max_memory_mb=resource_config.get('max_memory_mb'),
            cooldown_seconds=resource_config.get('cooldown_seconds', 5)
        )
        
        # Default allocation
        allocation_config = resource_config.get('allocation', {})
        self.allocation = ResourceAllocation(
            fuzzing_percent=allocation_config.get('fuzzing', 60.0),
            symbolic_exec_percent=allocation_config.get('symbolic_exec', 25.0),
            analysis_percent=allocation_config.get('analysis', 15.0)
        )
        
        # Track last check time for cooldown
        self.last_check_time = 0.0
        
        # Track violations
        self.cpu_violations = 0
        self.memory_violations = 0
        
        self.logger.info(f"Resource limits: CPU {self.limits.max_cpu_percent}%, Memory {self.limits.max_memory_percent}%")
    
    def check_resources(self) -> Dict[str, Any]:
        """
        Check current resource usage.
        
        Returns:
            Dictionary with resource status
        """
        # Respect cooldown
        current_time = time.time()
        if current_time - self.last_check_time < self.limits.cooldown_seconds:
            return {'status': 'cooldown'}
        
        self.last_check_time = current_time
        
        # Get current usage
        cpu_percent = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        memory_percent = mem.percent
        memory_mb = mem.used / (1024 * 1024)
        
        # Check violations
        cpu_over = cpu_percent > self.limits.max_cpu_percent
        memory_over = memory_percent > self.limits.max_memory_percent
        
        if self.limits.max_memory_mb:
            memory_over = memory_over or (memory_mb > self.limits.max_memory_mb)
        
        # Track violations
        if cpu_over:
            self.cpu_violations += 1
        if memory_over:
            self.memory_violations += 1
        
        status = {
            'timestamp': current_time,
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'memory_mb': memory_mb,
            'cpu_over_limit': cpu_over,
            'memory_over_limit': memory_over,
            'action_required': cpu_over or memory_over
        }
        
        if cpu_over:
            self.logger.warning(f"CPU usage high: {cpu_percent:.1f}% (limit: {self.limits.max_cpu_percent}%)")
        
        if memory_over:
            self.logger.warning(f"Memory usage high: {memory_percent:.1f}% (limit: {self.limits.max_memory_percent}%)")
        
        return status
    
    def should_throttle(self) -> bool:
        """Check if throttling is needed."""
        status = self.check_resources()
        
        if status.get('status') == 'cooldown':
            return False
        
        return status.get('action_required', False)
    
    def get_allocation(self, task: str) -> float:
        """
        Get resource allocation percentage for task.
        
        Args:
            task: Task name ('fuzzing', 'symbolic_exec', 'analysis')
            
        Returns:
            Percentage allocation (0-100)
        """
        if task == 'fuzzing':
            return self.allocation.fuzzing_percent
        elif task == 'symbolic_exec':
            return self.allocation.symbolic_exec_percent
        elif task == 'analysis':
            return self.allocation.analysis_percent
        else:
            self.logger.warning(f"Unknown task: {task}, returning 33%")
            return 33.0
    
    def rebalance_allocation(self, task_performance: Dict[str, float]) -> None:
        """
        Rebalance resource allocation based on task performance.
        
        Args:
            task_performance: Dict mapping task name to effectiveness score (0-1)
        """
        self.logger.info(f"Rebalancing allocation based on performance: {task_performance}")
        
        # Calculate new allocation based on performance
        total_score = sum(task_performance.values())
        
        if total_score == 0:
            self.logger.warning("All tasks have zero performance, keeping current allocation")
            return
        
        # Normalize to 100%
        self.allocation.fuzzing_percent = (task_performance.get('fuzzing', 0.5) / total_score) * 100
        self.allocation.symbolic_exec_percent = (task_performance.get('symbolic_exec', 0.3) / total_score) * 100
        self.allocation.analysis_percent = (task_performance.get('analysis', 0.2) / total_score) * 100
        
        self.logger.info(f"New allocation: Fuzzing {self.allocation.fuzzing_percent:.1f}%, "
                        f"SymEx {self.allocation.symbolic_exec_percent:.1f}%, "
                        f"Analysis {self.allocation.analysis_percent:.1f}%")
    
    def get_status(self) -> Dict[str, Any]:
        """Get controller status."""
        current = self.check_resources()
        
        return {
            'limits': self.limits.to_dict(),
            'allocation': self.allocation.to_dict(),
            'current_resources': current,
            'violations': {
                'cpu': self.cpu_violations,
                'memory': self.memory_violations
            }
        }
    
    def reset_violations(self) -> None:
        """Reset violation counters."""
        self.cpu_violations = 0
        self.memory_violations = 0

"""
Core interfaces for NeuroFuzz components.

This module defines the abstract base classes that all NeuroFuzz components must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum


class FuzzingAction(Enum):
    """Actions available to the RL agent."""
    FUZZING = 0
    SYMBOLIC_EXECUTION = 1
    # NOTE: Resource allocation is AUTOMATIC based on chosen action
    # - FUZZING action → allocates more CPU/threads/time to AFL++
    # - SYMBOLIC_EXECUTION action → allocates more CPU/time to angr
    # Not a separate action - agent chooses WHAT to do, system optimizes HOW


@dataclass
class BinaryTarget:
    """Represents a target function for fuzzing/symbolic execution."""
    name: str
    address: int
    vulnerability_score: float
    complexity: int
    call_depth: int
    avoid_functions: List[str]


@dataclass
class FuzzingStats:
    """Current fuzzing statistics."""
    total_executions: int
    exec_speed: float
    paths_total: int
    paths_new: int
    crashes_total: int
    crashes_new: int
    coverage_percentage: float
    time_elapsed: float


@dataclass
class AnalysisResult:
    """Binary analysis results."""
    binary_path: str
    targets: List[BinaryTarget]
    total_functions: int
    high_priority_targets: List[str]
    metadata: Dict[str, Any]


class IBinaryAnalyzer(ABC):
    """Interface for binary analysis components."""
    
    @abstractmethod
    def analyze_binary(self, binary_path: str) -> AnalysisResult:
        """
        Analyze binary and extract vulnerability information.
        
        Args:
            binary_path: Path to the binary to analyze
            
        Returns:
            AnalysisResult containing targets and metadata
        """
        pass


class IFuzzer(ABC):
    """Interface for fuzzer components (AFL++, LibFuzzer, etc.)."""
    
    @abstractmethod
    def start(self, binary_path: str, input_dir: str, output_dir: str, timeout_ms: int = 1000) -> bool:
        """
        Start the fuzzer process.
        
        Args:
            binary_path: Path to target binary
            input_dir: Directory containing seed inputs
            output_dir: Directory for fuzzer output
            timeout_ms: Execution timeout in milliseconds
            
        Returns:
            True if fuzzer started successfully
        """
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop the fuzzer process."""
        pass
    
    @abstractmethod
    def get_stats(self) -> FuzzingStats:
        """
        Get current fuzzing statistics.
        
        Returns:
            FuzzingStats object with current metrics
        """
        pass
    
    @abstractmethod
    def is_running(self) -> bool:
        """Check if fuzzer is currently running."""
        pass


class ISymbolicExecutor(ABC):
    """Interface for symbolic execution components."""
    
    @abstractmethod
    def find_input_for_target(self, target: BinaryTarget) -> Optional[bytes]:
        """
        Use symbolic execution to find input reaching target.
        
        Args:
            target: BinaryTarget to reach
            
        Returns:
            Input bytes that reach target, or None if not found
        """
        pass


class IRLEnvironment(ABC):
    """Interface for RL environment (Gymnasium-compatible)."""
    
    @abstractmethod
    def reset(self) -> tuple:
        """
        Reset environment to initial state.
        
        Returns:
            (observation, info) tuple
        """
        pass
    
    @abstractmethod
    def step(self, action: int) -> tuple:
        """
        Execute action and return result.
        
        Args:
            action: Action index from FuzzingAction enum
            
        Returns:
            (observation, reward, terminated, truncated, info) tuple
        """
        pass
    
    @abstractmethod
    def get_observation(self) -> Any:
        """Get current observation vector."""
        pass
    
    @abstractmethod
    def calculate_reward(self, stats: FuzzingStats) -> float:
        """
        Calculate reward based on fuzzing statistics.
        
        Args:
            stats: Current fuzzing statistics
            
        Returns:
            Reward value
        """
        pass


class IOrchestrator(ABC):
    """Interface for main orchestrator component."""
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize orchestrator with configuration.
        
        Args:
            config: Configuration dictionary
        """
        pass
    
    @abstractmethod
    def run_campaign(self, mode: str) -> Dict[str, Any]:
        """
        Run fuzzing campaign.
        
        Args:
            mode: "train" | "run" | "analyze"
            
        Returns:
            Campaign results dictionary
        """
        pass

"""
Energy Estimator (DEPRECATED - Use PowerTracker instead)

This module is kept for backward compatibility only.
New code should use src.utils.power_tracker.PowerTracker which provides:
- Real hardware measurements via Intel RAPL (pyRAPL)
- Step-by-step power tracking correlated with RL actions
- Backward compatible API with record(), get_report(), save_report()

Track power consumption during fuzzing campaigns
"""

import logging
import time
import psutil
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class EnergyReading:
    """Single energy reading.
    
    DEPRECATED: Use PowerMeasurement from power_tracker instead.
    """
    timestamp: float
    cpu_percent: float
    estimated_watts: float
    joules_delta: float
    action: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'cpu_percent': self.cpu_percent,
            'estimated_watts': self.estimated_watts,
            'joules_delta': self.joules_delta,
            'action': self.action
        }


@dataclass
class EnergyReport:
    """Energy consumption report."""
    total_joules: float
    total_kwh: float
    average_watts: float
    peak_watts: float
    duration_seconds: float
    readings_count: int
    per_action_energy: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_joules': self.total_joules,
            'total_kwh': self.total_kwh,
            'average_watts': self.average_watts,
            'peak_watts': self.peak_watts,
            'duration_seconds': self.duration_seconds,
            'readings_count': self.readings_count,
            'per_action_energy': self.per_action_energy
        }


class EnergyEstimator:
    """
    Estimate power consumption based on CPU usage.
    
    ⚠️ DEPRECATED: This class is maintained for backward compatibility only.
    New code should use PowerTracker from src.utils.power_tracker which provides:
    - Real hardware measurements (Intel RAPL via pyRAPL)
    - Psutil fallback estimation
    - Step-correlated power tracking
    - Full backward compatibility
    
    For Intel i7-13700H:
    - Base TDP: 45W
    - Max TDP: 115W
    - Typical: ~60W under fuzzing load
    
    Features:
    - CPU-based power estimation
    - Per-action energy tracking
    - Total campaign energy
    - Energy efficiency metrics
    """
    
    # System-specific power profile (i7-13700H)
    BASE_POWER_WATTS = 45.0     # Idle/base load
    MAX_POWER_WATTS = 115.0      # Maximum TDP
    TYPICAL_POWER_WATTS = 60.0   # Typical fuzzing load
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize energy estimator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Extract power profile from config
        energy_config = config.get('energy_estimation', {})
        self.base_power = energy_config.get('base_watts', self.BASE_POWER_WATTS)
        self.max_power = energy_config.get('max_watts', self.MAX_POWER_WATTS)
        
        # Tracking
        self.readings: List[EnergyReading] = []
        self.start_time: Optional[float] = None
        self.last_reading_time: Optional[float] = None
        
        # Per-action tracking
        self.action_energy: Dict[str, float] = {}
        self.current_action: Optional[str] = None
        
        self.logger.info(f"Energy estimation: {self.base_power}W base, {self.max_power}W max")
    
    def start(self) -> None:
        """Start energy tracking."""
        self.start_time = time.time()
        self.last_reading_time = self.start_time
        self.logger.info("Energy tracking started")
    
    def record(self, action: Optional[str] = None) -> EnergyReading:
        """
        Record energy consumption reading.
        
        Args:
            action: Current action being performed
            
        Returns:
            EnergyReading
        """
        if self.start_time is None:
            self.start()
        
        current_time = time.time()
        
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Estimate power consumption based on CPU
        # Linear interpolation between base and max power
        estimated_watts = self.base_power + (cpu_percent / 100.0) * (self.max_power - self.base_power)
        
        # Calculate energy delta (Joules = Watts * seconds)
        time_delta = current_time - (self.last_reading_time or current_time)
        joules_delta = estimated_watts * time_delta
        
        # Create reading
        reading = EnergyReading(
            timestamp=current_time,
            cpu_percent=cpu_percent,
            estimated_watts=estimated_watts,
            joules_delta=joules_delta,
            action=action
        )
        
        self.readings.append(reading)
        self.last_reading_time = current_time
        
        # Track per-action energy
        if action:
            self.current_action = action
            if action not in self.action_energy:
                self.action_energy[action] = 0.0
            self.action_energy[action] += joules_delta
        
        return reading
    
    def get_current_power(self) -> float:
        """Get current estimated power consumption in Watts."""
        if not self.readings:
            return self.base_power
        return self.readings[-1].estimated_watts
    
    def get_total_energy(self) -> float:
        """Get total energy consumed in Joules."""
        return sum(r.joules_delta for r in self.readings)
    
    def get_average_power(self) -> float:
        """Get average power consumption in Watts."""
        if not self.readings:
            return 0.0
        
        total_joules = self.get_total_energy()
        duration = self.get_duration()
        
        if duration == 0:
            return 0.0
        
        return total_joules / duration
    
    def get_duration(self) -> float:
        """Get tracking duration in seconds."""
        if self.start_time is None:
            return 0.0
        
        end_time = self.readings[-1].timestamp if self.readings else time.time()
        return end_time - self.start_time
    
    def get_report(self) -> EnergyReport:
        """Generate energy consumption report."""
        total_joules = self.get_total_energy()
        total_kwh = total_joules / (3600 * 1000)  # Convert J to kWh
        average_watts = self.get_average_power()
        peak_watts = max((r.estimated_watts for r in self.readings), default=0.0)
        duration = self.get_duration()
        
        return EnergyReport(
            total_joules=total_joules,
            total_kwh=total_kwh,
            average_watts=average_watts,
            peak_watts=peak_watts,
            duration_seconds=duration,
            readings_count=len(self.readings),
            per_action_energy=self.action_energy.copy()
        )
    
    def save_report(self, output_path: str) -> None:
        """Save energy report to JSON."""
        import json
        
        report = self.get_report()
        
        with open(output_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)
        
        self.logger.info(f"Saved energy report to {output_path}")
    
    def save_detailed_log(self, output_path: str) -> None:
        """Save detailed energy readings to JSONL."""
        with open(output_path, 'w') as f:
            for reading in self.readings:
                f.write(json.dumps(reading.to_dict()) + '\n')
        
        self.logger.info(f"Saved {len(self.readings)} energy readings to {output_path}")
    
    def reset(self) -> None:
        """Reset energy tracking."""
        self.readings.clear()
        self.action_energy.clear()
        self.start_time = None
        self.last_reading_time = None
        self.current_action = None
        self.logger.info("Energy tracking reset")
    
    def get_efficiency_score(self, crashes_found: int) -> float:
        """
        Calculate energy efficiency score.
        
        Args:
            crashes_found: Number of unique crashes discovered
            
        Returns:
            Efficiency score (crashes per kWh)
        """
        report = self.get_report()
        
        if report.total_kwh == 0:
            return 0.0
        
        return crashes_found / report.total_kwh

"""
Simple CPU Time Tracking with psutil
Tracks CPU usage and time per RL step
"""

import logging
import time
import psutil
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict
import json
from pathlib import Path


@dataclass
class PowerMeasurement:
    """Single power measurement at a specific step."""
    step: int
    timestamp: float
    action: str  # FUZZING, SYMBOLIC_EXECUTION
    cpu_percent: float = 0.0  # psutil: CPU utilization
    estimated_watts: float = 0.0  # Estimated power
    duration_seconds: float = 0.0  # Duration of this step
    reward: float = 0.0  # RL reward for correlation analysis
    crashes_found: int = 0  # Track what was achieved
    paths_found: int = 0
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PowerTracker:
    """
    Simple CPU time and usage tracker
    Logs at EVERY RL step for granular analysis
    """
    
    def __init__(self, config: Dict, campaign_dir: Path):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.campaign_dir = campaign_dir
        
        # Power measurement history
        self.measurements: List[PowerMeasurement] = []
        
        # psutil-based estimation (simple and works in VMs)
        energy_config = config.get('energy_estimation', {})
        self.base_watts = energy_config.get('base_watts', 45)
        self.max_watts = energy_config.get('max_watts', 115)
        self.measurement_source = energy_config.get('measurement_source', 'psutil_estimate')
        self.use_rapl_if_available = energy_config.get('use_rapl_if_available', False)
        self.rapl_label = energy_config.get('rapl_label')
        self.calibration_status = 'uncalibrated'
        self.rapl_available = False

        if self.use_rapl_if_available:
            try:
                import pyRAPL  # noqa: F401
                self.rapl_available = True
                self.measurement_source = self.rapl_label or 'rapl'
            except Exception:
                self.rapl_available = False
        
        # Tracking
        self.step_start_time = None
        self.step_start_energy = None
        self.current_step = 0
        self.current_action = None
        self.session_start_time = None  # For start() method
        
        self.logger.info(f"PowerTracker initialized (psutil-based, Base: {self.base_watts}W, Max: {self.max_watts}W)")
    
    def start(self):
        """
        Backward compatibility method for EnergyEstimator.start() calls.
        Marks the beginning of tracking session.
        """
        self.session_start_time = time.time()
        self.logger.info("Power tracking session started")
    
    def start_step(self, step: int, action: str):
        """Start tracking power for a new RL step."""
        self.current_step = step
        self.current_action = action
        self.step_start_time = time.time()
    
    def end_step(self, reward: float, crashes: int, paths: int) -> PowerMeasurement:
        """
        End step tracking and return power measurement.
        This is called at EVERY RL step.
        """
        duration = time.time() - self.step_start_time if self.step_start_time else 0
        
        measurement = PowerMeasurement(
            step=self.current_step,
            timestamp=time.time(),
            action=self.current_action,
            duration_seconds=duration,
            reward=reward,
            crashes_found=crashes,
            paths_found=paths
        )
        
        # Use psutil for power estimation (works in VMs)
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            measurement.cpu_percent = cpu_percent
            
            # Estimate power: base + (utilization_fraction * dynamic_range)
            dynamic_watts = (cpu_percent / 100.0) * (self.max_watts - self.base_watts)
            measurement.estimated_watts = self.base_watts + dynamic_watts
            
            self.logger.debug(f"[Step {self.current_step}] {measurement.estimated_watts:.2f}W (CPU: {cpu_percent:.1f}%, {duration:.2f}s)")
            
        except Exception as e:
            self.logger.error(f"Power estimation failed: {e}")
            measurement.estimated_watts = self.base_watts
        
        # Store measurement
        self.measurements.append(measurement)
        
        return measurement
    
    def record(self, action: str = "UNKNOWN") -> PowerMeasurement:
        """
        Backward compatibility method for EnergyEstimator.record() calls.
        
        Performs instant measurement (not tied to step boundaries).
        Used by callbacks that expect old EnergyEstimator interface.
        
        Args:
            action: Action name for tracking
            
        Returns:
            PowerMeasurement with current readings
        """
        measurement = PowerMeasurement(
            step=self.current_step,
            timestamp=time.time(),
            action=action,
            cpu_percent=psutil.cpu_percent(interval=0.1),
            estimated_watts=self._estimate_power_psutil(),
            duration_seconds=0.0,  # Instant measurement
            reward=0.0,
            crashes_found=0,
            paths_found=0
        )
        
        # Note: We don't append to measurements list for instant recordings
        # to avoid polluting step-based measurements
        return measurement
    
    def _estimate_power_psutil(self) -> float:
        """Estimate power based on CPU utilization (psutil fallback)."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            dynamic_watts = (cpu_percent / 100.0) * (self.max_watts - self.base_watts)
            return self.base_watts + dynamic_watts
        except:
            return self.base_watts

    def apply_calibration(self, base_watts: float, max_watts: float, status: str = 'calibrated') -> None:
        """Apply manual calibration values for base/max watts."""
        try:
            self.base_watts = float(base_watts)
            self.max_watts = float(max_watts)
            self.calibration_status = status
            self.logger.info(f"Applied energy calibration: base={self.base_watts}W, max={self.max_watts}W ({status})")
        except Exception as e:
            self.logger.warning(f"Failed to apply calibration values: {e}")
    
    def get_current_power_watts(self) -> float:
        """Get current power consumption in watts (for RL observation)."""
        if self.measurements:
            return self.measurements[-1].estimated_watts
        return self.base_watts
    
    def get_total_energy_kwh(self) -> float:
        """Get cumulative energy consumption in kWh."""
        # Calculate based on power * duration for each step
        total_watt_seconds = sum(
            m.estimated_watts * m.duration_seconds 
            for m in self.measurements 
            if m.estimated_watts and m.duration_seconds
        )
        # Watt-seconds -> Wh -> kWh
        watt_hours = total_watt_seconds / 3600
        return watt_hours / 1000
    
    def get_average_power_watts(self) -> float:
        """Get average power consumption across all steps."""
        if not self.measurements:
            return 0.0
        powers = [m.estimated_watts for m in self.measurements if m.estimated_watts > 0]
        return sum(powers) / len(powers) if powers else 0.0
    
    def get_power_by_action(self) -> Dict[str, float]:
        """Get average power consumption per action type."""
        action_power = {}
        action_counts = {}
        
        for m in self.measurements:
            if m.action not in action_power:
                action_power[m.action] = 0.0
                action_counts[m.action] = 0
            action_power[m.action] += m.estimated_watts
            action_counts[m.action] += 1
        
        return {
            action: action_power[action] / action_counts[action]
            for action in action_power
        }
    
    def get_power_efficiency_metrics(self) -> Dict:
        """Calculate power efficiency metrics for academic comparison."""
        total_energy_kwh = self.get_total_energy_kwh()
        total_crashes = sum(m.crashes_found for m in self.measurements)
        total_paths = sum(m.paths_found for m in self.measurements)
        
        return {
            'total_energy_kwh': total_energy_kwh,
            'average_power_watts': self.get_average_power_watts(),
            'peak_power_watts': max((m.estimated_watts for m in self.measurements), default=0),
            'total_crashes': total_crashes,
            'total_paths': total_paths,
            'crashes_per_kwh': total_crashes / total_energy_kwh if total_energy_kwh > 0 else 0,
            'paths_per_kwh': total_paths / total_energy_kwh if total_energy_kwh > 0 else 0,
            'power_by_action': self.get_power_by_action(),
            'measurement_source': self.measurement_source or 'psutil_estimate'
        }
    
    def save_detailed_log(self):
        """Save step-by-step power log to JSON for analysis."""
        log_file = self.campaign_dir / 'power_log_detailed.json'
        
        data = {
            'metadata': {
                'base_watts': self.base_watts,
                'max_watts': self.max_watts,
                'total_steps': len(self.measurements),
                'measurement_source': self.measurement_source or 'psutil_estimate',
                'use_rapl_if_available': self.use_rapl_if_available,
                'rapl_label': self.rapl_label,
                'calibration_status': self.calibration_status
            },
            'summary': self.get_power_efficiency_metrics(),
            'step_by_step': [m.to_dict() for m in self.measurements]
        }
        
        try:
            with open(log_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info(f"✓ Detailed power log saved: {log_file}")
        except Exception as e:
            self.logger.error(f"Failed to save power log: {e}")
    
    def get_normalized_power_for_observation(self) -> float:
        """Get normalized power (0-1) for RL observation space."""
        current_watts = self.get_current_power_watts()
        # Normalize: 0 = base_watts, 1 = max_watts
        normalized = (current_watts - self.base_watts) / (self.max_watts - self.base_watts)
        return max(0.0, min(1.0, normalized))
    
    def get_report(self) -> Dict:
        """
        Backward compatibility method for EnergyEstimator.get_report() calls.
        Returns report in same format as old EnergyEstimator.
        """
        return self.get_power_efficiency_metrics()
    
    def save_report(self, filepath: str):
        """
        Backward compatibility method for EnergyEstimator.save_report() calls.
        Saves JSON report to specified filepath.
        """
        try:
            import json
            from pathlib import Path
            
            report = self.get_report()
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"✓ Energy report saved: {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to save energy report: {e}")

"""
NeuroFuzz Evaluator
Generate academic reports with visualizations
"""

import logging
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass, field
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


@dataclass
class TrainingMetrics:
    """Training metrics for RL agent."""
    episodes: List[int] = field(default_factory=list)
    rewards: List[float] = field(default_factory=list)
    episode_lengths: List[int] = field(default_factory=list)
    learning_rate: List[float] = field(default_factory=list)
    loss: List[float] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'episodes': self.episodes,
            'rewards': self.rewards,
            'episode_lengths': self.episode_lengths,
            'learning_rate': self.learning_rate,
            'loss': self.loss
        }


@dataclass
class FuzzingMetrics:
    """Fuzzing metrics over time."""
    timestamps: List[float] = field(default_factory=list)
    total_paths: List[int] = field(default_factory=list)
    crashes: List[int] = field(default_factory=list)
    hangs: List[int] = field(default_factory=list)
    exec_speed: List[float] = field(default_factory=list)
    coverage_estimate: List[float] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamps': self.timestamps,
            'total_paths': self.total_paths,
            'crashes': self.crashes,
            'hangs': self.hangs,
            'exec_speed': self.exec_speed,
            'coverage_estimate': self.coverage_estimate
        }


@dataclass
class EvaluationReport:
    """Complete evaluation report."""
    campaign_name: str
    binary_path: str
    mode: str
    duration: float
    training_metrics: Optional[TrainingMetrics]
    fuzzing_metrics: FuzzingMetrics
    final_stats: Dict[str, Any]
    resource_usage: Dict[str, Any]
    key_findings: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'campaign_name': self.campaign_name,
            'binary_path': self.binary_path,
            'mode': self.mode,
            'duration': self.duration,
            'training_metrics': self.training_metrics.to_dict() if self.training_metrics else None,
            'fuzzing_metrics': self.fuzzing_metrics.to_dict(),
            'final_stats': self.final_stats,
            'resource_usage': self.resource_usage,
            'key_findings': self.key_findings
        }


class NeuroFuzzEvaluator:
    """
    Generate evaluation reports with visualizations.
    
    Features:
    - Training performance plots (episodes, rewards, loss)
    - Fuzzing metrics plots (paths, crashes, coverage)
    - Resource usage plots (CPU, memory)
    - JSON reports for post-analysis
    - Academic-style plots (publication ready)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize evaluator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configure matplotlib for publication quality
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 6)
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['xtick.labelsize'] = 10
        plt.rcParams['ytick.labelsize'] = 10
        plt.rcParams['legend.fontsize'] = 10
    
    def generate_report(
        self,
        campaign_name: str,
        binary_path: str,
        mode: str,
        duration: float,
        training_metrics: Optional[TrainingMetrics],
        fuzzing_metrics: FuzzingMetrics,
        final_stats: Dict[str, Any],
        resource_usage: Dict[str, Any],
        output_dir: str
    ) -> EvaluationReport:
        """
        Generate complete evaluation report.
        
        Args:
            campaign_name: Campaign name
            binary_path: Target binary path
            mode: Execution mode
            duration: Campaign duration
            training_metrics: Training metrics (if mode=train)
            fuzzing_metrics: Fuzzing metrics
            final_stats: Final fuzzing statistics
            resource_usage: Resource usage stats
            output_dir: Output directory
            
        Returns:
            EvaluationReport
        """
        self.logger.info(f"Generating evaluation report for {campaign_name}")
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate key findings
        key_findings = self._generate_findings(
            mode, training_metrics, fuzzing_metrics, final_stats, resource_usage
        )
        
        # Create report
        report = EvaluationReport(
            campaign_name=campaign_name,
            binary_path=binary_path,
            mode=mode,
            duration=duration,
            training_metrics=training_metrics,
            fuzzing_metrics=fuzzing_metrics,
            final_stats=final_stats,
            resource_usage=resource_usage,
            key_findings=key_findings
        )
        
        self._save_json_report(report, output_path / "evaluation_report.json")
        self._generate_plots(report, training_metrics, fuzzing_metrics, resource_usage, output_path)
        
        self.logger.info(f"Evaluation report saved to {output_dir}")
        return report
    
    def _generate_findings(
        self,
        mode: str,
        training_metrics: Optional[TrainingMetrics],
        fuzzing_metrics: FuzzingMetrics,
        final_stats: Dict[str, Any],
        resource_usage: Dict[str, Any]
    ) -> List[str]:
        """Generate key findings from metrics."""
        findings = []
        
        # Fuzzing findings (use correct field names from feedback_collector)
        total_crashes = final_stats.get('total_crashes') or 0  # Was 'saved_crashes'
        total_paths = final_stats.get('total_paths') or 0      # Was 'paths_total'
        exec_speed = final_stats.get('avg_exec_speed') or 0    # Was 'execs_per_sec'
        
        findings.append(f"Discovered {total_crashes} unique crashes")
        findings.append(f"Explored {total_paths} unique paths")
        findings.append(f"Average execution speed: {exec_speed:.0f} execs/sec")
        
        # Coverage findings
        if fuzzing_metrics.coverage_estimate:
            final_coverage = fuzzing_metrics.coverage_estimate[-1]
            findings.append(f"Estimated code coverage: {final_coverage:.1f}%")
        
        # Training findings
        if mode in ['train', 'all'] and training_metrics:
            if training_metrics.rewards:
                avg_reward = np.mean(training_metrics.rewards[-10:])
                findings.append(f"Average reward (last 10 episodes): {avg_reward:.2f}")
        
        # Resource findings
        if resource_usage:
            peak_cpu = resource_usage.get('peak_cpu') or 0
            peak_memory = resource_usage.get('peak_memory_mb') or 0
            findings.append(f"Peak CPU usage: {peak_cpu:.1f}%")
            findings.append(f"Peak memory usage: {peak_memory:.0f} MB")

        # Energy findings (label estimates)
        energy = resource_usage.get('energy_report') if resource_usage else None
        if energy:
            src = energy.get('measurement_source', 'estimated')
            total_energy = energy.get('total_energy_kwh') or 0
            avg_power = energy.get('average_power_watts') or 0
            findings.append(f"Energy ({src}): {total_energy:.6f} kWh, avg power {avg_power:.1f}W")
        
        return findings
    
    def _save_json_report(self, report: EvaluationReport, output_path: Path) -> None:
        """Save report to JSON."""
        
        class NumpyEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, np.integer):
                    return int(obj)
                if isinstance(obj, np.floating):
                    return float(obj)
                if isinstance(obj, np.ndarray):
                    return obj.tolist()
                return super(NumpyEncoder, self).default(obj)

        with open(output_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2, cls=NumpyEncoder)
        
        self.logger.info(f"Saved JSON report to {output_path}")

    def _load_enhanced_metrics(self, campaign_dir: Path) -> Dict[str, Any]:
        data = {
            'time_minutes': [],
            'paths': [],
            'crashes': [],
            'exec_speed': [],
            'coverage': [],
            'actions': [],
            'action_counts': {}
        }

        metrics_path = campaign_dir / "enhanced_metrics.jsonl"
        if metrics_path.exists():
            try:
                with open(metrics_path, 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        data['time_minutes'].append(entry.get('session_runtime', 0) / 60.0)
                        data['paths'].append(entry.get('paths_total', 0))
                        data['crashes'].append(entry.get('crashes_total', 0))
                        data['exec_speed'].append(entry.get('execs_per_sec', 0))
                        data['coverage'].append(entry.get('coverage_estimate', 0))
                        action = entry.get('action_taken') or entry.get('action')
                        if action:
                            data['actions'].append(action)
                if data['actions']:
                    data['action_counts'] = dict(Counter(data['actions']))
            except Exception as e:
                self.logger.warning(f"Failed to load enhanced metrics: {e}")

        return data

    def _load_power_data(self, campaign_dir: Path) -> Dict[str, Any]:
        power_data = {'summary': {}, 'steps': []}

        json_path = campaign_dir / "power_log_detailed.json"
        if json_path.exists():
            try:
                with open(json_path, 'r') as f:
                    raw = json.load(f)
                summary = raw.get('summary', {})
                steps = raw.get('step_by_step', [])
                base_ts = steps[0].get('timestamp') if steps else None
                time_minutes = []
                for step in steps:
                    if base_ts is not None:
                        time_minutes.append((step.get('timestamp', base_ts) - base_ts) / 60.0)
                    else:
                        time_minutes.append(len(time_minutes))
                power_data['summary'] = summary
                power_data['steps'] = [
                    {
                        'time_minutes': t,
                        'power': step.get('estimated_watts', 0),
                        'cpu': step.get('cpu_percent', 0),
                        'action': step.get('action', 'UNKNOWN'),
                        'reward': step.get('reward', 0),
                        'crashes': step.get('crashes_found', 0),
                        'paths': step.get('paths_found', 0),
                    }
                    for t, step in zip(time_minutes, steps)
                ]
                return power_data
            except Exception as e:
                self.logger.warning(f"Failed to load power_log_detailed.json: {e}")

        jsonl_path = campaign_dir / "power_tracking_detailed.jsonl"
        if jsonl_path.exists():
            try:
                steps = []
                with open(jsonl_path, 'r') as f:
                    for line in f:
                        if line.strip():
                            steps.append(json.loads(line))
                if steps:
                    base_time = steps[0].get('elapsed_time', 0)
                    power_data['steps'] = [
                        {
                            'time_minutes': (s.get('elapsed_time', base_time) - base_time) / 60.0,
                            'power': s.get('power_watts', 0),
                            'cpu': s.get('cpu_percent', 0),
                            'action': s.get('action', 'UNKNOWN'),
                            'reward': 0,
                            'crashes': 0,
                            'paths': 0,
                        }
                        for s in steps
                    ]
            except Exception as e:
                self.logger.warning(f"Failed to load power_tracking_detailed.jsonl: {e}")

        return power_data

    def _derive_time_series(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Compute deltas and helper series for plotting."""
        times = metrics_data.get('time_minutes', []) or []
        paths = metrics_data.get('paths', []) or []
        crashes = metrics_data.get('crashes', []) or []
        exec_speed = metrics_data.get('exec_speed', []) or []
        coverage = metrics_data.get('coverage', []) or []
        actions = metrics_data.get('actions', []) or []

        new_paths = []
        new_crashes = []
        new_paths_rate = []
        action_entropy = []
        cumulative_counts: Counter = Counter()

        for idx in range(len(times)):
            if idx == 0:
                new_paths.append(0)
                new_crashes.append(0)
                new_paths_rate.append(0)
            else:
                dp = max(0, paths[idx] - paths[idx - 1]) if idx < len(paths) else 0
                dc = max(0, crashes[idx] - crashes[idx - 1]) if idx < len(crashes) else 0
                dt = times[idx] - times[idx - 1] if times[idx] is not None and times[idx - 1] is not None else 0
                rate = (dp / dt) if dt and dt > 0 else 0
                new_paths.append(dp)
                new_crashes.append(dc)
                new_paths_rate.append(rate)

            if idx < len(actions):
                cumulative_counts[actions[idx]] += 1
                total = sum(cumulative_counts.values())
                if total > 0:
                    probs = [c / total for c in cumulative_counts.values() if c > 0]
                    entropy = -sum(p * np.log2(p) for p in probs)
                else:
                    entropy = 0
                action_entropy.append(entropy)

        return {
            'times': times,
            'paths': paths,
            'crashes': crashes,
            'exec_speed': exec_speed,
            'coverage': coverage,
            'actions': actions,
            'new_paths': new_paths,
            'new_crashes': new_crashes,
            'new_paths_rate': new_paths_rate,
            'action_entropy': action_entropy
        }

    def _plot_power_over_time(self, power_data: Dict[str, Any], output_path: Path) -> None:
        steps = power_data.get('steps') or []
        if not steps:
            return

        times = [s['time_minutes'] for s in steps]
        watts = [s.get('power', 0) for s in steps]

        plt.figure(figsize=(12, 6))
        plt.plot(times, watts, linewidth=2.5, color='#f39c12', marker='o', markersize=4, alpha=0.9)
        plt.fill_between(times, watts, alpha=0.2, color='#f39c12')
        plt.xlabel('Time (minutes)', fontsize=13, fontweight='bold')
        plt.ylabel('Power (Watts)', fontsize=13, fontweight='bold')
        plt.title('Power Consumption Over Time', fontsize=15, fontweight='bold', pad=20)
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved power over time plot to {output_path}")

    def _plot_rl_learning_curve(self, power_data: Dict[str, Any], training_metrics: Optional[TrainingMetrics], output_path: Path) -> None:
        """Plot RL learning curve with smoothing."""
        steps = power_data.get('steps') or []
        rewards = []
        times = []
        xlabel = 'Time (minutes)'
        title = 'RL Learning Curve'
        
        # Prefer training_metrics if available (episodic rewards)
        if training_metrics and training_metrics.rewards:
            rewards = training_metrics.rewards
            episodes = training_metrics.episodes
            if episodes and len(episodes) == len(rewards):
                times = episodes
                xlabel = 'Episode'
                title = 'RL Learning Curve (Episodic Reward)'
            else:
                # Fallback if lengths mismatch
                times = list(range(1, len(rewards) + 1))
                xlabel = 'Episode'
        
        # Fallback to step rewards if no training metrics
        if not rewards and steps:
            rewards = [s.get('reward', 0) for s in steps if s.get('reward') is not None]
            times = [s['time_minutes'] for s in steps[:len(rewards)]]
            xlabel = 'Time (minutes)'
            title = 'RL Learning Curve (Step Rewards)'
            
        if not rewards:
            return

        plt.figure(figsize=(12, 6))
        
        # Raw rewards
        plt.plot(times, rewards, alpha=0.3, color='#bdc3c7', label='Raw Reward')
        
        # Smoothed rewards (Moving Average)
        window_size = max(5, len(rewards) // 10)
        if window_size > 1:
            smoothed = np.convolve(rewards, np.ones(window_size)/window_size, mode='valid')
            valid_times = times[len(times)-len(smoothed):]
            plt.plot(valid_times, smoothed, linewidth=2.5, color='#2ecc71', label=f'Moving Avg (n={window_size})')
        
        plt.xlabel(xlabel, fontsize=13, fontweight='bold')
        plt.ylabel('Reward', fontsize=13, fontweight='bold')
        plt.title(title, fontsize=15, fontweight='bold', pad=20)
        plt.legend()
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved RL learning curve to {output_path}")

    def _plot_cumulative_reward(self, power_data: Dict[str, Any], output_path: Path) -> None:
        """Plot cumulative reward over time."""
        steps = power_data.get('steps') or []
        rewards = [s.get('reward', 0) for s in steps if s.get('reward') is not None]
        if not steps or not rewards:
            return

        times = [s['time_minutes'] for s in steps[:len(rewards)]]
        cumulative_rewards = np.cumsum(rewards)
        
        plt.figure(figsize=(12, 6))
        plt.plot(times, cumulative_rewards, linewidth=2.5, color='#8e44ad', marker='None', alpha=0.9)
        plt.fill_between(times, cumulative_rewards, alpha=0.1, color='#8e44ad')
        plt.xlabel('Time (minutes)', fontsize=13, fontweight='bold')
        plt.ylabel('Cumulative Reward', fontsize=13, fontweight='bold')
        plt.title('Cumulative Reward Over Time', fontsize=15, fontweight='bold', pad=20)
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved cumulative reward plot to {output_path}")

    def _plot_line(self, x: List[float], y: List[float], title: str, ylabel: str, output_path: Path, color: str) -> None:
        if not x or not y or len(x) != len(y):
            return
        plt.figure(figsize=(12, 6))
        plt.plot(x, y, linewidth=2.5, color=color, marker='o', markersize=3, alpha=0.9)
        plt.fill_between(x, y, alpha=0.18, color=color)
        plt.xlabel('Time (minutes)', fontsize=13, fontweight='bold')
        plt.ylabel(ylabel, fontsize=13, fontweight='bold')
        plt.title(title, fontsize=15, fontweight='bold', pad=20)
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved plot to {output_path}")

    def _plot_action_timeline(self, times: List[float], actions: List[str], output_path: Path) -> None:
        if not times or not actions:
            return
        n = min(len(times), len(actions))
        times = times[:n]
        actions = actions[:n]
        unique_actions = sorted(set(actions))
        if not unique_actions:
            return
        counts = {a: [0] * n for a in unique_actions}
        cumulative = Counter()
        for idx, act in enumerate(actions):
            cumulative[act] += 1
            for a in unique_actions:
                counts[a][idx] = cumulative[a]
        plt.figure(figsize=(12, 6))
        bottoms = np.zeros(n)
        for a in unique_actions:
            vals = np.array(counts[a])
            plt.fill_between(times, bottoms, bottoms + vals, step='mid', alpha=0.3, label=a)
            bottoms += vals
        plt.xlabel('Time (minutes)', fontsize=13, fontweight='bold')
        plt.ylabel('Cumulative action count', fontsize=13, fontweight='bold')
        plt.title('Action Timeline (Cumulative)', fontsize=15, fontweight='bold', pad=20)
        plt.legend()
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved action timeline to {output_path}")

    def _plot_symex_roi(self, series: Dict[str, Any], actions: List[str], output_path: Path) -> None:
        if not actions or not series.get('new_paths'):
            return
        n = min(len(actions), len(series['new_paths']))
        actions = actions[:n]
        new_paths = series['new_paths'][:n]
        new_crashes = series['new_crashes'][:n]
        roi = {}
        counts = Counter()
        for act, dp, dc in zip(actions, new_paths, new_crashes):
            counts[act] += 1
            if act not in roi:
                roi[act] = {'paths': 0, 'crashes': 0}
            roi[act]['paths'] += dp
            roi[act]['crashes'] += dc
        labels = list(roi.keys())
        if not labels:
            return
        paths_per_call = [roi[l]['paths'] / counts[l] if counts[l] else 0 for l in labels]
        crashes_per_call = [roi[l]['crashes'] / counts[l] if counts[l] else 0 for l in labels]
        x = np.arange(len(labels))
        width = 0.35
        plt.figure(figsize=(12, 6))
        plt.bar(x - width/2, paths_per_call, width, label='New paths per action', color='#3498db', alpha=0.8)
        plt.bar(x + width/2, crashes_per_call, width, label='New crashes per action', color='#e74c3c', alpha=0.8)
        plt.xticks(x, labels, fontsize=12)
        plt.ylabel('Avg outcome per action', fontsize=13, fontweight='bold')
        plt.title('Action ROI (per-step averages)', fontsize=15, fontweight='bold', pad=20)
        plt.legend()
        plt.grid(True, alpha=0.25, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved action ROI plot to {output_path}")

    def _plot_energy_efficiency(self, final_stats: Dict[str, Any], resource_usage: Dict[str, Any], output_path: Path) -> None:
        energy = (resource_usage or {}).get('energy_report') or {}
        total_energy = energy.get('total_energy_kwh')
        if not total_energy or total_energy <= 0:
            return
        crashes = final_stats.get('total_crashes', 0)
        execs = final_stats.get('total_executions', 0)
        
        # Calculate CPU-Hours (approximate based on wall time and avg CPU usage if available, else wall time)
        # Assuming single-core AFL, wall time is roughly CPU time. 
        # If we have avg_cpu_percent, we can refine it.
        avg_cpu = resource_usage.get('avg_cpu_percent', 100.0)
        duration_hours = (resource_usage.get('duration_seconds', 0) / 3600.0) or 1.0
        cpu_hours = duration_hours * (avg_cpu / 100.0)
        
        metrics = {
            'Crashes/kWh': crashes / total_energy if total_energy else 0,
            'Crashes/CPU-Hr': crashes / cpu_hours if cpu_hours > 0 else 0,
            'Execs/kWh': execs / total_energy if total_energy else 0,
            'Energy (kWh)': total_energy
        }
        labels = list(metrics.keys())
        values = list(metrics.values())
        colors = ['#e74c3c', '#e67e22', '#3498db', '#95a5a6']
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color=colors[:len(labels)], alpha=0.85)
        plt.ylabel('Value', fontsize=13, fontweight='bold')
        plt.title('Efficiency Metrics (Energy & Compute)', fontsize=15, fontweight='bold', pad=20)
        plt.grid(True, axis='y', alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved energy efficiency plot to {output_path}")

    def _plot_throughput_vs_power(self, metrics_data: Dict[str, Any], power_data: Dict[str, Any], output_path: Path) -> None:
        steps = power_data.get('steps') or []
        exec_speed = metrics_data.get('exec_speed') or []
        if not steps or not exec_speed:
            return
        n = min(len(steps), len(exec_speed))
        power = [s.get('power', 0) for s in steps[:n]]
        speed = exec_speed[:n]
        plt.figure(figsize=(10, 6))
        plt.scatter(power, speed, c='#8e44ad', alpha=0.7, edgecolors='none')
        plt.xlabel('Power (Watts)', fontsize=13, fontweight='bold')
        plt.ylabel('Execs/sec', fontsize=13, fontweight='bold')
        plt.title('Throughput vs Power', fontsize=15, fontweight='bold', pad=20)
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved throughput vs power scatter to {output_path}")

    def _generate_plots(
        self,
        report: EvaluationReport,
        training_metrics: Optional[TrainingMetrics],
        fuzzing_metrics: FuzzingMetrics,
        resource_usage: Dict[str, Any],
        evaluation_dir: Path
    ) -> None:
        """Generate all plots available from collected metrics."""
        evaluation_dir.mkdir(parents=True, exist_ok=True)
        campaign_dir = evaluation_dir.parent

        metrics_data = self._load_enhanced_metrics(campaign_dir)
        power_data = self._load_power_data(campaign_dir)
        series = self._derive_time_series(metrics_data)

        plot_steps = []

        plot_steps.extend([
            lambda: self._plot_action_distribution(metrics_data, power_data, evaluation_dir / "action_distribution.png"),
            lambda: self._plot_cpu_power_tracking(resource_usage, evaluation_dir / "cpu_power.png", power_data),
            lambda: self._plot_power_over_time(power_data, evaluation_dir / "power_over_time.png"),
            lambda: self._plot_rl_learning_curve(power_data, training_metrics, evaluation_dir / "learning_curve.png"),
            lambda: self._plot_cumulative_reward(power_data, evaluation_dir / "cumulative_reward.png"),
            lambda: self._plot_line(series['times'], series['crashes'], 'Crash Discovery Over Time', 'Crashes', evaluation_dir / "crashes_over_time.png", '#e74c3c'),
            lambda: self._plot_line(series['times'], series['paths'], 'Path Discovery Over Time', 'Total Paths', evaluation_dir / "paths_over_time.png", '#3498db'),
            lambda: self._plot_line(series['times'], series['new_paths_rate'], 'Path Novelty Rate', 'New paths per minute', evaluation_dir / "new_paths_rate.png", '#16a085'),
            lambda: self._plot_line(series['times'], series['exec_speed'], 'Execution Speed Over Time', 'Execs/sec', evaluation_dir / "exec_speed_over_time.png", '#2ecc71'),
            lambda: self._plot_line(series['times'], series['coverage'], 'Coverage Estimate Over Time', 'Coverage (%)', evaluation_dir / "coverage_over_time.png", '#9b59b6'),
            lambda: self._plot_action_timeline(series['times'], series['actions'], evaluation_dir / "action_timeline.png"),
            lambda: self._plot_line(series['times'][:len(series['action_entropy'])], series['action_entropy'], 'Action Entropy Over Time', 'Entropy (bits)', evaluation_dir / "action_entropy.png", '#34495e'),
            lambda: self._plot_symex_roi(series, series['actions'], evaluation_dir / "action_roi.png"),
            lambda: self._plot_energy_efficiency(report.final_stats, resource_usage, evaluation_dir / "energy_efficiency.png"),
            lambda: self._plot_throughput_vs_power(metrics_data, power_data, evaluation_dir / "throughput_vs_power.png"),
        ])

        for make_plot in plot_steps:
            try:
                make_plot()
            except Exception as e:
                self.logger.warning(f"Plot skipped: {e}")
    
    def _plot_cpu_power_tracking(self, resource_usage: Dict[str, Any], output_path: Path, power_data: Optional[Dict[str, Any]] = None) -> None:
        """Plot CPU usage and power consumption over time."""
        steps = (power_data or {}).get('steps') or []
        if steps:
            time_minutes = [s.get('time_minutes', 0) for s in steps]
            cpu_usage = [s.get('cpu', 0) for s in steps]
            power_watts = [s.get('power', 0) for s in steps]

            fig, ax1 = plt.subplots(figsize=(12, 6))
            ax1.plot(time_minutes, cpu_usage, linewidth=2.5, color='#3498db', marker='o', markersize=3, alpha=0.9, label='CPU Usage')
            ax1.fill_between(time_minutes, cpu_usage, alpha=0.2, color='#3498db')
            ax1.set_xlabel('Time (minutes)', fontsize=13, fontweight='bold')
            ax1.set_ylabel('CPU Usage (%)', fontsize=13, fontweight='bold', color='#3498db')
            ax1.tick_params(axis='y', labelcolor='#3498db')
            ax1.grid(True, alpha=0.3, linestyle='--')

            ax2 = ax1.twinx()
            ax2.plot(time_minutes, power_watts, linewidth=2.5, color='#f39c12', marker='s', markersize=3, alpha=0.9, label='Power')
            ax2.fill_between(time_minutes, power_watts, alpha=0.2, color='#f39c12')
            ax2.set_ylabel('Power (Watts)', fontsize=13, fontweight='bold', color='#f39c12')
            ax2.tick_params(axis='y', labelcolor='#f39c12')

            plt.title('CPU Usage & Power Consumption Over Time', fontsize=15, fontweight='bold', pad=20)
            fig.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            self.logger.info(f"Saved CPU/power tracking plot to {output_path}")
            return

        peak_cpu = resource_usage.get('peak_cpu', 0)
        plt.figure(figsize=(12, 6))
        plt.axhline(y=peak_cpu, color='#3498db', linewidth=3, linestyle='--', label=f'Peak CPU: {peak_cpu:.1f}%')
        plt.xlabel('Training Session', fontsize=13, fontweight='bold')
        plt.ylabel('CPU Usage (%)', fontsize=13, fontweight='bold')
        plt.title('CPU Usage - Training Session', fontsize=15, fontweight='bold', pad=20)
        plt.legend(fontsize=12)
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.ylim(0, 100)
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved CPU tracking plot to {output_path}")
    
    def _plot_action_distribution(self, metrics_data: Dict[str, Any], power_data: Dict[str, Any], output_path: Path) -> None:
        """Plot action distribution pie chart."""
        action_counts = metrics_data.get('action_counts', {}) if metrics_data else {}

        if not action_counts:
            steps = power_data.get('steps', [])
            if steps:
                actions = [s.get('action', 'UNKNOWN') for s in steps]
                action_counts = dict(Counter(actions))

        if not action_counts:
            summary = power_data.get('summary', {})
            power_by_action = summary.get('power_by_action', {}) if summary else {}
            if power_by_action:
                action_counts = {k: v for k, v in power_by_action.items()}

        if not action_counts:
            self.logger.warning("No action distribution data available")
            return

        labels = list(action_counts.keys())
        sizes = list(action_counts.values())
        colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12'][:len(labels)]
        
        plt.figure(figsize=(10, 8))
        wedges, texts, autotexts = plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                                            startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(13)
            autotext.set_fontweight('bold')
        
        plt.title('RL Agent Action Distribution', fontsize=15, fontweight='bold', pad=20)
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        self.logger.info(f"Saved action distribution plot to {output_path}")
    
    def _plot_fuzzing_metrics(self, metrics: FuzzingMetrics, output_path: Path) -> None:
        """Legacy method - now split into individual plots."""
        pass
        try:
            # Try to load high-resolution data from enhanced_metrics.jsonl
            campaign_dir = output_path.parent
            metrics_path = campaign_dir / "enhanced_metrics.jsonl"
            
            if metrics_path.exists():
                self.logger.info(f"Loading high-resolution fuzzing metrics from {metrics_path}")
                timestamps = []
                paths = []
                crashes = []
                exec_speeds = []
                coverages = []
                
                with open(metrics_path, 'r') as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            timestamps.append(data.get('session_runtime', 0))
                            paths.append(data.get('paths_total', 0))
                            crashes.append(data.get('crashes_total', 0))
                            exec_speeds.append(data.get('execs_per_sec', 0))
                            coverages.append(data.get('coverage_estimate', 0))
                
                if timestamps:
                    time_minutes = [t / 60 for t in timestamps]
                    
                    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
                    
                    # Total paths
                    axes[0, 0].plot(time_minutes, paths, linewidth=2, color='#3498db', alpha=0.8, marker='o')
                    axes[0, 0].set_xlabel('Time (minutes)', fontsize=11)
                    axes[0, 0].set_ylabel('Total Paths', fontsize=11)
                    axes[0, 0].set_title('Path Discovery Over Time', fontsize=12, fontweight='bold')
                    axes[0, 0].grid(True, alpha=0.3)
                    axes[0, 0].fill_between(time_minutes, paths, alpha=0.2, color='#3498db')
                    
                    # Crashes
                    axes[0, 1].plot(time_minutes, crashes, linewidth=2, color='#e74c3c', marker='o', markersize=3, alpha=0.8)
                    axes[0, 1].set_xlabel('Time (minutes)', fontsize=11)
                    axes[0, 1].set_ylabel('Crashes', fontsize=11)
                    axes[0, 1].set_title('Crash Discovery Over Time', fontsize=12, fontweight='bold')
                    axes[0, 1].grid(True, alpha=0.3)
                    axes[0, 1].fill_between(time_minutes, crashes, alpha=0.2, color='#e74c3c')
                    
                    # Execution speed
                    axes[1, 0].plot(time_minutes, exec_speeds, linewidth=2, color='#2ecc71', alpha=0.8, marker='o')
                    axes[1, 0].set_xlabel('Time (minutes)', fontsize=11)
                    axes[1, 0].set_ylabel('Execs/sec', fontsize=11)
                    axes[1, 0].set_title('Execution Speed Over Time', fontsize=12, fontweight='bold')
                    axes[1, 0].grid(True, alpha=0.3)
                    axes[1, 0].fill_between(time_minutes, exec_speeds, alpha=0.2, color='#2ecc71')
                    
                    # Coverage estimate
                    axes[1, 1].plot(time_minutes, coverages, linewidth=2, color='#9b59b6', alpha=0.8, marker='o')
                    axes[1, 1].set_xlabel('Time (minutes)', fontsize=11)
                    axes[1, 1].set_ylabel('Coverage (%)', fontsize=11)
                    axes[1, 1].set_title('Code Coverage Estimate', fontsize=12, fontweight='bold')
                    axes[1, 1].grid(True, alpha=0.3)
                    axes[1, 1].fill_between(time_minutes, coverages, alpha=0.2, color='#9b59b6')
                    
                    plt.tight_layout()
                    plt.savefig(output_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    
                    self.logger.info(f"Saved high-resolution fuzzing metrics plot ({len(timestamps)} datapoints) to {output_path}")
                    return
        
        except Exception as e:
            self.logger.warning(f"Failed to load enhanced metrics, falling back to sparse data: {e}")
        
        # Fallback to original sparse metrics
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Convert timestamps to relative minutes
        if metrics.timestamps:
            time_minutes = [(t - metrics.timestamps[0]) / 60 for t in metrics.timestamps]
        else:
            time_minutes = []
        
        # Total paths
        if metrics.total_paths:
            axes[0, 0].plot(time_minutes, metrics.total_paths, linewidth=2, color='blue', marker='o')
            axes[0, 0].set_xlabel('Time (minutes)')
            axes[0, 0].set_ylabel('Total Paths')
            axes[0, 0].set_title('Path Discovery Over Time')
            axes[0, 0].grid(True, alpha=0.3)
        
        # Crashes
        if metrics.crashes:
            axes[0, 1].plot(time_minutes, metrics.crashes, linewidth=2, color='red', marker='o')
            axes[0, 1].set_xlabel('Time (minutes)')
            axes[0, 1].set_ylabel('Crashes')
            axes[0, 1].set_title('Crash Discovery Over Time')
            axes[0, 1].grid(True, alpha=0.3)
        
        # Execution speed
        if metrics.exec_speed:
            axes[1, 0].plot(time_minutes, metrics.exec_speed, linewidth=2, color='green', marker='o')
            axes[1, 0].set_xlabel('Time (minutes)')
            axes[1, 0].set_ylabel('Execs/sec')
            axes[1, 0].set_title('Execution Speed Over Time')
            axes[1, 0].grid(True, alpha=0.3)
        
        # Coverage estimate
        if metrics.coverage_estimate:
            axes[1, 1].plot(time_minutes, metrics.coverage_estimate, linewidth=2, color='purple', marker='o')
            axes[1, 1].set_xlabel('Time (minutes)')
            axes[1, 1].set_ylabel('Coverage (%)')
            axes[1, 1].set_title('Code Coverage Estimate')
            axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Saved fuzzing metrics plot to {output_path}")
    
    def _plot_resource_usage(self, resource_usage: Dict[str, Any], output_path: Path) -> None:
        """Legacy method - now handled by _plot_resource_usage_single."""
        pass
    
    def _plot_summary(self, report: EvaluationReport, output_path: Path) -> None:
        """Legacy method - summary now in individual plots."""
        pass
        self.logger.info(f"Saved summary plot to {output_path}")
    
    def _plot_power_consumption(self, output_path: Path) -> None:
        """Legacy method - power tracking now in _plot_cpu_power_tracking."""
        pass
    
    def _plot_summary(self, report: EvaluationReport, output_path: Path) -> None:
        """Legacy method - summary now in individual plots."""
        pass


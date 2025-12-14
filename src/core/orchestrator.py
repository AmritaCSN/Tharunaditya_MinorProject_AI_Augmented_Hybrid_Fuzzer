"""
NeuroFuzz Main Orchestrator
Coordinates all components: analyzer, fuzzer, symbolic executor, RL agent
"""

import time
import logging
import shutil
from pathlib import Path
from typing import Dict, Any, Optional

from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback

from src.core.interfaces import IOrchestrator, BinaryTarget, FuzzingStats
from src.analysis.binary_analyzer import BinaryAnalyzer
from src.analysis.symbolic_executor import SymbolicExecutor
from src.analysis import TargetConfigGenerator, BinaryConfig, MultiCoreAnalysisEngine
from src.fuzzing.afl_fuzzer import AFLFuzzer
from src.rl.environment import NeuroFuzzEnv
from src.utils import (
    FeedbackCollector,
    EnergyEstimator,
    NeuroFuzzEvaluator,
    TrainingMetrics,
    FuzzingMetrics,
    AISeedGenerator,
    ResourceController,
    BinaryCompiler
)


class TimeLimitCallback(BaseCallback):
    """Callback to stop training after time limit."""
    
    def __init__(self, time_limit_seconds: int, verbose: int = 0):
        super().__init__(verbose)
        self.time_limit = time_limit_seconds
        self.start_time = 0
        self.last_log = 0
    
    def _on_training_start(self) -> None:
        self.start_time = time.time()
        self.last_log = self.start_time
    
    def _on_step(self) -> bool:
        elapsed = time.time() - self.start_time
        
        # Log progress every 2 minutes
        if time.time() - self.last_log > 120:
            remaining = (self.time_limit - elapsed) / 60
            progress = (elapsed / self.time_limit) * 100
            print(f"[TRAINING] Progress: {progress:.1f}% | Remaining: {remaining:.1f} minutes | Steps: {self.num_timesteps}")
            self.last_log = time.time()
        
        if elapsed > self.time_limit:
            print(f"\n[TRAINING] Time limit reached ({elapsed / 60:.1f} minutes)")
            return False
        return True


class DetailedProgressCallback(BaseCallback):
    """
    Real-time training progress callback with instant step-by-step visibility.
    
    Logs EVERY step immediately so users see:
    - Action taken (Fuzzing/SymEx/Reallocation) with icon
    - Reward received
    - AFL++ stats (executions, paths, crashes, speed)
    
    Also provides summary statistics every N episodes.
    """
    
    def __init__(self, env, fuzzer, feedback_collector, training_metrics, fuzzing_metrics, energy_estimator, log_interval: int = 10, verbose: bool = True):
        super().__init__(verbose)
        self.env = env
        self.fuzzer = fuzzer
        self.feedback_collector = feedback_collector
        self.training_metrics = training_metrics
        self.fuzzing_metrics = fuzzing_metrics
        self.energy_estimator = energy_estimator
        self.log_interval = log_interval
        self.episode_count = 0
        self.episode_rewards = []
        self.episode_lengths = []
        self.current_episode_reward = 0
        self.current_episode_length = 0
        self.start_time = time.time()
        self.last_afl_crashes = 0
        self.last_afl_paths = 0
        self.last_log_time = time.time()
        self.step_count = 0
        self.last_action_name = None
        self.peak_cpu = 0.0
        self.peak_memory_mb = 0.0
        
    def _on_training_start(self) -> None:
        self.start_time = time.time()
        self.last_log_time = self.start_time
        print("\n" + "="*80)
        print("REAL-TIME TRAINING METRICS (Every Step Logged)")
        print("="*80)
        
    def _on_step(self) -> bool:
        # Track episode progress (SB3 exposes 'rewards')
        if 'rewards' in self.locals:
            self.current_episode_reward += self.locals['rewards'][0]
            self.current_episode_length += 1
        
        # Display real-time action (every step for visibility)
        self.step_count += 1
        if self.step_count % 1 == 0:  # Show every step
            # Get last action from environment
            action_name = 'UNKNOWN'
            try:
                # Primary: pull from VecEnv attribute
                if hasattr(self.env, 'get_attr'):
                    values = self.env.get_attr('last_action_taken')
                    if values and values[0]:
                        action_name = values[0]
                elif hasattr(self.env, 'unwrapped') and hasattr(self.env.unwrapped, 'last_action_taken'):
                    action_name = self.env.unwrapped.last_action_taken
                # Fallback: value exposed directly by environment per step
                if action_name == 'UNKNOWN' and getattr(self, 'last_action_name', None):
                    action_name = self.last_action_name
            except Exception:
                if getattr(self, 'last_action_name', None):
                    action_name = self.last_action_name
            
            # Get current AFL stats
            stats = self.fuzzer.get_stats()
            reward = self.locals.get('rewards', [0])[0]
            
            # Collect fuzzing metrics (every 10 steps to avoid bloat)
            if self.step_count % 10 == 0:
                self.fuzzing_metrics.timestamps.append(time.time() - self.start_time)
                self.fuzzing_metrics.total_paths.append(stats.paths_total)
                self.fuzzing_metrics.crashes.append(stats.crashes_total)
                self.fuzzing_metrics.hangs.append(0)  # Not tracked currently
                self.fuzzing_metrics.exec_speed.append(stats.exec_speed)
                self.fuzzing_metrics.coverage_estimate.append(stats.coverage_percentage)
                
                # FIXED: Use unified PowerTracker for energy recording
                try:
                    reading = self.energy_estimator.record(action=action_name)
                    if self.verbose and self.step_count % 100 == 0:
                        print(f"[ENERGY] {reading.estimated_watts:.1f}W ({self.step_count} steps)")
                except Exception as e:
                    if self.verbose and self.step_count % 100 == 0:
                        print(f"[WARNING] Energy recording failed: {e}")
            
            # Track peak resources
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            self.peak_cpu = max(self.peak_cpu, cpu)
            self.peak_memory_mb = max(self.peak_memory_mb, mem.used / 1024 / 1024)
            
            # NOTE: Training metrics are collected at episode boundaries (see episode_done below)
            # This prevents duplicate/misleading metrics from mid-episode checkpoints
            
            action_icons = {
                'FUZZING': '🔨',
                'SYMBOLIC_EXECUTION': '🧩'
            }
            icon = action_icons.get(action_name, '•')
            
            print(f"[Step {self.step_count:5d}] {icon} {action_name:20s} | "
                  f"Reward: {reward:+6.2f} | "
                  f"Execs: {stats.total_executions:8,} | "
                  f"Paths: {stats.paths_total:4d} | "
                  f"Crashes: {stats.crashes_total:2d} | "
                  f"Speed: {stats.exec_speed:6.0f}/s")
        
        # Check if episode ended OR step limit reached (handle both terminated and truncated)
        episode_done = False
        if 'dones' in self.locals:
            episode_done = self.locals['dones'][0]
        elif 'truncateds' in self.locals:  # Handle truncated episodes (time limits)
            episode_done = self.locals['truncateds'][0]
        
        if episode_done:
            self.episode_count += 1
            self.episode_rewards.append(self.current_episode_reward)
            self.episode_lengths.append(self.current_episode_length)
            
            # FIXED: Always collect training metrics at episode boundaries
            self.training_metrics.episodes.append(self.episode_count)
            self.training_metrics.rewards.append(self.current_episode_reward)
            self.training_metrics.episode_lengths.append(self.current_episode_length)
            
            # Try to get learning rate from PPO model
            if hasattr(self.model, 'learning_rate'):
                lr = self.model.learning_rate
                if callable(lr):
                    lr = lr(1.0)  # Get current LR
                self.training_metrics.learning_rate.append(float(lr))
            
            # Try to get policy loss from logger (if available)
            try:
                if hasattr(self.model, 'logger') and self.model.logger:
                    losses = self.model.logger.name_to_value
                    if 'train/policy_loss' in losses:
                        self.training_metrics.loss.append(losses['train/policy_loss'])
            except:
                pass
            
            # Log detailed metrics every N episodes
            if self.episode_count % self.log_interval == 0:
                self._log_detailed_metrics()
            
            # Reset episode trackers
            self.current_episode_reward = 0
            self.current_episode_length = 0
        
        return True
    
    def _log_detailed_metrics(self):
        """Log comprehensive training metrics."""
        elapsed = time.time() - self.start_time
        since_last = time.time() - self.last_log_time
        
        print("\n" + "="*80)
        print(f"EPISODE {self.episode_count} SUMMARY | Elapsed: {elapsed/60:.1f}min")
        print("="*80)
        
        # Episode statistics
        if self.episode_rewards:
            recent_rewards = self.episode_rewards[-self.log_interval:]
            avg_reward = sum(recent_rewards) / len(recent_rewards)
            max_reward = max(recent_rewards)
            min_reward = min(recent_rewards)
            avg_length = sum(self.episode_lengths[-self.log_interval:]) / len(recent_rewards)
            
            print(f"\n📊 EPISODE STATS (last {len(recent_rewards)} episodes):")
            print(f"  • Avg Reward:  {avg_reward:+.3f} | Max: {max_reward:+.3f} | Min: {min_reward:+.3f}")
            print(f"  • Avg Length:  {avg_length:.1f} steps")
            print(f"  • Total Steps: {self.num_timesteps:,}")
        
        # Action distribution from environment
        if hasattr(self.env.unwrapped, 'action_counts'):
            action_counts = self.env.unwrapped.action_counts
            total_actions = sum(action_counts.values())
            if total_actions > 0:
                print(f"\n🎯 ACTION DISTRIBUTION (total {total_actions} actions):")
                for action, count in sorted(action_counts.items(), key=lambda x: x[1], reverse=True):
                    pct = (count / total_actions) * 100
                    bar = "█" * int(pct / 2)
                    print(f"  • {action:20s}: {count:4d} ({pct:5.1f}%) {bar}")
        
        # AFL++ metrics
        try:
            stats = self.fuzzer.get_stats()
            summary = self.feedback_collector.get_summary()
            
            new_crashes = stats.crashes_total - self.last_afl_crashes
            new_paths = stats.paths_total - self.last_afl_paths
            
            print(f"\n🔍 AFL++ FUZZING METRICS:")
            print(f"  • Total Execs:    {stats.total_executions:,}")
            print(f"  • Exec Speed:     {stats.exec_speed:.0f}/sec")
            print(f"  • Total Crashes:  {stats.crashes_total} (+{new_crashes} since last)")
            print(f"  • Total Paths:    {stats.paths_total} (+{new_paths} since last)")
            print(f"  • Coverage:       {stats.coverage_percentage:.2f}%")
            print(f"  • Time Elapsed:   {stats.time_elapsed}s")
            
            if summary:
                print(f"  • Crashes/Hour:   {summary.get('crashes_per_hour', 0):.1f}")
                print(f"  • Paths/Hour:     {summary.get('paths_per_hour', 0):.1f}")
            
            self.last_afl_crashes = stats.crashes_total
            self.last_afl_paths = stats.paths_total
            
        except Exception as e:
            print(f"  ⚠ AFL++ metrics unavailable: {e}")
        
        # Performance metrics
        steps_per_sec = self.num_timesteps / elapsed if elapsed > 0 else 0
        print(f"\n⚡ PERFORMANCE:")
        print(f"  • Training Speed:  {steps_per_sec:.1f} steps/sec")
        print(f"  • Time Since Last: {since_last:.1f}s")
        
        print("="*80 + "\n")
        self.last_log_time = time.time()


class NeuroFuzzOrchestrator(IOrchestrator):
    """Main orchestrator coordinating all NeuroFuzz components."""
    
    def __init__(self):
        """Initialize orchestrator."""
        self.config: Optional[Dict[str, Any]] = None
        self.logger = logging.getLogger(__name__)
        
        # Components
        self.analyzer: Optional[BinaryAnalyzer] = None
        self.fuzzer: Optional[AFLFuzzer] = None
        self.symbolic_executor: Optional[SymbolicExecutor] = None
        self.env: Optional[NeuroFuzzEnv] = None
        self.model: Optional[PPO] = None
        
        # New components (Phase 1)
        self.feedback_collector: Optional[FeedbackCollector] = None
        self.energy_estimator: Optional[EnergyEstimator] = None
        self.evaluator: Optional[NeuroFuzzEvaluator] = None
        
        # Phase 2 components
        self.target_generator: Optional[TargetConfigGenerator] = None
        self.seed_generator: Optional[AISeedGenerator] = None
        self.binary_config: Optional[BinaryConfig] = None
        
        # Phase 3 components
        self.resource_controller: Optional[ResourceController] = None
        
        # Adaptive resource allocation state (initialized after config is loaded)
        self.fuzzing_time_budget = 30  # Default 30 seconds, will be overridden by config
        self.min_fuzzing_time = 10      # Minimum 10 seconds (enough for AFL++ to work)
        self.max_fuzzing_time = 60      # Maximum 60 seconds
        self.symex_cost_history = []    # Track symbolic execution CPU cost
        self.symex_benefit_history = [] # Track symbolic execution benefit
        self.symex_seeds = set()        # Track seeds generated by symbolic execution
        self.last_symex_result = None   # Store last symbolic execution result for attribution
        self.symex_seed_attribution = {}  # seed_id -> {'paths': int, 'crashes': int}
        self.symex_blacklist = {}       # target_name -> cooldown_until (epoch seconds)
        self.last_resource_reallocate_time = 0
        
        # Metrics tracking
        self.training_metrics: Optional[TrainingMetrics] = None
        self.fuzzing_metrics: Optional[FuzzingMetrics] = None
        
        # State
        self.targets: list[BinaryTarget] = []
        self.current_target_idx: int = 0
        self.binary_path: Optional[str] = None
        self.campaign_dir: Optional[Path] = None
        
        self.logger.info("NeuroFuzz orchestrator created")
    
    def _validate_policy_health(self) -> bool:
        """
        Validate policy to detect degenerate behavior.
        
        Tests the policy on random observations to check action diversity.
        A healthy policy should not always choose the same action.
        
        Returns:
            True if policy is healthy (diverse actions), False if degenerate
        """
        if not self.model or not self.env:
            return True  # Can't validate without model/env
        
        try:
            import numpy as np
            
            # Sample 100 random observations
            action_counts = {0: 0, 1: 0}  # FUZZING, SYMBOLIC_EXECUTION
            num_samples = 100
            
            for _ in range(num_samples):
                # Generate random observation in valid range
                obs = self.env.observation_space.sample()
                
                # Get action from policy (deterministic mode)
                action, _ = self.model.predict(obs, deterministic=True)
                action_counts[int(action)] += 1
            
            # Check for degenerate behavior (>95% same action)
            max_action_pct = max(action_counts.values()) / num_samples
            
            if max_action_pct > 0.95:
                self.logger.warning(f"Degenerate policy detected: {max_action_pct*100:.1f}% same action")
                self.logger.warning(f"Action distribution: {action_counts}")
                return False
            
            self.logger.info(f"Policy health check: {action_counts[0]}% FUZZING, {action_counts[1]}% SYMBOLIC_EXECUTION")
            return True
            
        except Exception as e:
            self.logger.warning(f"Policy validation failed: {e}")
            return True  # Assume healthy if validation fails
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize orchestrator with configuration.
        
        Args:
            config: Configuration dictionary from YAML
        """
        self.config = config
        self.binary_path = config['binary']['target_path']
        
        # Load timing configuration from config
        rl_config = config.get('reinforcement_learning', {})
        self.fuzzing_time_budget = rl_config.get('step_duration_seconds', 30)
        self.logger.info(f"Set fuzzing time budget to {self.fuzzing_time_budget}s per RL step")
        
        print("\n" + "="*70)
        print("NEUROFUZZ INITIALIZATION")
        print("="*70)
        
        # AUTO-COMPILE: Check if target is source code
        source_path = Path(self.binary_path)
        compiler = BinaryCompiler()
        
        if compiler.is_source_file(str(source_path)):
            print(f"\n[AUTO-COMPILE] Detected source file: {source_path.name}")
            print("[AUTO-COMPILE] Compiling with AFL++ instrumentation...")
            
            success, compiled_binary, error = compiler.compile_source(str(source_path))
            
            if success:
                print(f"[AUTO-COMPILE] ✓ Compiled successfully: {compiled_binary}")
                
                # Verify instrumentation
                if compiler.verify_instrumentation(compiled_binary):
                    print("[AUTO-COMPILE] ✓ AFL++ instrumentation verified")
                else:
                    print("[AUTO-COMPILE] ⚠ Could not verify instrumentation (proceeding anyway)")
                
                # Update binary path to compiled version
                self.binary_path = compiled_binary
                self.logger.info(f"Using auto-compiled binary: {compiled_binary}")
            else:
                print(f"[AUTO-COMPILE] ✗ Compilation failed:")
                print(f"  {error}")
                raise RuntimeError(f"Failed to compile source file: {error}")
        else:
            # Verify it's a valid binary
            if not source_path.exists():
                raise FileNotFoundError(f"Binary not found: {self.binary_path}")
            
            print(f"[BINARY] Using pre-compiled binary: {source_path.name}")
        
        self.logger.info(f"Binary: {self.binary_path}")
        self.logger.info(f"Mode: {config['general']['mode']}")
        
        # Create data directories
        self._create_directories()
        
        # Set campaign directory
        campaign_name = config['general'].get('campaign_name', 'default_campaign')
        self.campaign_dir = Path('data/campaigns') / campaign_name
        self.campaign_dir.mkdir(parents=True, exist_ok=True)
        
        print("\n[STEP 1/8] Binary Analysis - Extracting functions and vulnerabilities...")
        
        # Initialize binary analyzer
        analysis_config = config.get('analysis', {})
        base_analyzer = BinaryAnalyzer(
            max_functions=analysis_config.get('max_functions', 100),
            timeout_per_function=analysis_config.get('timeout_per_function', 30)
        )
        
        # Wrap with MultiCoreAnalysisEngine
        self.analyzer = MultiCoreAnalysisEngine(base_analyzer, config)
        
        # Analyze binary and extract targets
        analysis_result = self.analyzer.analyze_binary(self.binary_path)
        
        print(f"    ✓ Found {analysis_result.total_functions} functions")
        print(f"    ✓ Identified {len(analysis_result.targets)} potential targets")
        
        print("\n[STEP 2/8] Target Prioritization - Filtering and scoring targets...")
        
        # Initialize TargetConfigGenerator
        self.target_generator = TargetConfigGenerator()
        self.binary_config = self.target_generator.generate_config(analysis_result)
        
        # Use filtered/enhanced targets from config
        self.targets = []
        for fuzzing_target in self.binary_config.targets:
            # Convert FuzzingTarget back to BinaryTarget for compatibility
            binary_target = BinaryTarget(
                name=fuzzing_target.name,
                address=int(fuzzing_target.address, 16) if isinstance(fuzzing_target.address, str) else fuzzing_target.address,
                vulnerability_score=fuzzing_target.priority,
                complexity=10,
                call_depth=5,
                avoid_functions=[]
            )
            self.targets.append(binary_target)
        
        print(f"    ✓ Priority queue created with {len(self.targets)} targets")
        high_priority = [t for t in self.targets if t.vulnerability_score >= 7.0]
        print(f"    ✓ High-priority targets: {len(high_priority)}")
        if high_priority:
            print(f"      Top 3: {', '.join([t.name for t in high_priority[:3]])}")
        
        # Save binary config for reference
        self.target_generator.save_config(
            self.binary_config,
            str(self.campaign_dir / 'binary_config.json')
        )

        
        # Save analysis performance report
        if hasattr(self.analyzer, 'get_performance_report'):
            try:
                perf_report = self.analyzer.get_performance_report()
                self.analyzer.save_report(str(self.campaign_dir / 'analysis_performance.json'))
            except Exception as e:
                pass
        
        print("\n[STEP 3/8] Seed Generation - Creating diverse initial inputs...")
        
        # Initialize AFL++ fuzzer
        self.fuzzer = AFLFuzzer()
        self.fuzzer.resume = config.get('afl', {}).get('resume', False)
        self.fuzzer.force_clean = config.get('afl', {}).get('force_clean', False)
        self.fuzzer.prompt_on_clean = config.get('afl', {}).get('prompt_on_clean', False)
        self.fuzzer.backup_on_clean = config.get('afl', {}).get('backup_on_clean', False)
        
        # Initialize AISeedGenerator
        self.seed_generator = AISeedGenerator(config)
        
        # Generate diverse seed corpus
        input_dir = config['afl']['input_dir']
        seed_hints = self.binary_config.seed_generation_hints if self.binary_config else []
        
        try:
            seed_summary = self.seed_generator.generate_seeds(
                output_dir=input_dir,
                hints=seed_hints,
                force_clean=self.fuzzer.force_clean  # Clean inputs if force_clean is set
            )
            print(f"    ✓ Generated {seed_summary.total_seeds} seeds")
            print(f"    ✓ Strategies used: {len(seed_summary.strategies_used)}")
            
            # Save seed summary
            self.seed_generator.save_summary(
                seed_summary,
                str(self.campaign_dir / 'seed_summary.json')
            )
        except Exception as e:
            print(f"    ⚠ Seed generation failed, using fallback seeds")
            self._ensure_seed_input()
        
        print("\n[STEP 4/8] Feedback System - Initializing AFL++ monitoring...")
        
        # Initialize FeedbackCollector
        afl_output_dir = config['afl']['output_dir']
        feedback_log = str(self.campaign_dir / 'enhanced_metrics.jsonl')
        self.feedback_collector = FeedbackCollector(
            afl_output_dir=afl_output_dir,
            log_file=feedback_log
        )
        print("    ✓ Feedback collector ready")
        
        print("\n[STEP 5/8] Symbolic Execution - Preparing constraint solver...")
        
        # Initialize symbolic executor if enabled
        if config.get('symbolic_execution', {}).get('enable', True):
            symex_config = config['symbolic_execution']
            self.symbolic_executor = SymbolicExecutor(
                binary_path=self.binary_path,
                max_depth=symex_config.get('max_depth', 50),
                max_states=symex_config.get('max_states', 256),
                timeout_seconds=symex_config.get('timeout_seconds', 180),
                symbolic_buffer_size=symex_config.get('symbolic_buffer_size', 256),
                soft_timeout_seconds=symex_config.get('soft_timeout_seconds', 120),
                use_crash_exploration=symex_config.get('use_crash_exploration', True)
            )
            print("    ✓ Symbolic executor initialized (CRASH-DIRECTED mode)")
        else:
            print("    ⊘ Symbolic execution disabled")
        
        print("\n[STEP 6/8] RL Environment - Setting up PPO training...")
        
        # Initialize RL environment
        # Get max_steps from campaign config if in 'run' mode, otherwise use default for training
        max_steps = 50  # Default for training
        if 'campaign' in config['reinforcement_learning']:
            max_steps = config['reinforcement_learning']['campaign'].get('max_steps', 50)
        
        base_env = NeuroFuzzEnv(
            orchestrator=self,
            targets=self.targets,
            config={'max_steps': max_steps}
        )
        
        # Wrap environment in VecEnv and VecNormalize for proper observation normalization
        from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
        self.env = DummyVecEnv([lambda: base_env])
        
        # Initialize or load PPO model
        rl_config = config['reinforcement_learning']
        model_path = Path(rl_config['model_path'])
        vecnormalize_path = model_path.parent / f"{model_path.stem}_vecnormalize.pkl"
        
        if model_path.exists() and vecnormalize_path.exists():
            print(f"    ✓ Loaded existing PPO model: {model_path.name}")
            print(f"    ✓ Loaded observation normalization: {vecnormalize_path.name}")
            # Load VecNormalize stats first
            self.env = VecNormalize.load(str(vecnormalize_path), self.env)
            self.env.training = False  # Disable updates during inference
            self.env.norm_reward = False  # Don't normalize rewards during run
            # Then load model
            self.model = PPO.load(str(model_path), env=self.env)
            
            # FIXED: Validate policy to detect degenerate behavior
            if self._validate_policy_health():
                print("    ✓ Policy validation passed (diverse action distribution)")
            else:
                print("    ⚠ WARNING: Policy may be degenerate (low action diversity)")
                print("    → Consider retraining with higher entropy coefficient")
                print("    → Run will monitor entropy and fall back to pure AFL if it collapses")
        else:
            print("    ✓ Created new PPO model with entropy regularization")
            # Wrap environment in VecNormalize for training (will save stats later)
            from stable_baselines3.common.vec_env import VecNormalize
            self.env = VecNormalize(self.env, norm_obs=True, norm_reward=False, clip_obs=10.0)
            
            self.model = PPO(
                rl_config.get('policy', 'MlpPolicy'),
                self.env,
                learning_rate=rl_config['training'].get('learning_rate', 0.0003),
                ent_coef=rl_config['training'].get('ent_coef', 0.02),  # Entropy regularization
                verbose=0
            )
        
        print("    ✓ Environment created (2 actions: Fuzzing, Symbolic Execution)")

        
        print("\n[STEP 7/8] Resource Management - Initializing controllers...")
        
        # FIXED: Use PowerTracker as primary energy tracking system (RAPL + psutil)
        from src.utils.power_tracker import PowerTracker
        self.power_tracker = PowerTracker(config, self.campaign_dir)
        print(f"    ✓ Power tracker ready (psutil-based estimation)")
        
        # DEPRECATED: EnergyEstimator is replaced by PowerTracker
        # Keeping reference for backward compatibility with old callbacks
        self.energy_estimator = self.power_tracker  # Point to unified system
        
        # Initialize ResourceController
        self.resource_controller = ResourceController(config)
        print(f"    ✓ Resource limits: CPU {self.resource_controller.limits.max_cpu_percent}% | Memory {self.resource_controller.limits.max_memory_percent}%")
        
        print("\n[STEP 8/8] Evaluation System - Preparing report generation...")
        
        # Initialize Evaluator
        self.evaluator = NeuroFuzzEvaluator(config)
        print("    ✓ Evaluator ready for report generation")
        
        # Initialize metrics tracking
        self.training_metrics = TrainingMetrics()
        self.fuzzing_metrics = FuzzingMetrics()
        
        print("\n" + "="*70)
        print("INITIALIZATION COMPLETE - ALL SYSTEMS READY")
        print("="*70 + "\n")
    
    def run_campaign(self, mode: str) -> Dict[str, Any]:
        """
        Run fuzzing campaign.
        
        Args:
            mode: "train" | "run" | "analyze"
            
        Returns:
            Campaign results dictionary
        """
        if mode == "analyze":
            return self._run_analyze_mode()
        elif mode == "train":
            return self._run_train_mode()
        elif mode == "run":
            return self._run_fuzzing_mode()
        else:
            raise ValueError(f"Unknown mode: {mode}")
    
    def _run_analyze_mode(self) -> Dict[str, Any]:
        """Run analysis-only mode."""
        self.logger.info("Running analysis mode")
        
        results = {
            'mode': 'analyze',
            'binary': self.binary_path,
            'total_targets': len(self.targets),
            'high_priority_targets': [t.name for t in self.targets if t.vulnerability_score >= 7.0],
            'targets': [
                {
                    'name': t.name,
                    'address': hex(t.address),
                    'vulnerability_score': t.vulnerability_score,
                    'complexity': t.complexity
                }
                for t in self.targets[:10]  # Top 10
            ]
        }
        
        self.logger.info(f"Analysis complete: {len(self.targets)} targets found")
        return results
    
    def _run_train_mode(self) -> Dict[str, Any]:
        """Run RL training mode."""
        
        # Use PPO-based RL training with adaptive selective symbolic execution
        training_config = self.config['reinforcement_learning']['training']
        return self._run_step_based_training()
    
    def _run_step_based_training(self) -> Dict[str, Any]:
        """PPO-based RL training with adaptive selective symbolic execution."""
        
        training_config = self.config['reinforcement_learning']['training']
        time_limit_minutes = training_config.get('time_limit_minutes', 30)
        total_timesteps = training_config.get('total_timesteps', 2000000)
        
        # Display NeuroFuzz banner
        print("\n" + "="*80)
        print(r"""    _   __                      ______              
   / | / /__  __  ___________  / ____/_  __________
  /  |/ / _ \/ / / / ___/ __ \/ /_  / / / /_  /_  /
 / /|  /  __/ /_/ / /  / /_/ / __/ / /_/ / / /_/ /_
/_/ |_/\___/\__,_/_/   \____/_/    \__,_/ /___/___/""")
        print("="*80)
        print("  AI-Augmented Hybrid Fuzzer | RL + AFL++ + Symbolic Execution")
        print(f"  Academic Research Project | M.Tech Cybersecurity Systems and Networks")
        print(f" Researcher: Tharunaditya Anuganti | Professor/Guide: Dr. Sriram Sankaran")
        print("="*80)
        print(f"\n[MODE] TRAINING - PPO Reinforcement Learning")
        print(f"[DURATION] {time_limit_minutes} minutes | Max Timesteps: {total_timesteps:,}")
        print(f"[LEARNING RATE] {training_config.get('learning_rate', 0.0003)}")
        print(f"[BINARY] {Path(self.config['binary']['target_path']).name}")
        print("="*80 + "\n")
        
        # Start energy tracking
        self.energy_estimator.start()
        
        # Start fuzzer
        print("[FUZZING] Starting AFL++ fuzzer...")
        self.reset_fuzzer()
        
        if self.fuzzer.is_running():
            print("[FUZZING] ✓ AFL++ running successfully")
        else:
            print("[FUZZING] ✗ AFL++ failed to start")
        
        # Check resources before training
        if self.resource_controller.should_throttle():
            print("[RESOURCES] ⚠ High system load detected, pausing briefly...")
            time.sleep(5)
        
        # Train with comprehensive logging callbacks
        start_time = time.time()
        time_callback = TimeLimitCallback(time_limit_minutes * 60)
        progress_callback = DetailedProgressCallback(
            env=self.env,
            fuzzer=self.fuzzer,
            feedback_collector=self.feedback_collector,
            training_metrics=self.training_metrics,
            fuzzing_metrics=self.fuzzing_metrics,
            energy_estimator=self.energy_estimator,
            log_interval=10,  # Summary stats every 10 episodes
            verbose=True
        )
        
        print(f"\n[TRAINING] PPO training started at {time.strftime('%H:%M:%S')}")
        print("[TRAINING] Learning optimal fuzzing strategy...")
        print("[TRAINING] Every action logged in real-time for instant visibility\n")
        
        self.model.learn(
            total_timesteps=total_timesteps,
            callback=[time_callback, progress_callback],
            log_interval=100
        )
        
        training_duration = time.time() - start_time
        
        print(f"\n[TRAINING] ✓ Training completed in {training_duration / 60:.1f} minutes")
        
        # Save model AND VecNormalize stats (critical for preventing policy collapse)
        model_path = Path(self.config['reinforcement_learning']['model_path'])
        model_path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save(str(model_path))
        
        # Save VecNormalize observation statistics
        from stable_baselines3.common.vec_env import VecNormalize
        if isinstance(self.env, VecNormalize):
            vecnormalize_path = model_path.parent / f"{model_path.stem}_vecnormalize.pkl"
            self.env.save(str(vecnormalize_path))
            print(f"[MODEL] ✓ Saved model to {model_path}")
            print(f"[MODEL] ✓ Saved observation normalization to {vecnormalize_path.name}")
        else:
            print(f"[MODEL] ✓ Saved to {model_path}")

        
        # Finalize training
        return self._finalize_training(start_time, training_duration, model_path)
    
    def _finalize_training(self, start_time: float, training_duration: float, model_path: Path) -> Dict[str, Any]:
        """Common training finalization code."""
        
        # Get final stats from FeedbackCollector
        final_stats = self.feedback_collector.get_summary()
        trends = self.feedback_collector.get_trends(window_size=10)

        # Ensure fuzzing metrics are not empty for short smoke runs
        if not self.fuzzing_metrics.timestamps:
            self.fuzzing_metrics.timestamps.append(time.time() - start_time)
            self.fuzzing_metrics.total_paths.append(final_stats.get('total_paths', 0))
            self.fuzzing_metrics.crashes.append(final_stats.get('total_crashes', 0))
            self.fuzzing_metrics.hangs.append(final_stats.get('total_hangs', 0))
            self.fuzzing_metrics.exec_speed.append(final_stats.get('avg_exec_speed', 0.0))
            self.fuzzing_metrics.coverage_estimate.append(final_stats.get('coverage_percentage', 0.0))

        # Backfill minimal training metrics if no episodes completed (very short runs)
        if self.training_metrics and not self.training_metrics.episodes:
            self.training_metrics.episodes.append(1)
            self.training_metrics.rewards.append(0.0)
            self.training_metrics.episode_lengths.append(getattr(self.env, 'current_step', 0))
            try:
                lr = self.model.learning_rate
                if callable(lr):
                    lr = lr(1.0)
                self.training_metrics.learning_rate.append(float(lr))
            except Exception:
                self.training_metrics.learning_rate.append(0.0)
            self.training_metrics.loss.append(0.0)
        
        print(f"\n[AFL++] Final Stats:")
        print(f"  • Total Executions: {final_stats.get('total_executions', 0):,}")
        print(f"  • Paths Found: {final_stats.get('total_paths', 0)}")
        print(f"  • Crashes Found: {final_stats.get('total_crashes', 0)}")
        print(f"  • Exec Speed: {final_stats.get('avg_exec_speed', 0):.0f}/sec")
        
        # Save detailed power log
        if self.power_tracker:
            self.power_tracker.save_detailed_log()
            power_metrics = self.power_tracker.get_power_efficiency_metrics()
            print(f"\n[POWER] Total: {power_metrics['total_energy_kwh']:.6f} kWh | Avg: {power_metrics['average_power_watts']:.1f}W")
            print(f"[POWER] Crashes/kWh: {power_metrics['crashes_per_kwh']:.2f} | Source: {power_metrics['measurement_source']}")
        
        # Stop fuzzer
        self.fuzzer.stop()
        print("[FUZZING] AFL++ stopped")
        
        # Extract crash test cases to campaign folder
        crash_count = self._extract_crashes()
        if crash_count > 0:
            print(f"[CRASHES] ✓ Extracted {crash_count} crash test cases to {self.campaign_dir / 'crashes'}")
        
        # Generate energy report
        energy_report = self.energy_estimator.get_report()
        self.energy_estimator.save_report(str(self.campaign_dir / 'energy_report.json'))
        print(f"\n[ENERGY] Total: {energy_report['total_energy_kwh']:.6f} kWh | Avg Power: {energy_report['average_power_watts']:.1f}W")
        
        # Generate evaluation report
        print("\n[EVALUATION] Generating reports...")
        try:
            eval_report = self.evaluator.generate_report(
                campaign_name=self.config['general'].get('campaign_name', 'train_campaign'),
                binary_path=self.binary_path,
                mode='train',
                duration=training_duration,
                training_metrics=self.training_metrics,
                fuzzing_metrics=self.fuzzing_metrics,
                final_stats=final_stats,
                resource_usage={
                    'energy_report': energy_report,
                    'resource_controller': self.resource_controller.get_status() if self.resource_controller else {},
                    'peak_cpu': progress_callback.peak_cpu if 'progress_callback' in locals() and hasattr(progress_callback, 'peak_cpu') else 0.0,
                    'peak_memory_mb': progress_callback.peak_memory_mb if 'progress_callback' in locals() and hasattr(progress_callback, 'peak_memory_mb') else 0.0
                },
                output_dir=str(self.campaign_dir / 'evaluation')
            )
            print(f"[EVALUATION] ✓ Reports saved to {self.campaign_dir / 'evaluation'}")
        except Exception as e:
            print(f"[EVALUATION] ⚠ Failed to generate report: {e}")
        
        return {
            'mode': 'train',
            'training_duration': training_duration,
            'model_path': str(model_path),
            'final_stats': final_stats,
            'energy_kwh': energy_report['total_energy_kwh'],
            'campaign_dir': str(self.campaign_dir)
        }
    
    def _extract_crashes(self) -> int:
        """
        Extract crash test cases from AFL++ output to campaign folder.
        Returns number of crashes extracted.
        """
        try:
            afl_crashes_dir = Path(self.config['afl']['output_dir']) / 'default' / 'crashes'
            if not afl_crashes_dir.exists():
                return 0
            
            # Create crashes directory in campaign folder
            campaign_crashes_dir = self.campaign_dir / 'crashes'
            campaign_crashes_dir.mkdir(exist_ok=True)
            
            # Copy all crash files (except README.txt)
            crash_count = 0
            for crash_file in afl_crashes_dir.iterdir():
                if crash_file.is_file() and crash_file.name != 'README.txt':
                    shutil.copy2(crash_file, campaign_crashes_dir / crash_file.name)
                    crash_count += 1
            
            return crash_count
        except Exception as e:
            self.logger.warning(f"Failed to extract crashes: {e}")
            return 0
    
    def _run_fuzzing_mode(self) -> Dict[str, Any]:
        """Run fuzzing campaign with trained model."""

        campaign_cfg = self.config.get('reinforcement_learning', {}).get('campaign', {})
        max_steps = int(campaign_cfg.get('max_steps', 50))
        time_limit_minutes = campaign_cfg.get('time_limit_minutes')
        time_limit_seconds = float(time_limit_minutes) * 60.0 if time_limit_minutes is not None else None
        start_monotonic = time.monotonic()
        deadline_monotonic = (start_monotonic + time_limit_seconds) if time_limit_seconds is not None else None
        
        # Display NeuroFuzz banner
        print("\n" + "="*80)
        print(r"""    _   __                      ______              
   / | / /__  __  ___________  / ____/_  __________
  /  |/ / _ \/ / / / ___/ __ \/ /_  / / / /_  /_  /
 / /|  /  __/ /_/ / /  / /_/ / __/ / /_/ / / /_/ /_
/_/ |_/\___/\__,_/_/   \____/_/    \__,_/ /___/___/""")
        print("="*80)
        print("  AI-Augmented Hybrid Fuzzer | RL + AFL++ + Symbolic Execution")
        print(f"  Academic Research Project | M.Tech Cybersecurity")
        print("="*80)
        print(f"\n[MODE] FUZZING CAMPAIGN - Using Trained Model")
        print(f"[STEPS] {max_steps} decision points")
        print(f"[MODEL] {Path(self.config['reinforcement_learning'].get('model_path', 'default')).name}")
        print(f"[BINARY] {Path(self.config['binary']['target_path']).name}")
        print("="*80 + "\n")
        
        # Start energy tracking
        self.energy_estimator.start()
        start_time = time.time()
        if time_limit_seconds is not None:
            print(f"[CAMPAIGN] Time limit: {time_limit_minutes} minutes (wall-clock)")
        else:
            print("[CAMPAIGN] Time limit: none (will run until max_steps)")
        
        # Start fuzzer
        print("[CAMPAIGN] Starting AFL++ fuzzer...")
        self.reset_fuzzer()
        
        if self.fuzzer.is_running():
            print("[CAMPAIGN] ✓ AFL++ running successfully")
        else:
            print("[CAMPAIGN] ✗ AFL++ failed to start")
        
        # Reset environment
        print("[CAMPAIGN] Initializing fuzzing environment...")
        # VecEnv returns array, not tuple
        from stable_baselines3.common.vec_env import VecEnv
        if isinstance(self.env, VecEnv):
            obs = self.env.reset()
        else:
            obs, info = self.env.reset()
        print("[CAMPAIGN] ✓ Environment ready\n")
        
        results = {
            'mode': 'run',
            'steps': [],
            'total_crashes': 0,
            'total_paths': 0
        }
        
        print(f"[CAMPAIGN] Starting {max_steps}-step campaign at {time.strftime('%H:%M:%S')}\n")
        
        try:
            for step in range(max_steps):
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    print("[CAMPAIGN] Time limit reached; stopping campaign")
                    break
                self.logger.debug(f"[DEBUG] Starting step {step+1}/{max_steps}")
                
                # Check resource throttling
                if step % 5 == 0 and self.resource_controller.should_throttle():
                    print(f"[RESOURCES] ⚠ High load detected at step {step + 1}, pausing...")
                    time.sleep(3)
                
                # Get action from trained model
                action, _states = self.model.predict(obs, deterministic=True)
                
                # Debug: log observation and action every 5 steps
                if step % 5 == 0:
                    self.logger.debug(f"[OBS] step={step+1}, obs={obs[0][:5]}..., action={int(action[0])}")
                
                # VecEnv returns action as array - convert to scalar
                if hasattr(action, '__iter__') and not isinstance(action, str):
                    action = int(action[0])
                else:
                    action = int(action)
                
                # Record energy for action
                action_name = ['fuzzing', 'symbolic_exec'][action]
                self.energy_estimator.record(action=action_name)
                
                # Execute action (VecEnv expects action as array)
                step_result = self.env.step([action])
                
                # VecEnv returns 4-tuple (obs, rewards, dones, infos) - old Gym API
                # Our base env returns 5-tuple (obs, reward, terminated, truncated, info) - Gymnasium API
                from stable_baselines3.common.vec_env import VecEnv
                if isinstance(self.env, VecEnv):
                    # VecEnv: (obs, rewards, dones, infos)
                    obs, rewards, dones, infos = step_result
                    reward = float(rewards[0])
                    terminated = bool(dones[0])
                    truncated = False  # VecEnv doesn't distinguish terminated/truncated
                    info = infos[0]
                else:
                    # Regular Gymnasium env: (obs, reward, terminated, truncated, info)
                    obs, reward, terminated, truncated, info = step_result
                    reward = float(reward)
                    terminated = bool(terminated)
                    truncated = bool(truncated)
                
                # Get current AFL++ stats
                current_stats = self.fuzzer.get_stats()
                
                # Display step progress
                action_display = {
                    'FUZZING': '🔨 FUZZING',
                    'SYMBOLIC_EXECUTION': '🧩 SYMBOLIC EXEC'
                }
                
                print(f"[STEP {step + 1:3d}/{max_steps}] {action_display[info['action_taken']]:<20} | "
                      f"Reward: {reward:+6.2f} | "
                      f"Paths: {current_stats.paths_total:4d} (+{info['new_paths']}) | "
                      f"Crashes: {current_stats.crashes_total:2d} (+{info['new_crashes']}) | "
                      f"Exec/s: {current_stats.exec_speed:6.0f}")

                # Safety: entropy collapse fallback to pure AFL
                if step % 10 == 0 and hasattr(self.env, 'action_history_entropy'):
                    recent_ent = self.env.action_history_entropy[-10:]
                    if recent_ent:
                        avg_ent = sum(recent_ent) / len(recent_ent)
                        if avg_ent < 0.1:
                            print("[RUN] ⚠ Action entropy collapsed; falling back to pure AFL for remaining steps")
                            remaining = max_steps - step - 1
                            self._run_pure_afl(remaining)
                            break

                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    print("[CAMPAIGN] Time limit reached after step; stopping campaign")
                    break
                
                # Log step
                step_info = {
                    'step': step + 1,
                    'action': info['action_taken'],
                    'reward': float(reward),
                    'new_paths': info['new_paths'],
                    'new_crashes': info['new_crashes']
                }
                results['steps'].append(step_info)
                
                if terminated or truncated:
                    print(f"\n[CAMPAIGN] Episode terminated, resetting environment...")
                    obs, info = self.env.reset()
                    
        except KeyboardInterrupt:
            print("\n[CAMPAIGN] ⚠ Interrupted by user")
        finally:
            campaign_duration = time.time() - start_time
            
            print("\n" + "="*70)
            print("CAMPAIGN COMPLETE")
            print("="*70)
            
            # Get final stats from FeedbackCollector
            final_stats = self.feedback_collector.get_summary()
            results['total_crashes'] = final_stats.get('total_crashes', 0)
            results['total_paths'] = final_stats.get('total_paths', 0)
            results['total_executions'] = final_stats.get('total_executions', 0)
            
            print(f"\n[RESULTS] Campaign Duration: {campaign_duration / 60:.1f} minutes")
            print(f"[RESULTS] Total Executions: {results['total_executions']:,}")
            print(f"[RESULTS] Paths Discovered: {results['total_paths']}")
            print(f"[RESULTS] Crashes Found: {results['total_crashes']}")
            print(f"[RESULTS] Steps Completed: {len(results['steps'])}/{max_steps}")
            
            # Stop fuzzer
            self.fuzzer.stop()
            print("\n[FUZZING] AFL++ stopped")
            
            # Extract crash test cases to campaign folder
            crash_count = self._extract_crashes()
            if crash_count > 0:
                print(f"[CRASHES] ✓ Extracted {crash_count} crash test cases to {self.campaign_dir / 'crashes'}")
            
            # Generate energy report
            energy_report = self.energy_estimator.get_report()
            self.energy_estimator.save_report(str(self.campaign_dir / 'energy_report.json'))
            efficiency = energy_report.get('crashes_per_kwh', 0.0)
            
            print(f"\n[ENERGY] Total: {energy_report['total_energy_kwh']:.6f} kWh")
            print(f"[ENERGY] Efficiency: {efficiency:.2f} crashes/kWh")
            
            results['energy_kwh'] = energy_report['total_energy_kwh']
            results['efficiency_score'] = efficiency
            
            # Save power tracker log (for detailed power consumption plots)
            if self.power_tracker:
                self.power_tracker.save_detailed_log()
                power_metrics = self.power_tracker.get_power_efficiency_metrics()
                print(f"[POWER] Crashes/kWh: {power_metrics['crashes_per_kwh']:.2f} | Source: {power_metrics['measurement_source']}")
            
            # Generate evaluation report
            print("\n[EVALUATION] Generating reports...")
            try:
                # Ensure fuzzing metrics not empty for short campaigns/fallbacks
                if not self.fuzzing_metrics.timestamps:
                    self.fuzzing_metrics.timestamps.append(campaign_duration)
                    self.fuzzing_metrics.total_paths.append(results['total_paths'])
                    self.fuzzing_metrics.crashes.append(results['total_crashes'])
                    self.fuzzing_metrics.hangs.append(0)
                    self.fuzzing_metrics.exec_speed.append(final_stats.get('avg_exec_speed', 0.0))
                    self.fuzzing_metrics.coverage_estimate.append(final_stats.get('coverage_percentage', 0.0))

                eval_report = self.evaluator.generate_report(
                    campaign_name=self.config['general'].get('campaign_name', 'fuzz_campaign'),
                    binary_path=self.binary_path,
                    mode='run',
                    duration=campaign_duration,
                    training_metrics=None,
                    fuzzing_metrics=self.fuzzing_metrics,
                    final_stats=final_stats,
                    resource_usage={
                        'energy_report': energy_report,
                        'resource_controller': self.resource_controller.get_status() if self.resource_controller else {},
                        'peak_cpu': final_stats.get('peak_cpu_percent', 0.0),
                        'peak_memory_mb': final_stats.get('peak_memory_mb', 0.0)
                    },
                    output_dir=str(self.campaign_dir / 'evaluation')
                )
                print(f"[EVALUATION] ✓ Reports saved to {self.campaign_dir / 'evaluation'}")
            except Exception as e:
                print(f"[EVALUATION] ⚠ Failed to generate report: {e}")
            
            results['campaign_dir'] = str(self.campaign_dir)
            
            print("\n" + "="*70 + "\n")
        
        return results

    def _run_pure_afl(self, remaining_steps: int) -> None:
        """Fallback loop: continue fuzzing without symex/RL decisions."""
        for i in range(remaining_steps):
            self.execute_fuzzing_step()
            stats = self.get_fuzzing_stats()
            print(f"[RUN][FALLBACK] Step {i+1}/{remaining_steps} | Execs: {stats.total_executions} | Paths: {stats.paths_total} | Crashes: {stats.crashes_total}")
    
    # Interface methods for environment
    
    def reset_fuzzer(self) -> None:
        """Reset fuzzer to clean state - should only be called at campaign start."""
        # Check if already running
        if self.fuzzer.is_running():
            self.logger.debug("AFL++ already running, no restart needed")
            return
            
        self.logger.info("Starting AFL++ fuzzer (initial start or after crash)")
        
        # Clean stale locks before start
        from pathlib import Path
        output_dir = Path(self.config['afl']['output_dir'])
        lock_file = output_dir / "default" / ".cur_input"
        if lock_file.exists():
            try:
                lock_file.unlink()
                self.logger.debug("Cleaned stale AFL++ lock file")
            except Exception as e:
                self.logger.warning(f"Could not clean lock file: {e}")
        
        # Start AFL++
        afl_config = self.config['afl']
        success = self.fuzzer.start(
            binary_path=self.binary_path,
            input_dir=afl_config['input_dir'],
            output_dir=afl_config['output_dir'],
            timeout_ms=afl_config.get('timeout_ms', 1000)
        )
        
        if not success:
            self.logger.error("AFL++ failed to start - this is critical")
            self.logger.error("Check: 1) Binary is AFL++ instrumented, 2) Input seeds exist, 3) No port conflicts")
        else:
            self.logger.info("AFL++ started successfully")
    
    def execute_fuzzing_step(self) -> None:
        """Execute fuzzing step with adaptive time budget."""
        sleep_time = self.fuzzing_time_budget

        if self.resource_controller:
            try:
                status = self.resource_controller.check_resources()

                # If system is under pressure, pause briefly to let AFL++ settle
                if status.get('status') != 'cooldown' and status.get('action_required'):
                    cooldown = self.resource_controller.limits.cooldown_seconds
                    cpu = status.get('cpu_percent')
                    mem = status.get('memory_percent')
                    self.logger.warning(
                        f"Resource pressure detected (CPU={cpu:.1f}%, MEM={mem:.1f}%), pausing {cooldown}s"
                    )
                    time.sleep(cooldown)
                    return

                # If nearing limits but not over, extend dwell slightly to reduce scheduling churn
                if status.get('cpu_over_limit') or status.get('memory_over_limit'):
                    sleep_time = min(self.max_fuzzing_time, sleep_time + self.resource_controller.limits.cooldown_seconds)
            except Exception as e:
                self.logger.debug(f"Resource-aware scheduling check failed: {e}")

        time.sleep(sleep_time)  # Use adaptive budget, not fixed 30s
    
    def execute_symbolic_execution(self, target: BinaryTarget) -> Dict[str, Any]:
        """Execute SELECTIVE symbolic execution (adaptive strategy).
        
        Only triggers when AFL++ is stuck (no new paths for 120s).
        Uses last AFL seed as starting point for concolic execution.
        
        Returns:
            dict with 'cpu_time', 'solution_found', 'seed_id', 'reason' for RL rewards
        """
        if not self.symbolic_executor:
            self.logger.warning("Symbolic execution disabled")
            return {'cpu_time': 0, 'solution_found': False, 'seed_id': None, 'reason': 'disabled'}
        
        # STEP 1: CHECK IF FUZZER IS STUCK (adaptive: exec-based heuristic)
        # Use execution-based threshold (more robust than time-based)
        current_input_size = 256  # Default, could be made dynamic based on AFL queue
        
        is_stuck, execs_since, threshold = self.feedback_collector.get_stuck_metrics(current_input_size=current_input_size)
        
        # SWEET SPOT LOGIC: Allow SymEx for high-priority targets even if not fully stuck
        # This implements "Semantic Vulnerability Prioritization"
        is_high_priority = target.vulnerability_score >= 7.0
        relaxed_threshold = threshold // 2
        
        should_run = is_stuck
        run_reason = 'stuck'
        
        if not should_run and is_high_priority and execs_since > relaxed_threshold:
            should_run = True
            run_reason = 'high_priority_target'
            self.logger.info(f"[SELECTIVE SYMEX] Triggering early for High-Priority Target '{target.name}' (Score: {target.vulnerability_score})")
            
        if not should_run:
            self.logger.info(f"[SELECTIVE SYMEX] Fuzzer not stuck - skipping (Execs since path: {execs_since}/{threshold})")
            return {
                'cpu_time': 0.0,
                'solution_found': False,
                'seed_id': None,
                'reason': 'not_stuck'  # RL will penalize if triggered unnecessarily
            }
        
        # STEP 2: GET LAST AFL SEED (concolic starting point)
        seed_input = self.feedback_collector.get_last_interesting_seed(self.config['afl']['output_dir'])
        if not seed_input:
            self.logger.warning("[SELECTIVE SYMEX] No AFL seed available")
            return {
                'cpu_time': 0.0,
                'solution_found': False,
                'seed_id': None,
                'reason': 'no_seed'
            }
        
        self.logger.info(f"[SELECTIVE SYMEX] ✓ Fuzzer stuck - attempting to unstick from {len(seed_input)}-byte seed")
        
        # Track cost (CPU time)
        import time
        start_cpu = time.process_time()
        start_wall = time.time()
        
        # STEP 3: RUN SYMBOLIC EXECUTION (will use clean binary automatically)
        # Run symbolic execution with subprocess timeout (industry standard, not signals)
        symex_timeout = self.config.get('symbolic_execution', {}).get('timeout_seconds', 180)
        solution = None
        
        try:
            # Use multiprocessing with timeout to avoid signal race conditions
            from multiprocessing import Process, Queue
            import queue
            
            result_queue = Queue()
            timed_out = False
            
            def symex_worker(q, executor, tgt, seed):
                try:
                    # DRILLER-STYLE: Pass seed to symbolic executor for selective symbolization
                    sol = executor.find_input_for_target(tgt, seed_input=seed)
                    q.put(('success', sol))
                except TimeoutError as e:
                    q.put(('timeout', str(e)))
                except Exception as e:
                    q.put(('error', str(e)))
            
            process = Process(target=symex_worker, args=(result_queue, self.symbolic_executor, target, seed_input))
            process.start()
            process.join(timeout=symex_timeout)
            
            if process.is_alive():
                # Timeout reached
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
                self.logger.warning(f"[SELECTIVE SYMEX] Timed out after {symex_timeout}s")
                timed_out = True
            else:
                # Process completed, get result
                try:
                    status, result = result_queue.get_nowait()
                    if status == 'success':
                        solution = result
                    elif status == 'timeout':
                        timed_out = True
                        self.logger.warning(f"[SELECTIVE SYMEX] Soft timeout: {result}")
                    else:
                        self.logger.error(f"[SELECTIVE SYMEX] Error: {result}")
                except queue.Empty:
                    pass
                    
        except Exception as e:
            self.logger.error(f"[SELECTIVE SYMEX] Wrapper error: {e}")
        
        # Calculate actual CPU cost
        cpu_time = time.process_time() - start_cpu
        wall_time = time.time() - start_wall
        
        # STEP 4: SAVE TO AFL QUEUE IF FOUND
        seed_id = None
        if solution:
            seed_id = self._save_seed_to_afl_queue(solution, target.name, int(start_wall))
            if seed_id:
                self.logger.info(f"[SELECTIVE SYMEX] ✓ Generated seed: {seed_id} ({len(solution)} bytes)")
                
                # Track this seed for future attribution
                if not hasattr(self, 'symex_seeds'):
                    self.symex_seeds = set()
                self.symex_seeds.add(seed_id)
                self.symex_seed_attribution[seed_id] = {'paths': 0, 'crashes': 0}
        
        # Track history for ROI calculation
        result_info = {
            'cpu_time': cpu_time,
            'wall_time': wall_time,
            'solution_found': solution is not None,
            'seed_id': seed_id,
            'target': target.name,
            'timeout': timed_out,
            'reason': 'unstick_attempt' if solution else ('timeout' if timed_out else 'no_solution')
        }
        
        self.symex_cost_history.append(cpu_time)
        # Don't calculate benefit here - it's measured later when crashes/paths are discovered
        
        # Keep only last 20 runs
        if len(self.symex_cost_history) > 20:
            self.symex_cost_history.pop(0)
        
        self.logger.info(f"[SELECTIVE SYMEX] Result: {cpu_time:.2f}s CPU ({wall_time:.1f}s wall), solution={'YES' if solution else 'NO'}")
        
        return result_info
    
    def _save_seed_to_afl_queue(self, seed_input: bytes, target_name: str, timestamp: int) -> Optional[str]:
        """Save symex-generated seed to AFL++ queue for fuzzing.
        
        Args:
            seed_input: Seed content to save
            target_name: Name of target function
            timestamp: Timestamp for unique ID
        
        Returns:
            Seed ID if saved successfully, None otherwise
        """
        try:
            # Generate unique seed ID for attribution tracking
            seed_id = f"symex_{target_name}_{timestamp}"
            
            # AFL++ queue directory
            queue_dir = Path(self.config['afl']['output_dir']) / 'default' / 'queue'
            queue_dir.mkdir(parents=True, exist_ok=True)
            
            # Save with AFL-compatible naming: id:XXXXXX,src:symex,op:unstuck
            seed_path = queue_dir / f"id:{timestamp},src:symex,op:unstuck,+cov"
            
            with open(seed_path, 'wb') as f:
                f.write(seed_input)
            
            self.logger.info(f"[SELECTIVE SYMEX] ✓ Saved to AFL queue: {seed_path.name}")
            return seed_id
            
        except Exception as e:
            self.logger.warning(f"[SELECTIVE SYMEX] Could not save seed: {e}")
            return None
        return result_info
    
    def _count_crashes(self) -> int:
        """Count crashes from filesystem."""
        try:
            from pathlib import Path
            output_dir = Path(self.config.get('afl', {}).get('output_dir', 'data/outputs'))
            crashes_dir = output_dir / 'default' / 'crashes'
            
            if not crashes_dir.exists():
                return 0
            
            crash_files = list(crashes_dir.glob('id:*'))
            return len(crash_files)
        except:
            return 0
    
    # Resource allocation happens automatically within actions
    # - FUZZING action: AFL++ gets optimized CPU/thread allocation
    # - SYMBOLIC_EXECUTION action: angr gets CPU/timeout allocation
    # No separate methods needed - embedded in execute_fuzzing_step() and execute_symbolic_execution()
    
    def get_fuzzing_stats(self) -> FuzzingStats:
        """Get current fuzzing statistics."""
        # Use FeedbackCollector for enhanced stats if available
        if self.feedback_collector:
            # Get current action from environment if available
            current_action = getattr(self, 'last_action_name', "UNKNOWN")
            try:
                if hasattr(self, 'env') and hasattr(self.env, 'get_attr'):
                    values = self.env.get_attr('last_action_taken')
                    if values:
                        for val in values:
                            if val:
                                current_action = val
                                break
                elif hasattr(self, 'env') and hasattr(self.env, 'unwrapped') and hasattr(self.env.unwrapped, 'last_action_taken'):
                    current_action = self.env.unwrapped.last_action_taken
            except Exception:
                pass
            
            # Get power reading
            estimated_watts = 0.0
            if hasattr(self, 'power_tracker') and self.power_tracker:
                estimated_watts = self.power_tracker.get_current_power_watts()
            
            enhanced_stats = self.feedback_collector.get_stats(
                action_taken=current_action,
                estimated_watts=estimated_watts
            )
            # Convert to FuzzingStats (matching interface)
            return FuzzingStats(
                total_executions=enhanced_stats.get('execs_done', 0),
                exec_speed=enhanced_stats.get('execs_per_sec', 0.0),
                paths_total=enhanced_stats.get('paths_total', 0),
                paths_new=enhanced_stats.get('paths_found', 0),
                crashes_total=enhanced_stats.get('saved_crashes', 0),
                crashes_new=0,  # Would need to track delta
                coverage_percentage=enhanced_stats.get('coverage_estimate', 0.0),
                time_elapsed=enhanced_stats.get('session_runtime', 0.0)
            )
        return self.fuzzer.get_stats()
    
    def _create_directories(self) -> None:
        """Create necessary directories."""
        dirs = self.config.get('directories', {})
        for key, path in dirs.items():
            Path(path).mkdir(parents=True, exist_ok=True)
        
        # Also create AFL input/output dirs
        Path(self.config['afl']['input_dir']).mkdir(parents=True, exist_ok=True)
        Path(self.config['afl']['output_dir']).mkdir(parents=True, exist_ok=True)
    
    def _ensure_seed_input(self) -> None:
        """Ensure seed input file exists."""
        input_dir = Path(self.config['afl']['input_dir'])
        seed_file = input_dir / "seed.txt"
        
        if not seed_file.exists():
            seed_file.write_bytes(b"AAAAAAAA\n")
            self.logger.info(f"Created default seed: {seed_file}")

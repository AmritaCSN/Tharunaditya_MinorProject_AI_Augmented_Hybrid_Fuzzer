"""
Reinforcement Learning Environment for NeuroFuzz
"""

import gymnasium as gym
import numpy as np
import logging
import time
from typing import Dict, Any, Optional, Tuple

from src.core.interfaces import (
    IRLEnvironment,
    FuzzingAction,
    FuzzingStats,
    BinaryTarget
)


class NeuroFuzzEnv(gym.Env, IRLEnvironment):
    """
    Gymnasium environment for NeuroFuzz.
    
    Observation Space: 12D - [paths, crashes, exec_speed, time, coverage, stuck_counter, 
                              path_discovery_rate, fuzzing_recency, code_coverage, symex_roi,
                              target_vulnerability_score, power_consumption]
    Action Space: Discrete(2) - [FUZZING, SYMBOLIC_EXECUTION]
    
    Resource allocation is automatic within each action (not a separate action).
    """
    
    def __init__(self, orchestrator: Any, targets: list[BinaryTarget], config: Dict[str, Any]):
        """
        Initialize RL environment.
        
        Args:
            orchestrator: Reference to main orchestrator
            targets: List of binary targets
            config: Configuration dictionary
        """
        super().__init__()
        
        self.orchestrator = orchestrator
        self.targets = targets
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Action space: 2 discrete actions (simplified - resource allocation automatic)
        self.action_space = gym.spaces.Discrete(2)
        
        # Observation space: 12-dimensional vector (added power consumption)
        # [paths, crashes, exec_speed, time, coverage, stuck_counter, 
        #  path_discovery_rate, fuzzing_recency, code_coverage, symex_roi,
        #  current_target_vulnerability_score, current_power_consumption]
        self.observation_space = gym.spaces.Box(
            low=0.0,
            high=1.0,
            shape=(12,),
            dtype=np.float32
        )
        
        # Environment state
        self.current_target_idx = 0
        self.stuck_counter = 0
        self.last_paths = 0
        self.last_crashes = 0
        self.episode_start_time = 0
        self.max_episode_steps = config.get('max_steps', 50)  # Increased to 50 for longer episodes to see long-term effects
        self.current_step = 0
        
        # Action history for masking (prevent spam)
        self.action_history = []  # Track last N actions
        self.max_consecutive_same_action = 5  # Allow max 5 consecutive same actions
        
        # Forced diversity tracking
        self.fuzzing_steps_since_last_fuzz = 0
        self.consecutive_zero_reward = 0
        self.last_action = None
        # Ensure callbacks always see an action label (avoids UNKNOWN on first log)
        self.last_action_taken = 'FUZZING'
        try:
            setattr(self.orchestrator, 'last_action_name', 'FUZZING')
        except Exception:
            pass
        
        # Symbolic execution tracking for attribution
        self.last_symex_result = None
        self.last_symex_crashes = 0
        self.paths_5_steps_ago = 0
        self.current_symex_target_name = None
        
        # CRITICAL: Track consecutive symbolic execution to prevent degenerate policy
        self.consecutive_symex_timeouts = 0
        self.consecutive_symex_failures = 0
        self.symex_backoff_until_step = 0
        self.symex_backoff_base = 3  # steps
        self.symex_backoff_max = 25  # steps
        
        # Reward shaping parameters (legacy - not used anymore)
        self.reward_crash = 1.0
        self.reward_new_path = 0.2
        self.penalty_stuck = -0.5
        
        self.logger.info(f"NeuroFuzz environment initialized with {len(targets)} targets")
    
    def reset(self, seed: Optional[int] = None, options: Optional[Dict] = None) -> Tuple:
        """
        Reset environment to initial state.
        
        Returns:
            (observation, info) tuple
        """
        super().reset(seed=seed)
        
        import time
        self.current_step = 0
        self.current_target_idx = 0
        self.stuck_counter = 0
        self.last_paths = 0
        self.last_crashes = 0
        self.episode_start_time = time.time()
        
        # Reset symbolic execution failure tracking
        self.consecutive_symex_timeouts = 0
        self.consecutive_symex_failures = 0
        self.last_symex_crashes = 0
        
        # Reset symbolic execution tracking
        self.last_symex_result = None
        self.last_symex_crashes = 0
        self.paths_5_steps_ago = 0
        self.current_symex_target_name = None
        
        # Reset action tracking
        self.action_counts = {a.name: 0 for a in FuzzingAction}
        self.last_action_taken = 'FUZZING'
        try:
            setattr(self.orchestrator, 'last_action_name', 'FUZZING')
        except Exception:
            pass
        
        # AFL++ runs CONTINUOUSLY during entire training session
        # Episodes are purely internal RL concept - AFL++ never stops
        # No need to check or restart here
        
        observation = self.get_observation()
        info = {'episode': 'started', 'target': self.targets[0].name if self.targets else 'none'}
        
        self.logger.debug("Environment reset (AFL++ continues running)")
        return observation, info
    
    def step(self, action: int) -> Tuple:
        """
        Execute action and return result.
        
        Args:
            action: Action index (0=Fuzzing, 1=Symbolic Execution)
            
        Returns:
            (observation, reward, terminated, truncated, info) tuple
        """
        self.current_step += 1
        
        # Set action for tracking FIRST before any stats collection
        action_enum = FuzzingAction(action)
        self.last_action_taken = action_enum.name
        self.last_action = action_enum.name
        
        # Get stats AFTER action is set (so it gets logged correctly)
        prev_stats = self.orchestrator.get_fuzzing_stats()
        prev_paths = prev_stats.paths_total
        prev_crashes = self._count_crashes_filesystem()
        
        # EMERGENCY ACTION MASKING - Prevent catastrophic repeated failures or overload
        original_action = action
        if self._should_block_symex(action):
            self.logger.debug("SymEx blocked (failures/timeouts/ROI/overload); forcing FUZZING this step")
            action = FuzzingAction.FUZZING.value
        
        # Track path progress for next check
        if self.current_step % 5 == 0:
            self.paths_5_steps_ago = self.last_paths
        
        # Update action_enum after masking
        action_enum = FuzzingAction(action)
        
        # UPDATE action tracking AFTER masking (so callback sees correct action)
        self.last_action_taken = action_enum.name
        self.last_action = action_enum.name
        
        # Track action distribution for logging
        if not hasattr(self, 'action_counts'):
            self.action_counts = {a.name: 0 for a in FuzzingAction}
        self.action_counts[action_enum.name] += 1

        # Expose last action directly to orchestrator for reliable logging
        try:
            setattr(self.orchestrator, 'last_action_name', action_enum.name)
        except Exception:
            pass

        # Track entropy/diversity for policy health (run-mode monitoring)
        if not hasattr(self, 'action_history_entropy'):
            self.action_history_entropy = []
        self._log_action_entropy()
        
        # Start power tracking for this step
        if hasattr(self.orchestrator, 'power_tracker') and self.orchestrator.power_tracker:
            self.orchestrator.power_tracker.start_step(self.current_step, action_enum.name)
        
        self.logger.debug(f"Step {self.current_step}: Action {action_enum.name} (forced={action != original_action})")
        
        # Execute action via orchestrator (2 actions: Fuzzing, Symbolic Execution)
        symex_result = None
        if action_enum == FuzzingAction.FUZZING:
            self.orchestrator.execute_fuzzing_step()
        
        elif action_enum == FuzzingAction.SYMBOLIC_EXECUTION:
            current_target = self.targets[self.current_target_idx] if self.targets else None
            self.current_symex_target_name = current_target.name if current_target else None
            if current_target:
                # Store result for attribution tracking
                symex_result = self.orchestrator.execute_symbolic_execution(current_target)
                self.last_symex_result = symex_result
                if symex_result is None:
                    self.consecutive_symex_failures += 1
                else:
                    self.consecutive_symex_failures = 0
        
        # Resource allocation happens AUTOMATICALLY within each action
        # - Fuzzing allocates more to AFL++
        # - Symbolic execution allocates more to angr
        
        # Log action execution
        action_names = ['FUZZING', 'SYMBOLIC_EXECUTION', 'REALLOCATE_RESOURCES', 'ANALYZE_TARGETS']
        action_name = action_names[action] if action < len(action_names) else f'UNKNOWN({action})'
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"[RL STEP {self.current_step}] Executing: {action_name}")
        self.logger.info(f"{'='*80}")
        self.logger.info(f"[BEFORE] Execs: {prev_stats.total_executions:,} | Paths: {prev_stats.paths_total} | Crashes: {prev_crashes}")
        
        # Get current stats and calculate reward
        stats = self.orchestrator.get_fuzzing_stats()
        
        # Use filesystem counter for more reliable crash detection
        actual_crashes = self._count_crashes_filesystem()
        new_paths = max(0, stats.paths_total - prev_paths)  # Clamp to 0 (prevent negative)
        new_crashes = max(0, actual_crashes - prev_crashes)
        
        reward = self._calculate_enhanced_reward(new_paths, new_crashes, action_enum.name, stats)
        
        # Log results
        self.logger.info(f"[AFTER]  Execs: {stats.total_executions:,} | Paths: {stats.paths_total} | Crashes: {actual_crashes}")
        self.logger.info(f"[DELTA]  +{new_paths} paths | +{new_crashes} crashes")
        
        # Log reward breakdown
        reward_parts = []
        if new_crashes > 0:
            reward_parts.append(f"+{new_crashes} crashes")
        if new_paths > 0:
            reward_parts.append(f"+{new_paths} paths")
        if action == FuzzingAction.SYMBOLIC_EXECUTION.value and symex_result and symex_result.get('solution_found'):
            reward_parts.append("+unstick bonus")
        reward_str = ", ".join(reward_parts) if reward_parts else "no change"
        self.logger.info(f"[REWARD] {reward:+.2f} ({reward_str})")
        self.logger.info(f"{'='*80}\n")
        
        # End power tracking for this step (logs power consumption with reward correlation)
        if hasattr(self.orchestrator, 'power_tracker') and self.orchestrator.power_tracker:
            self.orchestrator.power_tracker.end_step(reward, new_crashes, new_paths)
        
        # Track consecutive zero rewards for stuck detection
        if reward <= 0:
            self.consecutive_zero_reward += 1
        else:
            self.consecutive_zero_reward = 0
        
        # Update state
        self.last_paths = stats.paths_total
        self.last_crashes = actual_crashes
        self.last_action = action_enum.name
        self.last_action_taken = action_enum.name  # For callback visibility
        
        # Update action history for masking
        self.action_history.append(action)
        if len(self.action_history) > 20:  # Keep last 20 actions
            self.action_history.pop(0)
        
        # Get new observation
        observation = self.get_observation()
        
        # Check termination conditions
        terminated = False
        truncated = self.current_step >= self.max_episode_steps
        
        # Save action distribution when episode ends (for evaluator plots)
        if truncated or terminated:
            import json
            from pathlib import Path
            if hasattr(self.orchestrator, 'campaign_dir') and self.orchestrator.campaign_dir:
                campaign_dir = Path(self.orchestrator.campaign_dir)
                action_dist_file = campaign_dir / 'action_distribution.json'
                try:
                    with open(action_dist_file, 'w') as f:
                        json.dump(self.action_counts, f, indent=2)
                    self.logger.debug(f"Saved action distribution: {self.action_counts}")
                except Exception as e:
                    self.logger.warning(f"Failed to save action distribution: {e}")
        
        # Info dict
        info = {
            'action_taken': action_enum.name,
            'target': self.targets[self.current_target_idx].name if self.targets else 'none',
            'new_paths': stats.paths_new,
            'new_crashes': stats.crashes_new,
            'total_executions': stats.total_executions,
            'exec_speed': stats.exec_speed,
            'coverage_percentage': stats.coverage_percentage
        }
        
        return observation, reward, terminated, truncated, info

    def _log_action_entropy(self) -> None:
        """Track action entropy to detect degenerate policies in run mode."""
        try:
            import math
            total = sum(self.action_counts.values())
            if total == 0:
                return
            probs = [c / total for c in self.action_counts.values() if c > 0]
            entropy = -sum(p * math.log2(p) for p in probs)
            self.action_history_entropy.append(entropy)
            # If entropy collapses for long, orchestrator can decide to fall back (handled externally)
        except Exception:
            return

    def _should_block_symex(self, action: int) -> bool:
        """Decide whether to skip symbolic execution this step."""
        if action != FuzzingAction.SYMBOLIC_EXECUTION.value:
            return False

        # Ensure attribute is always present even if initialization changes
        if not hasattr(self, 'current_symex_target_name'):
            self.current_symex_target_name = None

        # Use local variable to avoid attribute errors under rare wrapper states
        target_name = getattr(self, 'current_symex_target_name', None)

        # CRITICAL: Force fuzzing for first 5 steps to bootstrap AFL++ corpus
        # Without this, symex has nothing to work with and agent gets stuck
        if self.current_step <= 5:
            return True

        # Step-based exponential backoff after repeated failures/timeouts
        if self.current_step < getattr(self, 'symex_backoff_until_step', 0):
            return True

        # System resource pressure
        if hasattr(self.orchestrator, 'resource_controller') and self.orchestrator.resource_controller:
            try:
                if self.orchestrator.resource_controller.should_throttle():
                    return True
            except Exception:
                pass

        # Repeated failures/timeouts - STRICTER THRESHOLD
        if self.consecutive_symex_failures >= 3 or self.consecutive_symex_timeouts >= 2:
            # Check if backoff is already active
            if self.current_step >= getattr(self, 'symex_backoff_until_step', 0):
                # Apply new backoff
                backoff = min(self.symex_backoff_max, self.symex_backoff_base * (self.consecutive_symex_failures + self.consecutive_symex_timeouts))
                self.symex_backoff_until_step = self.current_step + backoff
                self.logger.debug(f"SymEx blocked by failure threshold (failures={self.consecutive_symex_failures}, timeouts={self.consecutive_symex_timeouts}). Backing off for {backoff} steps.")
            return True

        # Low ROI backoff (use observation ROI estimate)
        obs = getattr(self, 'last_observation', None)
        if obs is None:
            try:
                obs = self.get_observation()
            except Exception:
                obs = None
        if obs is not None:
            # Check if fuzzer is NOT stuck (finding paths recently)
            # obs[10] is normalized_execs_stuck (0.0 = fresh path, 1.0 = very stuck)
            normalized_execs_stuck = float(obs[10]) if len(obs) > 10 else 1.0
            
            # BLOCK if we found a path recently (< 10k execs ago, approx 3 seconds)
            if normalized_execs_stuck < 0.1:
                return True

            symex_roi = float(obs[9]) if len(obs) > 9 else 0.0
            if symex_roi < 0.1 and self.consecutive_symex_failures >= 2:
                return True

        # Target-level blacklist from orchestrator (wall-clock cooldown)
        if hasattr(self.orchestrator, 'symex_blacklist') and target_name:
            cooldown_until = self.orchestrator.symex_blacklist.get(target_name)
            if cooldown_until and cooldown_until > time.time():
                return True

        return False
    
    def get_observation(self) -> np.ndarray:
        """
        Get current observation vector - UNIVERSAL across all binaries.
        
        Uses only fuzzing dynamics, not binary-specific features.
        This allows the model to transfer between different programs.
        
        Enhanced with adaptive stuck detection metrics for RL learning.
        
        Returns:
            12-dimensional observation array (normalized to [0, 1])
        """
        stats = self.orchestrator.get_fuzzing_stats()
        
        # Normalize metrics to [0, 1] range
        import time
        time_elapsed = time.time() - self.episode_start_time
        
        # ADAPTIVE METRIC: Executions since last path (KEY for RL learning when to trigger symex)
        execs_since_last_path = self.orchestrator.feedback_collector.get_execs_since_last_path()
        # Normalize: 100k execs = 1.0 (typical stuck threshold ~65k)
        normalized_execs_stuck = min(execs_since_last_path / 100000.0, 1.0)
        
        # Calculate symbolic execution ROI for agent decision-making (INDUSTRY CRITICAL)
        symex_roi = 0.0
        if hasattr(self.orchestrator, 'symex_cost_history') and len(self.orchestrator.symex_cost_history) >= 3:
            recent_costs = self.orchestrator.symex_cost_history[-5:]
            avg_cost = sum(recent_costs) / len(recent_costs) if recent_costs else 0.1
            
            # Benefit: did symex seeds cause crashes?
            symex_crashes = self._count_symex_crashes()
            symex_benefit = symex_crashes * 10  # Weight crashes heavily
            
            symex_roi = symex_benefit / max(avg_cost, 0.1)  # Benefit per CPU second
        
        # Get current target vulnerability score for semantic awareness
        current_target_score = 0.0
        if self.targets and len(self.targets) > 0:
            current_target = self.targets[self.current_target_idx]
            current_target_score = min(current_target.vulnerability_score / 10.0, 1.0)
        
        # UNIVERSAL FEATURES - work for any binary
        obs = np.array([
            # Fuzzing progress indicators
            min(stats.paths_total / 1000.0, 1.0),          # 0: paths discovered (normalized)
            min(stats.crashes_total / 10.0, 1.0),          # 1: crashes found (normalized)
            min(stats.exec_speed / 10000.0, 1.0),          # 2: fuzzer throughput
            
            # Time dynamics
            min(time_elapsed / 3600.0, 1.0),               # 3: elapsed time (1 hour scale)
            min(self.current_step / 1000.0, 1.0),          # 4: episode progress
            
            # Progress rate (paths per minute)
            min((stats.paths_total / max(time_elapsed/60, 1)) / 100.0, 1.0),  # 5: path discovery rate
            
            # Stagnation indicators
            min(self.stuck_counter / 10.0, 1.0),           # 6: stuck episodes
            min(self.fuzzing_steps_since_last_fuzz / 20.0, 1.0),  # 7: fuzzing recency
            
            # Coverage dynamics
            stats.coverage_percentage / 100.0,             # 8: code coverage
            
            # Symbolic execution effectiveness (CRITICAL FOR INTELLIGENT SCHEDULING)
            min(symex_roi / 10.0, 1.0),                    # 9: symex ROI (benefit per CPU second)
            
            # Adaptive stuck metric (NEW - KEY FOR LEARNING WHEN TO TRIGGER SYMEX)
            normalized_execs_stuck,                        # 10: execs since last path (0-1, ~65k = stuck)
            
            # Semantic vulnerability awareness
            current_target_score,                          # 11: current target vulnerability score
        ], dtype=np.float32)

        # Cache for ROI-based gating
        self.last_observation = obs
        
        return obs
    
    def _get_normalized_power(self) -> float:
        """Get normalized power consumption for RL observation."""
        if hasattr(self.orchestrator, 'power_tracker') and self.orchestrator.power_tracker:
            return self.orchestrator.power_tracker.get_normalized_power_for_observation()
        return 0.5  # Default if power tracker not available
    
    def calculate_reward(self, stats: FuzzingStats) -> float:
        """
        Calculate reward based on fuzzing statistics.
        
        Reward shaping:
        - +1.0 per new crash
        - +0.2 per new path
        - -0.5 if stuck (no progress)
        
        Args:
            stats: Current fuzzing statistics
            
        Returns:
            Reward value
        """
        reward = 0.0
        
        # Reward for new crashes
        new_crashes = stats.crashes_total - self.last_crashes
        if new_crashes > 0:
            reward += new_crashes * self.reward_crash
            self.stuck_counter = 0
        
        # Reward for new paths
        new_paths = stats.paths_total - self.last_paths
        if new_paths > 0:
            reward += new_paths * self.reward_new_path
            self.stuck_counter = 0
        
        # Penalty for being stuck
        if new_crashes == 0 and new_paths == 0:
            self.stuck_counter += 1
            if self.stuck_counter > 3:
                reward += self.penalty_stuck
        
        # Update tracking variables
        self.last_crashes = stats.crashes_total
        self.last_paths = stats.paths_total
        
        return reward
    
    def _calculate_enhanced_reward(self, new_paths: int, new_crashes: int, action: str, stats: FuzzingStats) -> float:
        """
        Enhanced reward function optimized for finding crashes efficiently.
        
        GOAL: Train agent to maximize crashes/kWh and find vulnerabilities faster than AFL++.
        
        Args:
            new_paths: Number of new paths found
            new_crashes: Number of new crashes found
            action: Action taken
            stats: Current fuzzing statistics
            
        Returns:
            Calculated reward value
        """
        try:
            reward = 0.0
            
            # MAIN SIGNAL: Crashes (HIGHLY VALUABLE - primary goal)
            if new_crashes > 0:
                reward += 10.0 * new_crashes  # +10.0 per crash (was +1.0)
                self.logger.info(f"🎯 NEW CRASH FOUND! Reward: +{10.0 * new_crashes:.1f}")
            
            # SECONDARY: New paths (exploration progress)
            if new_paths > 0:
                reward += 0.5 * min(new_paths, 20)  # +0.5 per path, max 20 (was +0.2)
                if new_paths >= 10:
                    self.logger.debug(f"📊 Discovered {new_paths} new paths, reward: +{0.5 * min(new_paths, 20):.1f}")
            
            # FUZZING: Outcome-based only (no free bonus)
            # Only reward if it produces results
            if action == 'FUZZING':
                if new_paths > 0 or new_crashes > 0:
                    reward += 0.1  # Small bonus for productive fuzzing
                    # DO NOT reset symbolic execution failure counters here
                    # We want backoff to persist until SymEx actually succeeds or backoff expires
                    # self.consecutive_symex_timeouts = 0
                    # self.consecutive_symex_failures = 0
                # No reward if nothing found (neutral)
            
            # SYMBOLIC EXECUTION REWARD SHAPING
            # CRITICAL: Only reward if symbolic execution actually helps
            if action == 'SYMBOLIC_EXECUTION':
                reward = self._symex_reward(new_paths, new_crashes, reward)
            
            # DIVERSITY TRACKING (for logging only, no reward shaping)
            if not hasattr(self, 'recent_actions'):
                self.recent_actions = []
            self.recent_actions.append(action)
            if len(self.recent_actions) > 20:
                self.recent_actions.pop(0)

            
            # STUCK PENALTY - Very minimal
            import time
            time_elapsed = time.time() - self.episode_start_time
            if new_paths == 0 and new_crashes == 0 and time_elapsed > 300:  # 5 minutes
                reward -= 0.05  # Tiny penalty
            
            return reward
            
        except Exception as e:
            self.logger.error(f"Reward calculation error: {e}")
            return 0.0

    def _symex_reward(self, new_paths: int, new_crashes: int, reward: float) -> float:
        """Reward shaping specific to symbolic execution outcomes.

        Attribution/backoff rules:
        - Bonus for crashes traced to symex seeds (filesystem attribution via filenames)
        - Light bonus for producing a viable seed even if crash not yet observed
        - SELECTIVE TRIGGER: Big reward if symex unsticks fuzzer, penalty if triggered when not stuck
        - Penalties for repeated timeouts/failed solves to trigger backoff
        - Tracks attribution into orchestrator.symex_seed_attribution when seed_id is present
        """
        try:
            result = self.last_symex_result or {}
            seed_id = result.get('seed_id') if isinstance(result, dict) else None
            solution_found = bool(result.get('solution_found')) if isinstance(result, dict) else False
            timed_out = bool(result.get('timeout')) if isinstance(result, dict) else False
            reason = result.get('reason', '') if isinstance(result, dict) else ''

            # SELECTIVE SYMEX REWARDS (adaptive decision-making)
            # Check if symex was triggered when not stuck
            if reason == 'not_stuck':
                # HEAVY Penalty for triggering symex unnecessarily
                self.logger.debug("[RL] Symex triggered when NOT stuck - HEAVY penalty")
                # Add short backoff to prevent spamming (force fuzzing for 5 steps)
                self.symex_backoff_until_step = max(getattr(self, 'symex_backoff_until_step', 0), self.current_step + 5)
                return reward - 5.0  # Was -1.0
            
            if reason == 'high_priority_target':
                # Bonus for targeting high-priority functions (Semantic Prioritization)
                self.logger.debug("[RL] Symex triggered for High-Priority Target - Bonus")
                reward += 2.0
            
            if reason == 'no_seed':
                # No seed available from AFL (early in fuzzing)
                self.logger.debug("[RL] Symex triggered but no AFL seed available")
                # Add short backoff
                self.symex_backoff_until_step = max(getattr(self, 'symex_backoff_until_step', 0), self.current_step + 5)
                return reward - 2.0  # Was -0.5
            
            # UNSTUCK DETECTION: Check if symex actually unstuck the fuzzer
            if solution_found and seed_id:
                # Wait briefly and check if new paths appeared after symex
                # This indicates symex successfully unstuck the fuzzer
                import time
                time.sleep(2)  # Brief wait for AFL to process new seed
                
                # Get fresh stats to see if paths increased
                fresh_stats = self.orchestrator.get_fuzzing_stats()
                current_paths = fresh_stats.paths_total
                
                # Check if we were stuck before and now have new paths
                if hasattr(self, '_paths_before_symex'):
                    if current_paths > self._paths_before_symex:
                        # HUGE REWARD - symex unstuck the fuzzer!
                        unstuck_reward = 20.0  # Was 15.0
                        reward += unstuck_reward
                        self.logger.info(f"[RL] ✓✓✓ SYMEX UNSTUCK FUZZER! +{unstuck_reward} reward (paths: {self._paths_before_symex} → {current_paths})")
                        self.consecutive_symex_failures = 0
                        self.consecutive_symex_timeouts = 0
                        return reward
                
                # Store current paths for next check
                self._paths_before_symex = current_paths

            # Attribute crashes specifically caused by symex seeds (filename src matches seed)
            symex_crashes_total = self._count_symex_crashes()
            new_symex_crashes = max(0, symex_crashes_total - getattr(self, 'last_symex_crashes', 0))
            self.last_symex_crashes = symex_crashes_total

            # Update orchestrator attribution map when a seed exists
            if seed_id and hasattr(self.orchestrator, 'symex_seed_attribution'):
                attrib = self.orchestrator.symex_seed_attribution.setdefault(seed_id, {'paths': 0, 'crashes': 0})
                attrib['paths'] += max(0, new_paths)
                attrib['crashes'] += new_symex_crashes

            # Strong reward when crashes are linked to symex seeds
            if new_symex_crashes > 0:
                reward += 20.0 * new_symex_crashes  # Was 15.0
                self.consecutive_symex_failures = 0
                self.consecutive_symex_timeouts = 0
                return reward

            # If a seed was produced, lightly reward the effort even before crash lands
            if solution_found and seed_id:
                reward += 1.0  # Was 0.5
                if new_paths > 0:
                    # Attribute early path discovery to symex-provided seed
                    reward += min(new_paths, 5) * 0.5  # Was 0.2
                self.consecutive_symex_failures = 0
            else:
                # No solution/seed generated
                self.consecutive_symex_failures += 1

            if timed_out:
                self.consecutive_symex_timeouts += 1

            # Penalty scales with repeated failures/timeouts to enforce backoff gating
            # INCREASED PENALTY SCALING
            penalty = 1.0 * self.consecutive_symex_failures + 2.0 * self.consecutive_symex_timeouts
            reward -= min(penalty, 10.0)

            # Apply exponential backoff on failures/timeouts
            if (self.consecutive_symex_failures + self.consecutive_symex_timeouts) >= 2:
                backoff = min(self.symex_backoff_max, self.symex_backoff_base * (self.consecutive_symex_failures + self.consecutive_symex_timeouts))
                # Only extend backoff if new calculation is further out
                new_backoff_step = self.current_step + backoff
                if new_backoff_step > getattr(self, 'symex_backoff_until_step', 0):
                    self.symex_backoff_until_step = new_backoff_step
                    self.logger.debug(f"SymEx backoff extended to step {self.symex_backoff_until_step} (failures={self.consecutive_symex_failures}, timeouts={self.consecutive_symex_timeouts})")
                
                # Target-level cooldown (wall time) to avoid hammering same function
                target_name = result.get('target') if isinstance(result, dict) else None
                if target_name and hasattr(self.orchestrator, 'symex_blacklist'):
                    import time
                    self.orchestrator.symex_blacklist[target_name] = time.time() + backoff

            return reward
        except Exception as e:
            self.logger.error(f"SymEx reward error: {e}")
            return reward
    
    def _count_crashes_filesystem(self) -> int:
        """
        Count crashes from filesystem (more reliable than stats file).
        
        Returns:
            Number of crashes found in filesystem
        """
        try:
            import glob
            from pathlib import Path
            
            output_dir = Path(self.config.get('afl', {}).get('output_dir', 'data/outputs'))
            crashes_dir = output_dir / 'default' / 'crashes'
            
            if not crashes_dir.exists():
                return 0
            
            # Count files starting with 'id:' in crashes directory
            crash_files = list(crashes_dir.glob('id:*'))
            return len(crash_files)
            
        except Exception as e:
            self.logger.error(f"Error counting crashes from filesystem: {e}")
            return 0
    
    def _count_symex_crashes(self) -> int:
        """Count crashes specifically from symbolic execution seeds.
        
        AFL++ crash files have format: id:XXXXXX,src:YYYYYYY,... 
        where src is the seed that caused the crash.
        We check if src matches symex seed IDs.
        """
        try:
            from pathlib import Path
            
            output_dir = Path(self.config.get('afl', {}).get('output_dir', 'data/outputs'))
            crashes_dir = output_dir / 'default' / 'crashes'
            
            if not crashes_dir.exists():
                return 0
            
            # Get symbolic execution seeds from orchestrator
            symex_seeds = getattr(self.orchestrator, 'symex_seeds', set())
            if not symex_seeds:
                return 0
            
            # Check crash files for symex origin
            symex_crash_count = 0
            crash_files = list(crashes_dir.glob('id:*'))
            
            for crash_file in crash_files:
                # Parse crash filename: id:000000,src:000123,...
                filename = crash_file.name
                if ',src:' in filename:
                    parts = filename.split(',src:')
                    if len(parts) > 1:
                        src_part = parts[1].split(',')[0]
                        # Check if source matches any symex seed
                        for symex_id in symex_seeds:
                            if symex_id in filename or src_part in symex_id:
                                symex_crash_count += 1
                                break
            
            return symex_crash_count
            
        except Exception as e:
            self.logger.error(f"Error counting symex crashes: {e}")
            return 0


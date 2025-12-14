import os
import stat
from pathlib import Path

import numpy as np
import pytest

from src.fuzzing.afl_fuzzer import AFLFuzzer
from src.utils.feedback_collector import FeedbackCollector
from src.rl.environment import NeuroFuzzEnv
from src.core.interfaces import BinaryTarget, FuzzingStats


class DummyResourceController:
    def __init__(self, should_throttle: bool = False):
        self._should_throttle = should_throttle

    def should_throttle(self):
        return self._should_throttle


class DummyOrchestrator:
    def __init__(self, resource_controller=None):
        self.resource_controller = resource_controller or DummyResourceController()

    def get_fuzzing_stats(self):
        return FuzzingStats(
            total_executions=0,
            exec_speed=0.0,
            paths_total=0,
            paths_new=0,
            crashes_total=0,
            crashes_new=0,
            coverage_percentage=0.0,
            time_elapsed=0.0,
        )

    # Placeholders used by env reward/observation helpers
    symex_cost_history = []
    symex_benefit_history = []
    power_tracker = None
    symex_seeds = set()


@pytest.fixture
def tmp_exec(tmp_path):
    """Create a dummy executable file."""
    binary = tmp_path / "dummy_bin"
    binary.write_text("echo test")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def test_afl_force_clean_guard(tmp_exec, tmp_path, monkeypatch):
    # Bypass AFL availability check
    monkeypatch.setattr(AFLFuzzer, "_check_afl_available", lambda self: True)

    fuzzer = AFLFuzzer()
    fuzzer.force_clean = False
    fuzzer.resume = False

    input_dir = tmp_path / "inputs"
    input_dir.mkdir()
    (input_dir / "seed").write_text("seed")

    output_dir = tmp_path / "outputs"
    output_dir.mkdir()

    # Should refuse to clean without force_clean
    started = fuzzer.start(str(tmp_exec), str(input_dir), str(output_dir))
    assert started is False


def test_afl_validate_resume_state(tmp_path, monkeypatch):
    monkeypatch.setattr(AFLFuzzer, "_check_afl_available", lambda self: True)
    fuzzer = AFLFuzzer()

    output_dir = tmp_path / "outputs"
    default_dir = output_dir / "default"
    queue_dir = default_dir / "queue"
    default_dir.mkdir(parents=True)
    queue_dir.mkdir()
    (queue_dir / "id:000000").write_text("seed")
    (default_dir / "fuzzer_stats").write_text("execs_done: 1")

    assert fuzzer._validate_resume_state(output_dir) is True

    # Remove queue to invalidate
    for child in queue_dir.iterdir():
        child.unlink()
    assert fuzzer._validate_resume_state(output_dir) is False


def test_feedback_collector_prefers_bitmap(tmp_path):
    afl_out = tmp_path / "outputs"
    stats_dir = afl_out / "default"
    stats_dir.mkdir(parents=True)
    stats_file = stats_dir / "fuzzer_stats"
    stats_file.write_text(
        """
        execs_done: 10
        execs_per_sec: 100.0
        corpus_count: 5
        bitmap_cvg: 12.34
        saved_crashes: 0
        saved_hangs: 0
        """
    )

    collector = FeedbackCollector(str(afl_out))
    stats = collector.get_stats()
    assert abs(stats.get("coverage_estimate", 0) - 12.34) < 0.01


def test_symex_gating_blocks_on_throttle():
    orchestrator = DummyOrchestrator(resource_controller=DummyResourceController(should_throttle=True))
    target = BinaryTarget(name="t", address=0, vulnerability_score=1.0, complexity=1, call_depth=1, avoid_functions=[])
    env = NeuroFuzzEnv(orchestrator=orchestrator, targets=[target], config={"max_steps": 10})

    # Action=1 is SYMBOLIC_EXECUTION
    assert env._should_block_symex(1) is True


def test_symex_gating_blocks_on_low_roi():
    orchestrator = DummyOrchestrator(resource_controller=DummyResourceController(should_throttle=False))
    target = BinaryTarget(name="t", address=0, vulnerability_score=1.0, complexity=1, call_depth=1, avoid_functions=[])
    env = NeuroFuzzEnv(orchestrator=orchestrator, targets=[target], config={"max_steps": 10})

    env.consecutive_symex_failures = 2
    env.last_observation = np.array([0] * 9 + [0.0, 0.0], dtype=np.float32)  # ROI at index 9 is 0.0

    assert env._should_block_symex(1) is True


def test_symex_gating_allows_when_healthy():
    orchestrator = DummyOrchestrator(resource_controller=DummyResourceController(should_throttle=False))
    target = BinaryTarget(name="t", address=0, vulnerability_score=1.0, complexity=1, call_depth=1, avoid_functions=[])
    env = NeuroFuzzEnv(orchestrator=orchestrator, targets=[target], config={"max_steps": 10})

    env.consecutive_symex_failures = 0
    env.consecutive_symex_timeouts = 0
    env.last_observation = np.array([0] * 9 + [1.0, 0.0], dtype=np.float32)  # ROI high

    assert env._should_block_symex(1) is False

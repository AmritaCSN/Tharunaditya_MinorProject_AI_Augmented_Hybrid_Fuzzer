import pytest
from src.rl.environment import NeuroFuzzEnv
from src.core.interfaces import FuzzingStats, BinaryTarget


class DummyOrchestrator:
    def __init__(self):
        self.fuzz_calls = 0
        self.symex_calls = 0
        self.symex_cost_history = []
        self.symex_seeds = set()
        self.power_tracker = None
        self.config = {"afl": {"output_dir": "data/outputs"}}

    def get_fuzzing_stats(self):
        return FuzzingStats(
            total_executions=1000,
            exec_speed=100.0,
            paths_total=10,
            paths_new=0,
            crashes_total=0,
            crashes_new=0,
            coverage_percentage=20.0,
            time_elapsed=1.0,
        )

    def execute_fuzzing_step(self):
        self.fuzz_calls += 1

    def execute_symbolic_execution(self, target):
        self.symex_calls += 1
        return {"solution_found": False, "timeout": True}


@pytest.fixture
def env():
    orchestrator = DummyOrchestrator()
    targets = [BinaryTarget(name="vuln_func", address=0x401000, vulnerability_score=8.0, complexity=5, call_depth=1, avoid_functions=[])]
    return NeuroFuzzEnv(orchestrator=orchestrator, targets=targets, config={"max_steps": 5})


def test_emergency_override_forces_fuzzing(env):
    """When symex fails repeatedly, the environment must force fuzzing."""
    env.consecutive_symex_failures = 5
    obs, reward, terminated, truncated, info = env.step(1)  # Request SYMBOLIC_EXECUTION
    assert env.last_action_taken == "FUZZING"
    assert env.orchestrator.fuzz_calls == 1
    assert env.orchestrator.symex_calls == 0


def test_reward_increases_on_new_paths(env):
    """Reward should be positive when new paths are found."""
    env.last_paths = 10
    env.last_crashes = 0

    # Return growing paths on successive calls (prev -> current)
    stats_seq = [
        FuzzingStats(
            total_executions=1050,
            exec_speed=110.0,
            paths_total=10,
            paths_new=0,
            crashes_total=0,
            crashes_new=0,
            coverage_percentage=22.0,
            time_elapsed=1.5,
        ),
        FuzzingStats(
            total_executions=1100,
            exec_speed=120.0,
            paths_total=15,  # +5 new paths
            paths_new=5,
            crashes_total=0,
            crashes_new=0,
            coverage_percentage=25.0,
            time_elapsed=2.0,
        ),
    ]
    stats_iter = iter(stats_seq)
    last_stat = stats_seq[-1]
    env.orchestrator.get_fuzzing_stats = lambda: next(stats_iter, last_stat)
    _, reward, _, _, _ = env.step(0)  # FUZZING
    assert reward > 0

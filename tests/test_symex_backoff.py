import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from src.rl.environment import NeuroFuzzEnv  # noqa: E402
from src.core.interfaces import BinaryTarget  # noqa: E402


class DummyOrchestrator:
    def __init__(self):
        self.symex_blacklist = {}
        self.symex_seed_attribution = {}
        self.symex_seeds = set()

    def get_fuzzing_stats(self):
        # Minimal stats for reward path
        return type('S', (), {
            'paths_total': 0,
            'crashes_total': 0,
            'paths_new': 0,
            'crashes_new': 0,
            'exec_speed': 0,
            'coverage_percentage': 0.0,
            'total_executions': 0,
            'time_elapsed': 0
        })()

    def execute_symbolic_execution(self, target):
        return None

    def execute_fuzzing_step(self):
        return None


@pytest.fixture
def env():
    orch = DummyOrchestrator()
    targets = [BinaryTarget(name='t1', address=0x1000, vulnerability_score=5.0, complexity=1, call_depth=1, avoid_functions=[])]
    env = NeuroFuzzEnv(orchestrator=orch, targets=targets, config={'max_steps': 10})
    return env


def test_backoff_sets_until_step(env, monkeypatch):
    env.current_step = 5
    env.last_symex_result = {'solution_found': False, 'timeout': True, 'target': 't1'}
    env.last_symex_crashes = 0
    monkeypatch.setattr(env, "_count_symex_crashes", lambda: 0)

    reward = env._symex_reward(new_paths=0, new_crashes=0, reward=0.0)

    assert reward < 0
    assert env.symex_backoff_until_step > env.current_step
    assert env.orchestrator.symex_blacklist['t1'] > time.time()


def test_should_block_during_backoff(env):
    env.current_step = 3
    env.symex_backoff_until_step = 10
    assert env._should_block_symex(1) is True


def test_target_blacklist_blocks(env):
    env.current_step = 20
    env.current_symex_target_name = 't1'
    env.orchestrator.symex_blacklist['t1'] = time.time() + 5
    assert env._should_block_symex(1) is True

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from src.rl.environment import NeuroFuzzEnv  # noqa: E402


class DummyOrchestrator:
    def __init__(self):
        self.symex_seed_attribution = {}
        self.symex_seeds = set()


def make_env():
    orch = DummyOrchestrator()
    env = NeuroFuzzEnv(orchestrator=orch, targets=[], config={'max_steps': 10})
    env.last_symex_crashes = 0
    return env, orch


def test_symex_crash_attribution(monkeypatch):
    env, orch = make_env()
    env.last_symex_result = {'seed_id': 'seed1', 'solution_found': True, 'timeout': False}
    env.last_symex_crashes = 0

    # Simulate one new crash from symex seed
    monkeypatch.setattr(env, "_count_symex_crashes", lambda: 1)

    reward = env._symex_reward(new_paths=0, new_crashes=0, reward=0.0)

    assert reward == pytest.approx(15.0)
    assert orch.symex_seed_attribution['seed1']['crashes'] == 1


def test_symex_seed_bonus_no_crash(monkeypatch):
    env, orch = make_env()
    env.last_symex_result = {'seed_id': 'seed2', 'solution_found': True, 'timeout': False}
    env.last_symex_crashes = 0

    monkeypatch.setattr(env, "_count_symex_crashes", lambda: 0)

    reward = env._symex_reward(new_paths=3, new_crashes=0, reward=0.0)

    assert reward == pytest.approx(1.1)
    assert orch.symex_seed_attribution['seed2']['paths'] == 3
    assert orch.symex_seed_attribution['seed2']['crashes'] == 0


def test_symex_penalty_on_failure(monkeypatch):
    env, _ = make_env()
    env.last_symex_result = {'seed_id': None, 'solution_found': False, 'timeout': True}
    env.last_symex_crashes = 0

    monkeypatch.setattr(env, "_count_symex_crashes", lambda: 0)

    reward = env._symex_reward(new_paths=0, new_crashes=0, reward=0.0)

    assert reward == pytest.approx(-0.5)
    assert env.consecutive_symex_failures == 1
    assert env.consecutive_symex_timeouts == 1

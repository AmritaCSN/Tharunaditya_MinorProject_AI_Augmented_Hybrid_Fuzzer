import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from src.core.orchestrator import NeuroFuzzOrchestrator  # noqa: E402
from src.core.interfaces import FuzzingStats  # noqa: E402


class DummyFuzzer:
    def __init__(self):
        self.started = False

    def is_running(self):
        return self.started

    def start(self, *args, **kwargs):
        self.started = True
        return True

    def stop(self):
        self.started = False

    def get_stats(self):
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


class DummyEnv:
    def __init__(self):
        self.action_history_entropy = [0.0] * 10  # Force collapse
        self.unwrapped = self
        self.last_action_taken = 'FUZZING'

    def reset(self):
        return 0, {}

    def step(self, action):
        # Return observation, reward, terminated, truncated, info
        return 0, 0.0, False, False, {
            'action_taken': 'FUZZING',
            'new_paths': 0,
            'new_crashes': 0,
        }


class DummyModel:
    def predict(self, obs, deterministic=True):
        return 0, None  # Always FUZZING


class DummyCollector:
    def get_summary(self):
        return {
            'total_crashes': 0,
            'total_paths': 0,
            'total_executions': 0,
            'avg_exec_speed': 0.0,
        }


class DummyPower:
    def start(self):
        pass

    def save_detailed_log(self):
        pass

    def get_power_efficiency_metrics(self):
        return {'crashes_per_kwh': 0, 'measurement_source': 'test', 'total_energy_kwh': 0, 'average_power_watts': 0}

    def save_report(self, *args, **kwargs):
        pass


class DummyEvaluator:
    def generate_report(self, *args, **kwargs):
        return {}


class DummyEnergyEstimator(DummyPower):
    def get_report(self):
        return {'total_energy_kwh': 0, 'average_power_watts': 0, 'measurement_source': 'test'}

    def save_report(self, *args, **kwargs):
        pass

    def record(self, action=None):
        return None


class DummyResourceController:
    def should_throttle(self):
        return False

    def get_status(self):
        return {}


@pytest.fixture
def orch():
    o = NeuroFuzzOrchestrator()
    o.config = {
        'afl': {'output_dir': 'data/outputs', 'input_dir': 'data/inputs', 'timeout_ms': 1000},
        'general': {'campaign_name': 'test', 'mode': 'run'},
        'reinforcement_learning': {'campaign': {'max_steps': 12}},
    }
    o.fuzzer = DummyFuzzer()
    o.env = DummyEnv()
    o.model = DummyModel()
    o.feedback_collector = DummyCollector()
    o.power_tracker = DummyPower()
    o.energy_estimator = DummyEnergyEstimator()
    o.evaluator = DummyEvaluator()
    o.resource_controller = DummyResourceController()
    o.campaign_dir = Path('data/test_campaign')
    o.campaign_dir.mkdir(parents=True, exist_ok=True)
    o.targets = []
    return o


def test_entropy_fallback_triggers_pure_afl(monkeypatch, orch):
    called = {'count': 0}

    def fake_run_pure_afl(remaining):
        called['count'] += 1

    monkeypatch.setattr(orch, '_run_pure_afl', fake_run_pure_afl)
    monkeypatch.setattr(orch, 'reset_fuzzer', lambda: None)

    result = orch._run_fuzzing_mode()

    assert called['count'] == 1
    # Ensure campaign results structure includes mode and campaign_dir (set in method)
    assert result['mode'] == 'run'

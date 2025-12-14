import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

import src.core.orchestrator as orchestrator  # noqa: E402


class StubResourceController:
    def __init__(self, status, cooldown=5):
        self.status = status
        self.limits = SimpleNamespace(cooldown_seconds=cooldown)

    def check_resources(self):
        return self.status

    def should_throttle(self):
        return self.status.get('action_required', False)


def test_execute_fuzzing_step_pauses_on_pressure(monkeypatch):
    sleep_calls = []

    def fake_sleep(duration):
        sleep_calls.append(duration)

    monkeypatch.setattr(orchestrator.time, "sleep", fake_sleep)

    rc_status = {
        'status': 'ok',
        'action_required': True,
        'cpu_percent': 95.0,
        'memory_percent': 90.0,
        'cpu_over_limit': True,
        'memory_over_limit': True,
    }
    rc = StubResourceController(rc_status, cooldown=4)

    orch = orchestrator.NeuroFuzzOrchestrator()
    orch.resource_controller = rc

    orch.execute_fuzzing_step()

    assert sleep_calls == [4]


def test_execute_fuzzing_step_extends_dwell_near_limits(monkeypatch):
    sleep_calls = []

    def fake_sleep(duration):
        sleep_calls.append(duration)

    monkeypatch.setattr(orchestrator.time, "sleep", fake_sleep)

    rc_status = {
        'status': 'ok',
        'action_required': False,
        'cpu_percent': 88.0,
        'memory_percent': 70.0,
        'cpu_over_limit': True,
        'memory_over_limit': False,
    }
    rc = StubResourceController(rc_status, cooldown=5)

    orch = orchestrator.NeuroFuzzOrchestrator()
    orch.resource_controller = rc

    orch.execute_fuzzing_step()

    assert sleep_calls == [35]
    assert orch.fuzzing_time_budget == 30
    assert orch.max_fuzzing_time == 60

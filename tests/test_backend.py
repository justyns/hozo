import pytest

import hozo
from hozo.backend import Backend, SandboxResult, get_backend
from hozo.bwrap import BubblewrapBackend
from hozo.errors import HozoError
from hozo.policy import SandboxRequest, resolve_policy


class _StubBackend(Backend):
    name = "stub"

    def __init__(self):
        self.ran = None

    def is_available(self):
        return True

    def build_argv(self, policy, *, proxy=None):
        return ["stub"]

    def run(self, policy, *, environ=None, capture=False):
        self.ran = policy
        return SandboxResult(0, None, None, policy, ["stub"], self.name)


def test_get_backend_default():
    backend = get_backend()
    assert backend.name == "bwrap" and isinstance(backend, BubblewrapBackend)


def test_get_unknown_backend_errors():
    with pytest.raises(HozoError):
        get_backend("nonexistent")


def test_bwrap_backend_build_argv(tmp_path):
    policy = resolve_policy(SandboxRequest(command=["true"], project=str(tmp_path)))
    assert get_backend().build_argv(policy)[0] == "bwrap"


def test_runner_delegates_to_injected_backend(tmp_path):
    backend = _StubBackend()
    result = hozo.SandboxRunner(backend).run(SandboxRequest(command=["true"], project=str(tmp_path)))
    assert result.returncode == 0 and result.backend == "stub"
    assert backend.ran is not None

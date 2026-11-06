import pytest

from backend.ssrf import TargetNotAllowedError, TargetPolicy


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/chat", "http://10.0.0.5/x", "http://192.168.1.10/x",
    "http://169.254.169.254/latest/meta-data", "http://[::1]/x", "http://[::ffff:127.0.0.1]/x",
    "http://0.0.0.0/x", "http://2130706433/x", "http://localhost:8001/chat",
])
def test_policy_blocks_internal_targets(url: str) -> None:
    with pytest.raises(TargetNotAllowedError):
        TargetPolicy().check(url)


def test_policy_allows_public_ip_and_operator_exceptions() -> None:
    TargetPolicy().check("http://93.184.216.34/chat")
    TargetPolicy(allowed_hosts=frozenset({"localhost"})).check("http://localhost:8001/chat")
    TargetPolicy(allow_private=True).check("http://10.0.0.5/x")
    with pytest.raises(TargetNotAllowedError):
        TargetPolicy().check("file:///etc/passwd")


def test_policy_from_env(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_ALLOWED_HOSTS", "lab, Other")
    assert TargetPolicy.from_env().allowed_hosts == {"lab", "other"}

"""WP7 offline tests: resilient LLM sender, cassette, request caps, key hygiene and the prompt."""

from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from gateheal.config import GateHealConfig, load_config
from gateheal.llm import (
    DEFAULT_ENDPOINT_URL,
    PROMPT_VERSION,
    LLMBackend,
    LLMBudgetExceeded,
    LLMCassette,
    LLMFatalError,
    LLMTransportError,
    ResilientLLMSender,
    build_wp7_system_prompt,
    sha256_hex,
    system_prompt_sha256,
)
from gateheal.models import ActionId

KEY = "sk-test-SECRET-0123456789"


def _cfg() -> GateHealConfig:
    return load_config(Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml")


def _completion(content: str, *, prompt_tokens: int = 11, completion_tokens: int = 7) -> str:
    return json.dumps(
        {
            "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
        }
    )


class _Resp:
    def __init__(self, text: str) -> None:
        self._text = text

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._text.encode("utf-8")


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(
        DEFAULT_ENDPOINT_URL, code, f"HTTP {code}", headers, io.BytesIO(b"{}")
    )


class _FakeUrlopen:
    """Plays a script of outcomes: a str is a 200 body, an Exception is raised."""

    def __init__(self, script: list[object]) -> None:
        self._script = list(script)
        self.requests: list[tuple[bytes, dict[str, str], float]] = []

    def __call__(self, request: object, timeout: float) -> _Resp:
        data = request.data  # type: ignore[attr-defined]
        headers = {k.lower(): v for k, v in request.header_items()}  # type: ignore[attr-defined]
        self.requests.append((data, headers, timeout))
        outcome = self._script.pop(0) if self._script else _completion("{}")
        if isinstance(outcome, Exception):
            raise outcome
        return _Resp(str(outcome))


def _sender(
    urlopen: _FakeUrlopen,
    *,
    mode: str = "live",
    cassette: LLMCassette | None = None,
    key: str | None = KEY,
    max_total_requests: int | None = None,
    sleeps: list[float] | None = None,
    max_http_attempts: int = 3,
) -> ResilientLLMSender:
    sleeps = sleeps if sleeps is not None else []
    return ResilientLLMSender(
        api_key_loader=lambda: key,
        mode=mode,  # type: ignore[arg-type]
        cassette=cassette,
        max_total_requests=max_total_requests,
        urlopen=urlopen,
        sleep_fn=sleeps.append,
        monotonic_clock=lambda: 1.0,
        max_http_attempts=max_http_attempts,
    )


def test_success_records_one_call_with_tokens_and_uses_bearer_key_and_own_timeout() -> None:
    fake = _FakeUrlopen([_completion("{}", prompt_tokens=21, completion_tokens=5)])
    sender = _sender(fake)
    out = sender(b'{"a": 1}', 10.0)
    assert json.loads(out)["usage"]["prompt_tokens"] == 21
    (call,) = sender.drain_calls()
    assert call.error_kind is None and call.replayed is False
    assert (call.prompt_tokens, call.completion_tokens, call.finish_reason) == (21, 5, "stop")
    assert call.request_sha256 == sha256_hex(b'{"a": 1}')
    assert call.http_attempts == 1
    _data, headers, timeout = fake.requests[0]
    assert headers["authorization"] == f"Bearer {KEY}"
    assert timeout == pytest.approx(60.0)  # not the proposer's 10 s action timeout
    assert sender.drain_calls() == ()  # drained


def test_retry_after_503_then_success_with_exponential_backoff() -> None:
    fake = _FakeUrlopen([_http_error(503), _http_error(503), _completion("{}")])
    sleeps: list[float] = []
    sender = _sender(fake, sleeps=sleeps)
    sender(b"x", 10.0)
    (call,) = sender.drain_calls()
    assert call.http_attempts == 3 and call.error_kind is None
    assert sleeps == [2.0, 4.0]
    assert sender.live_requests == 3


def test_network_error_backoff_then_success() -> None:
    fake = _FakeUrlopen([urllib.error.URLError("reset"), TimeoutError("slow"), _completion("{}")])
    sleeps: list[float] = []
    sender = _sender(fake, sleeps=sleeps)
    sender(b"x", 10.0)
    assert sleeps == [2.0, 4.0]
    (call,) = sender.drain_calls()
    assert call.http_attempts == 3 and call.error_kind is None


def test_retry_after_header_is_honoured_and_capped() -> None:
    fake = _FakeUrlopen([_http_error(429, "9"), _http_error(429, "9999"), _completion("{}")])
    sleeps: list[float] = []
    _sender(fake, sleeps=sleeps)(b"x", 10.0)
    assert sleeps == [9.0, 30.0]


def test_non_retryable_400_is_not_retried_and_becomes_a_transport_error_call() -> None:
    fake = _FakeUrlopen([_http_error(400), _completion("{}")])
    sender = _sender(fake)
    with pytest.raises(LLMTransportError):
        sender(b"x", 10.0)
    (call,) = sender.drain_calls()
    assert call.error_kind == "transport" and call.http_attempts == 1
    assert len(fake.requests) == 1


def test_retries_exhausted_is_a_transport_error_not_a_model_answer() -> None:
    fake = _FakeUrlopen([_http_error(503)] * 5)
    sender = _sender(fake, max_http_attempts=3)
    with pytest.raises(LLMTransportError):
        sender(b"x", 10.0)
    (call,) = sender.drain_calls()
    assert call.error_kind == "transport" and call.http_attempts == 3
    assert call.response_sha256 is None


def test_network_errors_are_retried_and_the_key_is_redacted_from_the_record() -> None:
    boom = urllib.error.URLError(f"connect failed while sending Bearer {KEY}")
    fake = _FakeUrlopen([boom, boom, boom])
    sender = _sender(fake)
    with pytest.raises(LLMTransportError) as excinfo:
        sender(b"x", 10.0)
    (call,) = sender.drain_calls()
    assert KEY not in (call.error or "")
    assert "[REDACTED]" in (call.error or "")
    assert KEY not in str(excinfo.value)


@pytest.mark.parametrize("code", [401, 402, 403])
def test_auth_and_billing_errors_stop_the_campaign(code: int) -> None:
    fake = _FakeUrlopen([_http_error(code)])
    with pytest.raises(LLMFatalError):
        _sender(fake)(b"x", 10.0)
    assert len(fake.requests) == 1


def test_missing_key_is_fatal_and_sends_nothing() -> None:
    fake = _FakeUrlopen([])
    with pytest.raises(LLMFatalError):
        _sender(fake, key=None)(b"x", 10.0)
    assert fake.requests == []


def test_total_request_cap_counts_every_http_attempt() -> None:
    fake = _FakeUrlopen([_http_error(503), _completion("{}"), _completion("{}")])
    sender = _sender(fake, max_total_requests=2)
    sender(b"a", 10.0)  # 503 then 200: two attempts, cap now reached
    assert sender.live_requests == 2
    with pytest.raises(LLMBudgetExceeded):
        sender(b"b", 10.0)
    assert len(fake.requests) == 2  # the capped request was never sent


def test_cassette_records_then_replays_without_a_request(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    fake = _FakeUrlopen([_completion("{}", prompt_tokens=3, completion_tokens=2)])
    rec = _sender(fake, mode="record", cassette=LLMCassette(path))
    first = rec(b"payload", 10.0)
    assert len(fake.requests) == 1

    replay_fake = _FakeUrlopen([])
    replay = _sender(replay_fake, mode="replay", cassette=LLMCassette(path), key=None)
    assert replay(b"payload", 10.0) == first
    (call,) = replay.drain_calls()
    assert call.replayed is True and call.latency_sec == 0.0 and call.error_kind is None
    assert call.prompt_tokens == 3 and call.completion_tokens == 2
    assert replay_fake.requests == []
    assert replay.live_requests == 0


def test_replay_miss_is_an_error_call_and_never_reaches_the_network(tmp_path: Path) -> None:
    fake = _FakeUrlopen([_completion("{}")])
    sender = _sender(fake, mode="replay", cassette=LLMCassette(tmp_path / "c.jsonl"))
    with pytest.raises(LLMTransportError):
        sender(b"never recorded", 10.0)
    (call,) = sender.drain_calls()
    assert call.error_kind == "replay_miss"
    assert fake.requests == []


def test_record_mode_hit_does_not_spend_a_request(tmp_path: Path) -> None:
    cassette = LLMCassette(tmp_path / "c.jsonl")
    fake = _FakeUrlopen([_completion("{}")])
    sender = _sender(fake, mode="record", cassette=cassette)
    sender(b"same", 10.0)
    sender(b"same", 10.0)
    assert len(fake.requests) == 1
    calls = sender.drain_calls()
    assert [c.replayed for c in calls] == [False, True]


def test_live_mode_never_touches_the_cassette(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    sender = _sender(_FakeUrlopen([_completion("{}")]), mode="live")
    sender(b"x", 10.0)
    assert not path.exists()


def test_replay_and_record_modes_require_a_cassette() -> None:
    for mode in ("record", "replay"):
        with pytest.raises(ValueError, match="cassette"):
            _sender(_FakeUrlopen([]), mode=mode)


def test_cassette_never_stores_the_key_and_tolerates_a_torn_last_line(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    cassette = LLMCassette(path)
    sender = _sender(_FakeUrlopen([_completion("{}")]), mode="record", cassette=cassette)
    sender(b'{"messages": []}', 10.0)
    text = path.read_text(encoding="utf-8")
    assert KEY not in text
    assert len(LLMCassette(path)) == 1
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"request_sha256": "abc", "resp')  # crash mid-write
    reloaded = LLMCassette(path)
    assert len(reloaded) == 1
    assert reloaded.get(sha256_hex(b'{"messages": []}')) is not None


def test_prompt_is_json_mode_compatible_and_describes_the_lab() -> None:
    cfg = _cfg()
    prompt = build_wp7_system_prompt(cfg)
    assert "json" in prompt.lower()  # required by the provider's JSON mode
    for action in ActionId:
        assert action.value in prompt
    for unit in cfg.inventory.services:
        assert unit in prompt
    assert "untrusted" in prompt
    assert "least disruptive" in prompt
    assert "approv" not in prompt.lower().replace("human_approved", "")  # no approval hints
    assert system_prompt_sha256(cfg) == sha256_hex(prompt.encode("utf-8"))
    assert PROMPT_VERSION  # bumped whenever the prompt text changes


def test_both_arms_get_the_same_request_settings_and_budget() -> None:
    cfg = _cfg()
    backend = LLMBackend(sender=_sender(_FakeUrlopen([])), max_tokens=321)
    arm_cfg = backend.arm_config(cfg)
    assert arm_cfg.budgets.max_llm_requests == 3
    assert arm_cfg.budgets.max_agent_rounds == 1
    assert cfg.budgets.max_llm_requests == 0  # the base config is not mutated
    info = backend.describe(cfg)
    assert info.max_tokens == 321 and info.temperature == 0.0
    assert info.provider_host == "api.deepseek.com"
    assert info.system_prompt_sha256 == system_prompt_sha256(arm_cfg)
    assert info.mode == "live" and info.http_timeout_sec == pytest.approx(60.0)
    dumped = info.model_dump_json()
    assert KEY not in dumped


def test_proposer_payload_has_json_mode_prompt_and_token_cap() -> None:
    cfg = _cfg()
    fake = _FakeUrlopen([_completion('{"proposals": []}')])
    backend = LLMBackend(sender=_sender(fake), max_tokens=250)
    proposer = backend.make_proposer(cfg)
    from gateheal.models import IncidentRecord

    incident = IncidentRecord(
        incident_id="i-1",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-28T12:00:00+00:00",
        services={},
    )
    batch = proposer.propose(incident)
    assert batch.proposals[0].action_id == ActionId.ABSTAIN_AND_ESCALATE.value  # empty list
    body = json.loads(fake.requests[0][0])
    assert body["temperature"] == 0.0
    assert body["max_tokens"] == 250
    assert body["response_format"] == {"type": "json_object"}
    assert body["messages"][0]["content"] == build_wp7_system_prompt(backend.arm_config(cfg))
    assert json.loads(body["messages"][1]["content"])["incident_id"] == "i-1"



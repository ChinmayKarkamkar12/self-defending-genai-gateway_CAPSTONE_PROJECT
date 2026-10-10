"""SESSION_POLICY=auto: the DQN only if its shipped verdict is GO, the
rule-based fallback otherwise. See app/core/defense/rl/policy.py."""
import json

import numpy as np
import pytest
import respx
from sqlalchemy import select

from app.config import settings
from app.core.defense.rl.actions import ACTION_ORDER
from app.core.defense.rl.dqn import DEFAULT_WEIGHTS_PATH, DQNPolicy, save_weights
from app.core.defense.rl.fallback_policy import RuleBasedPolicy
from app.core.defense.rl.features import N_SESSION_FEATURES
from app.core.defense.rl.policy import (
    get_session_policy,
    read_verdict,
    reset_session_policy_cache,
    verdict_path,
)
from app.core.providers.openai import OPENAI_BASE_URL
from app.db.models import SessionAction, SessionPolicyEvent
from tests.test_review_queue import classify_as, provider_reply, send


def weights(tmp_path, verdict: str | None, *, broken: bool = False) -> str:
    path = tmp_path / "agent.npz"
    w = np.zeros((len(ACTION_ORDER), N_SESSION_FEATURES))
    b = np.zeros(len(ACTION_ORDER))
    b[ACTION_ORDER.index(SessionAction.TIGHTEN)] = 1.0
    if broken:
        path.write_bytes(b"not an npz file")
    else:
        save_weights(path, [(w, b)])
    if verdict is not None:
        verdict_path(path).write_text(json.dumps({"decision": verdict}))
    return str(path)


def auto(monkeypatch, path: str):
    monkeypatch.setattr(settings, "SESSION_POLICY", "auto")
    monkeypatch.setattr(settings, "SESSION_DQN_WEIGHTS", path)
    reset_session_policy_cache()
    return get_session_policy()


def test_auto_is_the_default():
    from app.config import Settings

    assert Settings.model_fields["SESSION_POLICY"].default == "auto"


def test_auto_uses_the_dqn_only_on_a_go_verdict(tmp_path, monkeypatch):
    assert isinstance(auto(monkeypatch, weights(tmp_path, "GO")), DQNPolicy)


@pytest.mark.parametrize("verdict", ["NO-GO", "go", "", None])
def test_auto_falls_back_to_the_rule_otherwise(tmp_path, monkeypatch, verdict):
    assert isinstance(auto(monkeypatch, weights(tmp_path, verdict)), RuleBasedPolicy)


def test_auto_falls_back_when_go_weights_are_broken(tmp_path, monkeypatch):
    assert isinstance(auto(monkeypatch, weights(tmp_path, "GO", broken=True)), RuleBasedPolicy)


def test_unreadable_verdict_is_no_verdict(tmp_path):
    path = tmp_path / "agent.npz"
    verdict_path(path).write_text("{not json")
    assert read_verdict(path) is None
    verdict_path(path).write_text(json.dumps(["GO"]))
    assert read_verdict(path) is None


def test_shipped_files_agree():
    """Whatever the shipped verdict, auto must resolve to a working policy."""
    reset_session_policy_cache()
    verdict = read_verdict(DEFAULT_WEIGHTS_PATH)
    assert verdict in ("GO", "NO-GO")
    if DEFAULT_WEIGHTS_PATH.exists():
        DQNPolicy.load(DEFAULT_WEIGHTS_PATH)


async def test_auto_records_which_policy_decided(client, db_session, monkeypatch, tmp_path):
    classify_as(0.0)
    (tmp_path / "go").mkdir()
    (tmp_path / "nogo").mkdir()
    go = weights(tmp_path / "go", "GO")
    no_go = weights(tmp_path / "nogo", "NO-GO")
    with respx.mock:
        respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(return_value=provider_reply("ok"))
        auto(monkeypatch, go)
        assert (await send(client)).status_code == 200
        auto(monkeypatch, no_go)
        assert (await send(client)).status_code == 200

    runs = (
        await db_session.execute(select(SessionPolicyEvent).order_by(SessionPolicyEvent.created_at))
    ).scalars().all()
    assert [(r.policy, r.action) for r in runs] == [
        ("dqn", SessionAction.TIGHTEN),
        ("rule", SessionAction.MAINTAIN),
    ]

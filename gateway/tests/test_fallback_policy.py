"""Rule-based fallback and the action guards. See
project_plan/06b-adaptive-defense-rl-session-agent.md §6, §8."""
import pytest

from app.core.defense.rl.actions import guard, next_bias
from app.core.defense.rl.fallback_policy import MaintainPolicy, RuleBasedPolicy
from app.core.defense.rl.features import SessionSnapshot
from app.db.models import SessionAction


def run(consecutive: int, refused: int | None = None) -> SessionSnapshot:
    refused = consecutive if refused is None else refused
    return SessionSnapshot(
        request_count=max(refused, 1),
        outcome_counts={"block": refused, "allow": max(refused, 1) - refused},
        consecutive_refused=consecutive,
    )


@pytest.mark.parametrize(
    ("consecutive", "expected"),
    [
        (0, SessionAction.MAINTAIN),
        (1, SessionAction.MAINTAIN),
        (2, SessionAction.TIGHTEN),
        (3, SessionAction.TIGHTEN),
        (4, SessionAction.LOCKOUT),
        (9, SessionAction.LOCKOUT),
    ],
)
def test_tightens_after_consecutive_flags(consecutive, expected):
    assert RuleBasedPolicy().decide(run(consecutive)) == expected


def test_an_allowed_request_resets_the_run():
    # Five refusals in the session, but the latest request was allowed.
    assert RuleBasedPolicy().decide(run(0, refused=5)) == SessionAction.MAINTAIN


def test_maintain_policy_never_acts():
    assert MaintainPolicy().decide(run(10)) == SessionAction.MAINTAIN


def test_rule_parameters_validated():
    with pytest.raises(ValueError):
        RuleBasedPolicy(tighten_after=5, lockout_after=4)


def test_lockout_needs_two_refused_requests():
    clean = SessionSnapshot(request_count=8, outcome_counts={"allow": 8})
    assert guard(SessionAction.LOCKOUT, clean) == SessionAction.MAINTAIN
    assert guard(SessionAction.LOCKOUT, run(1)) == SessionAction.MAINTAIN
    assert guard(SessionAction.LOCKOUT, run(2)) == SessionAction.LOCKOUT
    # Two refusals anywhere in the session count, not only in a row.
    assert guard(SessionAction.LOCKOUT, run(0, refused=2)) == SessionAction.LOCKOUT


def test_challenge_while_pending_is_a_no_op():
    pending = SessionSnapshot(request_count=1, challenge_pending=True)
    assert guard(SessionAction.CHALLENGE, pending) == SessionAction.MAINTAIN
    assert guard(SessionAction.CHALLENGE, run(0)) == SessionAction.CHALLENGE


def test_bias_steps_stay_inside_6a_clamp():
    assert next_bias(0.0, SessionAction.TIGHTEN) == 0.25
    assert next_bias(0.9, SessionAction.TIGHTEN) == 1.0
    assert next_bias(-0.2, SessionAction.RELAX) == -0.3
    assert next_bias(0.5, SessionAction.CHALLENGE) == 0.5

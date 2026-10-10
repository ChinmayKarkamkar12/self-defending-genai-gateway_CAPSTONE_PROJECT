"""Session simulator (the RL training environment). See
project_plan/06b-adaptive-defense-rl-session-agent.md §2, §3, §8.

Scripted with one-prompt pools and fixed lengths, so every episode below
is fully determined."""
import pytest

from app.core.defense.rl.fallback_policy import MaintainPolicy, RuleBasedPolicy
from app.core.defense.rl.reward import (
    REQUEST_REWARD_WEIGHT,
    TERMINAL_REWARD,
    request_reward,
    terminal_reward,
)
from app.core.defense.rl.simulator import (
    ScoredPrompt,
    SessionSimulator,
    SimConfig,
    run_episode,
)
from app.db.models import DefenseAction, SessionAction, ThreatLabel

M, T, R, C, L = (
    SessionAction.MAINTAIN,
    SessionAction.TIGHTEN,
    SessionAction.RELAX,
    SessionAction.CHALLENGE,
    SessionAction.LOCKOUT,
)


def prompt(p: float, is_attack: bool) -> ScoredPrompt:
    return ScoredPrompt(
        threat_score={"benign": 1.0 - p, "prompt_injection": p, "jailbreak": 0.0},
        is_attack=is_attack,
    )


def sim(benign_p=0.0, attack_p=1.0, **config) -> SessionSimulator:
    defaults = dict(
        min_length=4, max_length=4, fp_user_rate=0.0, pii_request_rate=0.0, persistence=1.0
    )
    defaults.update(config)
    return SessionSimulator(
        [prompt(benign_p, False)], [prompt(attack_p, True)], SimConfig(**defaults), seed=0
    )


def play(env: SessionSimulator, actions: list[SessionAction]):
    env.reset(seed=1)
    rewards, done, info = [], False, {}
    for action in actions:
        assert not done, "episode ended earlier than scripted"
        _, reward, done, _, info = env.step(action)
        rewards.append(reward)
    return rewards, done, info


# ------------------------------------------------------------ termination


def test_episode_terminates_correctly():
    benign = sim(attack_session_rate=0.0)
    rewards, done, info = play(benign, [M, M, M])  # 4 requests: 1 at reset + 3 steps
    assert done and info["episode"].requests == 4
    with pytest.raises(RuntimeError):
        benign.step(M)

    # Attacker: 1 probe, then blocked attempts until the session's length.
    attack = sim(attack_session_rate=1.0, min_probes=1, max_probes=1)
    _, done, info = play(attack, [M, M, M])
    stats = info["episode"]
    assert done and stats.attack_requests == 3 and stats.attack_refused == 3
    assert not stats.breached


def test_attacker_who_gives_up_ends_the_session():
    env = sim(attack_session_rate=1.0, min_probes=1, max_probes=1, persistence=0.0)
    _, done, info = play(env, [M])
    assert done and info["episode"].gave_up and info["episode"].requests == 2


def test_breach_ends_the_session():
    # An attack the classifier scores 0 - its blind spot - is allowed.
    env = sim(attack_p=0.0, attack_session_rate=1.0, min_probes=1, max_probes=1)
    _, done, info = play(env, [M])
    assert done and info["episode"].breached


def test_lockout_ends_the_session_and_refuses_the_rest():
    env = sim(attack_session_rate=1.0, min_probes=0, max_probes=0, min_length=6, max_length=6)
    _, done, info = play(env, [L])
    stats = info["episode"]
    assert done and stats.locked_out and stats.locked_out_requests == 5


def test_lockout_without_evidence_is_guarded():
    # Benign session, nothing refused: lockout is carried out as maintain.
    env = sim(attack_session_rate=0.0)
    _, done, info = play(env, [L])
    assert not done and info["taken"] == "maintain"


# ----------------------------------------------------------------- reward


def test_reward_matches_documented_table():
    assert TERMINAL_REWARD == {
        (ThreatLabel.BENIGN, False): 1.0,
        (ThreatLabel.BENIGN, True): -0.5,
        (ThreatLabel.ATTACK, True): 1.5,
        (ThreatLabel.ATTACK, False): -2.0,
    }
    assert terminal_reward(ThreatLabel.ATTACK, intervened=True, breached=True) == -2.0
    assert request_reward(DefenseAction.ALLOW, False) == pytest.approx(0.2)
    assert request_reward(DefenseAction.ALLOW, True) == pytest.approx(-0.2)
    assert request_reward(DefenseAction.BLOCK, False) == pytest.approx(-0.06)

    # Benign, never intervened: 3 allowed requests + terminal +1.0.
    rewards, _, info = play(sim(attack_session_rate=0.0), [M, M, M])
    assert sum(rewards) == pytest.approx(3 * REQUEST_REWARD_WEIGHT * 1.0 + 1.0)
    assert info["episode"].env_return == pytest.approx(sum(rewards))

    # Benign, tightened once (no effect on p=0 requests): terminal -0.5.
    rewards, _, _ = play(sim(attack_session_rate=0.0), [T, M, M])
    assert sum(rewards) == pytest.approx(0.6 - 0.5)

    # Attack locked out after its first (blocked) request: 3 remaining
    # requests counted as blocked attacks, + terminal +1.5.
    env = sim(attack_session_rate=1.0, min_probes=0, max_probes=0)
    rewards, _, _ = play(env, [L])
    assert sum(rewards) == pytest.approx(3 * 0.2 * 0.5 + 1.5)

    # Locking out a benign session costs every remaining request.
    env = sim(benign_p=1.0, attack_session_rate=0.0)  # every benign request blocked
    rewards, _, _ = play(env, [L])
    assert sum(rewards) == pytest.approx(3 * 0.2 * -0.3 - 0.5)

    # Breach: -2.0 even though the agent tightened.
    env = sim(attack_p=0.0, attack_session_rate=1.0, min_probes=1, max_probes=1)
    rewards, _, _ = play(env, [T])
    assert sum(rewards) == pytest.approx(0.2 * -1.0 - 2.0)


def test_shaping_is_potential_based():
    """With gamma = 1 the shaping terms telescope to -coef * phi(s0), so
    they can't change which policy is best (only how fast it is learned)."""
    coef = 0.5
    env = sim(benign_p=0.4, attack_session_rate=0.0, shaping_coef=coef, gamma=1.0)
    rewards, _, info = play(env, [M, T, M])
    phi0 = 0.4  # the first request's score, the only one in the window at reset
    assert sum(rewards) - info["episode"].env_return == pytest.approx(-coef * phi0)


# ------------------------------------------------------ faithful to 6a


def test_bias_changes_6a_decisions_through_the_real_bandit():
    # p = 0.3: allow at bias 0, redact at 0.25-0.5, block from 0.75
    # (measured on the warm-start bandit - see PROGRESS.md).
    env = sim(benign_p=0.3, attack_session_rate=0.0, min_length=5, max_length=5)
    play(env, [T, T, T, M])
    snap = env.snapshot()
    assert snap.escalation_bias == 0.75
    assert snap.count(DefenseAction.ALLOW) == 1  # the request at reset, bias 0
    assert snap.count(DefenseAction.REDACT_AND_ALLOW) == 2  # bias 0.25, 0.5
    assert snap.count(DefenseAction.BLOCK) == 2  # bias 0.75 (twice)


def test_bias_cannot_catch_the_classifier_blind_spot():
    # Max bias still allows a p = 0 attack; only challenge stops it.
    env = sim(attack_p=0.0, attack_session_rate=1.0, min_probes=1, max_probes=1)
    _, done, info = play(env, [T])
    assert done and info["episode"].breached

    env = sim(attack_p=0.0, attack_session_rate=1.0, min_probes=1, max_probes=1)
    _, done, info = play(env, [C])
    assert not done
    assert env.snapshot().count(DefenseAction.ESCALATE_TO_HUMAN) == 1


def test_challenge_affects_exactly_one_request():
    env = sim(attack_session_rate=0.0)
    play(env, [C, M, M])
    snap = env.snapshot()
    assert snap.count(DefenseAction.ESCALATE_TO_HUMAN) == 1
    assert snap.count(DefenseAction.ALLOW) == 3


def test_relax_lowers_the_bias_to_6a_floor():
    env = sim(attack_session_rate=0.0)
    play(env, [R, R])
    assert env.snapshot().escalation_bias == -0.3


def test_episodes_are_reproducible_per_seed():
    pools = (
        [prompt(0.0, False), prompt(0.3, False), prompt(0.97, False)],
        [prompt(1.0, True), prompt(0.0, True), prompt(0.6, True)],
    )
    a = SessionSimulator(*pools, SimConfig(), seed=0)
    b = SessionSimulator(*pools, SimConfig(), seed=99)
    for seed in range(20):
        sa = run_episode(a, RuleBasedPolicy().decide, seed)
        sb = run_episode(b, RuleBasedPolicy().decide, seed)
        assert (sa.label, sa.actions, sa.env_return) == (sb.label, sb.actions, sb.env_return)


def test_rule_policy_locks_out_a_persistent_attacker():
    env = sim(
        attack_session_rate=1.0, min_probes=0, max_probes=0, min_length=10, max_length=10
    )
    stats = run_episode(env, RuleBasedPolicy().decide, seed=3)
    # Refused at reset (1), then 3 more: lockout after the 4th refusal.
    assert stats.actions == ["maintain", "tighten", "tighten", "lockout"]
    assert stats.locked_out and stats.intervened and not stats.breached

    stats = run_episode(env, MaintainPolicy().decide, seed=3)
    assert not stats.intervened and stats.requests == 10

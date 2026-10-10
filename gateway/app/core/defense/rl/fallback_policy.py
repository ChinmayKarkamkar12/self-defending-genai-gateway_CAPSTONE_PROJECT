"""Rule-based session policies. See
project_plan/06b-adaptive-defense-rl-session-agent.md §6.

`RuleBasedPolicy` is the fallback the plan requires before any DQN
training: it ships a working strategic layer whether or not the DQN
converges, behind the same interface (`decide(snapshot) -> SessionAction`),
so switching is the SESSION_POLICY setting, not a code change.

The rule is the plan's, exactly: tighten after 2 consecutive non-allow
outcomes from module 6a, lock out after 4. "Non-allow" = redact, block or
escalate - whatever didn't reach the provider untouched. It keeps
tightening while the run continues (one TIGHTEN_STEP per refused request,
up to 6a's maximum bias) and never relaxes or challenges.

`MaintainPolicy` is the do-nothing baseline of the evaluation.
"""
from app.core.defense.rl.features import SessionSnapshot
from app.db.models import SessionAction

TIGHTEN_AFTER = 2
LOCKOUT_AFTER = 4


class RuleBasedPolicy:
    name = "rule"

    def __init__(self, tighten_after: int = TIGHTEN_AFTER, lockout_after: int = LOCKOUT_AFTER):
        if not 1 <= tighten_after <= lockout_after:
            raise ValueError("need 1 <= tighten_after <= lockout_after")
        self.tighten_after = tighten_after
        self.lockout_after = lockout_after

    def decide(self, snapshot: SessionSnapshot) -> SessionAction:
        if snapshot.consecutive_refused >= self.lockout_after:
            return SessionAction.LOCKOUT
        if snapshot.consecutive_refused >= self.tighten_after:
            return SessionAction.TIGHTEN
        return SessionAction.MAINTAIN


class MaintainPolicy:
    name = "maintain"

    def decide(self, snapshot: SessionSnapshot) -> SessionAction:  # noqa: ARG002
        return SessionAction.MAINTAIN

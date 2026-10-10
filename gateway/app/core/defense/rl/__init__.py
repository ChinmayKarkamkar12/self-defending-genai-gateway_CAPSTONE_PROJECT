"""Module 6b: the strategic, per-session defense layer. See
project_plan/06b-adaptive-defense-rl-session-agent.md.

Everything here is plain numpy so the gateway, the simulator and the CI
test suite share one implementation. stable-baselines3 is only used
offline, in training/train_rl_agent.py; the gateway runs the exported
weights (dqn.py).
"""

# Demo script

The live demo for faculty, step by step: what to type, what to show, what to
say. About 10 minutes. Rehearse it at least twice on the machine you'll
present from (module 10's definition of done).

Commands are for Windows PowerShell, run from the repository folder. On
macOS/Linux use `./scripts/reset_demo.sh` instead of the `.ps1`; the
`docker compose` lines are the same.

## Before the presentation

**The day before**, on the presenting laptop:

1. Docker Desktop is running.
2. The trained classifier is at `training/checkpoints/final/` (config.json,
   model.safetensors, ...). On another laptop: copy that folder over, or put
   a Hugging Face read token in `.env` as `HF_TOKEN` (it downloads once).
3. Ollama is running with the model the demo asks: `ollama list` shows
   `llama3:latest` (else `ollama pull llama3`). Without Ollama the gateway
   still blocks, redacts and audits, but nothing gets answered.
4. Rehearse: run everything below once, start to finish.

**Ten minutes before**, reset to a clean, seeded state:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\reset_demo.ps1
```

It asks before deleting anything (type `yes`), creates `.env` with fresh
secrets if there isn't one, rebuilds, and seeds the demo (~1.5 minutes).
It prints the dashboard login; the password is also in `.env` as
`DEMO_ADMIN_PASSWORD`. When it says **Ready**:

- open http://localhost:3000 and sign in;
- keep a PowerShell window open in the repository folder;
- the dashboard already shows ~10 requests, 2 items waiting for review.

**What the seed created** (`gateway/scripts/seed_demo.py`): four teams, each
with its own API key and daily budget - Acme Support ($5), Research Lab
($0.03, the one the budget step runs out), Legal Ops ($2, PII *tokenized*
instead of masked) and Red Team Sandbox ($1, where attacks come from). Then
real requests through the gateway: questions answered by Llama 3, prompts
with personal data, an unknown model, two borderline prompts held for
review, one harmless prompt the classifier wrongly blocks (a real false
positive, worth admitting if asked), and two attacks. Nothing was written
into the audit log directly.

## The demo

### 0. The picture (1 min)

Overview screen. *"Every request an application sends passes these checks
before it reaches a model. The band is the traffic; where it narrows, a
check stopped something. Red is refused, purple is held for a person, ochre
was answered after cleaning."*

### 1. A normal request (1 min)

```powershell
docker compose exec gateway python -m scripts.demo benign
```

Shows the model's answer and the request's audit entry: attack probability
~0.03, the bandit's decision `allow`, cost. Then **Audit log** in the
dashboard: the newest row is that request.

*"The application didn't change anything except the URL it sends to. The
gateway scored it, found nothing to remove, let it through, and recorded
every decision."*

### 2. Personal data (1.5 min)

```powershell
docker compose exec gateway python -m scripts.demo pii
```

The prompt carries an email address and a phone number. Point out:

- the answer contains `[REDACTED_EMAIL_ADDRESS]` and `[REDACTED_PHONE_NUMBER]` -
  that's all the model ever received;
- the audit entry keeps only counts: `{'EMAIL_ADDRESS': 1, 'PHONE_NUMBER': 1}`;
- the last two lines: every table in the database was searched for the raw
  email and phone number - *not found in any table*.

Dashboard: **Personal data** shows each team's policy. Legal Ops *tokenizes*
instead of masking: each value becomes a unique token, and the original is
kept encrypted in the gateway's vault - never sent out, never in the logs.

### 3. An attack (2 min)

```powershell
docker compose exec gateway python -m scripts.demo attack
```

A prompt-injection attempt from the Red Team Sandbox: **422**, refused. The
entry shows the classifier's attack probability (~0.97) and the bandit's
decision (`block`), and the session agent's reaction (`tighten`).

*"Module 5 only scores. Module 6a, a contextual bandit, decides what to do
with the score - and learns from feedback. Module 6b watches the whole
session: this key has now been refused several times in a row."*

Run it **again** (twice if needed): after four refusals in a row the session
agent **locks the key** - the output says so, and the next request is refused
as `session locked`. Dashboard: **Threats → Sessions →** the newest Red Team
Sandbox session shows *Key locked out*; **Unlock key** releases it.

Then the **Review queue**: two borderline requests (scored 0.62 and 0.64)
the bandit held for a person. Decide one (*It's an attack*, or key **A**).
*"The verdict doesn't change what already happened - it's a label the
bandit learns from, so the next similar request is handled better."*

### 4. A budget running out (1.5 min)

```powershell
docker compose exec gateway python -m scripts.demo budget
```

Research Lab asks the same short question over and over; each answer is
charged and the remaining budget printed. After about four requests:
**402 budget_exceeded** - refused *before* the model is called.

Two honest notes, if asked:

- Local models are free, so the demo gives them a **pretend price**
  (`LOCAL_MODEL_DEMO_PRICE_PER_MILLION` in `.env`, set by the reset script).
  With OpenAI or Anthropic the real per-token prices apply.
- It refuses with a few tenths of a cent left: before calling the model the
  gateway reserves what the answer *could* cost (here up to 80 tokens), and
  that no longer fits.

Dashboard: **Cost & usage**, team **Research Lab**: the budget bar is full.

### 5. Tampering with the audit log (2 min)

In the PowerShell window:

```powershell
docker compose run --rm migrate python -m scripts.tamper_demo --postgres --hold
```

It verifies the chain, then **edits one entry directly in the database** - a
held or blocked request rewritten to `allow`, the way an insider would hide
an attack - and waits. In the dashboard: **Audit log → Check integrity**:
*Tampered: entry #N no longer matches - its contents were changed after it
was written*. Press **Enter** in PowerShell to put it back; **Check
integrity** again: *Intact*.

*"Each entry's hash covers its contents and the previous entry's hash, so
an edit anywhere breaks the chain from that point on, and verification
names the exact entry."*

Why `migrate`: that job has the database **owner's** login, which is what
it takes to get past the append-only trigger - the attacker this protects
against. The running gateway connects as `gateway_app`, which can't do it.
If asked, show it (it fails with *permission denied*):

```powershell
docker compose exec gateway python -m scripts.tamper_demo --postgres
```

## If something goes wrong

| Symptom | Fix |
|---|---|
| `reset_demo` stops with *the trained classifier is missing* | Copy `training/checkpoints/final/` onto this machine, or set `HF_TOKEN` in `.env`, and run it again |
| Steps answer *refused: no provider registered for model 'local-llama3:latest'* | `OLLAMA_BASE_URL` is missing from `.env` - the reset script adds it; or set `DEMO_MODEL` to a model you have a key for |
| Steps answer **502** | Ollama isn't running, or the model isn't pulled: start Ollama, `ollama pull llama3` |
| The attack step says *session locked* straight away | Expected after earlier rehearsals: unlock it in **Threats** (or reset) |
| The budget step says *refused* at once | The budget was spent in a rehearsal today: reset, or pick another team's budget in **Cost & usage** |
| Dashboard login fails | Username is `DEMO_ADMIN_USERNAME` in `.env` (default `admin`), password `DEMO_ADMIN_PASSWORD` |
| Anything else | `docker compose logs gateway --tail 50`; then reset |

## What's real and what's staged

Say this plainly if faculty ask - it's a strength, not a weakness:

- **Real:** every request goes through the full pipeline; the classifier is
  the trained model; the audit entries, review items, session lock and
  budget refusal are what the gateway actually decided.
- **Staged:** the teams and their budgets are demo settings; the price of the
  local model is pretend; the borderline prompts were chosen because the
  classifier scores them in the "unsure" band (0.62, 0.64).

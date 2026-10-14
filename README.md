<p align="center">
  <img src="docs/readme/hero.svg" width="100%" alt="Self-Defending GenAI Gateway: a security checkpoint between applications and the language models they call. Requests flow through a checkpoint; most are answered, some are cleaned, refused or held for review.">
</p>

<p align="center">
  <a href="https://github.com/ChinmayKarkamkar12/self-defending-genai-gateway_CAPSTONE_PROJECT/actions/workflows/ci.yml"><img src="https://github.com/ChinmayKarkamkar12/self-defending-genai-gateway_CAPSTONE_PROJECT/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
</p>

<p align="center">
  <a href="#the-problem">The problem</a> &nbsp;|&nbsp;
  <a href="#the-solution">The solution</a> &nbsp;|&nbsp;
  <a href="#how-a-request-flows">Workflow</a> &nbsp;|&nbsp;
  <a href="#architecture">Architecture</a> &nbsp;|&nbsp;
  <a href="#the-data">Data</a> &nbsp;|&nbsp;
  <a href="#results">Results</a> &nbsp;|&nbsp;
  <a href="#run-it">Run it</a>
</p>

---

## The problem

Companies are wiring large language models into their products (support
bots, internal assistants, document tools), usually by calling OpenAI or
Anthropic directly from each application. Every one of those calls carries
risks that nobody is watching:

- **Personal data leaks out.** Users paste emails, phone numbers, ID numbers
  and card numbers into prompts, and they go straight to a third-party
  provider.
- **Prompts can be hijacked.** *Prompt injection* ("ignore all previous
  instructions and…") and *jailbreaks* turn the model against the
  application that called it: it leaks its instructions, or does what the
  attacker wants instead of what the user asked.
- **Costs run away.** One buggy loop or abused key can spend a month's budget
  in an afternoon, and nobody knows which team did it.
- **There's no trustworthy record.** When something goes wrong, there's no
  log of what was sent, what was decided and why, and nothing to prove the
  log wasn't edited afterwards.
- **Fixed rules go stale.** A "block above score X" threshold can't adapt
  when attacks change, or when it starts blocking one team's normal traffic.

Each application team would have to solve all of this on its own, and most
won't.

## The solution

A **gateway**: one checkpoint that every application's model traffic passes
through. An application changes two settings in its OpenAI-style client, the
URL it sends to and the API key (now a gateway key), and from then on every
request is checked, cleaned, decided on, paid for and recorded before it
reaches a model, and every reply is checked before it reaches the user.

| | What it does | How |
|---|---|---|
| **Cost and usage governance** | Per-team daily or monthly budgets and per-key rate limits; refuses a request *before* the model is called if it could overspend | Redis counters updated atomically (Lua scripts); reserve the worst case, then settle against the real token count |
| **PII redaction** | Finds personal data in prompts and replaces it before anything leaves: emails, phone numbers, names, ID and card numbers, IP addresses, API keys | Microsoft Presidio + regex; masked (`[REDACTED_EMAIL_ADDRESS]`) or tokenized (original kept encrypted) per team |
| **Threat detection** | Scores every prompt for prompt injection and jailbreaks, and every reply for leaked instructions | A fine-tuned DeBERTa-v3 classifier (3 classes); long prompts scanned window by window |
| **Adaptive defense, per request** | Decides what to do with each score (allow, cut the risky part, send to a person, or block) and learns from reviewers' verdicts | A contextual bandit (LinUCB) with a calibrated warm start |
| **Adaptive defense, per session** | Watches a key's requests over time, and tightens, challenges or locks a key that looks like an attack in progress | Reinforcement learning (DQN) with a rule-based fallback, which is the default |
| **Tamper-evident audit log** | Records every request and every decision (never the raw prompt or PII); any later edit is detectable | A hash chain (each entry hashes the one before it), an append-only database trigger, and a restricted database role |
| **Admin dashboard** | Shows what the gateway is doing and lets admins act: review queue, budgets, PII policies, unlocking keys, verifying the log | Next.js, behind a username and password login |

Two rules hold everywhere. **Fail closed:** if any check breaks, the request
is refused, not waved through. **No raw PII or keys are ever logged or
stored:** tests plant them and then search every table, log line and
response.

<p align="center">
  <img src="docs/readme/dashboard-overview.png" width="100%" alt="The dashboard's overview: a band of requests narrowing at each check (session, budget, screening, provider), with totals: 18 requests, 8 answered, 10 stopped, 2 waiting for review, spend, and personal data removed.">
</p>

## How a request flows

<p align="center">
  <img src="docs/readme/workflow.svg" width="100%" alt="Animated: five requests pass through the checks in turn. An ordinary question is answered; a prompt with an email and SSN is cleaned and answered; an injection is blocked at the decision; a borderline request is held for review; an over-budget request is refused at the budget check. Each adds a linked entry to the audit log.">
</p>

1. **Sign-in.** The application's gateway API key is checked (only its
   SHA-256 is stored). A revoked key is refused on its very next request.
2. **Session.** If the session agent has locked this key, the request stops
   here.
3. **Budget.** The answer's worst-case cost is reserved against the team's
   budget, and the key's rate limit is checked. If either fails, the reply is
   **402** or **429** and the model is never called.
4. **Threat score.** The classifier scores the conversation, including text
   inside tool-call arguments.
5. **Personal data.** Detected PII is masked or tokenized.
6. **Decision.** The bandit chooses: allow, cut the suspicious part, hold for
   a person, or block.
7. **Model.** Only now does the cleaned prompt go to OpenAI, Anthropic or a
   local Ollama model.
8. **Reply check.** Before the user sees it, the reply is scanned for leaked
   system instructions and echoed redaction tokens, and its real cost is
   recorded.
9. **Audit.** Whatever happened (answered, refused, held or failed), the
   request's decisions are added to the hash-chained audit log.

## Architecture

<p align="center">
  <img src="docs/readme/architecture.svg" width="100%" alt="Applications send requests to the gateway (FastAPI), which runs the checks and calls OpenAI, Anthropic or Ollama. It stores data in PostgreSQL and Redis. The admin dashboard (Next.js) reaches the gateway's admin API through its own server. One-off jobs fetch the classifier, set up the database and seed demo data.">
</p>

| Part | Technology | Role |
|---|---|---|
| Gateway | Python 3.11, FastAPI, Pydantic v2 | The OpenAI-compatible endpoint (`/v1/chat/completions`), the pipeline of checks, and the admin API |
| Threat classifier | Hugging Face Transformers, DeBERTa-v3-base, fine-tuned | Attack probabilities per request, calibrated with temperature scaling |
| PII detection | Microsoft Presidio, spaCy, regex | Finds personal data in prompts and tool-call arguments |
| Adaptive defense | NumPy (LinUCB); stable-baselines3 (DQN, training only) | Per-request and per-session decisions |
| PostgreSQL 16 | SQLAlchemy 2, Alembic | Teams, hashed keys, budgets, policies, threat events, review queue, the audit chain |
| Redis 7 | Lua scripts | Spend counters, rate-limit buckets, session state, locks |
| Dashboard | Next.js 16, React 19, Tailwind 4, Recharts | The admin console; its server keeps the session in an httpOnly cookie |
| Deployment | Docker Compose | Four services and three one-off jobs, one command to start |

### Two layers of adaptive defense

<p align="center">
  <img src="docs/readme/defense.svg" width="100%" alt="Left: a contextual bandit chooses allow, cut, review or block for each request and learns from reviewers' verdicts. Right: a session agent watches a key's requests over time and can maintain, tighten, challenge or lock out; it nudges the bandit through an escalation bias.">
</p>

These are deliberately different techniques. A **contextual bandit** fits a
single request: its choice doesn't change what the next request looks like.
A **session agent** fits a sequence: locking a key changes the rest of the
session, so it needs states and delayed reward, which is **reinforcement
learning**. The DQN agent was trained and evaluated against criteria set
before training. It didn't meet them, so the rule-based policy stays the
default and the DQN is opt-in (`SESSION_POLICY=dqn`). That result is
reported as it is.

## The data

The threat classifier is trained on public datasets, each with its licence
checked. Version 2, the one that ships, uses:

| Source | Licence | Used as |
|---|---|---|
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | prompt injection, benign |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | jailbreak, benign |
| [tatsu-lab/alpaca](https://huggingface.co/datasets/tatsu-lab/alpaca) (sample) | CC-BY-NC-4.0 | ordinary instructions (benign) |
| [neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) | Apache-2.0 | injection, jailbreak, benign (including HackAPrompt submissions) |
| [TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) | MIT | jailbreak; its regular prompts as hard benign |
| [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) | MIT | hard benign: harmless prompts full of trigger words |
| [databricks/databricks-dolly-15k](https://huggingface.co/datasets/databricks/databricks-dolly-15k) | CC-BY-SA-3.0 | benign instructions |

<p align="center">
  <img src="docs/readme/data.svg" width="100%" alt="Rows per split by class: training 6,307 (3,521 benign, 1,661 prompt injection, 1,125 jailbreak); validation 830; locked test 950; old test 194.">
</p>

How the data was kept honest:

- **No leakage between splits.** Jailbreak datasets reuse templates with
  small edits, so exact de-duplication isn't enough: a first random split
  left 33 of 91 test attacks as near-copies of training rows.
  Near-duplicates are now clustered (shared word 8-grams, union-find) and
  each cluster goes to one split only. An independent re-check finds no
  cluster spanning two splits.
- **A locked test set.** The 950-row test file's SHA-256 was recorded when
  it was built, and each model is scored on it once.
- **Pass/fail decided in advance.** The criteria were written before
  training. v2 failed one of them (on the small old benchmark) and ships
  anyway; the reasons are recorded as an override, rather than the rule
  being quietly changed.

Datasets left out: those with no licence, and one whose "injection" label
means "off-topic" (it would teach the model to flag ordinary questions). The
session agent is trained on simulated sessions built from these scored
prompts, and the bandit is evaluated offline on the held-out splits. Details
are in [training/README.md](training/README.md).

## Results

<p align="center">
  <img src="docs/readme/results.svg" width="100%" alt="Classifier v2 on the 950-prompt locked test: macro-F1 0.908 (v1: 0.490), prompt-injection F1 0.949 (v1: 0.341), 3.1% of harmless prompts flagged (v1: 27.5%). 455 automated gateway tests, 97% line and branch coverage.">
</p>

- **Classifier:** macro-F1 **0.908** on the locked test set. It flags 3.1% of
  harmless prompts, down from 27.5%. Its weak spot is very short text
  ("hello" can score as an attack), which is documented, not hidden.
- **Per-request defense:** where the classifier is right, the bandit matches
  a tuned threshold without needing labelled tuning data. Where the
  classifier is consistently wrong in one score range, the bandit recovers
  from feedback and a fixed threshold can't: +0.141 reward per request
  with full feedback, in the drift experiment.
- **Per-session defense:** the DQN agents beat the rule on three of four
  simulated traffic patterns, but locked out more harmless sessions than the
  pre-set limit allowed and lost on the fourth, so they don't ship as the
  default.
- **Engineering:** 455 gateway tests (97% line + branch coverage) on real
  Postgres and Redis, 45 dashboard component tests, and 16 browser tests
  against the Docker stack. Cross-module tests plant PII and keys, then
  search every table, Redis key, log line and response for them.

Known limitations are tracked, never deleted, in
[LIMITATIONS.md](LIMITATIONS.md).

## Run it

You need Docker Desktop and the trained classifier at
`training/checkpoints/final/`. It isn't in git: copy the folder over, or put
a Hugging Face read token in `.env` as `HF_TOKEN` and it downloads on the
first start. For answers without a paid API key, run
[Ollama](https://ollama.com) with `ollama pull llama3`.

```powershell
git clone https://github.com/ChinmayKarkamkar12/self-defending-genai-gateway_CAPSTONE_PROJECT.git
cd self-defending-genai-gateway_CAPSTONE_PROJECT
powershell -ExecutionPolicy Bypass -File scripts\reset_demo.ps1   # Windows
./scripts/reset_demo.sh                                           # macOS / Linux
```

The script creates `.env` with every secret generated, builds and starts the
stack, sets up the database, and seeds demo teams, keys, an admin and real
traffic (about 1.5 minutes). It prints the dashboard login when it's ready.
If you run it again, it asks before deleting anything.

- Dashboard: <http://localhost:3000>
- Gateway: <http://localhost:8000> (any OpenAI-style client, `base_url=http://localhost:8000/v1`)
- Demo API keys: `docker compose exec gateway python -m scripts.demo keys`
- The live demo, step by step: [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)

<p align="center">
  <img src="docs/readme/dashboard-review.png" width="100%" alt="The dashboard's review queue: a request the defense held, with the text that was sent (personal data already removed), the classifier's scores, and buttons to mark it an attack or safe.">
</p>

<details>
<summary><b>How the stack starts</b></summary>

`docker-compose.yml` runs these in order:

1. `model` makes sure the classifier is in place, downloading it with
   `HF_TOKEN` if needed.
2. `migrate` applies the migrations and creates the `gateway_app` database
   role, logged in as the database owner.
3. The `gateway` starts and logs in only as `gateway_app`, so it can add
   audit entries but never change, delete or unprotect them.
4. The `dashboard` and the one-off `seed-traffic` job start last.

Postgres and Redis listen on 127.0.0.1 only.
</details>

<details>
<summary><b>Calling the gateway from code</b></summary>

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="<a gateway API key>")
reply = client.chat.completions.create(
    model="local-llama3:latest",  # or gpt-4o / claude-3-5-sonnet-20241022, with provider keys in .env
    messages=[{"role": "user", "content": "Summarise our refund policy in two lines."}],
)
```

Refusals come back as HTTP errors:

| Status | Meaning |
|---|---|
| **422** | Judged unsafe, or held for review |
| **402** | Budget spent |
| **429** | Rate limit |
| **503** | A check failed (fail-closed) |

Streaming (`"stream": true`) is refused, because the reply is checked as a
whole before it's returned. Every response carries an
`x-gateway-request-id` header that matches its audit entry.
</details>

<details>
<summary><b>Development and tests</b></summary>

```bash
# Gateway (Python 3.11): unit and integration tests, both backends
cd gateway
python -m venv .venv && .venv/Scripts/activate      # source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt
TEST_POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/postgres \
TEST_REDIS_URL=redis://localhost:6379/15 pytest -rs --cov
ruff check .

# Dashboard (Node 24)
cd dashboard
npm install
GATEWAY_URL=http://localhost:8000 npm run dev
npm run lint && npm run typecheck && npm test
E2E_ADMIN_USER=... E2E_ADMIN_PASSWORD=... npm run test:e2e
```

The Postgres + Redis test variants need `docker compose up -d postgres redis`;
the real-model tests need the trained classifier. What each test layer
proves, the coverage review, and what is deliberately not tested are in
[docs/TESTING.md](docs/TESTING.md). The README's illustrations are built by
[docs/readme/build_svgs.py](docs/readme/build_svgs.py).
</details>

## Repository layout

```
gateway/          FastAPI gateway: app/ (pipeline, modules), tests/, scripts/, alembic/
dashboard/        Next.js admin dashboard
training/         classifier, bandit and RL training and evaluation scripts
scripts/          reset_demo.ps1 / reset_demo.sh
docs/             testing strategy, demo script, project journey, ADRs
project_plan/     the module-by-module build plan
docker-compose.yml, .env.example
```

## Documentation

| Document | What's in it |
|---|---|
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | The live demo, step by step |
| [docs/TESTING.md](docs/TESTING.md) | Testing strategy, cross-cutting tests, coverage |
| [docs/PROJECT_JOURNEY.md](docs/PROJECT_JOURNEY.md) | What was built, why and how, module by module |
| [training/README.md](training/README.md) | Data, training, evaluations and their results |
| [LIMITATIONS.md](LIMITATIONS.md) | Every known limitation, and how the resolved ones were fixed |
| [docs/adr/](docs/adr/) | Architecture decisions (fail-closed, audit immutability) |
| [project_plan/](project_plan/00-INDEX.md) | The original plan |

## Team

A final-year capstone project by:

- **Chinmay Karkamkar** (ENG23DS0007)
- **Aditya S** (ENG23DS0001)
- **Priyanka M** (ENG23DS0026)

Guided by **Mr. Monish L**.

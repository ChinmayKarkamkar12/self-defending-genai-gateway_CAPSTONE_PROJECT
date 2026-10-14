"""Builds the README's illustrations (docs/readme/*.svg).

GitHub doesn't apply a README's own CSS, fonts or scripts, but it does show
SVG images, animations included. So the README is Markdown, and everything
visual is an SVG made here, in the dashboard's "checkpoint" identity
(dashboard/src/app/globals.css): Barlow Semi Condensed for headings,
Atkinson Hyperlegible Next for text, and the four decision colours, each
meaning the same thing everywhere.

The fonts are embedded (subsets in docs/readme/fonts/, SIL Open Font
License), because an SVG shown as an image can't load anything external.
Motion is SMIL (<animate>, <animateMotion>), which every major browser
plays inside an <img>. Every number drawn here comes from the project's own
records (training/README.md, PROGRESS.md, docs/TESTING.md).

    python docs/readme/build_svgs.py
"""
import base64
import math
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
FONTS = HERE / "fonts"

GROUND = "#e6eaee"
SURFACE = "#f5f7f9"
SHEET = "#ffffff"
INK = "#14243a"
INK2 = "#45566c"
INK3 = "#5a697c"
RULE = "#c6ced8"
RULE_SOFT = "#d9dfe6"
BAND = "#c3cedb"
ALLOWED = "#2f7d6b"
CLEANED = "#b7862b"
HELD = "#5b4bb7"
REFUSED = "#a6243a"
FAILED = "#5d6878"


def _font(name: str) -> str:
    return base64.b64encode((FONTS / name).read_bytes()).decode()


STYLE = f"""<style>
@font-face {{ font-family: Sign; font-weight: 600;
  src: url(data:font/woff2;base64,{_font("barlow-semicondensed-600.woff2")}) format("woff2"); }}
@font-face {{ font-family: Sign; font-weight: 700;
  src: url(data:font/woff2;base64,{_font("barlow-semicondensed-700.woff2")}) format("woff2"); }}
@font-face {{ font-family: Read; font-weight: 200 800;
  src: url(data:font/woff2;base64,{_font("atkinson-hyperlegible-next-var.woff2")}) format("woff2"); }}
.sign {{ font-family: Sign, "Barlow Semi Condensed", "Arial Narrow", sans-serif; }}
.read {{ font-family: Read, "Atkinson Hyperlegible Next", Verdana, sans-serif; }}
.flow {{ stroke-dasharray: 6 8; animation: flow 1.6s linear infinite; }}
@keyframes flow {{ to {{ stroke-dashoffset: -28; }} }}
@media (prefers-reduced-motion: reduce) {{ .flow {{ animation: none; }} }}
</style>"""


def svg(name: str, width: int, height: int, title: str, desc: str, body: str) -> None:
    doc = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" aria-labelledby="t d">
<title id="t">{escape(title)}</title>
<desc id="d">{escape(desc)}</desc>
{STYLE}
<rect width="{width}" height="{height}" rx="18" fill="{GROUND}"/>
{body}
</svg>
"""
    (HERE / name).write_text(doc, encoding="utf-8")
    print(f"{name}: {len(doc) // 1024} KB")


def text(x, y, s, size=16, cls="read", fill=INK, weight=400, anchor="start", extra=""):
    return (
        f'<text x="{x}" y="{y}" class="{cls}" font-size="{size}" font-weight="{weight}" '
        f'fill="{fill}" text-anchor="{anchor}" {extra}>{escape(s)}</text>'
    )


def lines(x, y, rows, size=16, gap=None, **kw):
    gap = gap or size * 1.45
    return "\n".join(text(x, y + i * gap, row, size, **kw) for i, row in enumerate(rows))


# ---------------------------------------------------------------- paths


def quad_len(p0, p1, p2, steps=200):
    total, prev = 0.0, p0
    for i in range(1, steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]
        total += math.dist(prev, (x, y))
        prev = (x, y)
    return total


def keytimes(*values):
    return ";".join(f"{v:.4f}" for v in values)


def packet(path, length, decide_at, colour, window, loop, end_hold=0.35, r=9):
    """A dot that waits, travels `path` during `window` (start, end seconds
    within a `loop`-second cycle), turns `colour` once it has gone
    `decide_at` px, rests, and fades. Invisible outside its window."""
    start, end = window
    s, e = start / loop, end / loop
    hold = min(1.0, (end + end_hold) / loop)
    fade = min(1.0, hold + 0.25 / loop)
    turn = s + (e - s) * (decide_at / length)
    eps = 0.002
    return f"""<circle r="{r}" fill="{INK}" opacity="0">
  <animateMotion dur="{loop}s" repeatCount="indefinite" path="{path}" calcMode="linear"
    keyPoints="0;0;1;1" keyTimes="{keytimes(0, s, e, 1)}"/>
  <animate attributeName="opacity" dur="{loop}s" repeatCount="indefinite"
    values="0;0;1;1;0;0" keyTimes="{keytimes(0, s, s + eps, hold, fade, 1)}"/>
  <animate attributeName="fill" dur="{loop}s" repeatCount="indefinite"
    values="{INK};{INK};{colour};{colour}" keyTimes="{keytimes(0, turn, turn + eps, 1)}"/>
</circle>"""


def appear(content, show, hide, loop):
    """Show `content` from `show` to `hide` seconds in each loop."""
    a, b = show / loop, hide / loop
    if b >= 0.99:  # visible until the loop restarts
        values, times = "0;0;1;1", keytimes(0, a, a + 0.004, 1)
    else:
        values, times = "0;0;1;1;0;0", keytimes(0, a, a + 0.004, b, b + 0.004, 1)
    return f"""<g opacity="0">{content}
  <animate attributeName="opacity" dur="{loop}s" repeatCount="indefinite"
    values="{values}" keyTimes="{times}"/>
</g>"""


def gate_icon(x, y, scale=1.0):
    """The dashboard's mark: a post with a striped barrier arm."""
    s = scale
    stripes = "".join(
        f'<rect x="{x + 8 * s + i * 14 * s}" y="{y - 3 * s}" width="{7 * s}" height="{9 * s}" fill="{REFUSED}"/>'
        for i in range(4)
    )
    return (
        f'<rect x="{x}" y="{y - 6 * s}" width="{7 * s}" height="{34 * s}" rx="{2 * s}" fill="{INK}"/>'
        f'<rect x="{x + 6 * s}" y="{y - 3 * s}" width="{58 * s}" height="{9 * s}" rx="{2 * s}" fill="{SHEET}" stroke="{INK}" stroke-width="{2 * s}"/>'
        + stripes
    )


# ----------------------------------------------------------------- hero


def hero():
    w, h, loop = 1280, 420, 9.0
    band_y, band_h = 330, 30
    mid = band_y + band_h / 2
    gate_x = 905
    through = f"M 40 {mid} H 1205"
    through_len = 1165

    def drop(depth):
        p0, p1, p2 = (gate_x - 46, mid), (gate_x, mid), (gate_x, mid + 46)
        length = (p0[0] - 40) + quad_len(p0, p1, p2) + depth
        return f"M 40 {mid} H {p0[0]} Q {p1[0]} {p1[1]} {p2[0]} {p2[1]} V {mid + 46 + depth}", length, p0[0] - 40

    dots = []
    plan = [  # (start s, outcome)
        (0.0, ALLOWED), (0.9, ALLOWED), (1.8, REFUSED), (2.7, CLEANED), (3.6, ALLOWED),
        (4.5, HELD), (5.4, ALLOWED), (6.3, REFUSED), (7.2, CLEANED),
    ]
    for start, colour in plan:
        if colour in (REFUSED, HELD):
            path, length, at = drop(0)
            travel = length / 330
        else:
            path, length, at = through, through_len, gate_x - 40
            travel = length / 330
        end = start + travel
        # wrap windows that run past the loop by shifting the whole plan
        if end + 0.6 > loop:
            start, end = start - (end + 0.6 - loop), loop - 0.6
        dots.append(packet(path, length, at, colour, (start, end), loop, end_hold=0.1, r=7))

    body = f"""
{gate_icon(80, 86, 1.1)}
{text(80, 168, "Self-Defending GenAI Gateway", 58, "sign", INK, 700)}
{lines(82, 208, [
    "A security checkpoint between applications and the language models they call.",
    "It removes personal data, stops prompt injection, caps spending, and keeps a",
    "tamper-evident record of every decision.",
], 19, fill=INK2)}
<rect x="40" y="{band_y}" width="1165" height="{band_h}" rx="4" fill="{BAND}"/>
<path d="M 1205 {band_y - 8} L 1236 {mid} L 1205 {band_y + band_h + 8} Z" fill="{ALLOWED}"/>
<rect x="{gate_x - 5}" y="{band_y - 64}" width="10" height="{band_h + 64}" rx="3" fill="{INK}"/>
<g transform="rotate(-32 {gate_x} {band_y - 58})">
  <rect x="{gate_x}" y="{band_y - 64}" width="150" height="12" rx="3" fill="{SHEET}" stroke="{INK}" stroke-width="2.5"/>
  {"".join(f'<rect x="{gate_x + 14 + i * 34}" y="{band_y - 62}" width="17" height="8" fill="{REFUSED}"/>' for i in range(4))}
</g>
{text(gate_x - 16, band_y - 70, "checkpoint", 15, "sign", INK, 600, "end")}
{text(1236, band_y - 18, "answered", 15, "sign", ALLOWED, 600, "end")}
{text(gate_x + 16, h - 14, "refused or held", 14, "read", INK3)}
{"".join(dots)}
"""
    svg("hero.svg", w, h, "Self-Defending GenAI Gateway",
        "Requests flow along a band through a checkpoint; most pass and turn green, "
        "some are cleaned (ochre), some are refused (red) or held for review (purple) "
        "and drop out at the checkpoint.", body)


# ------------------------------------------------------------- workflow


STAGES = [
    ("Sign-in", "gateway API key"),
    ("Session", "locked key? (6b)"),
    ("Budget", "spend, rate (3)"),
    ("Threat score", "DeBERTa (5)"),
    ("Personal data", "Presidio (4)"),
    ("Decision", "bandit (6a)"),
    ("Model", "provider call"),
    ("Reply check", "leaks (5)"),
    ("Answered", ""),
]


def workflow():
    w, h = 1280, 520
    band_y, band_h = 250, 34
    mid = band_y + band_h / 2
    x0, x1 = 60, 1215
    xs = [118 + i * 133 for i in range(len(STAGES))]
    ledger_y = 430

    scenarios = [
        # caption, outcome colour, stage index where it's decided, exits?, popup text
        ("An ordinary question", ALLOWED, 8, False, "answered, cost recorded"),
        ("A prompt with an email address and an SSN", CLEANED, 4, False,
         "email, SSN replaced by [REDACTED_…]"),
        ("“Ignore all previous instructions…”", REFUSED, 5, True, "attack 0.97: blocked"),
        ("A borderline request the defense isn't sure about", HELD, 5, True,
         "held for a person to review"),
        ("A team that has spent its daily budget", REFUSED, 2, True,
         "402: refused before the model"),
    ]
    window, gap = 4.2, 0.5
    loop = len(scenarios) * (window + gap)
    speed = 330.0

    parts = []
    # band, stages
    parts.append(f'<rect x="{x0}" y="{band_y}" width="{x1 - x0}" height="{band_h}" rx="4" fill="{BAND}"/>')
    parts.append(f'<path d="M {x1} {band_y - 8} L {x1 + 30} {mid} L {x1} {band_y + band_h + 8} Z" fill="{ALLOWED}"/>')
    for i, ((name, sub), x) in enumerate(zip(STAGES, xs, strict=True)):
        if i < len(STAGES) - 1:
            parts.append(f'<rect x="{x - 2}" y="{band_y - 26}" width="4" height="{band_h + 26}" rx="2" fill="{INK}" opacity="0.85"/>')
        parts.append(text(x, band_y - 62, name, 18, "sign", INK, 600, "middle"))
        if sub:
            parts.append(text(x, band_y - 40, sub, 13, "read", INK3, 400, "middle"))
    # pre/post call brackets
    parts.append(f'<path d="M {xs[0] - 40} 136 H {xs[5] + 40}" stroke="{RULE}" stroke-width="2"/>')
    parts.append(text((xs[0] + xs[5]) / 2, 126, "before the model is called", 14, "read", INK3, 400, "middle"))
    parts.append(f'<path d="M {xs[7] - 40} 136 H {xs[7] + 40}" stroke="{RULE}" stroke-width="2"/>')
    parts.append(text(xs[7], 126, "after", 14, "read", INK3, 400, "middle"))
    # ledger
    parts.append(f'<rect x="{x0}" y="{ledger_y}" width="{x1 - x0 + 30}" height="58" rx="10" fill="{SHEET}" stroke="{RULE}"/>')
    parts.append(text(x0 + 20, ledger_y + 25, "Audit log", 18, "sign", INK, 600))
    parts.append(text(x0 + 20, ledger_y + 45, "every request, whatever happened to it", 13, "read", INK3))
    parts.append(text(28, 58, "One request, every check", 30, "sign", INK, 700, extra='dx="12"'))

    link_x0 = x0 + 330
    for n, (caption, colour, stage, exits, popup) in enumerate(scenarios):
        t0 = n * (window + gap)
        stop_x = xs[stage]
        if exits:
            p0, p1, p2 = (stop_x - 40, mid), (stop_x, mid), (stop_x, mid + 40)
            down = ledger_y - 8 - (mid + 40)
            path = f"M {x0} {mid} H {p0[0]} Q {p1[0]} {p1[1]} {p2[0]} {p2[1]} V {ledger_y - 8}"
            length = (p0[0] - x0) + quad_len(p0, p1, p2) + down
            decide = stop_x - x0
        else:
            path = f"M {x0} {mid} H {x1 + 12}"
            length = x1 + 12 - x0
            decide = stop_x - x0
        travel = min(window - 0.4, length / speed)
        end = t0 + travel
        parts.append(packet(path, length, decide, colour, (t0, end), loop, end_hold=0.5))
        decided = t0 + travel * decide / length
        # caption, popup near the deciding stage, highlight on the stage
        parts.append(appear(
            f'<circle cx="48" cy="86" r="8" fill="{colour}"/>'
            + text(66, 92, caption, 20, "read", INK, 600),
            t0, t0 + window + gap * 0.8, loop))
        py = band_y + band_h + 34 if not exits else band_y + band_h + 30
        px = min(max(stop_x, 190), w - 190)
        anchor = "middle"
        if exits:
            px, anchor = stop_x + 20, "start"
            if stop_x > 900:
                px, anchor = stop_x - 20, "end"
        parts.append(appear(text(px, py + (34 if exits else 0), popup, 15, "read", colour, 600, anchor),
                            decided, t0 + window, loop))
        if n < len(scenarios):
            lx = link_x0 + n * 64
            parts.append(appear(
                f'<rect x="{lx}" y="{ledger_y + 16}" width="44" height="26" rx="6" fill="{colour}" opacity="0.9"/>'
                + (f'<path d="M {lx - 20} {ledger_y + 29} H {lx}" stroke="{INK}" stroke-width="3"/>' if n else ""),
                end + 0.3, loop - 0.05, loop))
    parts.append(text(link_x0 + 5 * 64 + 4, ledger_y + 34, "each entry hashes the one before it", 13, "read", INK3))

    svg("workflow.svg", w, h, "How a request moves through the gateway",
        "Five requests in turn: an ordinary question is answered; a prompt with personal "
        "data is cleaned and answered; an injection attack is blocked at the decision; a "
        "borderline request is held for review; an over-budget request is refused at the "
        "budget check. Every one adds a linked entry to the audit log.", "\n".join(parts))


# --------------------------------------------------------- architecture


def box(x, y, w, h, title, rows=(), fill=SHEET, stroke=RULE, title_size=19, row_size=14):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>']
    out.append(text(x + 18, y + 32, title, title_size, "sign", INK, 600))
    out.append(lines(x + 18, y + 56, list(rows), row_size, fill=INK2) if rows else "")
    return "\n".join(out)


def chip(x, y, w, label, colour=INK, sub=None):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{44 if sub else 32}" rx="8" fill="{SURFACE}" stroke="{RULE}"/>',
           f'<rect x="{x}" y="{y}" width="5" height="{44 if sub else 32}" rx="2" fill="{colour}"/>',
           text(x + 14, y + 21, label, 14, "read", INK, 600)]
    if sub:
        out.append(text(x + 14, y + 37, sub, 12, "read", INK3))
    return "\n".join(out)


def arrow(d, colour=INK3, width=2.5, animated=True, head=True):
    cls = ' class="flow"' if animated else ""
    marker = ' marker-end="url(#head)"' if head else ""
    return f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="{width}"{cls}{marker}/>'


def architecture():
    w, h = 1280, 700
    defs = f"""<defs><marker id="head" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="{INK3}"/></marker></defs>"""
    parts = [defs, text(40, 58, "Architecture", 30, "sign", INK, 700),
             text(40, 86, "Four services in Docker Compose. Applications change two settings: the URL they send to, and the API key.", 16, "read", INK2)]

    # left column
    parts.append(box(40, 130, 230, 120, "Applications", ["Any OpenAI-style client,", "pointed at the gateway", "with a gateway API key"]))
    parts.append(box(40, 470, 230, 110, "Admin's browser", ["Signs in with a", "username and password"]))
    # gateway
    gx, gy, gw, gh = 340, 120, 600, 330
    parts.append(f'<rect x="{gx}" y="{gy}" width="{gw}" height="{gh}" rx="16" fill="{SHEET}" stroke="{INK}" stroke-width="2"/>')
    parts.append(text(gx + 22, gy + 38, "Gateway", 24, "sign", INK, 700))
    parts.append(text(gx + 120, gy + 38, "FastAPI, Python 3.11", 15, "read", INK3))
    chips = [
        ("Session guard", HELD, "6b: locked keys"), ("Budget + rate", CLEANED, "3: Redis, atomic"),
        ("Threat score", REFUSED, "5: DeBERTa-v3"), ("PII redaction", CLEANED, "4: Presidio + regex"),
        ("Bandit decision", HELD, "6a: LinUCB"), ("Session agent", HELD, "6b: rule / DQN"),
        ("Reply check", REFUSED, "5: leak scan"), ("Usage", CLEANED, "3: real cost"),
        ("Audit writer", ALLOWED, "7: hash chain"),
    ]
    for i, (label, colour, sub) in enumerate(chips):
        col, row = i % 3, i // 3
        parts.append(chip(gx + 22 + col * 190, gy + 62 + row * 60, 176, label, colour, sub))
    parts.append(text(gx + 22, gy + 262, "Admin API /v1/admin: login, logs, review queue, budgets, policies, stats", 14, "read", INK2))
    parts.append(text(gx + 22, gy + 284, "Fail-closed: if any check breaks, the request is refused, not waved through.", 14, "read", INK2))
    parts.append(text(gx + 22, gy + 306, "Trained classifier mounted read-only; nothing raw is ever logged or stored.", 14, "read", INK2))
    # providers
    parts.append(box(1010, 130, 230, 150, "Model providers", ["OpenAI", "Anthropic", "Ollama (local, optional)"]))
    # dashboard
    parts.append(box(340, 500, 300, 150, "Dashboard", ["Next.js 16, React 19", "Its server keeps the session in", "an httpOnly cookie and forwards", "to the admin API"]))
    # data stores
    parts.append(box(700, 500, 240, 150, "PostgreSQL", ["teams, keys (hashed), budgets,", "policies, threat events, review", "queue, audit chain", "gateway logs in as gateway_app"]))
    parts.append(box(1010, 500, 230, 150, "Redis", ["spend counters,", "rate-limit buckets,", "session state and locks"]))
    parts.append(box(1010, 330, 230, 120, "One-off jobs", ["model: fetch classifier", "migrate: schema, role", "seed-traffic: demo data"], fill=SURFACE))

    # connections
    parts.append(arrow(f"M 272 190 H {gx - 6}"))
    parts.append(text(278, 180, "requests", 13, "read", INK3))
    parts.append(arrow(f"M {gx + gw + 2} 205 H 1004"))
    parts.append(text(gx + gw + 8, 195, "clean prompt", 13, "read", INK3))
    parts.append(arrow(f"M 1004 245 H {gx + gw + 6}"))
    parts.append(text(gx + gw + 8, 268, "checked reply", 13, "read", INK3))
    parts.append(arrow("M 272 525 H 334"))
    parts.append(arrow(f"M 490 494 V {gy + gh + 6}"))
    parts.append(text(500, 476, "admin API", 13, "read", INK3))
    parts.append(arrow(f"M 820 {gy + gh + 4} V 494", animated=True))
    parts.append(arrow(f"M 900 {gy + gh + 4} C 900 470 1100 470 1110 494", animated=True))

    svg("architecture.svg", w, h, "Architecture",
        "Applications send requests to the gateway, which runs the checks and calls OpenAI, "
        "Anthropic or a local Ollama model. The gateway keeps its data in PostgreSQL and "
        "Redis. The admin dashboard reaches the gateway's admin API through its own server.",
        "\n".join(parts))


# --------------------------------------------------------------- defense


def defense():
    w, h, loop = 1280, 470, 6.0
    defs = f"""<defs><marker id="head" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
<path d="M 0 0 L 10 5 L 0 10 z" fill="{INK3}"/></marker></defs>"""
    parts = [defs, text(40, 58, "Two layers of adaptive defense", 30, "sign", INK, 700),
             text(40, 86, "Different techniques for differently shaped problems: one request at a time, and a whole session.", 16, "read", INK2)]

    # left panel: bandit
    parts.append(f'<rect x="40" y="112" width="580" height="320" rx="14" fill="{SHEET}" stroke="{RULE}"/>')
    parts.append(text(64, 148, "Per request: contextual bandit", 21, "sign", INK, 700))
    parts.append(text(64, 172, "Module 6a, LinUCB with a calibrated warm start", 14, "read", INK3))
    parts.append(lines(64, 210, ["attack probability", "suspicious windows", "personal data found", "session strictness"], 14, gap=24, fill=INK2))
    parts.append(arrow("M 216 248 H 268"))
    parts.append(f'<rect x="274" y="214" width="96" height="70" rx="10" fill="{INK}"/>')
    parts.append(text(322, 246, "LinUCB", 17, "sign", SHEET, 600, "middle"))
    parts.append(text(322, 266, "one per action", 11, "read", "#c9d3df", 400, "middle"))
    for i, (label, colour) in enumerate([("allow", ALLOWED), ("cut the risky part", CLEANED), ("send to review", HELD), ("block", REFUSED)]):
        y = 196 + i * 30
        parts.append(arrow(f"M 372 249 C 395 249 395 {y + 10} 412 {y + 10}", head=False, animated=False, colour=RULE))
        parts.append(f'<rect x="414" y="{y}" width="12" height="20" rx="3" fill="{colour}"/>')
        parts.append(text(434, y + 15, label, 14, "read", INK, 600))
    parts.append(f'<rect x="64" y="338" width="532" height="70" rx="10" fill="{SURFACE}"/>')
    parts.append(arrow("M 520 338 C 520 310 330 310 330 290"))
    parts.append(lines(80, 362, ["Learns from reviewers' verdicts and leaked replies. A choice here", "doesn't change the next request, so a bandit is the right tool."], 14, fill=INK2))

    # right panel: session agent
    parts.append(f'<rect x="660" y="112" width="580" height="320" rx="14" fill="{SHEET}" stroke="{RULE}"/>')
    parts.append(text(684, 148, "Per session: reinforcement learning", 21, "sign", INK, 700))
    parts.append(text(684, 172, "Module 6b, DQN agent with a rule-based fallback (the default)", 14, "read", INK3))
    scores = [0.03, 0.04, 0.62, 0.97, 0.98]
    for i, sc in enumerate(scores):
        x = 700 + i * 70
        hgt = 10 + sc * 70
        colour = ALLOWED if sc < 0.5 else (HELD if sc < 0.8 else REFUSED)
        parts.append(f'<rect x="{x}" y="{290 - hgt}" width="34" height="{hgt}" rx="4" fill="{colour}" opacity="0.15">'
                     f'<animate attributeName="opacity" dur="{loop}s" repeatCount="indefinite" values="0.15;0.15;1;1" '
                     f'keyTimes="{keytimes(0, i * 0.12, i * 0.12 + 0.01, 1)}"/></rect>')
        parts.append(text(x + 17, 308, f"r{i + 1}", 12, "read", INK3, 400, "middle"))
    parts.append(text(700, 330, "one API key's requests, in order", 13, "read", INK3))
    actions = [("maintain", ALLOWED, 0.0), ("tighten", CLEANED, 0.36), ("challenge", HELD, 0.48), ("lock out", REFUSED, 0.6)]
    for i, (label, colour, at) in enumerate(actions):
        y = 196 + i * 30
        parts.append(f'<rect x="1072" y="{y}" width="12" height="20" rx="3" fill="{colour}"/>')
        parts.append(text(1092, y + 15, label, 14, "read", INK, 600))
        parts.append(f'<rect x="1066" y="{y - 4}" width="150" height="28" rx="6" fill="none" stroke="{colour}" stroke-width="2" opacity="0">'
                     f'<animate attributeName="opacity" dur="{loop}s" repeatCount="indefinite" values="0;0;1;1;0" '
                     f'keyTimes="{keytimes(0, at + 0.02, at + 0.03, min(at + 0.14, 0.97), min(at + 0.15, 0.98))}"/></rect>')
    parts.append(arrow("M 1050 250 H 1062", animated=False))
    parts.append(f'<rect x="684" y="338" width="532" height="70" rx="10" fill="{SURFACE}"/>')
    parts.append(lines(700, 362, ["Its actions change the rest of the session (a locked key stays", "locked), so it needs states and delayed reward: reinforcement learning."], 14, fill=INK2))

    # bias hook
    parts.append(arrow("M 690 190 C 560 186 330 178 322 208", colour=HELD))
    parts.append(text(520, 178, "escalation bias", 13, "read", HELD, 600, "middle"))
    parts.append(text(640, 448, "The session agent tilts the bandit's choices through one hook: escalation bias.", 14, "read", HELD, 600, "middle"))

    svg("defense.svg", w, h, "Two layers of adaptive defense",
        "Left: a contextual bandit chooses allow, cut, review or block for each request and "
        "learns from verdicts. Right: a session agent watches a key's requests over time and "
        "can tighten, challenge or lock the key; it nudges the bandit through an escalation bias.",
        "\n".join(parts))


# ------------------------------------------------------------------ data


def data():
    w, h = 1280, 400
    parts = [text(40, 58, "Training data for the threat classifier", 30, "sign", INK, 700),
             text(40, 86, "Classifier v2, the one that ships. Near-duplicates are clustered and kept within one split, so no test prompt is a copy of a training prompt.", 15, "read", INK2)]
    splits = [
        ("Training", 6307, 3521, 1661, 1125),
        ("Validation", 830, 463, 226, 141),
        ("Locked test", 950, 546, 292, 112),
        ("Old test (v1)", 194, 100, 29, 65),
    ]
    classes = [("benign", "#8fa1b6"), ("prompt injection", INK), ("jailbreak", "#4f6582")]
    scale = 840 / 6307
    for i, (name, total, *counts) in enumerate(splits):
        y = 130 + i * 56
        parts.append(text(40, y + 24, name, 18, "sign", INK, 600))
        parts.append(text(232, y + 24, f"{total:,}", 16, "read", INK2, 600, "end"))
        x = 250
        for (label, colour), n in zip(classes, counts, strict=True):
            width = max(n * scale, 2)
            parts.append(f'<rect x="{x}" y="{y + 4}" width="0" height="28" fill="{colour}">'
                         f'<animate attributeName="width" from="0" to="{width:.1f}" dur="0.9s" begin="{0.15 * i}s" fill="freeze"/></rect>')
            if width > 56 and total >= 1000:  # small rows get their counts beside the bar
                parts.append(text(x + 10, y + 23, f"{n:,}", 14, "read", SHEET, 600))
            x += width
        if counts and total < 1000:
            parts.append(text(x + 12, y + 23, " / ".join(f"{n:,}" for n in counts), 14, "read", INK3))
    lx = 250
    for label, colour in classes:
        parts.append(f'<rect x="{lx}" y="358" width="14" height="14" rx="3" fill="{colour}"/>')
        parts.append(text(lx + 22, 370, label, 14, "read", INK))
        lx += 190
    svg("data.svg", w, h, "Training data for the threat classifier",
        "Rows per split, by class: training 6,307 (3,521 benign, 1,661 prompt injection, 1,125 "
        "jailbreak); validation 830; locked test 950; old test 194.", "\n".join(parts))


# --------------------------------------------------------------- results


def results():
    w, h = 1280, 330
    parts = [text(40, 58, "Results", 30, "sign", INK, 700),
             text(40, 86, "Measured, not estimated. Classifier on the 950-prompt locked test set; tests on Postgres + Redis.", 15, "read", INK2)]
    tiles = [  # big number, label, note, bar fraction, colour, v1's value on the same bar
        ("0.908", "macro-F1", "was 0.490 with classifier v1", 0.908, ALLOWED, 0.490),
        ("0.949", "prompt-injection F1", "was 0.341 with classifier v1", 0.949, ALLOWED, 0.341),
        ("3.1%", "harmless prompts flagged", "was 27.5% with classifier v1", 0.031, REFUSED, 0.275),
        ("455", "automated gateway tests", "97% line + branch coverage", 0.97, INK, None),
    ]
    for i, (big, label, sub, frac, colour, before) in enumerate(tiles):
        x = 40 + i * 302
        parts.append(f'<rect x="{x}" y="112" width="284" height="186" rx="14" fill="{SHEET}" stroke="{RULE}"/>')
        parts.append(text(x + 22, 176, big, 50, "sign", INK, 700))
        parts.append(text(x + 22, 206, label, 17, "read", INK, 600))
        parts.append(text(x + 22, 228, sub, 13, "read", INK3))
        parts.append(f'<rect x="{x + 22}" y="254" width="240" height="10" rx="5" fill="{RULE_SOFT}"/>')
        parts.append(f'<rect x="{x + 22}" y="254" width="0" height="10" rx="5" fill="{colour}">'
                     f'<animate attributeName="width" from="0" to="{240 * frac:.1f}" dur="1.1s" begin="{0.2 + 0.2 * i}s" fill="freeze"/></rect>')
        if before is not None:
            bx = x + 22 + 240 * before
            parts.append(f'<rect x="{bx - 1.5}" y="248" width="3" height="22" rx="1" fill="{INK3}"/>')
            parts.append(text(bx, 286, "v1", 12, "read", INK3, 600, "middle"))
    svg("results.svg", w, h, "Results",
        "Classifier v2 on the 950-prompt locked test: macro-F1 0.908 (v1: 0.490), prompt-injection "
        "F1 0.949 (v1: 0.341), 3.1% of harmless prompts flagged (v1: 27.5%). 455 automated gateway tests, 97% coverage.",
        "\n".join(parts))


if __name__ == "__main__":
    hero()
    workflow()
    architecture()
    defense()
    data()
    results()

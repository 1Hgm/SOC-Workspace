"""SOC Workspace look and feel.

Design notes
  * Subject: analysts triaging a live incident in a hospital SOC.
  * Memorable element: the case "pulse", a heartbeat trace that takes the color of the
    peak severity, flatlines with no evidence, and sweeps while the AI is analyzing.
  * Color is information: deep ink-blue base, severity colors are the only strong colors,
    aqua is reserved for focus and the active tab.
  * Type: Schibsted Grotesk for the interface, JetBrains Mono only for real data
    (IOCs, timestamps).
  * Motion only answers an action (the analyzing trace). Reduced motion is respected.

All dynamic text goes through esc() before it is placed in HTML.
"""

import html
import os
import re

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

THEME_TOML = """[theme]
base = "dark"
primaryColor = "#6FD6E0"
backgroundColor = "#0F1522"
secondaryBackgroundColor = "#151F33"
textColor = "#E6ECF5"
"""

FONT_IMPORT = (
    "@import url('https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@400;500;600;700;800"
    "&family=JetBrains+Mono:wght@400;500&display=swap');"
)

CSS = """
:root{--ink:#0F1522;--panel:#151F33;--raise:#1B2840;--line:#27364F;--text:#E6ECF5;--mute:#8FA2BF;--aqua:#6FD6E0;
--critical:#F2555A;--high:#F59E42;--medium:#E9C94A;--low:#3FBF9B;--none:#5B6B85;
--mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Consolas,monospace}
.sev-critical{--sev:var(--critical);--sev-bg:rgba(242,85,90,.15)}
.sev-high{--sev:var(--high);--sev-bg:rgba(245,158,66,.15)}
.sev-medium{--sev:var(--medium);--sev-bg:rgba(233,201,74,.14)}
.sev-low{--sev:var(--low);--sev-bg:rgba(63,191,155,.15)}
.sev-none{--sev:var(--none);--sev-bg:rgba(91,107,133,.18)}
.stApp{background:var(--ink);color:var(--text);color-scheme:dark;
font-family:'Schibsted Grotesk',ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif}
[data-testid="stHeader"]{background:transparent}
footer{visibility:hidden}[data-testid="stAppDeployButton"],.stAppDeployButton{display:none}
.block-container{padding-top:1.3rem;max-width:1400px}
[data-testid="stSidebar"]{background:var(--panel);border-right:1px solid var(--line)}
.stApp h1,.stApp h2,.stApp h3,.stApp h4{color:var(--text);font-weight:700;letter-spacing:-.01em}
.stApp p,.stApp label,.stApp li{color:var(--text)}
[data-testid="stCaptionContainer"],[data-testid="stCaptionContainer"] p{color:var(--mute)}
textarea,input,button{font-family:inherit}
[data-baseweb="textarea"],[data-baseweb="input"],[data-baseweb="select"]>div{background:var(--raise)!important;border-color:var(--line)!important;border-radius:8px!important}
textarea,input{color:var(--text)!important}
[data-testid="stFileUploaderDropzone"]{background:var(--raise);border:1px dashed var(--line);border-radius:10px}
.stButton>button,.stDownloadButton>button,.stFormSubmitButton>button{background:var(--raise);color:var(--text);border:1px solid var(--line);border-radius:8px;font-weight:600;transition:border-color .15s,background .15s}
.stButton>button:hover,.stDownloadButton>button:hover,.stFormSubmitButton>button:hover{border-color:var(--aqua);color:#fff}
button[kind="primary"],button[kind="primaryFormSubmit"],[data-testid="stBaseButton-primary"],[data-testid="stBaseButton-primaryFormSubmit"]{background:var(--aqua)!important;color:#06202A!important;border-color:var(--aqua)!important}
button[kind="primary"] p,button[kind="primaryFormSubmit"] p,[data-testid="stBaseButton-primary"] p,[data-testid="stBaseButton-primaryFormSubmit"] p{color:#06202A!important;font-weight:700}.stTabs [data-baseweb="tab-list"]{gap:6px;border-bottom:1px solid var(--line)}
.stTabs [data-baseweb="tab"]{padding:10px 16px;color:var(--mute);font-weight:600}
.stTabs [aria-selected="true"]{color:var(--text)}
.stTabs [data-baseweb="tab-highlight"]{background:var(--aqua);height:3px}
.stTabs [data-baseweb="tab-border"]{background:transparent}
[data-testid="stExpander"] details{background:var(--panel);border:1px solid var(--line);border-radius:10px}
[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:10px;overflow:hidden}
[data-testid="stAlert"]{border-radius:8px}
.stProgress>div>div>div>div{background:var(--aqua)}[data-testid="stCheckbox"] label,[data-testid="stCheckbox"] label p,[data-testid="stCheckbox"] label span{white-space:normal!important;overflow:visible!important;text-overflow:clip!important;line-height:1.4}[data-testid="stCheckbox"]{margin-bottom:2px}[data-testid="stCode"] pre,[data-testid="stCode"] code{white-space:pre-wrap!important;word-break:break-all}
.hdr{display:flex;align-items:center;gap:32px;padding:4px 0 18px;margin-bottom:14px;border-bottom:1px solid var(--line)}
.hdr-main{flex:1 1 auto;min-width:0}
.brand{font-size:32px;font-weight:800;letter-spacing:-.025em;line-height:1.1}
.tag-line{color:var(--mute);font-size:14px;margin-top:4px}
.chips{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
.chip{border:1px solid var(--line);background:var(--raise);border-radius:999px;padding:3px 12px;font-size:13px;font-weight:600}
.chip.ghost{color:var(--mute);font-weight:500;border-style:dashed;background:transparent}
.pulse{flex:0 0 230px;width:230px;height:46px}
.pulse path{fill:none;stroke:var(--sev);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.peak{flex:0 0 auto;text-align:right}
.pk-l{display:block;color:var(--mute);font-size:12px;font-weight:600}
.pk-v{display:block;font-size:28px;font-weight:800;letter-spacing:-.02em;color:var(--sev)}.sev-none .pk-v{font-size:16px;font-weight:600;padding-top:8px}
.strip{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;border:1px solid var(--line);border-radius:10px;background:var(--panel);margin:0 0 18px;overflow:hidden}
.cell{padding:12px 18px;border-right:1px solid var(--line)}
.cell:last-child{border-right:none}
.cv{font-family:var(--mono);font-size:24px;font-weight:500;line-height:1.2}
.cv small{font-size:13px;color:var(--mute);font-family:inherit;font-weight:500;margin-left:6px}
.cl{color:var(--mute);font-size:12.5px;margin-top:2px;font-weight:500}.cs{font-size:12px;color:var(--mute);margin-top:3px}.cs.bad{color:var(--critical);font-weight:600}
.tally .cv{font-size:26px}
.sec{font-size:15px;font-weight:700;margin:2px 0 12px}
.rail{position:relative;margin:4px 0 8px 6px}
.rail:before{content:"";position:absolute;left:7px;top:8px;bottom:8px;width:2px;background:var(--line)}
.node{position:relative;padding:0 0 22px 34px}
.node:last-child{padding-bottom:4px}
.dot{position:absolute;left:0;top:3px;width:16px;height:16px;border-radius:50%;background:var(--ink);border:3px solid var(--sev);box-shadow:0 0 0 4px var(--ink)}
.meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.time{font-family:var(--mono);font-size:13px;color:var(--mute)}
.tag{background:var(--sev-bg);color:var(--sev);border-radius:4px;padding:1px 8px;font-size:12px;font-weight:700}
.who{color:var(--mute);font-size:12.5px}
.ntitle{font-size:16.5px;font-weight:700;margin:3px 0 4px}
.nsum{color:#C9D5E8;font-size:14px;line-height:1.5;max-width:70ch}
.iocs{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.ioc{font-family:var(--mono);font-size:12px;background:var(--raise);border:1px solid var(--line);border-radius:4px;padding:1px 7px}
.ioc.v-malicious{border-color:var(--critical);color:#FFB4B6}
.ioc.v-suspicious{border-color:var(--high);color:#FFD2A3}
.ioc.v-clean{border-color:var(--low)}
.more{color:var(--mute);font-size:12px;padding:2px 2px}
.trace{display:flex;gap:18px;align-items:center;border:1px solid var(--line);border-left:3px solid var(--aqua);background:var(--panel);border-radius:8px;padding:12px 18px;margin:12px 0}
.trace svg{flex:0 0 150px;width:150px;height:36px}
.trace path{fill:none;stroke:var(--aqua);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:46 200;animation:sweep 1.3s linear infinite}
@keyframes sweep{from{stroke-dashoffset:246}to{stroke-dashoffset:0}}
.trace path.base{stroke:var(--line);stroke-dasharray:none;animation:none}.trace .tt{font-weight:700}
.trace .tp{color:var(--mute);font-size:14px;margin-top:2px;max-width:80ch}
@media (prefers-reduced-motion:reduce){.trace path{animation:none;stroke-dasharray:none}.trace path:not(.base){stroke:var(--aqua)}}
.empty{border:1px dashed var(--line);border-radius:10px;padding:28px 26px;margin:10px 0 6px}
.empty b{font-size:18px;display:block;margin-bottom:6px}
.empty span{color:var(--mute)}
.scorebox{display:flex;align-items:center;gap:24px;margin:6px 0 18px}
.ring{width:132px;height:132px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),var(--line) 0);display:grid;place-items:center;flex:0 0 132px}
.ring-in{width:104px;height:104px;border-radius:50%;background:var(--ink);display:grid;place-items:center;text-align:center}
.ring-in b{font-family:var(--mono);font-size:34px;font-weight:500;line-height:1}
.ring-in span{color:var(--mute);font-size:12px;display:block;margin-top:2px}
.slabel{font-size:22px;font-weight:800;letter-spacing:-.01em}
.scoach{color:#C9D5E8;font-size:14.5px;max-width:70ch;margin-top:4px;line-height:1.5}
.brow{display:grid;grid-template-columns:230px 1fr 56px;gap:14px;align-items:center;margin:2px 0}
.brow .bl{font-weight:600;font-size:14px}
.bar{height:9px;background:var(--line);border-radius:5px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--c);border-radius:5px}
.brow .bs{font-family:var(--mono);text-align:right;font-size:14px}
.brat{color:var(--mute);font-size:13px;margin:0 0 12px 244px;max-width:90ch}
.lst{border-top:2px solid var(--lc);padding-top:10px}
.lst-h{font-weight:800;font-size:16px;margin-bottom:8px}
.lst ul{margin:0;padding-left:18px}
.lst li{margin:0 0 8px;font-size:14px;line-height:1.45;color:#C9D5E8}
.lst .cat{font-weight:700;color:var(--text)}
.lst-done{--lc:var(--low)}
.lst-gap{--lc:var(--high)}
.lst-next{--lc:var(--aqua)}
.prog{height:6px;background:var(--line);border-radius:3px;margin:2px 0 10px;overflow:hidden}
.prog i{display:block;height:100%;background:var(--aqua)}
.hub{width:100%;height:auto;max-height:380px}
.hub text{font-family:'Schibsted Grotesk',system-ui,sans-serif}
.notice{display:flex;gap:14px;align-items:flex-start;border:1px solid var(--line);background:var(--panel);border-radius:10px;padding:10px 16px;margin:0 0 14px;font-size:14px;line-height:1.5}.notice b{color:var(--aqua);white-space:nowrap}.notice span{color:#C9D5E8}
@media (max-width:900px){.hdr{flex-wrap:wrap;gap:12px}.pulse{display:none}.peak{text-align:left}.strip{grid-auto-flow:row;grid-template-columns:1fr 1fr}.cell{border-bottom:1px solid var(--line)}.brow{grid-template-columns:1fr 1fr 44px}.brat{margin-left:0}}
"""


# ---------- helpers ----------
def esc(value):
    """Escape for HTML. Also neutralizes $ so Markdown never starts a math block."""
    return html.escape("" if value is None else str(value), quote=True).replace("$", "&#36;")


def sev_class(sev):
    s = (sev or "").lower()
    return s if s in SEV_LABEL else "none"


def peak_severity(entries):
    best = max((e.get("severity", "low") for e in entries), key=lambda s: SEV_ORDER.get(s, 0), default=None)
    return best


def inject_css():
    """Minified (no blank lines) so Markdown keeps it as one HTML block."""
    css = re.sub(r"\s+", " ", FONT_IMPORT + CSS).strip()
    return f"<style>{css}</style>"


def ensure_theme_file(base_dir=None):
    """Create .streamlit/config.toml if missing. Returns True when it was just created."""
    folder = os.path.join(base_dir or os.getcwd(), ".streamlit")
    path = os.path.join(folder, "config.toml")
    if os.path.exists(path):
        return False
    try:
        os.makedirs(folder, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(THEME_TOML)
        return True
    except OSError:
        return False


# ---------- header + instrument strip ----------
PULSE_LIVE = "M0 24 H52 L60 24 L68 8 L78 40 L88 14 L96 24 H134 L142 24 L148 12 L156 34 L162 24 H230"
PULSE_FLAT = "M0 24 H230"


def header_html(case_id, analyst, peak):
    sev = sev_class(peak)
    chips = ""
    if case_id:
        chips += f'<span class="chip">Case {esc(case_id)}</span>'
    if analyst:
        chips += f'<span class="chip">{esc(analyst)}</span>'
    if not chips:
        chips = '<span class="chip ghost">Add a case ID in the sidebar</span>'
    value = SEV_LABEL.get(sev, "Waiting for evidence")
    return (
        f'<div class="hdr sev-{sev}"><div class="hdr-main"><div class="brand">SOC Workspace</div>'
        f'<div class="tag-line">Capture evidence, watch the case take shape, decide the next move.</div>'
        f'<div class="chips">{chips}</div></div>'
        f'<svg class="pulse" viewBox="0 0 230 46" aria-hidden="true"><path d="{PULSE_FLAT if sev == "none" else PULSE_LIVE}"/></svg>'
        f'<div class="peak"><span class="pk-l">Peak severity</span><span class="pk-v">{value}</span></div></div>'
    )


def strip_html(cells):
    """cells: (label, value_html[, sub_text[, sub_class]]). value_html must already be safe.
    sub_class "bad" colors the sub-line red; anything else stays muted."""
    out = []
    for cell in cells:
        label, value = cell[0], cell[1]
        sub = cell[2] if len(cell) > 2 and cell[2] else ""
        cls = f" {esc(cell[3])}" if len(cell) > 3 and cell[3] else ""
        sub_html = f'<div class="cs{cls}">{esc(sub)}</div>' if sub else ""
        out.append(f'<div class="cell"><div class="cv">{value}</div><div class="cl">{esc(label)}</div>{sub_html}</div>')
    return f'<div class="strip">{"".join(out)}</div>'


def instrument_strip(n_entries, span_min, n_iocs, mal_note, steps_done, steps_total, score):
    return strip_html([
        ("Evidence entries", str(n_entries)),
        ("Time span", f"{span_min}<small>min</small>" if span_min is not None else "-"),
        ("Indicators", str(n_iocs), mal_note, "" if "simulated" in (mal_note or "") else "bad"),
        ("Next steps done", f"{steps_done}<small>of {steps_total}</small>" if steps_total else "-"),
        ("Quality score", str(score["overall"]) if score else "-", score["label"] if score else "Not scored yet"),
    ])


# ---------- timeline ----------
def timeline_html(entries, verdict_of=None, max_chips=6):
    """Vertical rail, oldest first. entries: dicts from the app."""
    if not entries:
        return ""
    nodes = []
    for e in entries:
        sev = sev_class(e.get("severity"))
        t = e.get("event_time") or e.get("submitted") or ""
        chips = []
        for i in e.get("indicators", [])[:max_chips]:
            val = str(i.get("value", ""))
            v = verdict_of(i) if verdict_of else None
            cls = f" v-{v}" if v in ("malicious", "suspicious", "clean") else ""
            chips.append(f'<span class="ioc{cls}">{esc(val)}</span>')
        extra = len(e.get("indicators", [])) - max_chips
        if extra > 0:
            chips.append(f'<span class="more">+{extra} more</span>')
        who = f'<span class="who">{esc(e["analyst"])}</span>' if e.get("analyst") else ""
        nodes.append(
            f'<div class="node sev-{sev}"><div class="dot"></div>'
            f'<div class="meta"><span class="time">{esc(t)}</span><span class="tag">{SEV_LABEL.get(sev, "Info")}</span>{who}</div>'
            f'<div class="ntitle">{esc(e.get("title", "Event"))}</div>'
            f'<div class="nsum">{esc(e.get("summary", ""))}</div>'
            f'<div class="iocs">{"".join(chips)}</div></div>'
        )
    return f'<div class="rail">{"".join(nodes)}</div>'


def progress_html(done, total):
    pct = int(100 * done / total) if total else 0
    return f'<div class="prog"><i style="width:{pct}%"></i></div>'


# ---------- live analysis card ----------
def trace_html(text="", partial=""):
    body = f'<div class="tp">{esc(partial)}</div>' if partial else ""
    return (
        '<div class="trace"><svg viewBox="0 0 150 36" aria-hidden="true">'
        '<path class="base" d="M0 18 H40 L48 6 L56 30 L64 12 L70 18 H150"/>'
        '<path d="M0 18 H40 L48 6 L56 30 L64 12 L70 18 H150"/></svg>'
        f'<div><div class="tt">Analyzing{": " + esc(text) if text else ""}</div>{body}</div></div>'
    )


def empty_html(title, body):
    return f'<div class="empty"><b>{esc(title)}</b><span>{esc(body)}</span></div>'


# ---------- score ----------
def score_color(score):
    if score >= 85:
        return "var(--low)"
    if score >= 70:
        return "var(--aqua)"
    if score >= 50:
        return "var(--high)"
    return "var(--critical)"


def score_header_html(overall, label, coaching=""):
    coach = f'<div class="scoach">{esc(coaching)}</div>' if coaching else ""
    return (
        f'<div class="scorebox"><div class="ring" style="--p:{int(overall)};--c:{score_color(overall)}">'
        f'<div class="ring-in"><div><b>{int(overall)}</b><span>out of 100</span></div></div></div>'
        f'<div><div class="slabel">{esc(label)}</div>{coach}</div></div>'
    )


def bars_html(categories):
    rows = []
    for c in categories:
        col = score_color(c["score"] * 10)
        rows.append(
            f'<div class="brow"><div class="bl">{esc(c["label"])}</div>'
            f'<div class="bar" style="--c:{col}"><i style="width:{c["score"] * 10}%"></i></div>'
            f'<div class="bs">{int(c["score"])}/10</div></div>'
            f'<div class="brat">{esc(c["rationale"])} (weight {int(c["weight"])}%)</div>'
        )
    return "".join(rows)


def list_html(title, items, kind, label_for):
    lis = "".join(
        "<li>" + (f'<span class="cat">{esc(label_for(it["category"]))}:</span> ' if it.get("category") else "") + f'{esc(it["point"])}</li>'
        for it in items
    )
    return f'<div class="lst lst-{kind}"><div class="lst-h">{esc(title)}</div><ul>{lis}</ul></div>'


# ---------- integrations map ----------
def integration_map_svg(intel, outbound):
    """Hub and spoke. intel/outbound: lists of (label, configured_bool). Data flows in from
    intel sources on the left and out to tools on the right."""
    def place(items, x, anchor):
        n = len(items)
        ys = [150] if n == 1 else [int(66 + i * (190 / (n - 1))) for i in range(n)]
        return [(label, ok, x, y, anchor) for (label, ok), y in zip(items, ys)]

    nodes = place(intel, 92, "in") + place(outbound, 548, "out")
    parts = [
        '<svg class="hub" viewBox="0 0 640 300" role="img" aria-label="Connection map">',
        '<defs><marker id="ar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0 0 L8 4 L0 8 z" fill="#6FD6E0"/></marker></defs>',
    ]
    for label, ok, x, y, side in nodes:
        stroke = "#6FD6E0" if ok else "#3A4B69"
        dash = "" if ok else ' stroke-dasharray="5 5"'
        if side == "in":
            x1, x2 = x + 70, 278
            parts.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="150" stroke="{stroke}" stroke-width="2"{dash}'
                         + (' marker-end="url(#ar)"' if ok else "") + "/>")
        else:
            x1, x2 = 362, x - 70
            parts.append(f'<line x1="{x1}" y1="150" x2="{x2}" y2="{y}" stroke="{stroke}" stroke-width="2"{dash}'
                         + (' marker-end="url(#ar)"' if ok else "") + "/>")
    parts.append('<circle cx="320" cy="150" r="46" fill="#151F33" stroke="#6FD6E0" stroke-width="2"/>'
                 '<text x="320" y="147" text-anchor="middle" fill="#E6ECF5" font-size="14" font-weight="800">SOC</text>'
                 '<text x="320" y="165" text-anchor="middle" fill="#E6ECF5" font-size="14" font-weight="800">Workspace</text>')
    for label, ok, x, y, side in nodes:
        fill = "#1B2840" if ok else "#151F33"
        edge = "#3FBF9B" if ok else "#3A4B69"
        status = "Connected" if ok else "Not set up"
        parts.append(
            f'<rect x="{x - 70}" y="{y - 22}" width="140" height="44" rx="8" fill="{fill}" stroke="{edge}" stroke-width="1.6"/>'
            f'<circle cx="{x - 54}" cy="{y}" r="5" fill="{edge if ok else "none"}" stroke="{edge}" stroke-width="1.6"/>'
            f'<text x="{x - 42}" y="{y - 3}" fill="#E6ECF5" font-size="13" font-weight="700">{esc(label)}</text>'
            f'<text x="{x - 42}" y="{y + 13}" fill="#8FA2BF" font-size="11.5">{status}</text>'
        )
    parts.append('<text x="92" y="20" text-anchor="middle" fill="#8FA2BF" font-size="12" font-weight="600">Intel comes in</text>'
                 '<text x="548" y="20" text-anchor="middle" fill="#8FA2BF" font-size="12" font-weight="600">Case goes out</text></svg>')
    return "".join(parts)


# ---------- public-mode notice ----------
def notice_html(lead, text):
    """A compact strip for data-handling notes. Text is escaped."""
    return f'<div class="notice"><b>{esc(lead)}</b><span>{esc(text)}</span></div>'

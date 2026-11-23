"""SOC Workspace - AI-assisted investigation workspace for SOC analysts (hackathon POC).

Run with:  python -m streamlit run app.py
Use fake / sanitized data only.
"""

import hashlib
import io
import json
import os
import re
import time
from datetime import datetime

import pandas as pd
import streamlit as st
from PIL import Image

import demo
import integrations
import ioc_intel
import llm
import runtime
import scoring
import threat_intel
import ui
import workspace_io

PUBLIC = runtime.PUBLIC          # stateless, bring-your-own-key mode (see runtime.py)
Image.MAX_IMAGE_PIXELS = 40_000_000   # refuse decompression bombs

CACHE_FILE = "response_cache.json"
INTEL_WINDOW_HOURS = 24
INTEL_REFRESH_SECONDS = 900   # background refresh every 15 min
MAX_HISTORY = 6               # only send the last N entries as context (faster)
MAX_IMAGE_SIDE = 1600         # screenshots are shrunk before upload (faster)

ANALYSIS_PROMPT = """You are an assistant embedded in a SOC analyst's notes tool.
You receive the case history so far plus one new input (text note and/or screenshot).
Respond with ONLY a JSON object, no markdown fences, using exactly this schema, with
"summary" as the FIRST key:
{
  "summary": "2-3 sentence clean summary of what the new input shows and why it matters",
  "indicators": [{"type": "ip|domain|url|hash|user|host|email|process|other", "value": "..."}],
  "severity": "low|medium|high|critical",
  "timeline_event": {"time": "HH:MM if visible in the evidence, otherwise null", "title": "short event title"},
  "next_steps": ["3 to 5 concrete, prioritized actions the analyst should take next"]
}
Base next_steps on the WHOLE case so far, not just the latest input.
Never invent indicators that are not visible in the input."""

REPORT_PROMPT = """Write a concise incident report in Markdown from the investigation entries below.
Start with a title and, when provided, the Case ID and analyst name.
Sections: Executive Summary, Timeline, Indicators of Compromise, Assessment, Recommended Actions.
Use only the information provided."""

INTEL_PROMPT = """You are briefing a SOC team that protects a healthcare / life sciences organization.
Below are numbered news items from the last 24 hours. Write a briefing of 3 to 5 short bullets
covering what matters most to the team. Use ONLY the items provided: do not add facts, names,
or numbers that are not in them. End each bullet with the item numbers it relies on, like [2][5].
If the items are not specific to healthcare, say so in one short line first."""


# ---------- helpers ----------
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def _gemini_key():
    """The analyst's own key for this session (public mode). Never stored anywhere but session memory."""
    return (st.session_state.get("gemini_key") or "").strip() or None


def _err(e):
    """Error text with the analyst's keys removed, in case a service echoes one back."""
    msg = str(e)
    for k in ("gemini_key", "vt_key_in", "abuse_key_in"):
        v = (st.session_state.get(k) or "").strip()
        if v:
            msg = msg.replace(v, "***")
    return msg


def _cache_for(name):
    """Public mode: a per-session in-memory cache. Local mode: None, meaning the on-disk caches."""
    return st.session_state.setdefault(name, {}) if PUBLIC else None


def shrink_image(data, mime, strict=False):
    """Downscale + JPEG-compress screenshots: smaller upload, fewer tokens, faster reply."""
    try:
        img = Image.open(io.BytesIO(data))
        img.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        return buf.getvalue(), "image/jpeg"
    except Exception:
        if strict:
            raise ValueError("That image could not be read. Use a PNG or JPEG screenshot.")
        return data, mime


SUMMARY_RE = re.compile(r'"summary"\s*:\s*"((?:[^"\\]|\\.)*)')


def analyze(text, image_bytes, mime, history, on_progress=None, on_status=None, api_key=None, cache=None, info=None):
    """Stream the analysis from Gemini and return parsed JSON."""
    if image_bytes:
        image_bytes, mime = shrink_image(image_bytes, mime, strict=PUBLIC)

    recent = history[-MAX_HISTORY:]
    raw_key = f"{text}|{len(history)}".encode() + (image_bytes or b"")
    cache_key = hashlib.sha256(raw_key).hexdigest()
    persist = cache is None
    if persist:
        cache = load_cache()
    if cache_key in cache:
        return cache[cache_key]

    context = json.dumps(
        [{"time": h["event_time"] or h["submitted"], "summary": h["summary"]} for h in recent]
    )
    parts = [f"Case so far:\n{context}\n\nNew analyst input:\n{text or '(screenshot only)'}"]
    if image_bytes:
        from google.genai import types

        parts.append(types.Part.from_bytes(data=image_bytes, mime_type=mime))

    buf = ""
    for piece in llm.stream(
        parts,
        system_instruction=ANALYSIS_PROMPT,
        response_mime_type="application/json",
        temperature=0.2,
        on_status=on_status,
        api_key=api_key,
        info=info,
    ):
        buf += piece
        if on_progress:
            on_progress(buf)

    cleaned = buf.strip().removeprefix("```json").removesuffix("```").strip()
    data = json.loads(cleaned)
    cache[cache_key] = data
    if persist:
        save_cache(cache)
    return data


def generate_report(entries, analyst="", case_id="", api_key=None):
    payload = json.dumps(
        {
            "case_id": case_id or "n/a",
            "analyst": analyst or "n/a",
            "entries": [
                {
                    "time": e["event_time"] or e["submitted"],
                    "title": e["title"],
                    "summary": e["summary"],
                    "severity": e["severity"],
                    "indicators": e["indicators"],
                }
                for e in entries
            ],
        },
        indent=2,
    )
    return llm.generate(f"{REPORT_PROMPT}\n\nCase data:\n{payload}", api_key=api_key)


def report_appendix(enrichment, score):
    """Facts appended to the report without AI: IOC verdicts and the quality score."""
    out = []
    rows = [(v, r) for v, r in enrichment.items() if r.get("results")]
    if rows:
        out += ["", "## IOC enrichment", "", "| IOC | Verdict | Details |", "|---|---|---|"]
        for v, r in rows:
            detail = "; ".join(f"{x['source']}: {x['summary']}" for x in r["results"]).replace("|", "/")
            out.append(f"| {v} | {r['verdict']} | {detail} |")
    if score:
        out += ["", "## Investigation quality score", "", f"**{score['overall']}/100 ({score['label']})**", ""]
        out += [f"- {c['label']}: {c['score']}/10. {c['rationale']}" for c in score["categories"]]
        if score["coaching"]:
            out += ["", f"_Coaching: {score['coaching']}_"]
    return "\n".join(out)


SEV_ICON = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


# ---------- threat intel: instant snapshot + manual live refresh ----------
# No background threads and no auto-refresh: the panel does NO work unless the
# analyst clicks "Refresh live intel", so it can never slow down note analysis.
INTEL_FILE = "intel_snapshot.json"

SAMPLE_INTEL = {
    "live": False,
    "saved": None,
    "briefing": None,
    "ok": [],
    "failed": [],
    "items": [
        {"title": "SAMPLE: Ransomware group claims attack on regional hospital network",
         "link": "", "source": "Sample data", "published": None, "summary": "", "healthcare": True},
        {"title": "SAMPLE: Phishing campaign impersonates IT helpdesk at healthcare providers",
         "link": "", "source": "Sample data", "published": None, "summary": "", "healthcare": True},
        {"title": "SAMPLE: Vulnerability in medical imaging software under active exploitation",
         "link": "", "source": "Sample data", "published": None, "summary": "", "healthcare": True},
    ],
}


def pick_items(data):
    """Healthcare items if any, otherwise general items. Returns (items, is_healthcare)."""
    hc = [i for i in data["items"] if i["healthcare"]]
    return (hc[:8], True) if hc else (data["items"][:8], False)


def build_briefing(items, api_key=None):
    payload = json.dumps(
        [
            {"n": n, "source": i["source"], "title": i["title"], "summary": i["summary"][:200]}
            for n, i in enumerate(items, 1)
        ]
    )
    return llm.generate(f"{INTEL_PROMPT}\n\nItems:\n{payload}", api_key=api_key)


def save_snapshot(snap):
    if PUBLIC:
        return
    try:
        out = dict(snap)
        out["saved"] = snap["saved"].isoformat()
        out["items"] = [{**i, "published": i["published"].isoformat()} for i in snap["items"]]
        with open(INTEL_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f)
    except Exception:
        pass  # snapshot is a convenience; never break the app over it


def load_snapshot():
    if PUBLIC:
        return None
    try:
        with open(INTEL_FILE, "r", encoding="utf-8") as f:
            snap = json.load(f)
        snap["saved"] = datetime.fromisoformat(snap["saved"])
        for i in snap["items"]:
            i["published"] = datetime.fromisoformat(i["published"])
        return snap
    except Exception:
        return None


def time_ago(dt):
    if dt is None:
        return "sample"
    mins = int((datetime.now(dt.tzinfo) - dt).total_seconds() // 60)
    return f"{max(mins, 1)}m ago" if mins < 60 else f"{mins // 60}h ago"


@st.cache_data(ttl=900, show_spinner=False)
def _public_feed():
    """Public mode: public news only, shared by everyone, refreshed at most every 15 minutes."""
    data = threat_intel.fetch_recent(INTEL_WINDOW_HOURS)
    if not data["ok"]:
        raise RuntimeError("no feeds reachable")   # raised errors are not cached, so the next visit retries
    data["fetched"] = datetime.now()
    return data


@st.cache_data(ttl=60, show_spinner=False)
def _public_feed_fresh():
    """Manual refresh in public mode: at most one fetch per minute, however many clicks."""
    data = threat_intel.fetch_recent(INTEL_WINDOW_HOURS)
    data["fetched"] = datetime.now()
    return data


def _initial_intel():
    if PUBLIC:
        try:
            data = _public_feed()
            return {**data, "live": True, "saved": data["fetched"], "briefing": None}
        except Exception:
            return SAMPLE_INTEL
    return load_snapshot() or SAMPLE_INTEL


def render_threat_intel():
    st.subheader("🌐 Threat intel")
    st.caption(f"Last {INTEL_WINDOW_HOURS}h · healthcare & life sciences")

    if "intel" not in st.session_state:
        st.session_state.intel = _initial_intel()

    use_ai = st.checkbox("AI briefing on refresh", value=True)
    if PUBLIC and use_ai and not _gemini_key():
        st.caption("Add your Gemini key in the sidebar to get an AI briefing on refresh.")
    if st.button("Refresh live intel"):
        with st.spinner("Fetching live feeds..."):
            data = _public_feed_fresh() if PUBLIC else threat_intel.fetch_recent(INTEL_WINDOW_HOURS)
            items, _ = pick_items(data)
            briefing = None
            if use_ai and items and (_gemini_key() or not PUBLIC):
                try:
                    briefing = build_briefing(items, _gemini_key())
                except Exception:
                    briefing = "AI briefing unavailable (quota or model error). Items shown below."
            snap = {**data, "live": True, "saved": datetime.now(), "briefing": briefing}
            save_snapshot(snap)
            st.session_state.intel = snap

    snap = st.session_state.intel
    if snap["live"]:
        st.caption(f"✅ Live data · fetched {snap['saved']:%H:%M} · {len(snap['ok'])}/{len(threat_intel.FEEDS)} feeds")
    else:
        st.warning("SAMPLE DATA (not live). Click **Refresh live intel** to fetch real items.")

    items, is_hc = pick_items(snap)
    if not items:
        st.info("No items in the last 24h. Try refreshing, or check the feed list.")
    else:
        if snap["live"] and not is_hc:
            st.info("No healthcare-specific items in the last 24h. Showing general threats instead.")
        if snap.get("briefing"):
            st.markdown(snap["briefing"])
        with st.expander(f"Sources ({len(items)})", expanded=not snap.get("briefing")):
            for n, i in enumerate(items, 1):
                title = i["title"].replace("[", "(").replace("]", ")")
                head = f"[{title}]({i['link']})" if i["link"] else f"{title}"
                st.markdown(f"**{n}.** {head}  \n*{i['source']} · {time_ago(i['published'])}*")
    if snap["failed"]:
        st.caption("Unavailable: " + ", ".join(snap["failed"]))


def speed_test():
    """Time a tiny prompt on each candidate model (only runs when the button is clicked)."""
    rows = []
    for name in [llm.MODEL] + llm.fallbacks():
        t0, first = time.time(), None
        try:
            for _ in llm.stream("Reply with the single word: OK", model=name):
                if first is None:
                    first = time.time() - t0
            rows.append({"model": name, "first word (s)": round(first or 0, 1),
                         "total (s)": round(time.time() - t0, 1), "result": "ok"})
        except Exception as e:
            rows.append({"model": name, "first word (s)": None,
                         "total (s)": round(time.time() - t0, 1), "result": str(e)[:50]})
    return rows


# ---------- UI ----------
st.set_page_config(page_title="SOC Workspace", page_icon="🛡️", layout="wide")
_theme_created = False if PUBLIC else ui.ensure_theme_file()   # hosts ship their own .streamlit/config.toml
st.markdown(ui.inject_css(), unsafe_allow_html=True)
header_slot = st.empty()   # filled at the end of the script, once this run's data is known
strip_slot = st.empty()
if _theme_created:
    st.info("Theme file created. Stop the app (Ctrl+C) and run it again once to apply the full SOC Workspace look.")
if PUBLIC:
    st.markdown(
        ui.notice_html("Public workspace", "Nothing is stored on the server. Do not enter PHI, credentials or confidential data. AI requests go to Google using your own key."),
        unsafe_allow_html=True,
    )
    with st.expander("Privacy and data handling"):
        st.markdown(
            "**What this site stores:** nothing. Your notes, screenshots, indicators and scores exist in this session's memory on the server and are discarded when you close or refresh the page. The app writes nothing to disk or logs. The hosting platform may keep standard request logs, such as IP addresses.\n\n"
            "**What leaves the server:** your notes and screenshots are sent to Google's Gemini API with the key you paste. Google's terms say content sent through its free (unpaid) tier can be used to improve its products and read by human reviewers, and that sensitive information should not be submitted there. A key with billing enabled is treated as a paid service. If in doubt, use sanitized data.\n\n"
            "**Threat intel lookups:** only public IPs, domains, URLs and file hashes are sent to VirusTotal or AbuseIPDB, and only if you add your own keys in the IOC intel tab. Internal hosts, users, emails, notes and screenshots never go to those services.\n\n"
            "**Your keys:** held in session memory only, never written anywhere by this app, and removed from any error message before it is shown.\n\n"
            "**Keeping your work:** use *Save workspace* in the sidebar to download your case and *Load workspace* to resume it. Screenshots are not included in saved files.\n\n"
            "**Check your policy:** before using any third-party AI tool with incident data, check your organization's rules."
        )

for _k, _v in (("entries", []), ("report", None), ("enrichment", {}), ("score", None)):
    if _k not in st.session_state:
        st.session_state[_k] = _v

VERDICT_ICON = {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢", "unknown": "⚪", "error": "⚠️"}


def _clear_case_state():
    st.session_state.report = None
    st.session_state.enrichment = {}
    st.session_state.score = None
    st.session_state.pop("ioc_notes", None)
    for k in [k for k in st.session_state if str(k).startswith("step_")]:
        del st.session_state[k]


def _reset_case():
    st.session_state.entries = []
    _clear_case_state()


def _load_demo():
    st.session_state.entries = demo.demo_entries(st.session_state.get("analyst") or None)
    _clear_case_state()
    if not st.session_state.get("case_id"):
        st.session_state["case_id"] = demo.DEMO_CASE_ID


def _pick(label, options, key, default):
    """Pill selector with a fallback for older Streamlit versions."""
    if hasattr(st, "pills"):
        sel = st.pills(label, options, default=default, key=key, label_visibility="collapsed")
    else:
        sel = st.radio(label, options, horizontal=True, key=key, label_visibility="collapsed")
    return sel or default


def _verdict_of(indicator):
    kind = ioc_intel.ioc_kind(str(indicator.get("value", "")), indicator.get("type"))
    r = st.session_state.enrichment.get(ioc_intel.normalize(kind, str(indicator.get("value", ""))), {})
    return r.get("verdict") if r.get("results") else None


def _import_ws():
    up = st.session_state.get("ws_upload")
    if up is None:
        return
    try:
        loaded, analyst_in, case_in = workspace_io.import_workspace(up.getvalue().decode("utf-8", errors="replace"))
        st.session_state.entries = loaded
        _clear_case_state()
        st.session_state["analyst"] = analyst_in
        st.session_state["case_id"] = case_in
        st.session_state["ws_msg"] = ("ok", f"Loaded {len(loaded)} entries. Screenshots are not part of saved files.")
    except ValueError as e:
        st.session_state["ws_msg"] = ("error", str(e))


with st.sidebar:
    if PUBLIC:
        st.markdown("#### AI access")
        st.text_input("Your Gemini API key", type="password", key="gemini_key", placeholder="Paste your key",
                      help="Held in this session's memory only. Never saved or logged.")
        st.caption("Get a key at aistudio.google.com. On Google's free tier, submitted content may be used to improve its products, so use a billing-enabled key or sanitized data.")
        st.divider()
    st.markdown("#### Case")
    st.text_input("Analyst name", key="analyst", placeholder="e.g. A. Rivera")
    st.text_input("Case ID", key="case_id", placeholder="e.g. IR-2026-0142")
    st.button("Load demo case", on_click=_load_demo, width="stretch", help="Fills the Nurse Kim story instantly, with no AI call")
    st.button("Reset case", on_click=_reset_case, width="stretch")
    ws_slot = st.empty()   # the Save button is filled at the end of the script so it always has this run's data
    st.file_uploader("Load workspace (.json)", type=["json"], key="ws_upload", on_change=_import_ws,
                     help="Resume a case you saved earlier. Screenshots are not included in saved files.")
    _wm = st.session_state.get("ws_msg")
    if _wm:
        (st.success if _wm[0] == "ok" else st.error)(_wm[1])
    st.divider()
    if PUBLIC:
        st.caption(f"Model: {llm.MODEL}.")
    else:
        st.caption(f"Model: {llm.MODEL}. Repeated identical inputs are served from a local cache.")
        if st.button("Test model speed"):
            with st.spinner("Timing models..."):
                st.session_state.speed = speed_test()
        if st.session_state.get("speed"):
            st.dataframe(pd.DataFrame(st.session_state.speed), hide_index=True)
            st.caption("Set GEMINI_MODEL in .env to the fastest one, then restart.")

tab_inv, tab_score, tab_ioc, tab_int = st.tabs(["Investigation", "Quality score", "IOC intel", "Integrations"])

# ======================= Investigation =======================
with tab_inv:
    with st.form("input_form", clear_on_submit=True):
        note = st.text_area("Analyst note", height=110,
                            placeholder="Paste a log line or write what you found, e.g. User jsmith logged in from a new country at 14:32...")
        shot = st.file_uploader("Screenshot (optional)", type=["png", "jpg", "jpeg"])
        submitted = st.form_submit_button("Add to investigation", type="primary")
    live = st.empty()

    if submitted:
        if not note and not shot:
            st.warning("Add a note or a screenshot first.")
        elif PUBLIC and not _gemini_key():
            st.warning("Add your Gemini API key in the sidebar first. The demo case works without a key.")
        elif PUBLIC and len(note) > runtime.MAX_NOTE_CHARS:
            st.warning(f"Notes are limited to {runtime.MAX_NOTE_CHARS:,} characters. Split this into two entries.")
        elif PUBLIC and shot is not None and shot.size > runtime.MAX_IMAGE_BYTES:
            st.warning("Screenshots are limited to 4 MB. Crop or compress the image.")
        elif PUBLIC and len(st.session_state.entries) >= runtime.MAX_ENTRIES:
            st.warning(f"A workspace holds up to {runtime.MAX_ENTRIES} entries. Save it and start a new case.")
        else:
            image_bytes = shot.getvalue() if shot else None
            mime = shot.type if shot else None
            started = time.time()
            timing = {"first": None}
            call_info = {}

            def show_status(msg):
                live.markdown(ui.trace_html(msg), unsafe_allow_html=True)

            def show_progress(buf):
                if timing["first"] is None:
                    timing["first"] = time.time() - started
                m = SUMMARY_RE.search(buf)
                partial = m.group(1).replace("\\n", " ").replace('\\"', '"') if m else ""
                live.markdown(ui.trace_html("", partial), unsafe_allow_html=True)

            try:
                show_status(f"waiting for {llm.MODEL}")
                result = analyze(note, image_bytes, mime, st.session_state.entries, show_progress, show_status,
                                 api_key=_gemini_key(), cache=_cache_for("_analysis_cache"), info=call_info)
                evt = result.get("timeline_event", {})
                new_entry = {
                    "submitted": datetime.now().strftime("%H:%M"),
                    "event_time": evt.get("time"),
                    "title": evt.get("title", "Event"),
                    "summary": result.get("summary", ""),
                    "indicators": result.get("indicators", []),
                    "severity": result.get("severity", "medium"),
                    "next_steps": result.get("next_steps", []),
                    "note": note,
                    "image": image_bytes,
                    "analyst": st.session_state.get("analyst") or None,
                }
                new_entry = workspace_io.clean_entry(new_entry) or new_entry   # never trust model output blindly
                new_entry["image"] = image_bytes
                st.session_state.entries.append(new_entry)
                st.session_state.report = None
                live.empty()
                first = timing["first"]
                first_txt = f"first word {first:.1f}s, " if first is not None else ""
                st.caption(f"Analyzed: {first_txt}total {time.time() - started:.1f}s with {call_info.get('model') or llm.last_model}")
                st.toast(f"Added to the timeline: {new_entry['title']} ({ui.SEV_LABEL.get(ui.sev_class(new_entry['severity']), 'Info')})", icon="✅")
            except Exception as e:
                live.empty()
                st.error(f"AI call failed: {_err(e)}")

    entries = st.session_state.entries

    if not entries:
        st.markdown(
            ui.empty_html("No evidence yet", "Paste a log line or drop a screenshot above. The timeline, indicators and next steps build themselves as evidence arrives."),
            unsafe_allow_html=True,
        )
        st.button("Load the Nurse Kim demo case", on_click=_load_demo, key="empty_demo")
    else:
        left, right = st.columns([1.7, 1], gap="large")

        with left:
            st.markdown('<div class="sec">Case timeline</div>', unsafe_allow_html=True)
            sev_pick = _pick("Filter by severity", ["All", "Critical", "High", "Medium", "Low"], "sev_filter", "All")
            ordered = sorted(entries, key=lambda x: x["event_time"] or x["submitted"])
            shown = ordered if sev_pick == "All" else [e for e in ordered if ui.sev_class(e["severity"]) == sev_pick.lower()]
            if shown:
                st.markdown(ui.timeline_html(shown, _verdict_of), unsafe_allow_html=True)
            else:
                st.caption(f"No {sev_pick.lower()} entries yet.")

        with right:
            steps = entries[-1]["next_steps"]
            st.markdown('<div class="sec">Next steps</div>', unsafe_allow_html=True)
            done = 0
            for step in steps:
                if st.checkbox(step, key="step_" + hashlib.md5(step.encode()).hexdigest()[:10]):
                    done += 1
            st.markdown(ui.progress_html(done, len(steps)), unsafe_allow_html=True)
            st.caption(f"{done} of {len(steps)} done. Steps update with every new piece of evidence.")

            ext = [i["value"] for i in ioc_intel.collect_iocs(entries) if i["kind"] in ioc_intel.LOOKUP_KINDS]
            st.markdown('<div class="sec" style="margin-top:18px">External indicators</div>', unsafe_allow_html=True)
            if ext:
                st.code("\n".join(ext), language=None)
                st.caption("Use the copy icon to copy them all. Match them in the IOC intel tab.")
            else:
                st.caption("No external indicators yet.")

        shots = [e for e in entries if e["image"]]
        if shots:
            with st.expander(f"Screenshots ({len(shots)})"):
                cols = st.columns(min(3, len(shots)))
                for n, e in enumerate(shots):
                    cols[n % len(cols)].image(e["image"], caption=e["title"])

        rows = [{"type": i.get("type"), "value": i.get("value"), "from": e["title"]} for e in entries for i in e["indicators"]]
        if rows:
            with st.expander("Indicator table"):
                st.dataframe(pd.DataFrame(rows).drop_duplicates(subset=["type", "value"]), width="stretch")

        st.divider()
        if st.button("Generate incident report"):
            with st.spinner("Writing report..."):
                try:
                    body = generate_report(entries, st.session_state.get("analyst", ""), st.session_state.get("case_id", ""), api_key=_gemini_key())
                    st.session_state.report = body + "\n" + report_appendix(st.session_state.enrichment, st.session_state.score)
                except Exception as e:
                    st.error(f"Report failed: {_err(e)}")
        if st.session_state.report:
            st.markdown(st.session_state.report)
            st.download_button("Download report (.md)", st.session_state.report, file_name="incident_report.md")

entries = st.session_state.entries
analyst = st.session_state.get("analyst", "")
case_id = st.session_state.get("case_id", "")

# ======================= Quality score =======================
with tab_score:
    st.markdown('<div class="sec">Investigation quality score</div>', unsafe_allow_html=True)
    st.caption(
        "An AI review of what was done well, what is missing or not documented, and what to do next. "
        "It is a coaching aid, not a performance rating: a step missing from the notes may have been done but not written down."
    )
    if not entries:
        st.info("Add at least one entry in the Investigation tab first, or load the demo case from the sidebar.")
    else:
        m = scoring.local_metrics(entries, st.session_state.enrichment)
        st.markdown(ui.strip_html([
            ("Screenshots", str(m["with_screenshots"])),
            ("Unique indicators", str(m["unique_iocs"])),
            ("Indicators checked", str(m["iocs_checked"])),
            ("Timestamped", f"{m['pct_timestamped']}%"),
        ]), unsafe_allow_html=True)

        if st.button("Score this investigation", type="primary"):
            with st.spinner("Reviewing the investigation..."):
                try:
                    st.session_state.score = scoring.score_investigation(entries, st.session_state.enrichment, analyst, case_id, api_key=_gemini_key(), cache=_cache_for("_score_cache"))
                except Exception as e:
                    st.error(f"Scoring failed: {_err(e)}")

        sc = st.session_state.score
        if sc:
            if sc["entry_count"] != len(entries):
                st.warning(f"Scored on {sc['entry_count']} entries; {len(entries) - sc['entry_count']} added since. Score again to update.")
            st.markdown(ui.score_header_html(sc["overall"], sc["label"], sc["coaching"]), unsafe_allow_html=True)
            st.markdown(ui.bars_html(sc["categories"]), unsafe_allow_html=True)
            st.write("")
            cd, cn, cs = st.columns(3, gap="large")
            cd.markdown(ui.list_html("Done well", sc["done"], "done", scoring.category_label), unsafe_allow_html=True)
            cn.markdown(ui.list_html("Not done or not documented", sc["not_done"], "gap", scoring.category_label), unsafe_allow_html=True)
            cs.markdown(ui.list_html("Should do next", sc["should_do"], "next", scoring.category_label), unsafe_allow_html=True)
            st.caption(f"Scored at {sc['scored_at']} with {sc['model']}. The overall score is computed from the category scores and fixed weights.")

# ======================= IOC intel =======================
with tab_ioc:
    st.markdown('<div class="sec">IOC intel matching</div>', unsafe_allow_html=True)
    if PUBLIC:
        with st.expander("Use your own VirusTotal and AbuseIPDB keys (optional)"):
            st.text_input("VirusTotal API key", type="password", key="vt_key_in")
            st.text_input("AbuseIPDB API key", type="password", key="abuse_key_in")
            st.caption("Held in this session's memory only. Lookups run from the server and send public indicators only. Free VirusTotal keys are for non-commercial use.")
        vt_key = (st.session_state.get("vt_key_in") or "").strip() or None
        abuse_key = (st.session_state.get("abuse_key_in") or "").strip() or None
    else:
        vt_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    st.caption(
        f"VirusTotal key: {'set' if vt_key else 'not set'}. AbuseIPDB key: {'set' if abuse_key else 'not set'}. "
        "Without keys you still get one-click lookup links for every indicator."
    )
    demo_mode = st.checkbox(
        "Demo mode: simulate results for the fictional demo indicators (always labeled SIMULATED)",
        value=not (vt_key or abuse_key),
        key="ioc_demo",
    )
    st.caption(
        "Privacy: only public IPs, domains, URLs and file hashes are ever sent to an intel source. "
        "Private IPs, hostnames, users, emails, notes and screenshots stay on this machine."
    )
    iocs = ioc_intel.collect_iocs(entries)
    if not iocs:
        st.info("No indicators yet. Add notes or screenshots in the Investigation tab, or load the demo case from the sidebar.")
    else:
        if st.button("Enrich IOCs", type="primary"):
            with st.spinner("Matching indicators against intel sources..."):
                res, notes = ioc_intel.enrich(iocs, abuse_key, vt_key, demo_mode, cache=_cache_for("_ioc_cache"))
                st.session_state.enrichment.update(res)
                st.session_state.ioc_notes = notes
        for note_line in st.session_state.get("ioc_notes", []):
            st.caption(note_line)

        enr = st.session_state.enrichment
        counts = {v: 0 for v in ("malicious", "suspicious", "clean", "unknown")}
        local_n = 0
        for ioc in iocs:
            r = enr.get(ioc["value"], {})
            if r.get("results") and r.get("verdict") in counts:
                counts[r["verdict"]] += 1
            elif r.get("skipped") and ioc["kind"] not in ioc_intel.LOOKUP_KINDS:
                local_n += 1
        st.markdown(
            '<div class="tally">' + ui.strip_html([
                ("Malicious", f'<span style="color:var(--critical)">{counts["malicious"]}</span>'),
                ("Suspicious", f'<span style="color:var(--high)">{counts["suspicious"]}</span>'),
                ("Clean", f'<span style="color:var(--low)">{counts["clean"]}</span>'),
                ("Unknown", str(counts["unknown"])),
                ("Kept local", str(local_n)),
            ]) + "</div>",
            unsafe_allow_html=True,
        )

        type_pick = _pick("Filter by type", ["All", "ip", "domain", "url", "hash", "other"], "ioc_type_filter", "All")
        table = []
        for ioc in iocs:
            shown_type = ioc["type"] if ioc["kind"] == "other" else ioc["kind"]
            if type_pick != "All" and ioc["kind"] != type_pick:
                continue
            r = enr.get(ioc["value"], {})
            links = ioc_intel.lookup_links(ioc["kind"], ioc["value"])
            if r.get("results"):
                intel = " | ".join(f"{x['source']}: {x['summary']}" for x in r["results"])
                verdict = f"{VERDICT_ICON.get(r['verdict'], '')} {r['verdict']}"
            else:
                intel = r.get("skipped") or ""
                verdict = "-"
            table.append({
                "Verdict": verdict, "Type": shown_type, "IOC": ioc["value"], "Intel": intel,
                "VirusTotal": links.get("VirusTotal", ""), "AbuseIPDB": links.get("AbuseIPDB", ""),
                "OTX": links.get("OTX", ""), "Shodan": links.get("Shodan", ""),
            })
        df = pd.DataFrame(table, columns=["Verdict", "Type", "IOC", "Intel", "VirusTotal", "AbuseIPDB", "OTX", "Shodan"])
        link_cfg = {n: st.column_config.LinkColumn(n, display_text="open", width=78) for n in ("VirusTotal", "AbuseIPDB", "OTX", "Shodan")}
        link_cfg.update({
            "Verdict": st.column_config.TextColumn(width=105),
            "Type": st.column_config.TextColumn(width=70),
            "IOC": st.column_config.TextColumn(width=230),
            "Intel": st.column_config.TextColumn(width=250),
        })
        st.dataframe(df, column_config=link_cfg, hide_index=True, width="stretch")
        if any(x.get("simulated") for r in enr.values() for x in r.get("results", [])):
            st.warning("Some results are SIMULATED demo data, not real intel. They are excluded from reports sent to other tools.")
        st.download_button("Download IOC list (.csv)", df[["Verdict", "Type", "IOC", "Intel"]].to_csv(index=False), file_name="iocs.csv")

# ======================= Integrations =======================
with tab_int:
    st.markdown('<div class="sec">Integrations</div>', unsafe_allow_html=True)
    st.caption(
        "Credentials are read from your .env file only. Nothing is sent until you preview and confirm, "
        "and screenshots are never sent."
    )
    by_label = {i.label: i for i in integrations.INTEGRATIONS}
    st.markdown(
        ui.integration_map_svg(
            [("VirusTotal", bool(vt_key)), ("AbuseIPDB", bool(abuse_key))],
            [(i.label.split(" / ")[0].replace(" incident", "").replace(" notification", ""), (not PUBLIC) and i.configured()) for i in integrations.INTEGRATIONS],
        ),
        unsafe_allow_html=True,
    )

    if PUBLIC:
        st.info("Sending cases to ServiceNow, SOAR or Slack is turned off on the public site, because those connections need credentials stored on a server. Download the case below, or self-host SOC Workspace to connect your own tools.")
        if not entries:
            st.info("Add at least one entry in the Investigation tab first, or load the demo case from the sidebar.")
        else:
            include_notes_pub = st.checkbox("Include raw analyst notes in the download (may contain sensitive data)", value=False, key="pub_notes")
            payload_pub = integrations.build_case_payload(entries, analyst, case_id, st.session_state.score, st.session_state.enrichment, include_notes_pub)
            st.download_button("Download case JSON", json.dumps(payload_pub, indent=2), file_name="case.json", mime="application/json")
    else:
        with st.expander("Connection details and setup"):
            status = [
                {"Tool": "VirusTotal (intel)", "Status": "configured" if vt_key else "not configured", "Needs in .env": "VT_API_KEY"},
                {"Tool": "AbuseIPDB (intel)", "Status": "configured" if abuse_key else "not configured", "Needs in .env": "ABUSEIPDB_API_KEY"},
            ] + [
                {"Tool": i.label, "Status": "configured" if i.configured() else "not configured", "Needs in .env": ", ".join(i.env_vars)}
                for i in integrations.INTEGRATIONS
            ]
            st.dataframe(pd.DataFrame(status), hide_index=True, width="stretch")
            st.code(
                "# add to your .env file, then restart the app\n"
                "VT_API_KEY=...\n"
                "ABUSEIPDB_API_KEY=...\n"
                "SOAR_WEBHOOK_URL=https://...        # Tines, Shuffle, n8n and other webhook-triggered SOAR tools\n"
                "SOAR_WEBHOOK_TOKEN=...              # optional, sent as a Bearer token\n"
                "SERVICENOW_INSTANCE=dev12345        # or your full host name\n"
                "SERVICENOW_USER=...\n"
                "SERVICENOW_PASSWORD=...\n"
                "SERVICENOW_TABLE=incident           # optional, e.g. sn_si_incident\n"
                "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...",
                language="text",
            )

        if not entries:
            st.info("Add at least one entry in the Investigation tab first, or load the demo case from the sidebar.")
        else:
            dest = st.selectbox("Send this case to", list(by_label))
            integ = by_label[dest]
            include_notes = st.checkbox("Include raw analyst notes (may contain sensitive data)", value=False)
            payload = integrations.build_case_payload(
                entries, analyst, case_id, st.session_state.score, st.session_state.enrichment, include_notes
            )
            with st.expander("Preview exactly what will be sent", expanded=True):
                st.json(integ.preview(payload))
            if not integ.configured():
                st.warning(f"{dest} is not configured. Add to .env: {', '.join(integ.missing())}")
            confirm = st.checkbox(f"I confirm this case data may be sent to {dest}", key=f"confirm_{integ.key}")
            b1, b2 = st.columns(2)
            if b1.button("Test connection", disabled=not integ.configured()):
                ok, msg = integ.test()
                (st.success if ok else st.error)(msg)
            if b2.button("Send case", disabled=not (integ.configured() and confirm), type="primary"):
                ok, msg = integ.send(payload)
                (st.success if ok else st.error)(msg)
            st.download_button("Download case JSON", json.dumps(payload, indent=2), file_name="case.json", mime="application/json")


# ======================= header + instrument strip (filled last) =======================
_peak = ui.peak_severity(entries)
_steps = entries[-1]["next_steps"] if entries else []
_done = sum(1 for s in _steps if st.session_state.get("step_" + hashlib.md5(s.encode()).hexdigest()[:10]))
_enr = st.session_state.enrichment
_mal = [x for r in _enr.values() if r.get("verdict") == "malicious" for x in r.get("results", [])]
_all_sim = bool(_mal) and all(x.get("simulated") for x in _mal)
_mal_n = sum(1 for r in _enr.values() if r.get("verdict") == "malicious")
_mal_note = f"{_mal_n} malicious" + (" (simulated)" if _all_sim else "") if _mal_n else ""
header_slot.markdown(ui.header_html(case_id, analyst, _peak), unsafe_allow_html=True)
strip_slot.markdown(
    ui.instrument_strip(len(entries), scoring.local_metrics(entries)["span_minutes"], len(ioc_intel.collect_iocs(entries)), _mal_note, _done, len(_steps), st.session_state.score),
    unsafe_allow_html=True,
)


_safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", case_id or "workspace")[:60] or "workspace"
with ws_slot.container():
    st.download_button("Save workspace (.json)", workspace_io.export_workspace(entries, analyst, case_id),
                       file_name=f"{_safe_name}.json", mime="application/json", width="stretch", disabled=not entries,
                       help="Keeps your case on your computer. Screenshots are not included.")


# ---------- threat intel panel ----------
# Rendered LAST so the form and investigation views always appear first.
with st.sidebar:
    st.divider()
    render_threat_intel()

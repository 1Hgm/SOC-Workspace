"""Save and load a case as a plain JSON file, so the analyst keeps their own data.

The public site stores nothing on the server, so a page refresh ends the session. A saved
workspace file lets an analyst resume later. Screenshots are not included (they stay out of
the file to keep it small and private); enrichment and scores can be re-run.

Loaded files are untrusted input: everything is type-checked, trimmed and capped before use.
"""

import json
import re

import runtime

APP_ID = "soc-workspace"
VERSION = 1
MAX_FILE_CHARS = 2_000_000
SEVERITIES = {"low", "medium", "high", "critical"}
_TIME = re.compile(r"^\d{1,2}:\d{2}$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _s(value, limit):
    if value is None:
        return ""
    return _CTRL.sub("", str(value))[:limit]


def _time(value):
    """HH:MM within a real clock range, otherwise None. Checked on the full value, not a trimmed one."""
    v = _s(value, 12).strip()
    if _TIME.match(v):
        hours, minutes = (int(x) for x in v.split(":"))
        if hours < 24 and minutes < 60:
            return v
    return None


def export_workspace(entries, analyst="", case_id=""):
    """JSON text for download. No screenshots."""
    keep = ("submitted", "event_time", "title", "summary", "indicators", "severity", "next_steps", "note", "analyst")
    return json.dumps(
        {
            "app": APP_ID,
            "version": VERSION,
            "case_id": case_id or "",
            "analyst": analyst or "",
            "entries": [{k: e.get(k) for k in keep} for e in entries],
        },
        indent=2,
    )


def _entry(raw):
    if not isinstance(raw, dict):
        return None
    indicators = []
    for i in (raw.get("indicators") if isinstance(raw.get("indicators"), list) else [])[:30]:
        if isinstance(i, dict) and _s(i.get("value"), 300).strip():
            indicators.append({"type": _s(i.get("type"), 20).strip() or "other", "value": _s(i.get("value"), 300).strip()})
    steps = [_s(x, 300) for x in (raw.get("next_steps") if isinstance(raw.get("next_steps"), list) else [])[:8] if _s(x, 300).strip()]
    sev = _s(raw.get("severity"), 10).lower()
    entry = {
        "submitted": _time(raw.get("submitted")) or "00:00",
        "event_time": _time(raw.get("event_time")),
        "title": _s(raw.get("title"), 200).strip() or "Event",
        "summary": _s(raw.get("summary"), 2000),
        "indicators": indicators,
        "severity": sev if sev in SEVERITIES else "medium",
        "next_steps": steps,
        "note": _s(raw.get("note"), runtime.MAX_NOTE_CHARS),
        "image": None,
        "analyst": _s(raw.get("analyst"), 80).strip() or None,
    }
    return entry if (entry["summary"] or entry["note"] or entry["title"] != "Event") else None


clean_entry = _entry   # used by the app to normalise AI output as well as loaded files


def import_workspace(text):
    """Parse and validate a saved workspace. Returns (entries, analyst, case_id).

    Raises ValueError with a plain-English message when the file is not usable.
    """
    if not isinstance(text, str) or len(text) > MAX_FILE_CHARS:
        raise ValueError("That file is too large to be a workspace file.")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise ValueError("That file is not valid JSON.")
    if not isinstance(data, dict) or data.get("app") != APP_ID:
        raise ValueError("That is not a SOC Workspace file.")
    if data.get("version") != VERSION:
        raise ValueError("That workspace file is from an unsupported version.")
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("The workspace file has no entries.")
    entries = [e for e in (_entry(r) for r in raw_entries[: runtime.MAX_ENTRIES]) if e]
    if not entries:
        raise ValueError("The workspace file has no usable entries.")
    return entries, _s(data.get("analyst"), 80).strip(), _s(data.get("case_id"), 80).strip()

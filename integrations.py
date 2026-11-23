"""Connect SOC Workspace to other tools.

Built in:
  * SOAR / generic webhook : POST the case as JSON to any webhook-triggered tool
                             (Tines, Shuffle, n8n, ...). Cortex XSOAR and Splunk SOAR
                             can ingest webhooks/REST too but may need a dedicated connector.
  * ServiceNow             : create an incident through the Table REST API.
  * Slack                  : post a case summary to an incoming webhook.

Safety rules (enforced here and in the UI):
  * Credentials come from .env ONLY. They are never stored in the app or in Git.
  * Nothing is sent until the analyst previews the payload and confirms.
  * Screenshots are never sent. Raw analyst notes are excluded unless the analyst opts in.
  * SIMULATED demo enrichment is never included in outbound payloads.
  * Only https:// URLs are allowed (http only for localhost testing).

.env settings:
  SOAR_WEBHOOK_URL=https://...        SOAR_WEBHOOK_TOKEN=...   (optional, sent as Bearer)
  SERVICENOW_INSTANCE=dev12345        SERVICENOW_USER=...   SERVICENOW_PASSWORD=...
  SERVICENOW_TABLE=incident           (optional; e.g. sn_si_incident for Security Incident Response)
  SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

To add another tool: subclass Integration, implement configured / preview / send / test,
and add it to INTEGRATIONS.
"""

import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

import ioc_intel

TIMEOUT = 10
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# ServiceNow urgency/impact: 1 = high, 2 = medium, 3 = low
SN_MAP = {"critical": (1, 1), "high": (1, 2), "medium": (2, 2), "low": (3, 3)}


# ---------- payload ----------
def peak_severity(entries):
    return max((e.get("severity", "low") for e in entries), key=lambda s: SEV_ORDER.get(s, 0), default="low")


def build_case_payload(entries, analyst="", case_id="", score=None, enrichment=None, include_notes=False):
    """The case as plain JSON. No screenshots; notes only if include_notes is True."""
    peak = peak_severity(entries)
    top = max(entries, key=lambda e: SEV_ORDER.get(e.get("severity", "low"), 0), default=None)
    timeline = []
    for e in sorted(entries, key=lambda x: x.get("event_time") or x.get("submitted") or ""):
        item = {
            "time": e.get("event_time") or e.get("submitted"),
            "title": e.get("title"),
            "severity": e.get("severity"),
            "summary": e.get("summary"),
            "analyst": e.get("analyst"),
        }
        if include_notes:
            item["analyst_note"] = e.get("note")
        timeline.append(item)

    iocs = []
    for ioc in ioc_intel.collect_iocs(entries):
        r = (enrichment or {}).get(ioc["value"], {})
        real = [x for x in r.get("results", []) if not x.get("simulated")]
        iocs.append({
            "type": ioc["type"],
            "value": ioc["value"],
            "verdict": ioc_intel.worst(real) if real else None,
            "sources": [{"source": x["source"], "verdict": x["verdict"], "summary": x["summary"]} for x in real],
        })

    case = {
        "id": case_id or None,
        "analyst": analyst or None,
        "title": f"{(top or {}).get('title', 'Investigation')}",
        "severity": peak,
        "timeline": timeline,
        "iocs": iocs,
        "next_steps": (entries[-1].get("next_steps", []) if entries else []),
    }
    if score:
        case["quality_score"] = {"overall": score["overall"], "label": score["label"]}
    return {
        "source": "soc-workspace",
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "case": case,
    }


def case_text(payload, limit=3500):
    """Plain-text rendering for ticket descriptions and chat messages."""
    c = payload["case"]
    lines = [f"Case: {c.get('id') or 'n/a'} | Analyst: {c.get('analyst') or 'n/a'} | Severity: {c['severity'].upper()}", "", "Timeline:"]
    for t in c["timeline"]:
        lines.append(f"- {t['time']} [{t['severity']}] {t['title']}: {t['summary']}")
    if c["iocs"]:
        lines += ["", "IOCs:"]
        for i in c["iocs"]:
            lines.append(f"- {i['type']}: {i['value']}" + (f" ({i['verdict']})" if i.get("verdict") else ""))
    if c["next_steps"]:
        lines += ["", "Suggested next steps:"] + [f"- {s}" for s in c["next_steps"]]
    text = "\n".join(lines)
    return text if len(text) <= limit else text[: limit - 20] + "\n...[truncated]"


# ---------- helpers ----------
def _valid_url(url):
    p = urlparse(url or "")
    if p.scheme == "https" and p.hostname:
        return True
    return p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1", "::1")


def _mask(url):
    """Hide path/query tokens (Slack and SOAR URLs often embed secrets)."""
    p = urlparse(url or "")
    return f"{p.scheme}://{p.hostname}/***" if p.hostname else "<not set>"


def _post(url, **kw):
    try:
        return requests.post(url, timeout=TIMEOUT, **kw), None
    except requests.RequestException as e:
        return None, f"network error: {str(e)[:80]}"


class Integration:
    key = ""
    label = ""
    env_vars = ()

    def missing(self):
        return [v for v in self.env_vars if not os.getenv(v)]

    def configured(self):
        return not self.missing()


# ---------- SOAR / generic webhook ----------
class SOARWebhook(Integration):
    key = "soar"
    label = "SOAR / generic webhook"
    env_vars = ("SOAR_WEBHOOK_URL",)

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if os.getenv("SOAR_WEBHOOK_TOKEN"):
            h["Authorization"] = f"Bearer {os.getenv('SOAR_WEBHOOK_TOKEN')}"
        return h

    def preview(self, payload):
        masked = {k: ("Bearer ****" if k == "Authorization" else v) for k, v in self._headers().items()}
        return {"method": "POST", "url": _mask(os.getenv("SOAR_WEBHOOK_URL")), "headers": masked,
                "body": {"event": "case_update", **payload}}

    def send(self, payload):
        url = os.getenv("SOAR_WEBHOOK_URL")
        if not _valid_url(url):
            return False, "SOAR_WEBHOOK_URL must be an https:// URL."
        r, err = _post(url, headers=self._headers(), json={"event": "case_update", **payload})
        if err:
            return False, err
        return (200 <= r.status_code < 300), f"HTTP {r.status_code}" + ("" if r.ok else f": {r.text[:120]}")

    def test(self):
        url = os.getenv("SOAR_WEBHOOK_URL")
        if not _valid_url(url):
            return False, "SOAR_WEBHOOK_URL must be an https:// URL."
        r, err = _post(url, headers=self._headers(), json={"event": "connection_test", "source": "soc-workspace"})
        if err:
            return False, err
        return (200 <= r.status_code < 300), f"HTTP {r.status_code}"


# ---------- ServiceNow ----------
class ServiceNow(Integration):
    key = "servicenow"
    label = "ServiceNow incident"
    env_vars = ("SERVICENOW_INSTANCE", "SERVICENOW_USER", "SERVICENOW_PASSWORD")

    def _host(self):
        inst = (os.getenv("SERVICENOW_INSTANCE") or "").strip().lower()
        inst = re.sub(r"^https?://", "", inst).strip("/")
        if inst and "." not in inst:
            inst += ".service-now.com"
        return inst if re.fullmatch(r"[a-z0-9.-]+", inst or "") else ""

    def _table(self):
        t = os.getenv("SERVICENOW_TABLE") or "incident"
        return t if re.fullmatch(r"[a-z0-9_]+", t) else "incident"

    def _url(self):
        h = self._host()
        return f"https://{h}/api/now/table/{self._table()}" if h else ""

    def _body(self, payload):
        c = payload["case"]
        urgency, impact = SN_MAP.get(c["severity"], (2, 2))
        short = f"[SOC Workspace] {c.get('id') or 'Case'}: {c['title']}"
        return {"short_description": short[:160], "description": case_text(payload),
                "urgency": str(urgency), "impact": str(impact)}

    def preview(self, payload):
        return {"method": "POST", "url": self._url() or "<SERVICENOW_INSTANCE not set>",
                "headers": {"Authorization": "Basic ****", "Content-Type": "application/json"},
                "body": self._body(payload)}

    def send(self, payload):
        url = self._url()
        if not url:
            return False, "SERVICENOW_INSTANCE is missing or invalid."
        r, err = _post(url, auth=(os.getenv("SERVICENOW_USER"), os.getenv("SERVICENOW_PASSWORD")),
                       headers={"Content-Type": "application/json", "Accept": "application/json"},
                       json=self._body(payload))
        if err:
            return False, err
        if r.status_code == 201:
            res = r.json().get("result", {})
            return True, f"Created {res.get('number', 'record')} (sys_id {res.get('sys_id', '?')})"
        if r.status_code == 401:
            return False, "Authentication failed. Check SERVICENOW_USER / SERVICENOW_PASSWORD."
        if r.status_code == 403:
            return False, f"Permission denied on table '{self._table()}'."
        return False, f"HTTP {r.status_code}: {r.text[:120]}"

    def test(self):
        url = self._url()
        if not url:
            return False, "SERVICENOW_INSTANCE is missing or invalid."
        try:
            r = requests.get(url, params={"sysparm_limit": 1},
                             auth=(os.getenv("SERVICENOW_USER"), os.getenv("SERVICENOW_PASSWORD")),
                             headers={"Accept": "application/json"}, timeout=TIMEOUT)
        except requests.RequestException as e:
            return False, f"network error: {str(e)[:80]}"
        if r.status_code == 200:
            return True, "Connected (read access to the table confirmed)."
        return False, f"HTTP {r.status_code}"


# ---------- Slack ----------
class Slack(Integration):
    key = "slack"
    label = "Slack notification"
    env_vars = ("SLACK_WEBHOOK_URL",)

    def _body(self, payload):
        c = payload["case"]
        head = f"*SOC Workspace* · {c.get('id') or 'Case'} · severity *{c['severity'].upper()}*\n"
        return {"text": head + case_text(payload, limit=2500)}

    def preview(self, payload):
        return {"method": "POST", "url": _mask(os.getenv("SLACK_WEBHOOK_URL")),
                "headers": {"Content-Type": "application/json"}, "body": self._body(payload)}

    def send(self, payload):
        url = os.getenv("SLACK_WEBHOOK_URL")
        if not _valid_url(url):
            return False, "SLACK_WEBHOOK_URL must be an https:// URL."
        r, err = _post(url, json=self._body(payload))
        if err:
            return False, err
        return (r.status_code == 200), f"HTTP {r.status_code}" + ("" if r.ok else f": {r.text[:80]}")

    def test(self):
        url = os.getenv("SLACK_WEBHOOK_URL")
        if not _valid_url(url):
            return False, "SLACK_WEBHOOK_URL must be an https:// URL."
        r, err = _post(url, json={"text": "SOC Workspace connection test."})
        if err:
            return False, err
        return (r.status_code == 200), f"HTTP {r.status_code}"


INTEGRATIONS = [SOARWebhook(), ServiceNow(), Slack()]

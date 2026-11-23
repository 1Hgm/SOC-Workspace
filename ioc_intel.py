"""IOC matching against OSINT sources.

Two layers, so the feature always works:
  1. Lookup links (no key needed): one-click links to VirusTotal, AbuseIPDB,
     AlienVault OTX and Shodan next to every IOC.
  2. Live enrichment (optional, free API keys in .env): VirusTotal and AbuseIPDB
     verdicts inside the app.
       VT_API_KEY=...          (free public API: 4 requests/min, 500/day,
                                non-commercial use only)
       ABUSEIPDB_API_KEY=...   (free plan: 1,000 checks/day)

Privacy rules (enforced in code):
  * Only PUBLIC IPs, domains, URLs and file hashes are ever sent to a third party.
  * Private IPs, hostnames, usernames, emails, process names, analyst notes and
    screenshots never leave this machine.
  * Fictional demo IOCs (documentation IP ranges, .example domains) are never
    sent; they can optionally be SIMULATED, and every simulated result is labeled.
"""

import base64
import hashlib
import ipaddress
import json
import re
import time
from urllib.parse import quote, urlparse

import requests

CACHE_FILE = "ioc_cache.json"
CACHE_TTL_SECONDS = 24 * 3600
TIMEOUT = 8
VT_PER_MINUTE = 4  # VirusTotal free public API limit

LOOKUP_KINDS = ("ip", "domain", "url", "hash")
VERDICT_RANK = {"malicious": 4, "suspicious": 3, "clean": 2, "unknown": 1, "error": 0}

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$", re.IGNORECASE
)
FILE_EXTS = {
    "exe", "dll", "ps1", "bat", "cmd", "sh", "js", "vbs", "doc", "docx", "xls", "xlsx", "pdf",
    "zip", "txt", "png", "jpg", "lnk", "msi", "scr", "tmp", "log", "py", "iso", "dat", "bin",
}
RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal", "lan", "corp", "home"}
DEMO_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


# ---------- parsing ----------
def refang(value):
    """Turn defanged IOCs (hxxps://evil[.]com) back into normal form for lookups."""
    v = (value or "").strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    for old, new in (("[://]", "://"), ("[.]", "."), ("(.)", "."), ("[dot]", "."),
                     ("[:]", ":"), ("[@]", "@"), ("[at]", "@")):
        v = v.replace(old, new)
    return v


def ioc_kind(value, hinted=None):
    """Classify an IOC: ip | domain | url | hash | email | other."""
    v = refang(value)
    hint = (hinted or "").lower()
    if hint in ("user", "host", "process"):
        return "other"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(v):
        return "hash"
    if re.match(r"^https?://", v, re.IGNORECASE):
        return "url"
    if EMAIL_RE.match(v):
        return "email"
    if DOMAIN_RE.match(v) and v.rsplit(".", 1)[-1].lower() not in FILE_EXTS:
        return "domain"
    return "other"


def normalize(kind, value):
    v = refang(value)
    return v.lower() if kind in ("domain", "hash", "email") else v


def collect_iocs(entries):
    """Unique IOCs across all entries: [{'kind','value','type','from'}]."""
    seen, out = set(), []
    for e in entries:
        for i in e.get("indicators", []):
            raw = str(i.get("value", "")).strip()
            if not raw:
                continue
            kind = ioc_kind(raw, i.get("type"))
            value = normalize(kind, raw)
            if value in seen:
                continue
            seen.add(value)
            out.append({"kind": kind, "value": value, "type": i.get("type") or kind, "from": e.get("title", "")})
    return out


# ---------- safety ----------
def _host_of(kind, value):
    return (urlparse(value).hostname or "") if kind == "url" else value


def _tld(host):
    return host.rsplit(".", 1)[-1].lower() if "." in host else ""


def is_demo_ioc(kind, value):
    """Fictional IOCs (documentation IP ranges, reserved TLDs) used in demos."""
    host = _host_of(kind, value)
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in DEMO_NETS)
    except ValueError:
        pass
    return kind in ("domain", "url") and _tld(host) in RESERVED_TLDS


def safe_to_send(kind, value):
    """(ok, reason). Only public IPs, domains, URLs and hashes may leave the machine."""
    if kind == "hash":
        return True, ""
    if kind in ("ip", "domain", "url"):
        host = _host_of(kind, value)
        try:
            ip = ipaddress.ip_address(host)
            return (ip.is_global, "" if ip.is_global else "private or reserved address stays local")
        except ValueError:
            pass
        if _tld(host) in RESERVED_TLDS or not host:
            return False, "reserved or internal domain stays local"
        return True, ""
    return False, "kept local (users, hosts, emails and process names are never sent)"


# ---------- lookup links (no key needed) ----------
def lookup_links(kind, value):
    """One-click OSINT links for an IOC. Empty for private/internal values."""
    v = refang(value)
    if kind not in LOOKUP_KINDS:
        return {}
    ok, _ = safe_to_send(kind, v)
    if not ok and not is_demo_ioc(kind, v):
        return {}
    links = {}
    if kind == "ip":
        links["VirusTotal"] = f"https://www.virustotal.com/gui/ip-address/{v}"
        links["AbuseIPDB"] = f"https://www.abuseipdb.com/check/{v}"
        links["OTX"] = f"https://otx.alienvault.com/indicator/ip/{v}"
        links["Shodan"] = f"https://www.shodan.io/host/{v}"
    elif kind == "domain":
        links["VirusTotal"] = f"https://www.virustotal.com/gui/domain/{v}"
        links["OTX"] = f"https://otx.alienvault.com/indicator/domain/{v}"
    elif kind == "url":
        links["VirusTotal"] = f"https://www.virustotal.com/gui/search/{quote(v, safe='')}"
        host = urlparse(v).hostname
        if host:
            links["OTX"] = f"https://otx.alienvault.com/indicator/domain/{host}"
    elif kind == "hash":
        links["VirusTotal"] = f"https://www.virustotal.com/gui/file/{v}"
        links["OTX"] = f"https://otx.alienvault.com/indicator/file/{v}"
    return links


# ---------- verdicts ----------
def _verdict_abuse(score):
    return "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"


def _verdict_vt(malicious, suspicious):
    if malicious >= 5:
        return "malicious"
    return "suspicious" if (malicious >= 1 or suspicious >= 1) else "clean"


def worst(results):
    live = [r for r in results if r.get("verdict") in VERDICT_RANK and r["verdict"] != "error"]
    if live:
        return max(live, key=lambda r: VERDICT_RANK[r["verdict"]])["verdict"]
    return "error" if results else None


def _err(source, msg):
    return {"source": source, "verdict": "error", "summary": msg}


# ---------- live lookups ----------
def check_abuseipdb(ip, key):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return _err("AbuseIPDB", f"network error: {str(e)[:60]}")
    if r.status_code == 200:
        d = r.json().get("data", {})
        score = int(d.get("abuseConfidenceScore", 0))
        return {
            "source": "AbuseIPDB",
            "verdict": _verdict_abuse(score),
            "score": score,
            "summary": f"score {score}/100 · {d.get('totalReports', 0)} reports · "
                       f"{d.get('countryCode') or '?'} · {d.get('isp') or '?'}",
        }
    if r.status_code in (401, 403):
        return _err("AbuseIPDB", "API key rejected")
    if r.status_code == 429:
        return _err("AbuseIPDB", "daily quota reached (free plan: 1,000 checks/day)")
    return _err("AbuseIPDB", f"HTTP {r.status_code}")


def _vt_path(kind, value):
    if kind == "ip":
        return f"ip_addresses/{value}"
    if kind == "domain":
        return f"domains/{value}"
    if kind == "hash":
        return f"files/{value}"
    return "urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")


def check_virustotal(kind, value, key):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{_vt_path(kind, value)}",
            headers={"x-apikey": key},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return _err("VirusTotal", f"network error: {str(e)[:60]}")
    if r.status_code == 200:
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(x) for x in stats.values()) or 0
        extra = f", {sus} suspicious" if sus else ""
        return {
            "source": "VirusTotal",
            "verdict": _verdict_vt(mal, sus),
            "summary": f"{mal}/{total} engines flag malicious{extra}",
        }
    if r.status_code == 404:
        return {"source": "VirusTotal", "verdict": "unknown", "summary": "not found in VirusTotal"}
    if r.status_code in (401, 403):
        return _err("VirusTotal", "API key rejected")
    if r.status_code == 429:
        return _err("VirusTotal", "rate limit hit (free: 4/min, 500/day)")
    return _err("VirusTotal", f"HTTP {r.status_code}")


# ---------- demo simulation ----------
DEMO_KNOWN = {  # (AbuseIPDB score or None, VirusTotal malicious engines) for the Nurse Kim demo
    "203.0.113.45": (94, 17),
    "198.51.100.23": (88, 12),
    "198.51.100.77": (81, 9),
    "203.0.113.99": (97, 21),
    "northbridge-login.example": (None, 15),
    "northbridge-health-helpdesk.example": (None, 11),
    "cdn-sync-update.example": (None, 13),
}


def simulate(kind, value):
    """Deterministic FAKE results for fictional demo IOCs. Always labeled SIMULATED."""
    known = DEMO_KNOWN.get(value) or DEMO_KNOWN.get(_host_of(kind, value))
    if known:
        abuse, vt_mal = known
    else:
        h = int(hashlib.sha256(value.encode()).hexdigest()[:4], 16)
        abuse = h % 100 if kind == "ip" else None
        vt_mal = (h // 100) % 20
    out = []
    if kind == "ip" and abuse is not None:
        out.append({"source": "AbuseIPDB", "verdict": _verdict_abuse(abuse), "score": abuse,
                    "summary": f"SIMULATED · score {abuse}/100", "simulated": True})
    out.append({"source": "VirusTotal", "verdict": _verdict_vt(vt_mal, 0),
                "summary": f"SIMULATED · {vt_mal}/92 engines flag malicious", "simulated": True})
    return out


# ---------- cache ----------
def _load_cache():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception:
        pass


def _cache_get(cache, source, value, now):
    hit = cache.get(f"{source}|{value}")
    if hit and now - hit["t"] < CACHE_TTL_SECONDS:
        return hit["res"]
    return None


def _cache_put(cache, source, value, res, now):
    if res.get("verdict") in ("malicious", "suspicious", "clean", "unknown") and not res.get("pending"):
        cache[f"{source}|{value}"] = {"t": now, "res": res}


# ---------- orchestration ----------
def _pack(kind, results, skipped=None):
    return {"kind": kind, "results": results, "verdict": worst(results) if results else None, "skipped": skipped}


def enrich(iocs, abuse_key=None, vt_key=None, demo=False, cache=None):
    """Match IOCs against OSINT sources.

    Returns (results, notes): results maps IOC value -> {'kind','results','verdict','skipped'}.

    cache: optional dict (public mode: per-session memory, nothing touches disk). When None, a
    local file cache is used.
    """
    now = time.time()
    persist = cache is None
    if persist:
        cache = _load_cache()
    recent_vt = [t for t in cache.get("_vt_calls", []) if now - t < 60]
    vt_budget = max(0, VT_PER_MINUTE - len(recent_vt))
    results, notes = {}, []
    local = deferred = missing_keys = 0

    for ioc in iocs:
        kind, value = ioc["kind"], ioc["value"]
        if kind not in LOOKUP_KINDS:
            results[value] = _pack(kind, [], "kept local")
            local += 1
            continue
        if is_demo_ioc(kind, value):
            if demo:
                results[value] = _pack(kind, simulate(kind, value))
            else:
                results[value] = _pack(kind, [], "fictional IOC, not sent (turn on Demo mode to simulate)")
            continue
        ok, reason = safe_to_send(kind, value)
        if not ok:
            results[value] = _pack(kind, [], reason)
            local += 1
            continue

        res = []
        if kind == "ip" and abuse_key:
            r = _cache_get(cache, "AbuseIPDB", value, now)
            if not r:
                r = check_abuseipdb(value, abuse_key)
                _cache_put(cache, "AbuseIPDB", value, r, now)
            res.append(r)
        if vt_key:
            r = _cache_get(cache, "VirusTotal", value, now)
            if r:
                res.append(r)
            elif vt_budget > 0:
                vt_budget -= 1
                recent_vt.append(time.time())
                r = check_virustotal(kind, value, vt_key)
                _cache_put(cache, "VirusTotal", value, r, now)
                res.append(r)
            else:
                deferred += 1
                res.append({"source": "VirusTotal", "verdict": "unknown", "pending": True,
                            "summary": "deferred: free tier allows 4 lookups/min. Click Enrich again in a minute."})
        if not res:
            missing_keys += 1
            results[value] = _pack(kind, [], "no API key configured (use the lookup links)")
        else:
            results[value] = _pack(kind, res)

    cache["_vt_calls"] = recent_vt
    if persist:
        _save_cache(cache)
    if local:
        notes.append(f"{local} item(s) kept local (private IPs, hosts, users, emails are never sent).")
    if deferred:
        notes.append(f"{deferred} VirusTotal lookup(s) deferred by the free 4/min limit. Click Enrich again in a minute.")
    if missing_keys:
        notes.append(f"{missing_keys} IOC(s) not looked up because no API key is set. Use the lookup links instead.")
    return results, notes

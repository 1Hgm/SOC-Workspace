"""Recent threat intel from public RSS/Atom feeds. No API keys needed.

Edit FEEDS to add or remove sources. If a feed URL stops working, the app
simply skips it and shows which feeds failed.
"""

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape

import requests

FEEDS = {
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "HIPAA Journal": "https://www.hipaajournal.com/feed/",
    "The Record": "https://therecord.media/feed",
    "SecurityWeek": "https://feeds.feedburner.com/securityweek",
    "DataBreaches.net": "https://databreaches.net/feed/",
}

HC_PATTERN = re.compile(
    r"\b(hospitals?|health\w*|medical|medicine|patients?|pharma\w*|biotech\w*|"
    r"life sciences?|clinical|clinics?|hipaa|ehr|drug ?makers?|laborator\w*|"
    r"genomic\w*|diagnostics?|telehealth|medtech)\b",
    re.IGNORECASE,
)

HEADERS = {"User-Agent": "Mozilla/5.0 (SOC-Scribe hackathon POC)"}


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _child_text(el, names):
    for c in el:
        if _local(c.tag) in names and (c.text or "").strip():
            return c.text.strip()
    return ""


def _link(el):
    for c in el:
        if _local(c.tag) == "link":
            href = c.get("href") or (c.text or "").strip()
            if href:
                return href
    return ""


def _clean(text, limit=300):
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", unescape(text)).strip()
    return text[:limit]


def _parse_date(value):
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_feed(xml_bytes, source):
    """Parse RSS 2.0 or Atom bytes into a list of item dicts."""
    root = ET.fromstring(xml_bytes)
    items = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        title = _clean(_child_text(el, {"title"}), 200)
        published = _parse_date(_child_text(el, {"pubDate", "published", "updated", "date"}))
        if not title or not published:
            continue
        summary = _clean(_child_text(el, {"description", "summary", "content", "encoded"}))
        link = _link(el)
        if not link.lower().startswith(("http://", "https://")):
            link = ""  # never render javascript: or other schemes from untrusted feeds
        items.append(
            {
                "title": title,
                "link": link,
                "source": source,
                "published": published,
                "summary": summary,
                "healthcare": bool(HC_PATTERN.search(f"{title} {summary}")),
            }
        )
    return items


def _fetch_one(name, url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=5)
        resp.raise_for_status()
        return name, parse_feed(resp.content, name), None
    except Exception as e:  # network, HTTP, or XML error: skip this feed
        return name, [], str(e)[:80]


def fetch_recent(hours=24):
    """Return {'items': newest-first list within `hours`, 'ok': [...], 'failed': [...]}."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    with ThreadPoolExecutor(max_workers=len(FEEDS)) as pool:
        results = list(pool.map(lambda kv: _fetch_one(*kv), FEEDS.items()))

    items, ok, failed, seen = [], [], [], set()
    for name, feed_items, err in results:
        if err:
            failed.append(name)
            continue
        ok.append(name)
        for it in feed_items:
            key = it["title"].lower()
            if it["published"] >= cutoff and key not in seen:
                seen.add(key)
                items.append(it)
    items.sort(key=lambda x: x["published"], reverse=True)
    return {"items": items, "ok": ok, "failed": failed}

"""Runtime mode and limits.

SOC_PUBLIC_MODE=1 turns on the stateless, bring-your-own-key mode meant for a public site:
  * no files are written (no caches, snapshots or theme files)
  * every AI call uses the analyst's own Gemini key, held only in their session memory
  * keys and credentials in server environment variables are never used
  * sending cases to ServiceNow, SOAR or Slack is disabled (credentials would have to live
    on the server)
Without the flag the app behaves as before: a local, single-user tool.
"""

import os

_TRUE = ("1", "true", "yes", "on")


def _detect_public():
    """Public mode is switched on by, in order:
      1. the SOC_PUBLIC_MODE environment variable (an explicit 0/false also wins)
      2. running on Google Cloud Run (it sets K_SERVICE), so a deploy there is safe by default
      3. SOC_PUBLIC_MODE in Streamlit's Secrets (Streamlit Community Cloud)
    """
    explicit = os.getenv("SOC_PUBLIC_MODE")
    if explicit is not None and explicit.strip() != "":
        return explicit.strip().lower() in _TRUE
    if os.getenv("K_SERVICE"):
        return True
    try:
        import streamlit as st

        return str(st.secrets.get("SOC_PUBLIC_MODE", "")).strip().lower() in _TRUE
    except Exception:
        return False


PUBLIC = _detect_public()

# Limits that keep a public instance small and cheap to run
MAX_ENTRIES = 60               # evidence entries per session
MAX_NOTE_CHARS = 8000          # characters per analyst note
MAX_IMAGE_BYTES = 4 * 1024 * 1024

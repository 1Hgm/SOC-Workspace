"""Small Gemini helper used by app.py.

Speed + reliability tricks:
  * asks for LOW "thinking" (latency saver); falls back automatically if the
    model rejects that setting
  * streaming, so text can be shown while it is still being generated
  * if Google answers 503 "high demand", retries briefly (1s, 2s), then
    automatically tries a backup Flash model (auto-discovered, or set
    GEMINI_FALLBACK_MODEL in .env, comma-separated for several)
  * if the main model hits a quota limit (429), also tries the backup model

This module is imported once and stays in memory between Streamlit reruns, so
the client, flags, and discovered backups persist.
"""

import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import types

import runtime

load_dotenv()

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
last_model = MODEL  # which model answered most recently (shown in the UI)

_client = None
_thinking_ok = True
_fallbacks = None

SKIP_WORDS = ("image", "tts", "audio", "live", "robotics", "computer-use", "embedding", "lite-preview-image")


def client(api_key=None):
    """A Gemini client.

    With api_key (public mode: the analyst's own key) a fresh client is built for that call and
    never stored, so keys cannot leak between sessions. Without it, the local .env key is used,
    except in public mode, where the server's environment is deliberately ignored.
    """
    global _client
    if api_key:
        return genai.Client(api_key=api_key)
    if runtime.PUBLIC:
        raise RuntimeError("Add your Gemini API key in the sidebar to use the AI features.")
    if _client is None:
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            raise RuntimeError("GEMINI_API_KEY not found. Add it to your .env file.")
        _client = genai.Client(api_key=key)
    return _client


def _release(c, api_key):
    """Close a client we created for one call (public mode). The shared local client stays open.

    google-genai closes its HTTP connection when a Client object is garbage collected, so a
    client created inline would be closed mid-stream. We keep a reference for the whole call
    and close it ourselves afterwards.
    """
    if api_key:
        try:
            c.close()
        except Exception:
            pass  # test fakes and older SDKs may not have close()


def _msg(err):
    return str(err).lower()


def _is_thinking_error(err):
    return "think" in _msg(err)


def _is_busy(err):
    return any(k in _msg(err) for k in ("503", "unavailable", "high demand", "overloaded", "504", "deadline"))


def _is_quota(err):
    return "429" in _msg(err) or "resource_exhausted" in _msg(err)


def _config(use_thinking, cfg):
    if use_thinking:
        return types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_level="low"), **cfg
        )
    return types.GenerateContentConfig(**cfg)


def fallbacks(api_key=None):
    """Backup models to try when the main one is overloaded. Looked up once, lazily."""
    global _fallbacks
    if _fallbacks is not None:
        return _fallbacks
    env = os.getenv("GEMINI_FALLBACK_MODEL", "")
    names = [m.strip() for m in env.split(",") if m.strip()]
    if not names:
        try:
            found = []
            c = client(api_key)   # keep a reference while the model list is read
            try:
                for m in c.models.list():
                    n = (m.name or "").removeprefix("models/")
                    actions = getattr(m, "supported_actions", None) or []
                    if (
                        "flash" in n
                        and n != MODEL
                        and "generateContent" in actions
                        and not any(w in n for w in SKIP_WORDS)
                    ):
                        found.append(n)
            finally:
                _release(c, api_key)
            stable = sorted([n for n in found if "preview" not in n and "exp" not in n], reverse=True)
            other = sorted([n for n in found if n not in stable], reverse=True)
            names = (stable + other)[:2]
        except Exception:
            names = []
    _fallbacks = [n for n in names if n != MODEL]
    return _fallbacks


def stream(contents, model=None, on_status=None, api_key=None, info=None, **cfg):
    """Yield text pieces as they arrive, with retry + backup-model fallback.

    model:     use exactly this model (no fallback), handy for speed tests
    on_status: optional callback(str) that reports retries / model switches
    api_key:   the caller's own key (public mode); never stored
    info:      optional dict that receives {'model': name} for this call only
    """
    global _thinking_ok, last_model

    def say(msg):
        if on_status:
            on_status(msg)

    candidates = [model or MODEL]
    last_err = None
    i = 0
    while i < len(candidates):
        name = candidates[i]
        for attempt in range(3):
            use = _thinking_ok
            got_any = False
            c = None
            try:
                c = client(api_key)   # keep this reference until the stream is finished
                for chunk in c.models.generate_content_stream(
                    model=name, contents=contents, config=_config(use, cfg)
                ):
                    got_any = True
                    if chunk.text:
                        yield chunk.text
                last_model = name
                if info is not None:
                    info["model"] = name
                return
            except Exception as e:
                last_err = e
                if got_any:
                    raise  # failed mid-answer: can't restart without duplicating text
                if use and _is_thinking_error(e):
                    _thinking_ok = False
                    continue
                if _is_busy(e) and attempt < 2:
                    say(f"{name} is busy, retrying ({attempt + 2}/3)...")
                    time.sleep(1.0 * (attempt + 1))
                    continue
                if _is_busy(e) or _is_quota(e):
                    break  # give up on this model, try the next one
                raise  # real error (bad key, bad request...): show it
            finally:
                if c is not None:
                    _release(c, api_key)   # closes only per-call clients, after the stream ends or fails
        if i == 0 and model is None:
            candidates += fallbacks(api_key)
        i += 1
        if i < len(candidates):
            say(f"{name} unavailable, switching to {candidates[i]}...")
    raise RuntimeError(
        "Gemini is overloaded or out of quota right now, and backup models did not help. "
        f"Wait a minute and try again. Last error: {last_err}"
    )


def generate(contents, retries=0, api_key=None, **cfg):
    """Return the full response text (same retry/fallback behaviour as stream)."""
    return "".join(stream(contents, api_key=api_key, **cfg))

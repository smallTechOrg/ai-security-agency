from __future__ import annotations

# Runtime selection for the LLM used by report intelligence.
# Deterministic (no LLM) is the default to keep testing free; live providers
# are only invoked when explicitly selected in the UI.

AVAILABLE = [
    {"id": "deterministic", "label": "Deterministic (no LLM, free)", "provider": "none", "model": ""},
    {"id": "gemini", "label": "Gemini 2.5 Flash Lite (cheap testing)", "provider": "gemini", "model": "gemini-2.5-flash-lite"},
    {"id": "gemini-flash", "label": "Gemini 2.5 Flash", "provider": "gemini", "model": "gemini-2.5-flash"},
    {"id": "openai", "label": "OpenAI GPT-4.1 mini (demo)", "provider": "openai", "model": "gpt-4.1-mini"},
]

_IDS = {a["id"]: a for a in AVAILABLE}
_current = {"mode": "deterministic"}


def get_mode() -> str:
    return _current["mode"]


def current_entry() -> dict:
    return _IDS.get(_current["mode"], AVAILABLE[0])


def set_mode(mode: str) -> dict:
    if mode not in _IDS:
        raise ValueError(f"unknown intelligence mode: {mode}")
    _current["mode"] = mode
    return current_entry()

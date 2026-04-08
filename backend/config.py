import re
import os

# Enable online STT fallback when offline fails
os.environ["SENTINEL_ALLOW_ONLINE_STT"] = "1"

ASSISTANT_NAME = "zaris"
ASSISTANT_DISPLAY_NAME = "Zaris AI"
USER_TITLE = "operator"

ASSISTANT_ALIASES = [
    "zaris",
    "hey zaris",
    "ok zaris",
    "jarvis",
    "hey jarvis",
    "sentinel",
    "security",
    "guard system",
    "security console",
    "cyber guard",
    "secure mode",
    "dhriti",
    "dhrithi",
    "dhirithi",
    "driti",
]


def normalize_assistant_text(text):
    if not text:
        return text

    normalized = str(text)
    normalized = re.sub(r"\bmamu\b", USER_TITLE, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bdhriti\b", ASSISTANT_DISPLAY_NAME, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bdhrithi\b", ASSISTANT_DISPLAY_NAME, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bdhirithi\b", ASSISTANT_DISPLAY_NAME, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bdriti\b", ASSISTANT_DISPLAY_NAME, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bsentinel\b", ASSISTANT_DISPLAY_NAME, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bzaris\b", ASSISTANT_DISPLAY_NAME, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bjarvis\b", ASSISTANT_DISPLAY_NAME, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bhey\s+t\.y\.1\b", f"Hey {ASSISTANT_DISPLAY_NAME}", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bhaan\s+sir\s*,", "Haan operator,", normalized, flags=re.IGNORECASE)
    return normalized


GEMINI_API_KEY = ""

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

LLM_PROVIDER = "groq"

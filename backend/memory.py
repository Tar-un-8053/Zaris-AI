# backend/memory.py
import json
import os
from datetime import datetime

from backend.config import ASSISTANT_DISPLAY_NAME, normalize_assistant_text

MEMORY_FILE = "backend/memory.json"
HISTORY_FILE = "backend/chat_history.json"


def load_memory():
    if not os.path.exists(MEMORY_FILE):
        return {}
    with open(MEMORY_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_memory(memory):
    with open(MEMORY_FILE, "w", encoding="utf-8") as file:
        json.dump(memory, file, ensure_ascii=False, indent=2)


def remember(key, value):
    memory = load_memory()
    memory[key] = value
    save_memory(memory)


def recall(key):
    memory = load_memory()
    return memory.get(key)


def _load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return []


def _save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, ensure_ascii=False, indent=2)


def add_conversation(user_text, assistant_reply, command_type="chat"):
    history = _load_history()
    cleaned_reply = normalize_assistant_text(assistant_reply)
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user_text,
        "assistant": cleaned_reply,
        "dhriti": cleaned_reply,
        "type": command_type,
    }
    history.append(entry)

    if len(history) > 500:
        history = history[-500:]

    _save_history(history)


def get_recent_history(n=3):
    history = _load_history()
    return history[-n:] if history else []


def get_history_summary():
    recent = get_recent_history(8)
    if not recent:
        return ""

    lines = []
    for entry in recent:
        assistant_reply = entry.get("assistant") or entry.get("dhriti") or ""
        lines.append(f"User: {entry.get('user', '')}")
        lines.append(f"{ASSISTANT_DISPLAY_NAME}: {normalize_assistant_text(assistant_reply)}")

    return "\n".join(lines)


def get_total_conversations():
    history = _load_history()
    return len(history)

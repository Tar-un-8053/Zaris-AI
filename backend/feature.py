import json
import os
import threading
import time
from pathlib import Path

import speech_recognition as sr
import backend.command as command_runtime

from backend.command import capture_audio_with_lock, is_speaking, speak, takecommand, transcribe_audio, request_cancel, clear_cancel, is_cancel_requested
from backend.security.zaris_core import ZARIS_HELP_TEXT, execute_core_command, normalize_core_command
from backend.security.storage import log_security_event

_wake_recognizer = sr.Recognizer()
_wake_recognizer.energy_threshold = 350
_wake_recognizer.dynamic_energy_threshold = True
_wake_recognizer.dynamic_energy_adjustment_damping = 0.15
_wake_recognizer.dynamic_energy_ratio = 1.5
_wake_recognizer.pause_threshold = 0.5
_wake_recognizer.non_speaking_duration = 0.15
_wake_recognizer.phrase_threshold = 0.15

WAKE_WORDS = [
    "zaris",
    "hey zaris",
    "ok zaris",
    "jarvis",
    "hey jarvis",
]

BYE_WORDS = [
    "bye",
    "stop",
    "standby",
    "cancel",
    "band",
    "ruk",
    "bas",
]

TERMINATE_WORDS = [
    "terminate",
    "cancel command",
    "stop command",
    "abort",
    "ruk jao",
    "band karo",
    "cancel karo",
    "stop current",
    "stop execution",
    "abort command",
    "kill command",
]

SECURITY_HELP_TEXT = ZARIS_HELP_TEXT
PERMANENT_MIC_LISTENING = os.getenv("SENTINEL_PERMANENT_MIC", "0").strip().lower() not in {"0", "false", "no"}
CHATBOT_SINGLE_TURN_MODE = os.getenv("SENTINEL_SINGLE_TURN_CHAT", "0").strip().lower() not in {"0", "false", "no"}
ZARIS_CORE_ONLY_MODE = os.getenv("ZARIS_CORE_ONLY_MODE", os.getenv("JARVIS_CORE_ONLY_MODE", "0")).strip().lower() not in {"0", "false", "no"}
HOTWORD_TIMEOUT_SEC = 0.8
HOTWORD_PHRASE_LIMIT_SEC = 2.0
DIRECT_COMMAND_COOLDOWN_SEC = 2.0


def _read_int_env(name, default_value):
    raw = os.getenv(name)
    if raw is None:
        return default_value
    try:
        value = int(str(raw).strip())
        return max(0, value)
    except Exception:
        return default_value


def _read_float_env(name, default_value):
    raw = os.getenv(name)
    if raw is None:
        return default_value
    try:
        value = float(str(raw).strip())
        return max(0.0, value)
    except Exception:
        return default_value


DEFAULT_SILENCE_LIMIT = 0 if PERMANENT_MIC_LISTENING else 3
CONVERSATION_MAX_SILENCE = _read_int_env("SENTINEL_CONVERSATION_MAX_SILENCE", DEFAULT_SILENCE_LIMIT)
COMMAND_REPEAT_WINDOW_SEC = _read_float_env("SENTINEL_COMMAND_REPEAT_WINDOW_SEC", 2.2)
HELP_REPEAT_WINDOW_SEC = _read_float_env("SENTINEL_HELP_REPEAT_WINDOW_SEC", 30.0)
SELF_ECHO_WINDOW_SEC = _read_float_env("SENTINEL_SELF_ECHO_WINDOW_SEC", 22.0)
POST_SPEECH_DELAY_SEC = 0.5
VOICE_CHAT_ENABLED = os.getenv("SENTINEL_VOICE_CHAT", "1").strip().lower() not in {"0", "false", "no"}
CUSTOM_COMMANDS_FILE = os.getenv("SENTINEL_CUSTOM_COMMANDS_FILE", "backend/custom_commands.json").strip()
DEDUPED_SOURCES = {"mic_button", "always_on_mic", "wake_phrase", "wake_listener", "conversation"}
DIRECT_COMMANDS = {
    "scan downloads",
    "show risky files",
    "system status",
    "last scan summary",
    "jarvis help",
    "security setup",
    "security status",
    "security mode on",
    "unlock system",
    "show intruder log",
    "show full history",
    "capture intruder",
    "threat score",
    "panic mode",
    "decoy mode",
    "lock laptop for security",
    "continuous auth on",
    "continuous auth off",
    "startup protection on",
    "startup protection off",
    "security face enroll",
    "security voice enroll",
    "quick security",
    "cyber hardening",
    "vault status",
    "vault setup",
    "vault unlock",
    "vault lock",
    "vault backup",
    "alert status",
    "test alert",
    "popup alert on",
    "popup alert off",
    "sound alert on",
    "sound alert off",
    "email alert on",
    "email alert off",
    "telegram alert on",
    "telegram alert off",
    "memory dashboard",
    "study history",
    "weak topics",
    "strong topics",
    "revision plan",
    "verify memory integrity",
    "scan folders",
    "show duplicates",
    "show unused",
    "folder scan status",
    "activity today",
    "activity log",
    "delete file",
    "delete folder",
    "check file",
    "daily summary",
    "show alerts",
    "test alert",
    "telegram on",
    "telegram off",
    "show disk",
    "show memory",
    "show processes",
    "show graph",
}
SENSITIVE_HISTORY_MARKERS = [
    "set security pin",
    "pin set",
    "set security phrase",
    "security phrase set",
    "vault setup",
    "vault unlock",
    "vault protect",
    "vault restore",
    "set alert email password",
    "telegram alert setup",
]

_last_wake_adjust = 0
_wake_active = True
_conversation_active = False
_last_direct_command = ""
_last_direct_command_at = 0.0
_last_handled_command = ""
_last_handled_command_at = 0.0
_last_handled_command_source = ""
_custom_commands_mtime = None
_custom_alias_rules = []
_custom_reply_rules = []


def _normalize_text(text):
    return str(text or "").strip().lower()


def _normalize_phrase(text):
    return " ".join(str(text or "").strip().lower().split())


def _load_custom_commands():
    global _custom_commands_mtime, _custom_alias_rules, _custom_reply_rules

    commands_path = Path(CUSTOM_COMMANDS_FILE or "backend/custom_commands.json")

    try:
        current_mtime = commands_path.stat().st_mtime
    except FileNotFoundError:
        _custom_commands_mtime = None
        _custom_alias_rules = []
        _custom_reply_rules = []
        return
    except Exception as exc:
        print(f"Custom commands stat failed: {exc}")
        return

    if _custom_commands_mtime is not None and current_mtime == _custom_commands_mtime:
        return

    try:
        payload = json.loads(commands_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Custom commands load failed: {exc}")
        return

    alias_rules = []
    for item in payload.get("aliases", []):
        if not isinstance(item, dict):
            continue

        rewrite_to = _normalize_phrase(item.get("rewrite_to"))
        triggers = item.get("triggers", item.get("trigger", []))
        if isinstance(triggers, str):
            triggers = [triggers]

        if not rewrite_to:
            continue

        for trigger in triggers:
            normalized_trigger = _normalize_phrase(trigger)
            if normalized_trigger:
                alias_rules.append((normalized_trigger, rewrite_to))

    reply_rules = []
    for item in payload.get("replies", []):
        if not isinstance(item, dict):
            continue

        reply_text = str(item.get("reply", "")).strip()
        triggers = item.get("triggers", item.get("trigger", []))
        if isinstance(triggers, str):
            triggers = [triggers]

        if not reply_text:
            continue

        for trigger in triggers:
            normalized_trigger = _normalize_phrase(trigger)
            if normalized_trigger:
                reply_rules.append((normalized_trigger, reply_text))

    alias_rules.sort(key=lambda pair: len(pair[0]), reverse=True)
    reply_rules.sort(key=lambda pair: len(pair[0]), reverse=True)

    _custom_alias_rules = alias_rules
    _custom_reply_rules = reply_rules
    _custom_commands_mtime = current_mtime


def _match_custom_alias(normalized_query):
    _load_custom_commands()
    normalized = _normalize_phrase(normalized_query)
    if not normalized:
        return ""

    for trigger, rewrite_to in _custom_alias_rules:
        if normalized == trigger or trigger in normalized:
            return rewrite_to
    return ""


def _match_custom_reply(normalized_query):
    _load_custom_commands()
    normalized = _normalize_phrase(normalized_query)
    if not normalized:
        return ""

    for trigger, reply_text in _custom_reply_rules:
        if normalized == trigger or trigger in normalized:
            return reply_text
    return ""


def _sanitize_query_for_history(query):
    text = str(query or "").strip()
    lowered = text.lower()

    for marker in SENSITIVE_HISTORY_MARKERS:
        marker_lower = marker.lower()
        if lowered.startswith(marker_lower):
            return f"{marker} [REDACTED]"
        if marker_lower in lowered:
            return f"{marker} [REDACTED]"
    return text


def _log_activity_history(event_type, success=True, query="", source="", reason="", metadata=None):
    try:
        safe_query = _sanitize_query_for_history(query)
        log_security_event(
            event_type,
            success,
            reason=reason or event_type,
            voice_text=safe_query,
            metadata={
                "source": source or "unknown",
                **(metadata or {}),
            },
        )
    except Exception as exc:
        print(f"History log skip: {exc}")


def _is_bye(query):
    q = _normalize_text(query)
    return any(word in q for word in BYE_WORDS)


def _is_terminate(query):
    q = _normalize_text(query)
    return any(word in q for word in TERMINATE_WORDS)


def _check_wake_word(text):
    normalized = _normalize_text(text)
    if not normalized:
        return False, ""

    for wake_word in WAKE_WORDS:
        if wake_word in normalized:
            remaining = normalized.split(wake_word, 1)[1].strip(" ,.-")
            return True, remaining
    return False, ""


def _maybe_adjust_wake_noise(source):
    global _last_wake_adjust

    now = time.time()
    if now - _last_wake_adjust < 10:
        return

    _wake_recognizer.adjust_for_ambient_noise(source, duration=0.08)
    _last_wake_adjust = now


def _rewrite_inline_command(query):
    normalized = _normalize_text(query)
    if not normalized:
        return ""

    if "help jarvis" in normalized:
        return "jarvis help"

    script_aliases = {
        "\u0905\u0932\u0930\u094d\u091f": "alert",
        "\u0938\u093f\u0915\u094d\u092f\u094b\u0930\u093f\u091f\u0940": "security",
        "\u0939\u0947\u0932\u094b": "hello",
        "\u0939\u0947\u0932\u094d\u092a": "help",
    }
    normalized = script_aliases.get(normalized, normalized)

    jarvis_core_command = normalize_core_command(normalized)
    if jarvis_core_command:
        return jarvis_core_command

    custom_alias = _match_custom_alias(normalized)
    if custom_alias:
        return custom_alias

    tail_aliases = {
        "set pin": "set security pin",
        "pin set": "set security pin",
        "set phrase": "set security phrase",
        "phrase set": "set security phrase",
        "pin hata": "remove security pin",
        "remove pin": "remove security pin",
        "clear pin": "remove security pin",
        "study add": "memory add",
        "add study": "memory add",
        "add memory": "memory add",
        "note add": "memory add",
        "scan file": "scan file",
        "check file": "scan file",
        "file scan": "scan file",
        "is this file safe": "scan file",
        "check if file safe": "scan file",
        "analyze file": "scan file",
        "scan this": "scan file",
        "is file harmful": "scan file",
        "is file dangerous": "scan file",
    }
    for source, target in tail_aliases.items():
        if normalized.startswith(source):
            tail = normalized[len(source) :].strip(" :.-")
            return f"{target} {tail}".strip()

    if normalized.startswith("memory add"):
        return normalized

    alias_groups = [
        ("security setup", ["security setup", "guard setup", "configure security", "setup security"]),
        ("security status", ["security status", "guard status", "system status", "status report"]),
        ("security mode on", ["security mode on", "start security", "security on", "guard mode on", "protect my laptop", "activate security"]),
        ("unlock system", ["unlock system", "security off", "disarm security", "unlock laptop", "disable security"]),
        ("show intruder log", ["show intruder log", "show security log", "security logs", "intruder logs", "open logs", "show logs", "security report", "show recent history"]),
        ("show full history", ["show full history", "show activity history", "show all history", "all history", "system history", "full history", "complete history"]),
        ("capture intruder", ["capture intruder", "intruder capture", "security snapshot", "capture evidence"]),
        ("alert status", ["alert status", "alerts status", "security alert status"]),
        ("test alert", ["test alert", "send test alert", "security test alert"]),
        ("popup alert on", ["popup alert on", "alert popup on"]),
        ("popup alert off", ["popup alert off", "alert popup off"]),
        ("sound alert on", ["sound alert on", "alert sound on", "alarm on"]),
        ("sound alert off", ["sound alert off", "alert sound off", "alarm off"]),
        ("email alert on", ["email alert on", "mail alert on"]),
        ("email alert off", ["email alert off", "mail alert off"]),
        ("telegram alert on", ["telegram alert on", "phone alert on"]),
        ("telegram alert off", ["telegram alert off", "phone alert off"]),
        ("threat score", ["threat score", "security score", "threat level", "cyber status"]),
        (
            "cyber hardening",
            [
                "cyber hardening",
                "full security mode",
                "harden security",
                "security harden",
                "step up",
                "step up security",
                "step up karo",
                "security step up",
                "high security mode",
                "strict security mode",
            ],
        ),
        ("panic mode", ["panic mode", "security emergency", "cyber emergency", "system emergency", "red alert"]),
        ("decoy mode", ["decoy mode", "launch decoy", "fake desktop", "open fake desktop"]),
        ("lock laptop for security", ["lock laptop", "guard lock laptop", "security lock laptop"]),
        ("continuous auth on", ["continuous auth on", "continuous guard on", "continuous monitoring on", "monitor mode on"]),
        ("continuous auth off", ["continuous auth off", "continuous guard off", "continuous monitoring off", "monitor mode off"]),
        ("vault status", ["vault status", "secure vault status", "vault info", "vault list"]),
        ("vault setup", ["vault setup", "secure vault setup", "setup vault"]),
        ("vault unlock", ["vault unlock", "unlock vault", "open vault"]),
        ("vault lock", ["vault lock", "lock vault", "close vault"]),
        ("vault backup", ["vault backup", "backup vault", "secure backup"]),
        ("vault protect", ["vault protect", "protect file", "encrypt file"]),
        ("vault restore", ["vault restore", "restore vault file", "decrypt vault file"]),
        ("startup protection on", ["startup protection on", "security startup on", "auto arm on startup", "auto start security"]),
        ("startup protection off", ["startup protection off", "security startup off", "disable auto arm"]),
        ("security face enroll", ["security face enroll", "register face", "face register", "owner face enroll", "register owner face", "enroll owner face"]),
        ("security voice enroll", ["security voice enroll", "register voice", "voice enroll", "owner voice enroll"]),
        ("quick security", ["security bootstrap", "quick security", "quick guard mode", "face guard mode"]),
        (
            "memory dashboard",
            ["memory dashboard", "memory status", "study dashboard", "what did i study", "kya padha"],
        ),
        ("study history", ["study history", "memory history", "recent study"]),
        ("weak topics", ["weak topics", "weak areas", "weak area", "where am i weak"]),
        ("strong topics", ["strong topics", "strong areas", "strong area", "my strengths"]),
        (
            "revision plan",
            ["revision plan", "revision suggestion", "suggest revision", "what should i revise", "revise plan"],
        ),
        (
            "verify memory integrity",
            ["verify memory integrity", "memory integrity", "tamper check", "verify integrity"],
        ),
    ]

    for canonical, variants in alias_groups:
        if any(variant in normalized for variant in variants):
            return canonical

    if normalized in {
        "alert",
        "commands",
        "helo",
        "hello",
        "hi",
        "jarvis",
        "jarvis help",
        "security",
        "security help",
        "show commands",
    }:
        return "jarvis help"

    return normalized


def _extract_direct_security_command(query):
    canonical = _rewrite_inline_command(query)
    if not canonical:
        return ""

    if canonical in DIRECT_COMMANDS:
        return canonical

    if canonical.startswith("set security pin "):
        return canonical

    if canonical.startswith("set security phrase "):
        return canonical

    if canonical.startswith("memory add "):
        return canonical

    return ""


def _command_in_cooldown(command_text):
    global _last_direct_command, _last_direct_command_at

    now = time.time()
    if command_text == _last_direct_command and now - _last_direct_command_at < DIRECT_COMMAND_COOLDOWN_SEC:
        return True

    _last_direct_command = command_text
    _last_direct_command_at = now
    return False


def _is_duplicate_command(normalized_command, source):
    global _last_handled_command, _last_handled_command_at, _last_handled_command_source

    if not normalized_command:
        return False

    if source not in DEDUPED_SOURCES:
        _last_handled_command = normalized_command
        _last_handled_command_at = time.time()
        _last_handled_command_source = source
        return False

    now = time.time()
    repeat_window_sec = COMMAND_REPEAT_WINDOW_SEC
    if normalized_command == "jarvis help":
        repeat_window_sec = max(COMMAND_REPEAT_WINDOW_SEC, HELP_REPEAT_WINDOW_SEC)

    if (
        normalized_command == _last_handled_command
        and (now - _last_handled_command_at) < repeat_window_sec
        and (
            source == _last_handled_command_source
            or (
                source in DEDUPED_SOURCES
                and _last_handled_command_source in DEDUPED_SOURCES
            )
        )
    ):
        return True

    _last_handled_command = normalized_command
    _last_handled_command_at = now
    _last_handled_command_source = source
    return False


def _dedupe_command_key(normalized_command):
    if not normalized_command:
        return ""

    if normalized_command in {"zaris help", "jarvis help", "security help", "help zaris", "help jarvis"}:
        return "zaris help"

    core_command = normalize_core_command(normalized_command)
    if core_command:
        return core_command

    return normalized_command


def _is_likely_self_echo(normalized_command, source):
    if not normalized_command:
        return False

    if source not in {"always_on_mic", "wake_phrase", "wake_listener", "conversation"}:
        return False

    spoken_at = float(getattr(command_runtime, "last_spoken_at", 0.0) or 0.0)
    if spoken_at <= 0.0:
        return False

    if (time.time() - spoken_at) > SELF_ECHO_WINDOW_SEC:
        return False

    spoken_text = " ".join(str(getattr(command_runtime, "last_spoken_text", "") or "").strip().lower().split())
    if not spoken_text:
        return False

    dedupe_key = _dedupe_command_key(normalized_command)

    spoken_words = set(spoken_text.split())
    command_words = set(normalized_command.split())
    overlap_count = len(spoken_words & command_words)
    if len(command_words) >= 2 and overlap_count >= min(2, len(command_words)):
        overlap_ratio = overlap_count / len(command_words) if command_words else 0
        if overlap_ratio > 0.6:
            return True

    if dedupe_key not in {"zaris help", "jarvis help"}:
        if "zaris core commands" in spoken_text or "zaris commands" in spoken_text or "jarvis core commands" in spoken_text or "jarvis commands" in spoken_text:
            if dedupe_key in {"zaris help", "jarvis help"}:
                return True
        return False

    if "zaris core commands" in spoken_text or "zaris commands" in spoken_text or "jarvis core commands" in spoken_text or "jarvis commands" in spoken_text:
        return True

    if "youtube" in spoken_text and "apps" in spoken_text and "chat" in spoken_text:
        return True

    if "system commands" in spoken_text and "help" in spoken_text:
        return True

    if normalized_command in spoken_text:
        return True

    return False


def _try_youtube_and_app_commands(query, normalized, source):
    import webbrowser
    from backend.helper import extract_yt_term
    
    q = normalized
    
    # Direct YouTube open patterns
    if "youtube" in q and ("open" in q or "chalao" in q or "khol" in q or len(q.split()) <= 2):
        webbrowser.open("https://www.youtube.com")
        speak("YouTube khol raha hoon.")
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="youtube_opened",
            metadata={"normalized": normalized},
        )
        return True
    
    # Google open
    if ("google" in q and ("open" in q or "chalao" in q or "khol" in q)) or ("open google" in q):
        webbrowser.open("https://www.google.com")
        speak("Google khol raha hoon.")
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="google_opened",
            metadata={"normalized": normalized},
        )
        return True
    
    # Song/Play patterns - check these early
    song_keywords = ["song", "gaana", "gana", "songs", "play", "chalao", "चलाओ", "बजा", "baja"]
    if any(kw in q for kw in song_keywords):
        search_term = extract_yt_term(query)
        if search_term and len(search_term) >= 2:
            url = f"https://www.youtube.com/results?search_query={search_term}"
            webbrowser.open(url)
            speak(f"YouTube pe '{search_term}' search kar raha hoon.")
            _log_activity_history(
                "command_history",
                True,
                query=query,
                source=source,
                reason="youtube_search",
                metadata={"normalized": normalized, "search_term": search_term},
            )
            return True
    
    return False


def _handle_file_scan_command(query, normalized, source):
    from backend.file_scanner import scan_file, build_scan_reply
    from backend.security.zaris_core import check_file_threat
    
    q = normalized
    
    file_keywords = ["scan file", "check file", "file scan", "analyze file", "scan this", "is file", "check if"]
    has_file_keyword = any(kw in q for kw in file_keywords)
    
    if not has_file_keyword:
        return None
    
    import re
    # Match quoted paths first (handles paths with spaces)
    path_match = re.search(r'["\']([^"\']+)["\']', query, re.IGNORECASE)
    
    if not path_match:
        # Match Windows paths with potential spaces
        path_match = re.search(r'(?:scan|check|analyze)\s+(?:file\s+)?(?:path\s+)?([A-Za-z]:\\[^\s]*|/[^\s]+)', query, re.IGNORECASE)
    
    if not path_match:
        # Match paths with extensions
        path_match = re.search(r'([A-Za-z]:\\[^\s]+|[^\s]+\.[a-zA-Z0-9]{2,4})', query, re.IGNORECASE)
    
    if path_match:
        file_path = path_match.group(1).strip('"\'')
        result = scan_file(file_path)
        reply = build_scan_reply(result)
        speak(reply)
        
        # Check if file is harmful and show popup if needed
        try:
            threat_result = check_file_threat(file_path)
            if threat_result.get("found") and threat_result.get("should_block"):
                import eel
                threat_info = {
                    "file_path": file_path,
                    "file_name": threat_result.get("file_name", ""),
                    "is_rat": threat_result.get("is_rat", False),
                    "is_malware": threat_result.get("is_malware", False),
                    "risk_level": threat_result.get("risk_level", "unknown"),
                    "risk_score": threat_result.get("threat").risk_score if threat_result.get("threat") else 0,
                    "warnings": threat_result.get("threat").warnings if threat_result.get("threat") else []
                }
                eel.showThreatAlert(threat_info)
        except Exception as e:
            print(f"Threat popup error: {e}")
        
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="file_scanned",
            metadata={"normalized": normalized, "file": file_path, "risk": result.get("risk_level", "unknown")},
        )
        return True
    
    speak("File path bataiye jise scan karna hai. Jaise: scan file C:\\Downloads\\test.exe")
    _log_activity_history(
        "command_history",
        True,
        query=query,
        source=source,
        reason="file_scan_request_path",
        metadata={"normalized": normalized},
    )
    return True


def _try_voice_chat_fallback(query, normalized, source, reason="command_handled_chat"):
    if not VOICE_CHAT_ENABLED:
        return False

    try:
        from backend.smart_reply import smart_reply
        from backend.memory import add_conversation

        reply_text = smart_reply(query)
        if not reply_text:
            return False

        speak(reply_text)
        try:
            add_conversation(query, reply_text, command_type="voice_chat")
        except Exception as exc:
            print(f"Conversation memory save failed: {exc}")

        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason=reason,
            metadata={"normalized": normalized},
        )
        return True
    except Exception as exc:
        print(f"Voice chat fallback failed: {exc}")
        return False


def startup_greeting():
    try:
        from backend.security.manager import get_startup_security_message, get_security_status_message

        startup_message = get_startup_security_message()
        if startup_message:
            _log_activity_history(
                "system_history",
                True,
                source="startup",
                reason="startup_message_spoken",
                metadata={"message": startup_message},
            )
            speak(startup_message)
            return

        status_message = get_security_status_message()
        _log_activity_history(
            "system_history",
            True,
            source="startup",
            reason="status_message_spoken",
            metadata={"message": status_message},
        )
        speak(status_message)
    except Exception as exc:
        print(f"Security startup greeting fallback: {exc}")
        _log_activity_history(
            "system_history",
            False,
            source="startup",
            reason="startup_greeting_fallback",
            metadata={"error": str(exc)},
        )
        speak("Security console ready. Manual guard commands available.")


def handle_query(query, source="unknown"):
    clear_cancel()
    if not query:
        return False

    normalized = _rewrite_inline_command(query)
    if not normalized:
        return False

    if _is_terminate(query):
        request_cancel()
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="terminate_requested",
            metadata={"normalized": normalized},
        )
        speak("Theek hai, current command cancel kar diya.")
        clear_cancel()
        return True

    if _is_likely_self_echo(normalized, source):
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="command_ignored_echo",
            metadata={"normalized": normalized},
        )
        return False

    dedupe_key = _dedupe_command_key(normalized)

    if _is_duplicate_command(dedupe_key, source):
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="command_deduped",
            metadata={"normalized": normalized, "dedupe_key": dedupe_key},
        )
        return False

    _log_activity_history(
        "command_history",
        True,
        query=query,
        source=source,
        reason="command_received",
        metadata={"normalized": normalized, "dedupe_key": dedupe_key},
    )

    if normalized in {"jarvis help", "security help"}:
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="command_help",
            metadata={"normalized": normalized},
        )
        speak(SECURITY_HELP_TEXT)
        return True

    core_command = normalize_core_command(normalized)
    if core_command:
        reply_text = execute_core_command(core_command, original_query=query)
        speak(reply_text)
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="command_handled_core",
            metadata={"normalized": core_command},
        )
        return True

    custom_reply = _match_custom_reply(normalized)
    if custom_reply:
        speak(custom_reply)
        _log_activity_history(
            "command_history",
            True,
            query=query,
            source=source,
            reason="command_handled_custom_reply",
            metadata={"normalized": normalized},
        )
        return True

    if ZARIS_CORE_ONLY_MODE:
        if _try_voice_chat_fallback(query, normalized, source, reason="command_handled_chat_core_mode"):
            return True

        _log_activity_history(
            "command_history",
            False,
            query=query,
            source=source,
            reason="command_blocked_core_only",
            metadata={"normalized": normalized},
        )
        speak(SECURITY_HELP_TEXT)
        return False

    try:
        from backend.security.manager import handle_security_command

        if handle_security_command(query, normalized):
            _log_activity_history(
                "command_history",
                True,
                query=query,
                source=source,
                reason="command_handled",
                metadata={"normalized": normalized},
            )
            return True
    except Exception as exc:
        print(f"Security command routing failed: {exc}")
        _log_activity_history(
            "command_history",
            False,
            query=query,
            source=source,
            reason="command_error",
            metadata={"normalized": normalized, "error": str(exc)},
        )
        speak("Security engine abhi available nahi hai.")
        return False

    if _try_youtube_and_app_commands(query, normalized, source):
        return True

    file_result = _handle_file_scan_command(query, normalized, source)
    if file_result:
        return True

    if _try_voice_chat_fallback(query, normalized, source):
        return True

    _log_activity_history(
        "command_history",
        False,
        query=query,
        source=source,
        reason="command_unhandled",
        metadata={"normalized": normalized},
    )
    speak(SECURITY_HELP_TEXT)
    return False


def _continuous_conversation(eel_module, first_query=None, source="conversation"):
    global _conversation_active, _wake_active

    _conversation_active = True
    _wake_active = False

    if first_query:
        handle_query(first_query, source=source)
        if CHATBOT_SINGLE_TURN_MODE:
            try:
                eel_module.wakeWordMicStop(first_query)
            except Exception:
                pass
            _conversation_active = False
            _wake_active = True
            try:
                eel_module.conversationEnded()
            except Exception:
                pass
            _log_activity_history(
                "system_history",
                True,
                source=source,
                reason="conversation_single_turn_end",
            )
            return

    silence_count = 0
    max_silence = CONVERSATION_MAX_SILENCE

    while _conversation_active:
        try:
            eel_module.conversationListening()
        except Exception:
            pass

        query = takecommand(timeout=3.4, phrase_time_limit=4.0)

        if query:
            print(f"Conversation heard: '{query}'")
            if _is_bye(query):
                print(f"Bye word detected, ending conversation")
                try:
                    eel_module.wakeWordMicStop(query)
                except Exception:
                    pass
                _log_activity_history(
                    "system_history",
                    True,
                    query=query,
                    source=source,
                    reason="conversation_standby_requested",
                )
                speak("Security console standby pe chali gayi.")
                _conversation_active = False
                _wake_active = True
                break

            try:
                eel_module.wakeWordMicStart(query)
            except Exception:
                pass

            handled = handle_query(query, source=source)

            if handled:
                silence_count = 0
            else:
                silence_count += 1
                if max_silence > 0 and silence_count >= max_silence:
                    _log_activity_history(
                        "system_history",
                        True,
                        source=source,
                        reason="conversation_timeout_standby",
                    )
                    speak("Security console standby pe hai. Mic ya wake phrase se dobara activate karo.")
                    try:
                        eel_module.wakeWordMicStop("")
                    except Exception:
                        pass
                    break

            try:
                eel_module.wakeWordMicStop(query)
            except Exception:
                pass
            if CHATBOT_SINGLE_TURN_MODE:
                break
            continue

        silence_count += 1
        if max_silence > 0 and silence_count >= max_silence:
            _log_activity_history(
                "system_history",
                True,
                source=source,
                reason="conversation_timeout_standby",
            )
            speak("Security console standby pe hai. Mic ya wake phrase se dobara activate karo.")
            try:
                eel_module.wakeWordMicStop("")
            except Exception:
                pass
            break

    _conversation_active = False
    _wake_active = True

    try:
        eel_module.conversationEnded()
    except Exception:
        pass
    _log_activity_history(
        "system_history",
        True,
        source=source,
        reason="conversation_ended",
    )


def hotword():
    global _wake_active
    import eel

    print("Zaris AI wake listener active. 'zaris' bolo.")

    while True:
        try:
            if is_speaking or not _wake_active or _conversation_active:
                time.sleep(0.3)
                continue

            audio, capture_error = capture_audio_with_lock(
                _wake_recognizer,
                timeout=HOTWORD_TIMEOUT_SEC,
                phrase_time_limit=HOTWORD_PHRASE_LIMIT_SEC,
                adjust_callback=_maybe_adjust_wake_noise,
                lock_timeout=0.25,
            )

            if capture_error in {"timeout", "busy"}:
                continue

            if capture_error:
                time.sleep(0.5)
                continue

            detected_text = transcribe_audio(
                audio,
                languages=("en-US", "en-IN", "hi-IN"),
                lowercase=True,
                verbose=False,
            )

            if not detected_text:
                continue

            found, remaining_cmd = _check_wake_word(detected_text)
            direct_command = _extract_direct_security_command(detected_text) if PERMANENT_MIC_LISTENING else ""

            if direct_command and _command_in_cooldown(direct_command):
                continue

            if not found and direct_command:
                _log_activity_history(
                    "input_history",
                    True,
                    query=direct_command,
                    source="always_on_mic",
                    reason="direct_command_detected",
                    metadata={"heard_text": _sanitize_query_for_history(detected_text)},
                )
                try:
                    eel.wakeWordDetected()
                except Exception:
                    pass

                try:
                    eel.wakeWordMicStart(direct_command)
                except Exception:
                    pass

                handle_query(direct_command, source="always_on_mic")

                try:
                    eel.wakeWordMicStop(direct_command)
                except Exception:
                    pass
                continue

            if not found:
                continue

            _log_activity_history(
                "input_history",
                True,
                query=detected_text,
                source="wake_listener",
                reason="wake_word_detected",
                metadata={"remaining_command": _sanitize_query_for_history(remaining_cmd)},
            )

            try:
                eel.wakeWordDetected()
            except Exception:
                pass

            if remaining_cmd:
                try:
                    eel.wakeWordMicStart(remaining_cmd)
                except Exception:
                    pass
                _continuous_conversation(eel, first_query=remaining_cmd, source="wake_phrase")
                continue

            speak("Zaris AI active. Command bolo.")

            try:
                eel.wakeWordMicStart("")
            except Exception:
                pass

            query = takecommand(timeout=3.4, phrase_time_limit=4.0)
            if query:
                try:
                    eel.wakeWordMicStop(query)
                except Exception:
                    pass
                _continuous_conversation(eel, first_query=query, source="wake_phrase")
            else:
                try:
                    eel.wakeWordMicStop("")
                except Exception:
                    pass
                speak("Command clear nahi mila. Dobara try karo.")

        except Exception as exc:
            print(f"Security hotword loop error (recovering): {exc}")
            _log_activity_history(
                "system_history",
                False,
                source="wake_listener",
                reason="wake_loop_error",
                metadata={"error": str(exc)},
            )
            time.sleep(1)


def start_hotword():
    thread = threading.Thread(target=hotword, daemon=True)
    thread.start()
    print("Zaris AI hotword thread started.")
    _log_activity_history(
        "system_history",
        True,
        source="startup",
        reason="wake_hotword_thread_started",
    )

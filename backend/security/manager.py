import os
import re
import subprocess
import threading
import time
import random
from datetime import datetime
from pathlib import Path

from backend import system_control as sc
from backend.command import listen_for_command_audio, speak, takecommand
from backend.face_rec import (
    cv2,
    face_engine_message,
    face_engine_ready,
    get_registered_faces,
    recognize_face,
    register_face,
)
from backend.security.alerts import dispatch_security_alerts
from backend.security.forensics import (
    capture_screenshot,
    capture_screenshot_burst,
    capture_screen_recording,
    open_decoy_workspace,
    write_forensic_summary,
)
from backend.security.storage import (
    DECOY_DIR,
    INTRUDER_DIR,
    adjust_threat_score,
    build_security_report,
    count_recent_failed_auth_attempts,
    get_threat_score,
    hash_value,
    load_security_config,
    log_security_event,
    save_security_config,
    set_threat_score,
    verify_value,
)
from backend.security.vault import (
    backup_vault,
    list_vault_files,
    lock_vault,
    protect_file,
    restore_file,
    setup_vault,
    unlock_vault,
    vault_status_message,
)
from backend.security.voice_auth import compare_voiceprints, create_voiceprint
from backend.memory_twin import (
    add_study_record,
    parse_quick_add_command,
    voice_history_reply,
    voice_integrity_reply,
    voice_revision_reply,
    voice_strong_topics_reply,
    voice_weak_topics_reply,
)

try:
    import psutil
except Exception:
    psutil = None


_STATE_LOCK = threading.Lock()
_STARTUP_CHECKED = False
_SERVICES_STARTED = False
_SERVICE_THREADS = []
_KNOWN_REMOVABLE_DEVICES = set()
_KNOWN_SUSPICIOUS_PROCESSES = set()
_KNOWN_DOWNLOAD_FILES = {}
_CONTINUOUS_AUTH_MISSES = 0

_POSITIVE_WORDS = {
    "yes",
    "haan",
    "ha",
    "han",
    "ok",
    "theek",
    "kar",
    "sure",
    "enable",
}
_NEGATIVE_WORDS = {"no", "nahi", "skip", "baad", "cancel", "mat", "nah"}
_PIN_DIGITS = {
    "zero": "0",
    "oh": "0",
    "o": "0",
    "ek": "1",
    "one": "1",
    "do": "2",
    "two": "2",
    "teen": "3",
    "three": "3",
    "char": "4",
    "chaar": "4",
    "four": "4",
    "paanch": "5",
    "panch": "5",
    "five": "5",
    "chhe": "6",
    "che": "6",
    "six": "6",
    "saat": "7",
    "seven": "7",
    "aath": "8",
    "eight": "8",
    "nau": "9",
    "nine": "9",
}
_VOICE_CHALLENGE_WORDS = [
    "alpha seven",
    "blue nine",
    "shadow three",
    "cyber five",
    "guard one",
    "orbit six",
]


def _normalize_text(text):
    return str(text or "").strip().lower()


def _looks_positive(text):
    tokens = set(re.findall(r"[a-zA-Z]+", _normalize_text(text)))
    return bool(tokens & _POSITIVE_WORDS)


def _looks_negative(text):
    tokens = set(re.findall(r"[a-zA-Z]+", _normalize_text(text)))
    return bool(tokens & _NEGATIVE_WORDS)


def _extract_inline_tail(query, markers):
    lowered = _normalize_text(query)
    for marker in markers:
        if marker in lowered:
            tail = lowered.split(marker, 1)[1].strip(" :.-")
            if tail:
                return tail
    return ""


def _extract_inline_tail_raw(query, markers):
    original = str(query or "").strip()
    lowered = original.lower()
    for marker in markers:
        marker_lower = str(marker or "").lower()
        if marker_lower in lowered:
            start = lowered.index(marker_lower) + len(marker_lower)
            tail = original[start:].strip(" :.-")
            if tail:
                return tail
    return ""


def _extract_pin(text):
    normalized = _normalize_text(text)
    digits = "".join(re.findall(r"\d", normalized))
    if len(digits) >= 4:
        return digits

    tokens = re.findall(r"[a-zA-Z]+", normalized)
    mapped = [_PIN_DIGITS[token] for token in tokens if token in _PIN_DIGITS]
    joined = "".join(mapped)
    return joined if len(joined) >= 4 else ""


def _resolve_owner_face_candidate(config):
    configured = (config.get("owner_face_name") or "").strip()
    if configured:
        return configured

    faces = get_registered_faces()
    return faces[0] if faces else ""


def _profile_ready(config):
    require_phrase = bool(config.get("require_phrase"))
    require_voice = bool(config.get("require_voiceprint"))
    require_face = bool(config.get("require_face"))
    require_pin = bool(config.get("require_pin"))

    phrase_ready = (not require_phrase) or bool(config.get("phrase", {}).get("hash"))
    voice_ready = (not require_voice) or bool(config.get("voiceprint"))
    face_ready = (not require_face) or bool(_resolve_owner_face_candidate(config))
    pin_ready = (not require_pin) or bool(config.get("pin", {}).get("hash"))

    has_any_factor = any([require_phrase, require_voice, require_face, require_pin])
    return has_any_factor and phrase_ready and voice_ready and face_ready and pin_ready


def is_security_enabled():
    return bool(load_security_config().get("enabled"))


def get_security_status_message():
    config = load_security_config()
    if not _profile_ready(config):
        return "Security setup abhi incomplete hai. 'security setup' chalao."

    factors = []
    if config.get("require_phrase"):
        factors.append("phrase")
    if config.get("require_voiceprint") and config.get("voiceprint"):
        factors.append("voice")
    if config.get("require_face"):
        factors.append("face")
    if config.get("require_pin") and config.get("pin", {}).get("hash"):
        factors.append("pin")

    state = "active" if config.get("enabled") else "standby"
    owner = config.get("owner_name") or "owner"
    factor_text = ", ".join(factors) if factors else "none"
    return (
        f"Security guard {state} hai. Owner profile {owner} pe set hai. "
        f"Verification factors: {factor_text}. Threat score {config.get('threat_score', 0)}/{config.get('threat_score_max', 100)} hai."
    )


def _bootstrap_face_guard(enable_now=False, auto_start=True):
    config = load_security_config()
    candidate = _resolve_owner_face_candidate(config)
    if not candidate:
        return False, "Registered owner face mila hi nahi. Pehle face register karo."

    config["owner_name"] = config.get("owner_name") if config.get("owner_name") and config.get("owner_name") != "Owner" else candidate
    config["owner_face_name"] = candidate
    config["require_face"] = True
    config["require_phrase"] = True
    config["require_voiceprint"] = True
    config["require_pin"] = False
    config["auto_arm_on_startup"] = bool(auto_start)

    phrase_ready = bool(config.get("phrase", {}).get("hash"))
    voice_ready = bool(config.get("voiceprint"))

    if not phrase_ready or not voice_ready:
        config["enabled"] = False
        save_security_config(config)
        missing = []
        if not phrase_ready:
            missing.append("security phrase")
        if not voice_ready:
            missing.append("owner voiceprint")
        log_security_event(
            "bootstrap",
            False,
            reason="voice_required_bootstrap_blocked",
            metadata={
                "owner_name": config["owner_name"],
                "owner_face_name": candidate,
                "enabled": False,
                "auto_arm_on_startup": bool(auto_start),
                "missing": missing,
            },
        )
        missing_text = " and ".join(missing)
        return (
            False,
            f"Owner verification ke liye {missing_text} required hai. 'security setup' ya 'security voice enroll' chalao.",
        )

    if enable_now:
        config["enabled"] = True
    save_security_config(config)
    log_security_event(
        "bootstrap",
        True,
        reason="voice_face_guard_bootstrap",
        metadata={
            "owner_name": config["owner_name"],
            "owner_face_name": candidate,
            "enabled": bool(enable_now),
            "auto_arm_on_startup": bool(auto_start),
        },
    )
    return True, f"Voice + face cyber guard {candidate} ke naam se configure ho gaya."


def _get_ids_score(config, key, default_value):
    return int(((config or {}).get("ids", {}).get("scoring", {}) or {}).get(key, default_value))


def _capture_forensic_bundle(reason, metadata=None, include_photo=True, include_screens=True, include_video=None):
    evidence = {"photo": "", "screenshots": [], "summary": "", "video": ""}
    config = load_security_config()
    forensic_config = config.get("forensics", {}) or {}

    if include_photo:
        photo_path, _photo_message = _capture_intruder_photo(prefix="intruder")
        if photo_path:
            evidence["photo"] = photo_path

    if include_screens:
        evidence["screenshots"] = capture_screenshot_burst(prefix="forensic_screen", count=2)

    capture_video = forensic_config.get("capture_video", True) if include_video is None else include_video
    if capture_video:
        video_path, _video_message = capture_screen_recording(
            prefix="forensic_video",
            duration_sec=forensic_config.get("video_duration_sec", 4),
            fps=forensic_config.get("video_fps", 4),
        )
        if video_path:
            evidence["video"] = video_path

    evidence["summary"] = write_forensic_summary(reason, extra=metadata or {})
    return evidence


def _maybe_trigger_decoy(config, actions):
    if not (config.get("decoy", {}) or {}).get("enabled", False):
        return
    if not (config.get("decoy", {}) or {}).get("open_on_intrusion", False):
        return
    ok, result = open_decoy_workspace()
    actions.append("decoy_workspace_opened" if ok else f"decoy_failed:{result}")


def _register_threat(reason, delta, metadata=None, event_type="threat_event", success=False, evidence_path="", actions=None):
    config = load_security_config()
    current_score = adjust_threat_score(delta)
    lock_threshold = int(config.get("threat_score_lock_threshold", 70))
    actions = list(actions or [])

    log_security_event(
        event_type,
        success,
        reason=reason,
        evidence_path=evidence_path,
        actions=actions,
        metadata={
            "threat_delta": int(delta),
            "threat_score": current_score,
            **(metadata or {}),
        },
    )

    if current_score >= lock_threshold:
        forensic = _capture_forensic_bundle(
            reason=f"threat_score_threshold:{reason}",
            metadata={"threat_score": current_score, **(metadata or {})},
            include_photo=True,
            include_screens=True,
        )
        if forensic.get("photo"):
            actions.append("intruder_photo_saved")
        if forensic.get("screenshots"):
            actions.append("screenshots_saved")
        if forensic.get("video"):
            actions.append("screen_record_saved")
        if forensic.get("summary"):
            actions.append("forensic_summary_saved")

        try:
            sc.lock_pc()
            actions.append("lock_workstation")
        except Exception as exc:
            actions.append(f"lock_failed:{exc}")

        _maybe_trigger_decoy(config, actions)

        alert_message = f"Cyber threat threshold crossed. Reason: {reason}. Threat score {current_score}."
        actions.extend(
            dispatch_security_alerts(
                config,
                alert_message,
                attachment_path=forensic.get("photo") or "",
                metadata={
                    "reason": reason,
                    "threat_score": current_score,
                    **(metadata or {}),
                },
            )
        )

        log_security_event(
            "threat_response",
            False,
            reason=f"threshold_response:{reason}",
            evidence_path=forensic.get("photo") or "",
            actions=actions,
            metadata={
                "threat_score": current_score,
                "screenshots": forensic.get("screenshots", []),
                "video_path": forensic.get("video", ""),
                "summary_path": forensic.get("summary", ""),
                **(metadata or {}),
            },
        )

    return current_score


def _mark_auth_anomaly(config, action_label):
    ids_config = config.get("ids", {}) or {}
    if not ids_config.get("alert_on_unusual_hour", True):
        return

    now_hour = datetime.now().hour
    start_hour = int(ids_config.get("allowed_login_start_hour", 6))
    end_hour = int(ids_config.get("allowed_login_end_hour", 23))
    is_unusual = now_hour < start_hour or now_hour >= end_hour
    if not is_unusual:
        return

    score = _get_ids_score(config, "unusual_login_hour", 12)
    _register_threat(
        reason="unusual_login_hour",
        delta=score,
        metadata={"action": action_label, "hour": now_hour},
        event_type="anomaly",
        success=False,
    )


def _random_voice_challenge(config):
    if not config.get("require_phrase") and not config.get("require_voiceprint"):
        return True, 1.0, "Voice challenge skipped."

    anti_spoof = (config.get("anti_spoof", {}) or {})
    if not anti_spoof.get("voice_challenge", True):
        return True, 1.0, "Voice challenge skipped."

    challenge = random.choice(_VOICE_CHALLENGE_WORDS)
    speak(f"Anti spoof check ke liye bolo: {challenge}")
    heard_text, challenge_audio = listen_for_command_audio(timeout=6, phrase_time_limit=4)
    heard_text = _normalize_text(heard_text)
    if heard_text != challenge:
        return False, 0.0, "Random voice challenge mismatch."

    if config.get("require_voiceprint") and config.get("voiceprint"):
        live_voiceprint = create_voiceprint(challenge_audio, heard_text)
        voice_ok, voice_score, voice_reason = compare_voiceprints(
            config["voiceprint"],
            live_voiceprint,
            threshold=max(0.55, float(config.get("voice_match_threshold", 0.63)) - 0.04),
        )
        if not voice_ok:
            return False, voice_score, voice_reason
        return True, voice_score, "Random voice challenge passed."

    return True, 1.0, "Random voice challenge passed."


def arm_security_mode(reason="manual"):
    config = load_security_config()
    if not _profile_ready(config):
        return "Security setup incomplete hai. Pehle 'security setup' chalao."

    if config.get("enabled"):
        return "Security mode pehle se active hai."

    config["enabled"] = True
    save_security_config(config)
    log_security_event(
        "security_mode",
        True,
        reason=f"armed:{reason}",
        metadata={"enabled": True, "reason": reason},
    )
    return "Security mode active ho gaya. Ab main guard mode me hoon."


def disarm_security_mode(reason="manual"):
    config = load_security_config()
    if not config.get("enabled"):
        return "Security mode already off hai."

    config["enabled"] = False
    save_security_config(config)
    log_security_event(
        "security_mode",
        True,
        reason=f"disarmed:{reason}",
        metadata={"enabled": False, "reason": reason},
    )
    return "Security mode off ho gaya. Guard standby pe hai."


def should_block_regular_command(_query):
    return is_security_enabled()


def get_startup_security_message():
    global _STARTUP_CHECKED

    with _STATE_LOCK:
        if _STARTUP_CHECKED:
            return None
        _STARTUP_CHECKED = True

    config = load_security_config()
    if not _profile_ready(config):
        candidate = _resolve_owner_face_candidate(config)
        if candidate:
            ok, message = _bootstrap_face_guard(enable_now=True, auto_start=True)
            if ok:
                return (
                    f"{message} Startup se security mode active kar diya. "
                    "Ab ye machine full guard mode me chalegi."
                )
            return message
        return "Security profile abhi setup nahi hai. 'security setup' ya registered owner face ke saath quick bootstrap chalao."

    if config.get("auto_arm_on_startup") and _profile_ready(config) and not config.get("enabled"):
        config["enabled"] = True
        save_security_config(config)
        log_security_event(
            "startup",
            True,
            reason="auto_armed_on_startup",
            metadata={"enabled": True},
        )
        return "Security guard startup pe activate ho gaya. Owner verification ab required hai."

    if config.get("enabled"):
        return "Security guard already active hai. Sensitive commands ke liye owner verification lagega."

    if config.get("auto_arm_on_startup") and not _profile_ready(config):
        return "Security auto-start skip hua kyunki setup abhi complete nahi hai."

    return None


def _capture_intruder_photo(prefix="intruder"):
    if cv2 is None:
        return None, "Camera module unavailable."

    camera = cv2.VideoCapture(0)
    if not camera.isOpened():
        return None, "Camera open nahi hua."

    try:
        time.sleep(0.3)
        ok, frame = camera.read()
        if not ok or frame is None:
            return None, "Camera frame capture fail hua."

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(INTRUDER_DIR, f"{prefix}_{timestamp}.jpg")
        cv2.imwrite(path, frame)
        return path, "Intruder photo saved."
    finally:
        camera.release()


def _configure_phrase(phrase_text=None, audio_sample=None):
    config = load_security_config()

    phrase_text = _normalize_text(phrase_text)
    if not phrase_text:
        speak("Nayi security phrase bolo.")
        phrase_text, audio_sample = listen_for_command_audio(timeout=6, phrase_time_limit=5)
        phrase_text = _normalize_text(phrase_text)

    if not phrase_text:
        return False, "Phrase samajh nahi aayi."

    salt, digest = hash_value(phrase_text)
    config["phrase"] = {"salt": salt, "hash": digest}

    voiceprint = create_voiceprint(audio_sample, phrase_text) if audio_sample else {}
    if voiceprint:
        config["voiceprint"] = voiceprint
        config["require_voiceprint"] = True

    save_security_config(config)
    log_security_event("configuration", True, reason="secret_phrase_updated")
    return True, "Security phrase aur baseline voice sample save ho gaya."


def _configure_pin(pin_text=None):
    config = load_security_config()

    pin_text = pin_text or ""
    pin_value = _extract_pin(pin_text)
    if not pin_value:
        speak("Security PIN bolo. Nahi rakhna ho to skip bolo.")
        heard_pin = takecommand()
        if _looks_negative(heard_pin):
            config["require_pin"] = False
            config["pin"] = {"salt": "", "hash": ""}
            save_security_config(config)
            log_security_event("configuration", True, reason="pin_skipped")
            return True, "PIN skip kar diya."
        pin_value = _extract_pin(heard_pin)

    if not pin_value:
        return False, "Valid PIN samajh nahi aaya."

    salt, digest = hash_value(pin_value)
    config["pin"] = {"salt": salt, "hash": digest}
    config["require_pin"] = True
    save_security_config(config)
    log_security_event("configuration", True, reason="pin_updated")
    return True, "Security PIN save ho gaya."


def _clear_pin():
    config = load_security_config()
    config["require_pin"] = False
    config["pin"] = {"salt": "", "hash": ""}
    save_security_config(config)
    log_security_event("configuration", True, reason="pin_cleared")
    return "Security PIN hata diya."


def _enroll_owner_face():
    config = load_security_config()
    if not face_engine_ready():
        return False, face_engine_message()

    owner_name = config.get("owner_name") or "Owner"
    speak(f"Face enrollment start kar rahi hoon. {owner_name} camera ke saamne aa jao.")
    success, message = register_face(owner_name, num_samples=25)
    if success:
        config["owner_face_name"] = owner_name
        config["require_face"] = True
        save_security_config(config)
        log_security_event("configuration", True, reason="owner_face_enrolled")
    return success, message


def _enroll_owner_voice():
    config = load_security_config()
    if not _profile_ready(config):
        return False, "Pehle security phrase set karo."

    speak("Wahi secret phrase bolo jisse main tumhari voiceprint refresh karun.")
    phrase_text, audio_sample = listen_for_command_audio(timeout=6, phrase_time_limit=5)
    phrase_text = _normalize_text(phrase_text)
    if not phrase_text:
        return False, "Phrase sunai nahi di."

    if not verify_value(phrase_text, config["phrase"]["salt"], config["phrase"]["hash"]):
        return False, "Phrase secret phrase se match nahi hui."

    voiceprint = create_voiceprint(audio_sample, phrase_text)
    if not voiceprint:
        return False, "Voice sample weak tha, dubara try karo."

    config["voiceprint"] = voiceprint
    config["require_voiceprint"] = True
    save_security_config(config)
    log_security_event("configuration", True, reason="voiceprint_enrolled")
    return True, "Voiceprint update ho gaya."


def _set_auto_start(enabled):
    config = load_security_config()
    config["auto_arm_on_startup"] = bool(enabled)
    save_security_config(config)
    log_security_event(
        "configuration",
        True,
        reason="auto_arm_updated",
        metadata={"auto_arm_on_startup": bool(enabled)},
    )
    return (
        "Startup protection on kar diya. App chalu hote hi security arm hogi."
        if enabled
        else "Startup protection off kar diya."
    )


def _merge_alert_settings(patch):
    config = load_security_config()
    alerts = config.get("alerts", {}) or {}

    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(alerts.get(key), dict):
            alerts[key] = {
                **(alerts.get(key, {}) or {}),
                **value,
            }
        else:
            alerts[key] = value

    config["alerts"] = alerts
    save_security_config(config)
    return alerts


def _alert_status_message():
    config = load_security_config()
    alerts = config.get("alerts", {}) or {}
    email_cfg = alerts.get("email", {}) or {}
    telegram_cfg = alerts.get("telegram", {}) or {}

    email_ready = all(
        email_cfg.get(key)
        for key in ["smtp_server", "smtp_port", "username", "password", "from_email", "to_email"]
    )
    telegram_ready = bool(telegram_cfg.get("bot_token") and telegram_cfg.get("chat_id"))

    email_state = "on" if email_cfg.get("enabled") else "off"
    telegram_state = "on" if telegram_cfg.get("enabled") else "off"

    return (
        f"Alert status: popup {'on' if alerts.get('popup', True) else 'off'}, "
        f"sound {'on' if alerts.get('sound', True) else 'off'}, "
        f"email {email_state} ({'ready' if email_ready else 'setup needed'}), "
        f"telegram {telegram_state} ({'ready' if telegram_ready else 'setup needed'})."
    )


def _set_alert_toggle(key, enabled):
    alerts = _merge_alert_settings({key: bool(enabled)})
    log_security_event(
        "configuration",
        True,
        reason=f"{key}_alert_updated",
        metadata={key: bool(enabled)},
    )
    return f"{key.title()} alert {'on' if alerts.get(key) else 'off'} kar diya."


def _set_channel_alert_toggle(channel, enabled):
    alerts = _merge_alert_settings({channel: {"enabled": bool(enabled)}})
    log_security_event(
        "configuration",
        True,
        reason=f"{channel}_alert_updated",
        metadata={channel: {"enabled": bool(enabled)}},
    )
    return f"{channel.title()} alert {'on' if alerts.get(channel, {}).get('enabled') else 'off'} kar diya."


def _configure_telegram_alert(query):
    markers = ["telegram alert setup", "setup telegram alert", "set telegram alert"]
    tail = _extract_inline_tail_raw(query, markers)
    if not tail:
        message = "Telegram setup ke liye text mode me likho: telegram alert setup <bot_token> <chat_id>"
        speak(message)
        return False, message

    parts = tail.split()
    if len(parts) < 2:
        message = "Telegram setup incomplete hai. Format: telegram alert setup <bot_token> <chat_id>"
        speak(message)
        return False, message

    bot_token = parts[0].strip()
    chat_id = parts[1].strip()
    _merge_alert_settings(
        {
            "telegram": {
                "bot_token": bot_token,
                "chat_id": chat_id,
                "enabled": True,
            }
        }
    )
    log_security_event(
        "configuration",
        True,
        reason="telegram_alert_setup",
        metadata={"chat_id": chat_id, "enabled": True},
    )
    message = "Telegram alert setup complete ho gaya."
    speak(message)
    return True, message


def _configure_email_alert_field(query, markers, field_key, label, cast_int=False):
    raw_value = _extract_inline_tail_raw(query, markers)
    if not raw_value:
        message = f"{label} set karne ke liye text mode me command ke baad value likho."
        speak(message)
        return False, message

    value = raw_value.strip()
    if cast_int:
        try:
            value = int(value)
        except Exception:
            message = f"{label} number hona chahiye."
            speak(message)
            return False, message

    _merge_alert_settings({"email": {field_key: value}})
    log_security_event(
        "configuration",
        True,
        reason=f"email_alert_{field_key}_updated",
        metadata={field_key: "***" if "password" in field_key else value},
    )
    message = f"{label} save ho gaya."
    speak(message)
    return True, message


def _test_alert_dispatch():
    config = load_security_config()
    actions = dispatch_security_alerts(
        config,
        "Manual Sentinel alert test triggered.",
        metadata={"manual": True, "source": "test_alert"},
    )
    log_security_event(
        "alert_test",
        True,
        reason="manual_alert_test",
        actions=actions,
        metadata={"actions": actions},
    )
    message = "Test alert trigger kar diya."
    if actions:
        message += f" Actions: {', '.join(actions)}."
    speak(message)
    return True


def _resolve_sensitive_value(query, markers, prompt_text, normalize=False):
    inline_value = _extract_inline_tail(query, markers) if normalize else _extract_inline_tail_raw(query, markers)
    if inline_value:
        return _normalize_text(inline_value) if normalize else inline_value.strip()

    speak(prompt_text)
    heard_value = takecommand()
    if not heard_value:
        return ""
    return _normalize_text(heard_value) if normalize else str(heard_value).strip()


def _setup_vault_command(query):
    secret_text = _resolve_sensitive_value(
        query,
        ["vault setup", "secure vault setup", "setup vault"],
        "Vault secret bolo. Text command use kar rahe ho to command ke baad secret bhi likh sakte ho.",
        normalize=False,
    )
    ok, result = setup_vault(secret_text)
    log_security_event("vault", ok, reason="vault_setup", metadata={"configured": ok})
    speak(result)
    return ok


def _unlock_vault_command(query):
    secret_text = _resolve_sensitive_value(
        query,
        ["vault unlock", "unlock vault", "open vault"],
        "Vault secret bolo.",
        normalize=False,
    )
    ok, result = unlock_vault(secret_text)
    log_security_event("vault", ok, reason="vault_unlock", metadata={"unlocked": ok})
    speak(result)
    return ok


def _protect_file_in_vault(query):
    file_path = _resolve_sensitive_value(
        query,
        ["vault protect", "protect file", "encrypt file"],
        "Kaunsi file secure vault me daalni hai? Full path bolo ya type karo.",
        normalize=False,
    )
    ok, result = protect_file(file_path)
    log_security_event(
        "vault",
        ok,
        reason="vault_protect_file",
        evidence_path=result if ok else "",
        metadata={"source_path": file_path, "vault_output": result if ok else ""},
    )
    speak("File secure vault me encrypt kar di." if ok else result)
    return ok


def _restore_file_from_vault(query):
    vault_name = _resolve_sensitive_value(
        query,
        ["vault restore", "restore vault file", "decrypt vault file"],
        "Kaunsi encrypted vault file restore karni hai? File name bolo.",
        normalize=False,
    )
    ok, result = restore_file(vault_name)
    log_security_event(
        "vault",
        ok,
        reason="vault_restore_file",
        evidence_path=result if ok else "",
        metadata={"vault_file": vault_name, "restore_output": result if ok else ""},
    )
    speak("Vault file restore kar di." if ok else result)
    return ok


def _backup_vault_command():
    ok, result = backup_vault()
    log_security_event(
        "vault",
        ok,
        reason="vault_backup",
        evidence_path=result if ok else "",
        metadata={"backup_path": result if ok else ""},
    )
    speak("Vault backup create kar diya." if ok else result)
    return ok


def _guided_security_setup():
    config = load_security_config()

    speak("Security setup start kar rahi hoon.")
    speak("Owner name bolo. Nahi bolna ho to skip bolo.")
    owner_name = takecommand()
    if owner_name and not _looks_negative(owner_name):
        config["owner_name"] = owner_name.strip().title()
        save_security_config(config)

    speak("Ab unlock ke liye secret phrase bolo.")
    phrase_text, audio_sample = listen_for_command_audio(timeout=6, phrase_time_limit=5)
    ok, message = _configure_phrase(phrase_text=phrase_text, audio_sample=audio_sample)
    if not ok:
        speak(message)
        return message

    config = load_security_config()
    config["owner_name"] = config.get("owner_name") or "Owner"
    save_security_config(config)

    speak("PIN lagana hai to ab bolo. Skip bolke bina PIN ke aage badh sakte ho.")
    pin_result_ok, pin_message = _configure_pin()

    if face_engine_ready():
        speak("Face verification bhi enable karna hai? Haan ya nahi bolo.")
        face_answer = takecommand()
        if _looks_positive(face_answer):
            face_ok, face_message = _enroll_owner_face()
            speak(face_message)
        else:
            config = load_security_config()
            config["require_face"] = False
            save_security_config(config)
            face_message = "Face verification skip kar diya."
    else:
        config = load_security_config()
        config["require_face"] = False
        save_security_config(config)
        face_message = face_engine_message()

    speak("Startup protection enable karni hai? Haan ya nahi bolo.")
    startup_answer = takecommand()
    if _looks_positive(startup_answer):
        startup_message = _set_auto_start(True)
    else:
        startup_message = _set_auto_start(False)

    config = load_security_config()
    config["enabled"] = False
    save_security_config(config)
    log_security_event("setup", True, reason="guided_security_setup_complete")

    summary = (
        "Security setup complete. "
        f"{message} {pin_message if pin_result_ok else 'PIN configure nahi hua.'} "
        f"{face_message} {startup_message}"
    )
    speak(summary)
    return summary


def _verify_phrase_and_voice(config):
    if not config.get("require_phrase") and not config.get("require_voiceprint"):
        return {
            "ok": True,
            "reason": "Voice factor skipped.",
            "voice_text": "",
            "voice_score": 1.0,
        }

    speak("Owner verification ke liye secret phrase bolo.")
    phrase_text, audio_sample = listen_for_command_audio(timeout=6, phrase_time_limit=5)
    phrase_text = _normalize_text(phrase_text)
    if not phrase_text:
        return {
            "ok": False,
            "reason": "Secret phrase sunai nahi di.",
            "voice_text": "",
            "voice_score": 0.0,
        }

    phrase_ok = verify_value(phrase_text, config["phrase"]["salt"], config["phrase"]["hash"])
    if not phrase_ok:
        return {
            "ok": False,
            "reason": "Secret phrase mismatch.",
            "voice_text": phrase_text,
            "voice_score": 0.0,
        }

    if config.get("require_voiceprint") and not config.get("voiceprint"):
        return {
            "ok": False,
            "reason": "Owner voiceprint enrolled nahi hai. 'security voice enroll' bolo.",
            "voice_text": phrase_text,
            "voice_score": 0.0,
        }

    if config.get("require_voiceprint") and config.get("voiceprint"):
        live_voiceprint = create_voiceprint(audio_sample, phrase_text)
        voice_ok, voice_score, voice_reason = compare_voiceprints(
            config["voiceprint"],
            live_voiceprint,
            threshold=float(config.get("voice_match_threshold", 0.63)),
        )
        if not voice_ok:
            return {
                "ok": False,
                "reason": voice_reason,
                "voice_text": phrase_text,
                "voice_score": voice_score,
            }
        return {
            "ok": True,
            "reason": "Phrase and voice matched.",
            "voice_text": phrase_text,
            "voice_score": voice_score,
        }

    return {
        "ok": True,
        "reason": "Phrase matched.",
        "voice_text": phrase_text,
        "voice_score": 1.0,
    }


def _verify_face(config):
    if not config.get("require_face"):
        return True, "", 0.0, "Face factor skipped."

    from backend.face_rec import get_face_status
    
    is_ready, status_msg = get_face_status()
    if not is_ready:
        return False, "", 0.0, status_msg

    expected_name = _normalize_text(_resolve_owner_face_candidate(config) or config.get("owner_name"))
    face_name, confidence = recognize_face(timeout=4, show_window=False)
    normalized_name = _normalize_text(face_name)

    if normalized_name and (not expected_name or normalized_name == expected_name):
        return True, face_name or "", confidence or 0.0, "Face matched."

    if normalized_name and expected_name and normalized_name != expected_name:
        return False, face_name or "", confidence or 0.0, "Unknown or non-owner face detected."

    return False, "", confidence or 0.0, "Owner face verify nahi hua."


def _verify_pin(config, inline_pin=None):
    if not config.get("require_pin") or not config.get("pin", {}).get("hash"):
        return True, "PIN factor skipped."

    pin_value = _extract_pin(inline_pin or "")
    if not pin_value:
        speak("Security PIN bolo.")
        heard_pin = takecommand()
        pin_value = _extract_pin(heard_pin)

    if not pin_value:
        return False, "PIN samajh nahi aaya."

    if verify_value(pin_value, config["pin"]["salt"], config["pin"]["hash"]):
        return True, "PIN matched."
    return False, "PIN mismatch."


def _handle_intrusion(reason, voice_text="", face_name="", face_confidence=0.0, voice_score=0.0, pin_ok=None):
    config = load_security_config()
    forensic = _capture_forensic_bundle(
        reason=reason,
        metadata={
            "voice_text": voice_text,
            "face_name": face_name,
            "face_confidence": face_confidence,
            "voice_score": voice_score,
            "pin_ok": pin_ok,
        },
        include_photo=True,
        include_screens=True,
    )

    photo_path = forensic.get("photo") or ""
    actions = []
    if photo_path:
        actions.append("intruder_photo_saved")
    if forensic.get("screenshots"):
        actions.append("screenshots_saved")
    if forensic.get("video"):
        actions.append("screen_record_saved")
    if forensic.get("summary"):
        actions.append("forensic_summary_saved")

    consecutive_failures = count_recent_failed_auth_attempts(limit=max(3, config.get("failed_attempt_threshold", 3))) + 1
    should_lock = config.get("enabled") or consecutive_failures >= int(config.get("failed_attempt_threshold", 3))
    if should_lock:
        try:
            sc.lock_pc()
            actions.append("lock_workstation")
        except Exception as exc:
            actions.append(f"lock_failed:{exc}")

    _maybe_trigger_decoy(config, actions)

    alert_message = f"Unauthorized access detected. Reason: {reason}"
    actions.extend(
        dispatch_security_alerts(
            config,
            alert_message,
            attachment_path=photo_path,
            metadata={
                "reason": reason,
                "voice_text": voice_text,
                "face_name": face_name,
                "face_confidence": face_confidence,
                "voice_score": voice_score,
                "pin_ok": pin_ok,
                "consecutive_failures": consecutive_failures,
                "screenshots": forensic.get("screenshots", []),
                "video_path": forensic.get("video", ""),
                "summary_path": forensic.get("summary", ""),
            },
        )
    )

    threat_delta = _get_ids_score(config, "failed_auth", 15)
    lowered_reason = _normalize_text(reason)
    if "unknown" in lowered_reason or "face" in lowered_reason:
        threat_delta = max(threat_delta, _get_ids_score(config, "unknown_face", 30))
    elif "voice" in lowered_reason:
        threat_delta = max(threat_delta, _get_ids_score(config, "voice_mismatch", 18))
    elif "pin" in lowered_reason:
        threat_delta = max(threat_delta, _get_ids_score(config, "pin_mismatch", 12))

    current_score = _register_threat(
        reason=reason,
        delta=threat_delta,
        metadata={
            "voice_text": voice_text,
            "face_name": face_name,
            "face_confidence": face_confidence,
            "voice_score": voice_score,
            "pin_ok": pin_ok,
            "consecutive_failures": consecutive_failures,
        },
        event_type="intrusion",
        success=False,
        evidence_path=photo_path,
        actions=actions,
    )

    return photo_path, actions, consecutive_failures, current_score


def _authorize_owner(action_label, inline_pin=None, disarm_on_success=False):
    config = load_security_config()

    requires_save = False
    if not config.get("require_phrase"):
        config["require_phrase"] = True
        requires_save = True
    if not config.get("require_voiceprint"):
        config["require_voiceprint"] = True
        requires_save = True
    if not config.get("require_face"):
        config["require_face"] = True
        requires_save = True
    if requires_save:
        save_security_config(config)

    if not config.get("phrase", {}).get("hash"):
        message = "Owner verification ke liye secret phrase set karni hogi. 'security setup' ya 'set security phrase' bolo."
        speak(message)
        return False, message

    if not config.get("voiceprint"):
        message = "Owner verification ke liye owner voiceprint zaroori hai. 'security voice enroll' bolo."
        speak(message)
        return False, message

    if not _profile_ready(config):
        message = "Security setup incomplete hai. Pehle 'security setup' chalao."
        speak(message)
        return False, message

    phrase_result = _verify_phrase_and_voice(config)
    face_name = ""
    face_confidence = 0.0
    pin_ok = None

    if phrase_result["ok"]:
        face_ok, face_name, face_confidence, face_reason = _verify_face(config)
    else:
        face_ok, face_reason = False, phrase_result["reason"]

    if phrase_result["ok"] and face_ok:
        pin_ok, pin_reason = _verify_pin(config, inline_pin=inline_pin)
    else:
        pin_ok, pin_reason = False, "PIN check skipped."

    if phrase_result["ok"] and face_ok and (pin_ok or pin_reason == "PIN factor skipped."):
        challenge_ok, challenge_score, challenge_reason = _random_voice_challenge(config)
    else:
        challenge_ok, challenge_score, challenge_reason = False, 0.0, "Voice challenge skipped."

    granted = (
        phrase_result["ok"]
        and face_ok
        and (pin_ok or pin_reason == "PIN factor skipped.")
        and challenge_ok
    )

    if granted:
        actions = []
        if disarm_on_success:
            config["enabled"] = False
            save_security_config(config)
            actions.append("security_disarmed")

        log_security_event(
            "auth_attempt",
            True,
            reason=f"access_granted:{action_label}",
            voice_text=phrase_result["voice_text"],
            face_name=face_name,
            face_confidence=face_confidence,
            voice_score=max(phrase_result["voice_score"], challenge_score),
            pin_ok=True if pin_reason == "PIN factor skipped." else pin_ok,
            actions=actions,
            metadata={"action": action_label, "challenge": challenge_reason},
        )
        _mark_auth_anomaly(config, action_label)
        message = "Owner verified. Access granted."
        speak(message)
        return True, message

    if not phrase_result["ok"]:
        reason = phrase_result["reason"]
    elif not face_ok:
        reason = face_reason
    elif not challenge_ok:
        reason = challenge_reason
    else:
        reason = pin_reason

    evidence_path, actions, consecutive_failures, current_score = _handle_intrusion(
        reason,
        voice_text=phrase_result["voice_text"],
        face_name=face_name,
        face_confidence=face_confidence,
        voice_score=max(phrase_result["voice_score"], challenge_score),
        pin_ok=pin_ok,
    )
    log_security_event(
        "auth_attempt",
        False,
        reason=reason,
        voice_text=phrase_result["voice_text"],
        face_name=face_name,
        face_confidence=face_confidence,
        voice_score=max(phrase_result["voice_score"], challenge_score),
        pin_ok=pin_ok,
        evidence_path=evidence_path or "",
        actions=actions,
        metadata={
            "action": action_label,
            "consecutive_failures": consecutive_failures,
            "challenge": challenge_reason,
            "threat_score": current_score,
        },
    )
    message = "Access denied. Security response activate kar diya."
    speak(message)
    return False, message


def verify_owner_identity(action_label="owner_identity_check"):
    return _authorize_owner(action_label, disarm_on_success=False)


def _open_report_in_notepad(path):
    try:
        os.startfile(path)
        return True
    except Exception:
        try:
            subprocess.Popen(["notepad.exe", path])
            return True
        except Exception:
            return False


def _show_security_logs():
    report_path = build_security_report(
        limit=40,
        title="SENTINEL SECURITY REPORT",
        report_prefix="security_report",
    )
    _open_report_in_notepad(report_path)
    log_security_event(
        "history_report",
        True,
        reason="recent_security_report_opened",
        metadata={"report_path": report_path, "limit": 40},
    )
    speak("Recent intruder log report khol diya.")
    return True


def _show_full_history():
    report_path = build_security_report(
        limit=0,
        title="SENTINEL FULL ACTIVITY HISTORY",
        report_prefix="full_history_report",
    )
    _open_report_in_notepad(report_path)
    log_security_event(
        "history_report",
        True,
        reason="full_activity_history_opened",
        metadata={"report_path": report_path, "limit": "all"},
    )
    speak("Full activity history khol di. Isme system, command, alert, auth aur forensic events sab included hain.")
    return True


def _manual_intruder_capture():
    config = load_security_config()
    forensic = _capture_forensic_bundle(
        reason="manual_intruder_capture",
        metadata={"manual": True},
        include_photo=True,
        include_screens=True,
    )
    photo_path = forensic.get("photo") or ""
    actions = []
    if photo_path:
        actions.append("intruder_photo_saved")
    if forensic.get("screenshots"):
        actions.append("screenshots_saved")
    if forensic.get("video"):
        actions.append("screen_record_saved")
    if forensic.get("summary"):
        actions.append("forensic_summary_saved")

    actions.extend(
        dispatch_security_alerts(
            config,
            "Manual security capture triggered.",
            attachment_path=photo_path,
            metadata={"reason": "manual_intruder_capture"},
        )
    )
    current_score = _register_threat(
        reason="manual_intruder_capture",
        delta=_get_ids_score(config, "manual_capture", 8),
        metadata={"manual": True},
        event_type="manual_capture",
        success=False,
        evidence_path=photo_path,
        actions=actions,
    )
    log_security_event(
        "manual_capture",
        False,
        reason="manual_intruder_capture",
        evidence_path=photo_path or "",
        actions=actions,
        metadata={"threat_score": current_score},
    )
    speak("Manual intruder capture complete.")
    return True


def _launch_decoy_mode():
    ok, result = open_decoy_workspace()
    if ok:
        log_security_event(
            "decoy_mode",
            True,
            reason="decoy_workspace_opened",
            metadata={"path": result},
        )
        speak("Decoy workspace open kar diya.")
    else:
        speak("Decoy workspace open nahi ho paya.")
    return ok


def _panic_mode():
    config = load_security_config()
    forensic = _capture_forensic_bundle(
        reason="panic_mode",
        metadata={"trigger": "voice_command"},
        include_photo=True,
        include_screens=True,
    )
    actions = []
    if forensic.get("photo"):
        actions.append("intruder_photo_saved")
    if forensic.get("screenshots"):
        actions.append("screenshots_saved")
    if forensic.get("video"):
        actions.append("screen_record_saved")
    if forensic.get("summary"):
        actions.append("forensic_summary_saved")

    try:
        sc.lock_pc()
        actions.append("lock_workstation")
    except Exception as exc:
        actions.append(f"lock_failed:{exc}")

    _maybe_trigger_decoy(config, actions)
    actions.extend(
        dispatch_security_alerts(
            config,
            "Security panic mode activated.",
            attachment_path=forensic.get("photo") or "",
            metadata={
                "screenshots": forensic.get("screenshots", []),
                "video_path": forensic.get("video", ""),
                "summary_path": forensic.get("summary", ""),
            },
        )
    )
    current_score = _register_threat(
        reason="panic_mode",
        delta=_get_ids_score(config, "panic_mode", 45),
        metadata={"manual": True},
        event_type="panic_mode",
        success=False,
        evidence_path=forensic.get("photo") or "",
        actions=actions,
    )
    set_threat_score(max(current_score, int(config.get("threat_score_lock_threshold", 70))))
    speak("Panic mode activate ho gaya. System lock aur alerts trigger kar diye.")
    return True


def _set_continuous_auth(enabled):
    config = load_security_config()
    config["continuous_auth"] = {
        **(config.get("continuous_auth", {}) or {}),
        "enabled": bool(enabled),
    }
    save_security_config(config)
    log_security_event(
        "configuration",
        True,
        reason="continuous_auth_updated",
        metadata={"enabled": bool(enabled)},
    )
    return (
        "Continuous authentication on kar diya. Background face verification chalega."
        if enabled
        else "Continuous authentication off kar diya."
    )


def _reset_threat_status():
    set_threat_score(0)
    log_security_event("threat_reset", True, reason="manual_reset")
    return "Threat score reset kar diya."


def _apply_cyber_hardening():
    config = load_security_config()
    vault_config = config.get("vault", {}) or {}

    config["auto_arm_on_startup"] = True
    config["decoy"] = {
        **(config.get("decoy", {}) or {}),
        "enabled": True,
        "open_on_intrusion": True,
    }
    config["continuous_auth"] = {
        **(config.get("continuous_auth", {}) or {}),
        "enabled": True,
    }
    config["forensics"] = {
        **(config.get("forensics", {}) or {}),
        "capture_video": True,
    }
    if config.get("phrase", {}).get("hash"):
        config["require_phrase"] = True
    if config.get("voiceprint"):
        config["require_voiceprint"] = True
    if _resolve_owner_face_candidate(config):
        config["require_face"] = True
    if config.get("pin", {}).get("hash"):
        config["require_pin"] = True

    save_security_config(config)

    active = []
    missing = []
    if config.get("require_phrase") and config.get("phrase", {}).get("hash"):
        active.append("phrase")
    else:
        missing.append("phrase")
    if config.get("require_voiceprint") and config.get("voiceprint"):
        active.append("voiceprint")
    else:
        missing.append("voiceprint")
    if config.get("require_face") and _resolve_owner_face_candidate(config):
        active.append("face")
    else:
        missing.append("face")
    if config.get("require_pin") and config.get("pin", {}).get("hash"):
        active.append("pin")
    else:
        missing.append("pin")
    if vault_config.get("enabled"):
        active.append("vault")
    else:
        missing.append("vault")

    log_security_event(
        "configuration",
        True,
        reason="cyber_hardening_applied",
        metadata={"active": active, "missing": missing},
    )

    message = (
        f"Cyber hardening apply ho gaya. Active: {', '.join(active) if active else 'none'}. "
        f"Missing: {', '.join(missing) if missing else 'none'}. "
        "Continuous auth, auto arm, decoy intrusion mode, aur forensic video on kar diya."
    )
    speak(message)
    return message


def _list_removable_devices():
    devices = set()
    if psutil is None:
        return devices

    try:
        for part in psutil.disk_partitions(all=False):
            options = (part.opts or "").lower()
            device_name = part.device or ""
            if "removable" in options or device_name.lower().startswith(("e:", "f:", "g:", "h:", "i:")):
                devices.add(device_name)
    except Exception:
        return set()
    return devices


def _list_suspicious_processes(config):
    if psutil is None:
        return set()

    watchlist = {name.lower() for name in ((config.get("ids", {}) or {}).get("suspicious_processes", []) or [])}
    found = set()
    try:
        for process in psutil.process_iter(["name"]):
            name = (process.info.get("name") or "").lower()
            if name in watchlist:
                found.add(name)
    except Exception:
        return set()
    return found


def _downloads_dir():
    return Path(os.path.expanduser("~")) / "Downloads"


def _normalize_risky_extensions(ids_config):
    risky_extensions = set()
    for extension in (ids_config.get("risky_extensions", []) or []):
        normalized = str(extension or "").strip().lower()
        if not normalized:
            continue
        if not normalized.startswith("."):
            normalized = f".{normalized}"
        risky_extensions.add(normalized)
    return risky_extensions or {".exe", ".bat", ".msi"}


def _snapshot_download_files(downloads_path):
    snapshot = {}
    try:
        for entry in os.scandir(downloads_path):
            if not entry.is_file():
                continue
            try:
                snapshot[entry.path] = entry.stat().st_mtime
            except Exception:
                snapshot[entry.path] = 0.0
    except Exception:
        return {}
    return snapshot


def _classify_download_file(file_path, risky_extensions):
    extension = Path(file_path).suffix.lower()
    if extension in risky_extensions:
        return "risky", extension
    return "safe", extension


def _usb_monitor_loop():
    global _KNOWN_REMOVABLE_DEVICES

    while True:
        time.sleep(8)
        config = load_security_config()
        ids_config = config.get("ids", {}) or {}
        if not ids_config.get("enabled", True) or not ids_config.get("monitor_usb", True):
            continue

        current_devices = _list_removable_devices()
        if not _KNOWN_REMOVABLE_DEVICES:
            _KNOWN_REMOVABLE_DEVICES = current_devices
            continue

        new_devices = current_devices - _KNOWN_REMOVABLE_DEVICES
        if new_devices:
            delta = _get_ids_score(config, "usb_inserted", 20)
            for device in sorted(new_devices):
                _register_threat(
                    reason="new_usb_device_detected",
                    delta=delta,
                    metadata={"device": device},
                    event_type="ids_usb",
                    success=False,
                )
        _KNOWN_REMOVABLE_DEVICES = current_devices


def _process_monitor_loop():
    global _KNOWN_SUSPICIOUS_PROCESSES

    while True:
        config = load_security_config()
        ids_config = config.get("ids", {}) or {}
        interval_sec = max(8, int(ids_config.get("monitor_interval_sec", 12)))
        time.sleep(interval_sec)
        if not ids_config.get("enabled", True) or not ids_config.get("monitor_processes", True):
            continue

        found = _list_suspicious_processes(config)
        new_hits = found - _KNOWN_SUSPICIOUS_PROCESSES
        if new_hits:
            delta = _get_ids_score(config, "suspicious_process", 25)
            for name in sorted(new_hits):
                _register_threat(
                    reason="suspicious_process_detected",
                    delta=delta,
                    metadata={"process": name},
                    event_type="ids_process",
                    success=False,
                )
        _KNOWN_SUSPICIOUS_PROCESSES = found


def _downloads_monitor_loop():
    global _KNOWN_DOWNLOAD_FILES

    while True:
        config = load_security_config()
        ids_config = config.get("ids", {}) or {}
        interval_sec = max(3, int(ids_config.get("downloads_monitor_interval_sec", 6)))
        time.sleep(interval_sec)

        if not ids_config.get("enabled", True) or not ids_config.get("monitor_downloads", True):
            _KNOWN_DOWNLOAD_FILES = {}
            continue

        downloads_path = _downloads_dir()
        if not downloads_path.exists() or not downloads_path.is_dir():
            _KNOWN_DOWNLOAD_FILES = {}
            continue

        current_snapshot = _snapshot_download_files(str(downloads_path))
        if not _KNOWN_DOWNLOAD_FILES:
            _KNOWN_DOWNLOAD_FILES = current_snapshot
            continue

        new_file_paths = [path for path in current_snapshot if path not in _KNOWN_DOWNLOAD_FILES]
        risky_extensions = _normalize_risky_extensions(ids_config)

        for file_path in sorted(new_file_paths):
            classification, extension = _classify_download_file(file_path, risky_extensions)
            if classification != "risky":
                continue

            file_name = Path(file_path).name
            extension_text = extension or "no-extension"
            alert_message = f"Risky download detected: {file_name} ({extension_text})"
            metadata = {
                "classification": classification,
                "file_name": file_name,
                "file_path": file_path,
                "extension": extension,
                "downloads_dir": str(downloads_path),
            }

            actions = dispatch_security_alerts(
                config,
                alert_message,
                metadata=metadata,
            )

            _register_threat(
                reason="risky_download_detected",
                delta=_get_ids_score(config, "risky_download", 18),
                metadata=metadata,
                event_type="ids_download",
                success=False,
                actions=actions,
            )

        _KNOWN_DOWNLOAD_FILES = current_snapshot


def _continuous_auth_loop():
    global _CONTINUOUS_AUTH_MISSES

    while True:
        time.sleep(10)
        config = load_security_config()
        continuous = config.get("continuous_auth", {}) or {}
        if not continuous.get("enabled", False):
            _CONTINUOUS_AUTH_MISSES = 0
            continue
        if not face_engine_ready():
            continue

        interval_sec = max(30, int(continuous.get("interval_sec", 90)))
        time.sleep(max(1, interval_sec - 10))

        face_ok, face_name, face_confidence, face_reason = _verify_face(config)
        if face_ok:
            _CONTINUOUS_AUTH_MISSES = 0
            continue

        _CONTINUOUS_AUTH_MISSES += 1
        threshold = max(1, int(continuous.get("miss_threshold", 2)))
        if _CONTINUOUS_AUTH_MISSES < threshold:
            continue

        _CONTINUOUS_AUTH_MISSES = 0
        delta = _get_ids_score(config, "continuous_auth_fail", 20)
        forensic = _capture_forensic_bundle(
            reason="continuous_auth_fail",
            metadata={
                "face_name": face_name,
                "face_confidence": face_confidence,
                "reason": face_reason,
            },
            include_photo=True,
            include_screens=True,
        )
        actions = []
        if forensic.get("photo"):
            actions.append("intruder_photo_saved")
        if forensic.get("screenshots"):
            actions.append("screenshots_saved")
        if forensic.get("video"):
            actions.append("screen_record_saved")
        if forensic.get("summary"):
            actions.append("forensic_summary_saved")

        current_score = _register_threat(
            reason="continuous_auth_fail",
            delta=delta,
            metadata={
                "face_name": face_name,
                "face_confidence": face_confidence,
                "reason": face_reason,
            },
            event_type="continuous_auth",
            success=False,
            evidence_path=forensic.get("photo") or "",
            actions=actions,
        )
        log_security_event(
            "continuous_auth",
            False,
            reason=face_reason,
            face_name=face_name,
            face_confidence=face_confidence,
            evidence_path=forensic.get("photo") or "",
            actions=actions,
            metadata={"threat_score": current_score, "video_path": forensic.get("video", "")},
        )


def start_cyber_security_services():
    global _SERVICES_STARTED

    with _STATE_LOCK:
        if _SERVICES_STARTED:
            return
        _SERVICES_STARTED = True

    thread_specs = [
        ("usb_monitor", _usb_monitor_loop),
        ("process_monitor", _process_monitor_loop),
        ("downloads_monitor", _downloads_monitor_loop),
        ("continuous_auth", _continuous_auth_loop),
    ]

    for name, target in thread_specs:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        _SERVICE_THREADS.append(thread)

    log_security_event(
        "service_start",
        True,
        reason="cyber_security_services_started",
        metadata={"threads": [name for name, _ in thread_specs]},
    )


def handle_security_command(query, q=None):
    q = q or _normalize_text(query)
    inline_pin = _extract_pin(query)

    if any(phrase in q for phrase in ["memory add", "study add", "add study", "add memory", "note add"]):
        parsed = parse_quick_add_command(query)
        if not parsed:
            speak("Format bolo: memory add topic :: notes confidence 1 to 5 duration 20")
            return True

        result = add_study_record(
            topic=parsed.get("topic", "General"),
            content=parsed.get("content", ""),
            source_type="voice",
            confidence=parsed.get("confidence", 3),
            duration_min=parsed.get("duration_min", 20),
            importance=8,
            source="voice_command",
        )
        speak(result.get("message") or "Study entry save ho gayi.")
        return True

    if any(
        phrase in q
        for phrase in [
            "what did i study",
            "study history",
            "memory history",
            "memory dashboard",
            "kya padha",
        ]
    ):
        speak(voice_history_reply())
        return True

    if any(phrase in q for phrase in ["weak topics", "weak area", "weak areas", "where am i weak"]):
        speak(voice_weak_topics_reply())
        return True

    if any(phrase in q for phrase in ["strong topics", "strong area", "strong areas", "my strengths"]):
        speak(voice_strong_topics_reply())
        return True

    if any(
        phrase in q
        for phrase in [
            "revision plan",
            "revision suggestion",
            "suggest revision",
            "what should i revise",
            "revise plan",
        ]
    ):
        speak(voice_revision_reply())
        return True

    if any(
        phrase in q
        for phrase in ["verify memory integrity", "memory integrity", "tamper check", "verify integrity"]
    ):
        speak(voice_integrity_reply())
        return True

    if any(phrase in q for phrase in ["security bootstrap", "quick security", "face guard mode", "quick guard mode"]):
        ok, message = _bootstrap_face_guard(enable_now=True, auto_start=True)
        speak(message)
        return True

    if any(phrase in q for phrase in ["security setup", "guard setup", "configure security", "security configure"]):
        _guided_security_setup()
        return True

    if any(phrase in q for phrase in ["security status", "guard status", "security report status"]):
        speak(get_security_status_message())
        return True

    if any(phrase in q for phrase in ["alert status", "alerts status", "security alert status"]):
        speak(_alert_status_message())
        return True

    if any(phrase in q for phrase in ["test alert", "send test alert", "security test alert"]):
        _test_alert_dispatch()
        return True

    if any(phrase in q for phrase in ["popup alert on", "alert popup on"]):
        speak(_set_alert_toggle("popup", True))
        return True

    if any(phrase in q for phrase in ["popup alert off", "alert popup off"]):
        speak(_set_alert_toggle("popup", False))
        return True

    if any(phrase in q for phrase in ["sound alert on", "alert sound on", "alarm on"]):
        speak(_set_alert_toggle("sound", True))
        return True

    if any(phrase in q for phrase in ["sound alert off", "alert sound off", "alarm off"]):
        speak(_set_alert_toggle("sound", False))
        return True

    if any(phrase in q for phrase in ["telegram alert setup", "setup telegram alert", "set telegram alert"]):
        _configure_telegram_alert(query)
        return True

    if any(phrase in q for phrase in ["telegram alert on", "phone alert on"]):
        speak(_set_channel_alert_toggle("telegram", True))
        return True

    if any(phrase in q for phrase in ["telegram alert off", "phone alert off"]):
        speak(_set_channel_alert_toggle("telegram", False))
        return True

    if any(phrase in q for phrase in ["email alert on", "mail alert on"]):
        speak(_set_channel_alert_toggle("email", True))
        return True

    if any(phrase in q for phrase in ["email alert off", "mail alert off"]):
        speak(_set_channel_alert_toggle("email", False))
        return True

    if any(phrase in q for phrase in ["set alert smtp server", "alert smtp server set"]):
        _configure_email_alert_field(query, ["set alert smtp server", "alert smtp server set"], "smtp_server", "SMTP server")
        return True

    if any(phrase in q for phrase in ["set alert smtp port", "alert smtp port set"]):
        _configure_email_alert_field(query, ["set alert smtp port", "alert smtp port set"], "smtp_port", "SMTP port", cast_int=True)
        return True

    if any(phrase in q for phrase in ["set alert email username", "alert email username set"]):
        _configure_email_alert_field(query, ["set alert email username", "alert email username set"], "username", "Email username")
        return True

    if any(phrase in q for phrase in ["set alert email password", "alert email password set"]):
        _configure_email_alert_field(query, ["set alert email password", "alert email password set"], "password", "Email password")
        return True

    if any(phrase in q for phrase in ["set alert from email", "alert from email set"]):
        _configure_email_alert_field(query, ["set alert from email", "alert from email set"], "from_email", "From email")
        return True

    if any(phrase in q for phrase in ["set alert to email", "alert to email set"]):
        _configure_email_alert_field(query, ["set alert to email", "alert to email set"], "to_email", "To email")
        return True

    if any(phrase in q for phrase in ["threat score", "cyber status", "security score"]):
        config = load_security_config()
        speak(
            f"Current threat score {get_threat_score()} hai out of {config.get('threat_score_max', 100)}."
        )
        return True

    if any(
        phrase in q
        for phrase in [
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
        ]
    ):
        _apply_cyber_hardening()
        return True

    if any(phrase in q for phrase in ["reset threat", "clear threat score", "security reset"]):
        speak(_reset_threat_status())
        return True

    if any(phrase in q for phrase in ["set security phrase", "update security phrase", "security phrase set"]):
        inline_phrase = _extract_inline_tail(query, ["set security phrase", "update security phrase", "security phrase set"])
        ok, message = _configure_phrase(phrase_text=inline_phrase or None)
        speak(message)
        return True

    if any(phrase in q for phrase in ["set security pin", "security pin set", "update security pin", "pin set"]):
        inline_text = _extract_inline_tail(query, ["set security pin", "security pin set", "update security pin", "pin set"])
        ok, message = _configure_pin(pin_text=inline_text)
        speak(message)
        return True

    if any(phrase in q for phrase in ["remove security pin", "clear security pin", "pin hata", "pin remove"]):
        speak(_clear_pin())
        return True

    if any(phrase in q for phrase in ["security voice enroll", "enroll security voice", "register security voice"]):
        ok, message = _enroll_owner_voice()
        speak(message)
        return True

    if any(phrase in q for phrase in ["security face enroll", "enroll security face", "register security face"]):
        ok, message = _enroll_owner_face()
        speak(message)
        return True

    if any(phrase in q for phrase in ["vault status", "secure vault status", "vault info", "vault list"]):
        files = list_vault_files()
        suffix = f" Encrypted files: {', '.join(files[:5])}." if files else ""
        speak(vault_status_message() + suffix)
        return True

    if any(phrase in q for phrase in ["vault setup", "secure vault setup", "setup vault"]):
        _setup_vault_command(query)
        return True

    if any(phrase in q for phrase in ["vault unlock", "unlock vault", "open vault"]):
        _unlock_vault_command(query)
        return True

    if any(phrase in q for phrase in ["vault lock", "lock vault", "close vault"]):
        ok, message = lock_vault()
        log_security_event("vault", ok, reason="vault_lock", metadata={"locked": ok})
        speak(message)
        return True

    if any(phrase in q for phrase in ["vault protect", "protect file", "encrypt file"]):
        _protect_file_in_vault(query)
        return True

    if any(phrase in q for phrase in ["vault restore", "restore vault file", "decrypt vault file"]):
        _restore_file_from_vault(query)
        return True

    if any(phrase in q for phrase in ["vault backup", "backup vault", "secure backup"]):
        _backup_vault_command()
        return True

    if any(phrase in q for phrase in ["startup protection on", "security startup on", "auto arm on startup"]):
        speak(_set_auto_start(True))
        return True

    if any(phrase in q for phrase in ["startup protection off", "security startup off", "disable auto arm"]):
        speak(_set_auto_start(False))
        return True

    if any(phrase in q for phrase in ["continuous auth on", "continuous authentication on", "continuous guard on"]):
        speak(_set_continuous_auth(True))
        return True

    if any(phrase in q for phrase in ["continuous auth off", "continuous authentication off", "continuous guard off"]):
        speak(_set_continuous_auth(False))
        return True

    if any(phrase in q for phrase in ["security mode on", "secure mode on", "start security", "protect my laptop", "guard mode on"]):
        config = load_security_config()
        if not _profile_ready(config) and _resolve_owner_face_candidate(config):
            ok, bootstrap_message = _bootstrap_face_guard(enable_now=False, auto_start=True)
            if not ok:
                speak(bootstrap_message)
                return True
        speak(arm_security_mode(reason="manual_command"))
        return True

    if any(phrase in q for phrase in ["lock laptop for security", "security lock laptop", "guard lock laptop"]):
        speak(arm_security_mode(reason="lock_request"))
        sc.lock_pc()
        return True

    if any(phrase in q for phrase in ["unlock system", "security off", "disarm security", "security mode off", "unlock laptop"]):
        _authorize_owner("security_unlock", inline_pin=inline_pin, disarm_on_success=True)
        return True

    if any(
        phrase in q
        for phrase in [
            "show full history",
            "show activity history",
            "show all history",
            "all history",
            "system history",
            "full history",
        ]
    ):
        _show_full_history()
        return True

    if any(phrase in q for phrase in ["show intruder log", "show security log", "security logs", "security report", "show recent history"]):
        _show_security_logs()
        return True

    if any(phrase in q for phrase in ["capture intruder", "security snapshot", "guard capture"]):
        _manual_intruder_capture()
        return True

    if any(phrase in q for phrase in ["panic mode", "system emergency", "security emergency", "cyber emergency"]):
        _panic_mode()
        return True

    if any(phrase in q for phrase in ["decoy mode", "launch decoy", "open fake desktop"]):
        _launch_decoy_mode()
        return True

    return False

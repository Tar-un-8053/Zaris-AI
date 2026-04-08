import copy
import datetime as dt
import hashlib
import json
import os
import secrets
import sqlite3
import threading


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
SECURITY_DATA_DIR = os.path.join(ROOT_DIR, "security_data")
INTRUDER_DIR = os.path.join(SECURITY_DATA_DIR, "intruders")
REPORTS_DIR = os.path.join(SECURITY_DATA_DIR, "reports")
EVIDENCE_DIR = os.path.join(SECURITY_DATA_DIR, "evidence")
DECOY_DIR = os.path.join(SECURITY_DATA_DIR, "decoy_desktop")
VAULT_DIR = os.path.join(SECURITY_DATA_DIR, "vault")
VAULT_STORE_DIR = os.path.join(VAULT_DIR, "store")
VAULT_RESTORE_DIR = os.path.join(VAULT_DIR, "restore")
VAULT_BACKUP_DIR = os.path.join(VAULT_DIR, "backup")
CONFIG_PATH = os.path.join(SECURITY_DATA_DIR, "config.json")
LOG_DB_PATH = os.path.join(SECURITY_DATA_DIR, "security_logs.db")

_STORAGE_LOCK = threading.Lock()

DEFAULT_SECURITY_CONFIG = {
    "enabled": False,
    "auto_arm_on_startup": False,
    "owner_name": "Owner",
    "owner_face_name": "",
    "require_phrase": True,
    "require_voiceprint": True,
    "require_face": True,
    "require_pin": False,
    "voice_match_threshold": 0.63,
    "failed_attempt_threshold": 3,
    "threat_score": 0,
    "threat_score_lock_threshold": 70,
    "threat_score_max": 100,
    "phrase": {
        "salt": "",
        "hash": "",
    },
    "pin": {
        "salt": "",
        "hash": "",
    },
    "voiceprint": {},
    "continuous_auth": {
        "enabled": False,
        "interval_sec": 90,
        "miss_threshold": 2,
    },
    "anti_spoof": {
        "voice_challenge": True,
    },
    "ids": {
        "enabled": True,
        "monitor_usb": True,
        "monitor_processes": True,
        "monitor_downloads": True,
        "monitor_interval_sec": 12,
        "downloads_monitor_interval_sec": 6,
        "risky_extensions": [
            ".exe",
            ".bat",
            ".msi",
        ],
        "allowed_login_start_hour": 6,
        "allowed_login_end_hour": 23,
        "alert_on_unusual_hour": True,
        "suspicious_processes": [
            "wireshark.exe",
            "fiddler.exe",
            "burpsuite.exe",
            "processhacker.exe",
            "procexp.exe",
            "nmap.exe",
            "mimikatz.exe",
            "ettercap.exe",
            "keylogger.exe",
            "john.exe",
            "hashcat.exe",
        ],
        "scoring": {
            "failed_auth": 15,
            "unknown_face": 30,
            "voice_mismatch": 18,
            "pin_mismatch": 12,
            "unusual_login_hour": 12,
            "usb_inserted": 20,
            "suspicious_process": 25,
            "risky_download": 18,
            "continuous_auth_fail": 20,
            "panic_mode": 45,
            "manual_capture": 8,
        },
    },
    "decoy": {
        "enabled": True,
        "open_on_intrusion": False,
    },
    "forensics": {
        "capture_video": True,
        "video_duration_sec": 4,
        "video_fps": 4,
    },
    "vault": {
        "enabled": False,
        "locked": True,
        "salt": "",
        "verifier_hash": "",
        "last_backup": "",
    },
    "self_protection": {
        "owner_auth_required_for_shutdown": True,
        "allow_exit_without_owner": False,
    },
    "alerts": {
        "popup": True,
        "sound": True,
        "email": {
            "enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "from_email": "",
            "to_email": "",
        },
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": "",
        },
    },
}


def ensure_security_storage():
    with _STORAGE_LOCK:
        os.makedirs(SECURITY_DATA_DIR, exist_ok=True)
        os.makedirs(INTRUDER_DIR, exist_ok=True)
        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        os.makedirs(DECOY_DIR, exist_ok=True)
        os.makedirs(VAULT_DIR, exist_ok=True)
        os.makedirs(VAULT_STORE_DIR, exist_ok=True)
        os.makedirs(VAULT_RESTORE_DIR, exist_ok=True)
        os.makedirs(VAULT_BACKUP_DIR, exist_ok=True)

        connection = sqlite3.connect(LOG_DB_PATH)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    reason TEXT,
                    voice_text TEXT,
                    face_name TEXT,
                    face_confidence REAL,
                    voice_score REAL,
                    pin_ok INTEGER,
                    evidence_path TEXT,
                    actions_json TEXT,
                    metadata_json TEXT
                )
                """
            )
            connection.commit()
        finally:
            connection.close()


def _deep_merge(defaults, overrides):
    result = copy.deepcopy(defaults)
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_security_config():
    ensure_security_storage()

    if not os.path.exists(CONFIG_PATH):
        save_security_config(DEFAULT_SECURITY_CONFIG)
        return copy.deepcopy(DEFAULT_SECURITY_CONFIG)

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        data = {}

    merged = _deep_merge(DEFAULT_SECURITY_CONFIG, data)
    if merged != data:
        save_security_config(merged)
    return merged


def save_security_config(config):
    ensure_security_storage()
    merged = _deep_merge(DEFAULT_SECURITY_CONFIG, config)
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(merged, handle, ensure_ascii=False, indent=2)
    return merged


def update_security_config(patch):
    config = load_security_config()
    config = _deep_merge(config, patch)
    return save_security_config(config)


def get_threat_score():
    config = load_security_config()
    return int(config.get("threat_score", 0))


def set_threat_score(score):
    config = load_security_config()
    max_score = int(config.get("threat_score_max", 100))
    config["threat_score"] = max(0, min(max_score, int(score)))
    save_security_config(config)
    return config["threat_score"]


def adjust_threat_score(delta):
    config = load_security_config()
    max_score = int(config.get("threat_score_max", 100))
    current = int(config.get("threat_score", 0))
    updated = max(0, min(max_score, current + int(delta)))
    config["threat_score"] = updated
    save_security_config(config)
    return updated


def hash_value(value, salt=None):
    normalized = str(value or "").strip().lower()
    salt = salt or secrets.token_hex(8)
    digest = hashlib.sha256(f"{salt}:{normalized}".encode("utf-8")).hexdigest()
    return salt, digest


def verify_value(value, salt, expected_hash):
    if not salt or not expected_hash:
        return False
    _salt, digest = hash_value(value, salt=salt)
    return digest == expected_hash


def log_security_event(
    event_type,
    success,
    reason="",
    voice_text="",
    face_name="",
    face_confidence=None,
    voice_score=None,
    pin_ok=None,
    evidence_path="",
    actions=None,
    metadata=None,
):
    ensure_security_storage()

    connection = sqlite3.connect(LOG_DB_PATH)
    try:
        connection.execute(
            """
            INSERT INTO security_logs (
                created_at,
                event_type,
                success,
                reason,
                voice_text,
                face_name,
                face_confidence,
                voice_score,
                pin_ok,
                evidence_path,
                actions_json,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                event_type,
                1 if success else 0,
                reason or "",
                voice_text or "",
                face_name or "",
                face_confidence,
                voice_score,
                None if pin_ok is None else (1 if pin_ok else 0),
                evidence_path or "",
                json.dumps(actions or [], ensure_ascii=False),
                json.dumps(metadata or {}, ensure_ascii=False),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def get_recent_security_logs(limit=10):
    ensure_security_storage()

    connection = sqlite3.connect(LOG_DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        if limit is None or int(limit) <= 0:
            rows = connection.execute(
                """
                SELECT *
                FROM security_logs
                ORDER BY id DESC
                """
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT *
                FROM security_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
    finally:
        connection.close()

    entries = []
    for row in rows:
        entry = dict(row)
        try:
            entry["actions"] = json.loads(entry.pop("actions_json") or "[]")
        except Exception:
            entry["actions"] = []
        try:
            entry["metadata"] = json.loads(entry.pop("metadata_json") or "{}")
        except Exception:
            entry["metadata"] = {}
        entry["success"] = bool(entry.get("success"))
        if entry.get("pin_ok") is not None:
            entry["pin_ok"] = bool(entry["pin_ok"])
        entries.append(entry)
    return entries


def count_recent_failed_auth_attempts(limit=10):
    attempts = get_recent_security_logs(limit=limit)
    count = 0
    for entry in attempts:
        if entry.get("event_type") != "auth_attempt":
            continue
        if entry.get("success"):
            break
        count += 1
    return count


def count_total_security_logs():
    ensure_security_storage()

    connection = sqlite3.connect(LOG_DB_PATH)
    try:
        row = connection.execute("SELECT COUNT(*) FROM security_logs").fetchone()
        return int(row[0] if row else 0)
    finally:
        connection.close()


def build_security_report(limit=25, title="SENTINEL SECURITY REPORT", report_prefix="security_report"):
    ensure_security_storage()
    logs = get_recent_security_logs(limit=limit)
    total_logs = count_total_security_logs()
    config = load_security_config()
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORTS_DIR, f"{report_prefix}_{timestamp}.txt")

    lines = [
        title,
        f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Threat score: {config.get('threat_score', 0)}/{config.get('threat_score_max', 100)}",
        f"Security mode active: {config.get('enabled')}",
        f"Vault enabled: {(config.get('vault', {}) or {}).get('enabled', False)}",
        f"Total events recorded: {total_logs}",
        f"Entries included in this report: {len(logs)}",
        "",
    ]

    if not logs:
        lines.append("No security events recorded yet.")
    else:
        for entry in logs:
            lines.append(f"[{entry.get('created_at', '')}] {entry.get('event_type', '').upper()}")
            lines.append(f"Success: {entry.get('success')}")
            lines.append(f"Reason: {entry.get('reason', '') or '-'}")
            lines.append(f"Voice text: {entry.get('voice_text', '') or '-'}")
            lines.append(f"Face: {entry.get('face_name', '') or '-'}")
            lines.append(f"Face confidence: {entry.get('face_confidence', '') or '-'}")
            lines.append(f"Voice score: {entry.get('voice_score', '') or '-'}")
            lines.append(f"PIN ok: {entry.get('pin_ok', '') if entry.get('pin_ok') is not None else '-'}")
            lines.append(f"Evidence: {entry.get('evidence_path', '') or '-'}")
            lines.append(f"Actions: {', '.join(entry.get('actions', [])) or '-'}")
            lines.append(f"Metadata: {json.dumps(entry.get('metadata', {}), ensure_ascii=False)}")
            lines.append("")

    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    return report_path

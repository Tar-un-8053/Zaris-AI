import base64
import hashlib
import io
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None


ROOT_DIR = Path(__file__).resolve().parent.parent
SECURITY_DATA_DIR = ROOT_DIR / "security_data"

MEMORY_DIR = SECURITY_DATA_DIR / "memory_twin"
UPLOADS_DIR = MEMORY_DIR / "uploads"
RECORDS_PATH = MEMORY_DIR / "records.json"
LEDGER_PATH = MEMORY_DIR / "ledger.json"
ACCESS_EVENTS_PATH = MEMORY_DIR / "access_events.json"
ALERT_STATE_PATH = MEMORY_DIR / "alert_state.json"
KEY_PATH = MEMORY_DIR / "master.key"

MAX_RECORDS = 1500
ACCESS_EVENT_LIMIT = 500
SUSPICIOUS_WINDOW_SEC = 120
SUSPICIOUS_BURST_THRESHOLD = 12
ALERT_COOLDOWN_SEC = 180

_STORAGE_LOCK = threading.Lock()

_STOPWORDS = {
    "the",
    "is",
    "are",
    "was",
    "were",
    "and",
    "or",
    "with",
    "without",
    "that",
    "this",
    "from",
    "into",
    "for",
    "have",
    "has",
    "had",
    "can",
    "could",
    "should",
    "would",
    "will",
    "you",
    "your",
    "about",
    "what",
    "when",
    "where",
    "which",
    "while",
    "topic",
    "study",
    "notes",
    "note",
    "this",
    "then",
    "than",
    "their",
    "them",
    "they",
    "hai",
    "haan",
    "nahi",
    "kya",
    "ka",
    "ke",
    "ki",
    "aur",
}


def _log_security_event(*args: Any, **kwargs: Any) -> None:
    try:
        from backend.security.storage import log_security_event

        log_security_event(*args, **kwargs)
    except Exception:
        pass


def _load_security_config() -> Dict[str, Any]:
    try:
        from backend.security.storage import load_security_config

        return load_security_config()
    except Exception:
        return {}


def _get_recent_security_logs(limit: int = 10) -> List[Dict[str, Any]]:
    try:
        from backend.security.storage import get_recent_security_logs

        return get_recent_security_logs(limit=limit)
    except Exception:
        return []


def _dispatch_security_alerts(
    config: Dict[str, Any],
    message: str,
    attachment_path: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> List[str]:
    try:
        from backend.security.alerts import dispatch_security_alerts

        return dispatch_security_alerts(
            config,
            message,
            attachment_path=attachment_path,
            metadata=metadata,
        )
    except Exception:
        return []


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_storage() -> None:
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    if not RECORDS_PATH.exists():
        _write_json(RECORDS_PATH, [])
    if not LEDGER_PATH.exists():
        _write_json(LEDGER_PATH, [])
    if not ACCESS_EVENTS_PATH.exists():
        _write_json(ACCESS_EVENTS_PATH, [])
    if not ALERT_STATE_PATH.exists():
        _write_json(ALERT_STATE_PATH, {"last_access_alert_epoch": 0})


def _read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def _safe_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        numeric = int(value)
    except Exception:
        numeric = int(default)
    return max(minimum, min(maximum, numeric))


def _safe_topic(topic: str) -> str:
    clean = re.sub(r"\s+", " ", str(topic or "").strip())
    if not clean:
        return "General"
    return clean[:72]


def _sanitize_filename(name: str) -> str:
    candidate = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(name or "").strip())
    return candidate[:100] or f"upload_{int(time.time())}.dat"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _build_cipher() -> "Fernet":
    if Fernet is None:
        raise RuntimeError("cryptography package is required for encrypted memory storage.")
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
    key = KEY_PATH.read_bytes().strip()
    return Fernet(key)


def _encrypt_payload(payload: Dict[str, Any]) -> str:
    cipher = _build_cipher()
    blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return cipher.encrypt(blob).decode("utf-8")


def _decrypt_payload(cipher_text: str) -> Dict[str, Any]:
    if not cipher_text:
        return {}
    try:
        cipher = _build_cipher()
        raw = cipher.decrypt(cipher_text.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except (InvalidToken, ValueError):
        return {}
    except Exception:
        return {}


def _extract_keywords(text: str, limit: int = 6) -> List[str]:
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9+-]{2,}", str(text or "").lower())
    if not tokens:
        return []

    freq: Dict[str, int] = {}
    for token in tokens:
        if token in _STOPWORDS:
            continue
        freq[token] = freq.get(token, 0) + 1

    ranked = sorted(freq.items(), key=lambda item: (-item[1], item[0]))
    return [key for key, _count in ranked[:limit]]


def _build_summary(content: str, keyword_limit: int = 4) -> str:
    raw = re.sub(r"\s+", " ", str(content or "").strip())
    if not raw:
        return ""

    sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", raw)
        if sentence and sentence.strip()
    ]
    if sentences:
        summary = " ".join(sentences[:2])
    else:
        summary = raw[:220]

    keywords = _extract_keywords(raw, limit=keyword_limit)
    if keywords:
        summary = f"{summary} Focus: {', '.join(keywords)}."

    return summary[:320]


def _append_ledger_block(record_id: str, record_hash: str) -> str:
    ledger = _read_json(LEDGER_PATH, [])
    if not isinstance(ledger, list):
        ledger = []

    index = len(ledger) + 1
    previous_hash = ledger[-1].get("block_hash", "GENESIS") if ledger else "GENESIS"
    timestamp = _utc_now_iso()
    block_hash = _sha256_text(f"{index}|{record_id}|{record_hash}|{previous_hash}|{timestamp}")

    block = {
        "index": index,
        "timestamp": timestamp,
        "record_id": record_id,
        "record_hash": record_hash,
        "previous_hash": previous_hash,
        "block_hash": block_hash,
    }
    ledger.append(block)
    _write_json(LEDGER_PATH, ledger)
    return block_hash


def _verify_integrity_internal(log_event: bool = False) -> Dict[str, Any]:
    _ensure_storage()
    records = _read_json(RECORDS_PATH, [])
    ledger = _read_json(LEDGER_PATH, [])

    if not isinstance(records, list):
        records = []
    if not isinstance(ledger, list):
        ledger = []

    record_map = {str(item.get("record_id")): item for item in records}
    issues: List[str] = []
    previous_hash = "GENESIS"

    for block in ledger:
        index = int(block.get("index", 0))
        record_id = str(block.get("record_id", ""))
        record_hash = str(block.get("record_hash", ""))
        block_prev = str(block.get("previous_hash", ""))
        timestamp = str(block.get("timestamp", ""))
        stored_hash = str(block.get("block_hash", ""))

        expected_hash = _sha256_text(f"{index}|{record_id}|{record_hash}|{block_prev}|{timestamp}")
        if block_prev != previous_hash:
            issues.append(f"Chain link mismatch at block {index}.")
        if expected_hash != stored_hash:
            issues.append(f"Block hash mismatch at block {index}.")

        record = record_map.get(record_id)
        if not record:
            issues.append(f"Ledger references missing record {record_id}.")
        else:
            record_content_hash = str(record.get("content_hash", ""))
            if record_content_hash != record_hash:
                issues.append(f"Record hash mismatch for {record_id}.")

        previous_hash = stored_hash or previous_hash

    result = {
        "is_valid": len(issues) == 0,
        "total_blocks": len(ledger),
        "issues": issues[:10],
        "checked_at": _utc_now_iso(),
    }

    if log_event:
        _log_security_event(
            "memory_integrity_check",
            result["is_valid"],
            reason="memory_twin_ledger_verification",
            metadata={
                "total_blocks": len(ledger),
                "issue_count": len(issues),
            },
        )

    return result


def verify_integrity() -> Dict[str, Any]:
    with _STORAGE_LOCK:
        return _verify_integrity_internal(log_event=True)


def _record_access_event(action: str, source: str) -> None:
    now_epoch = int(time.time())
    events = _read_json(ACCESS_EVENTS_PATH, [])
    if not isinstance(events, list):
        events = []

    events.append(
        {
            "at": now_epoch,
            "action": str(action or "unknown"),
            "source": str(source or "unknown"),
        }
    )
    events = events[-ACCESS_EVENT_LIMIT:]
    _write_json(ACCESS_EVENTS_PATH, events)

    recent = [event for event in events if now_epoch - int(event.get("at", 0)) <= SUSPICIOUS_WINDOW_SEC]
    if len(recent) >= SUSPICIOUS_BURST_THRESHOLD:
        _trigger_suspicious_access_alert(len(recent), source)


def _trigger_suspicious_access_alert(event_count: int, source: str) -> None:
    state = _read_json(ALERT_STATE_PATH, {"last_access_alert_epoch": 0})
    if not isinstance(state, dict):
        state = {"last_access_alert_epoch": 0}

    now_epoch = int(time.time())
    last_alert_epoch = int(state.get("last_access_alert_epoch", 0))
    if now_epoch - last_alert_epoch < ALERT_COOLDOWN_SEC:
        return

    config = _load_security_config()
    message = (
        f"Memory Twin alert: unusual access burst detected ({event_count} actions in "
        f"{SUSPICIOUS_WINDOW_SEC} sec) from {source}."
    )
    alert_actions = _dispatch_security_alerts(
        config,
        message,
        metadata={
            "event_count": event_count,
            "source": source,
            "window_sec": SUSPICIOUS_WINDOW_SEC,
        },
    )

    _log_security_event(
        "memory_access_anomaly",
        False,
        reason="burst_access_detected",
        actions=alert_actions,
        metadata={
            "event_count": event_count,
            "source": source,
        },
    )

    state["last_access_alert_epoch"] = now_epoch
    _write_json(ALERT_STATE_PATH, state)


def _normalize_confidence(value: Any) -> int:
    return _safe_int(value, default=3, minimum=1, maximum=5)


def _normalize_duration(value: Any) -> int:
    return _safe_int(value, default=20, minimum=5, maximum=240)


def _normalize_importance(value: Any) -> int:
    return _safe_int(value, default=7, minimum=1, maximum=10)


def add_study_record(
    topic: str,
    content: str,
    source_type: str = "text",
    confidence: int = 3,
    duration_min: int = 20,
    importance: int = 7,
    file_name: str = "",
    source: str = "ui",
) -> Dict[str, Any]:
    with _STORAGE_LOCK:
        try:
            _ensure_storage()

            clean_content = re.sub(r"\s+", " ", str(content or "").strip())
            if not clean_content:
                return {"ok": False, "message": "Empty content cannot be stored."}

            clean_topic = _safe_topic(topic)
            clean_source_type = str(source_type or "text").strip().lower()[:24]
            confidence = _normalize_confidence(confidence)
            duration_min = _normalize_duration(duration_min)
            importance = _normalize_importance(importance)

            summary = _build_summary(clean_content)
            keywords = _extract_keywords(clean_content)
            payload = {
                "content": clean_content,
                "summary": summary,
                "keywords": keywords,
            }
            encrypted_payload = _encrypt_payload(payload)

            records = _read_json(RECORDS_PATH, [])
            if not isinstance(records, list):
                records = []

            record_id = uuid.uuid4().hex[:14]
            content_hash = _sha256_text(clean_content)
            block_hash = ""
            if importance >= 7:
                block_hash = _append_ledger_block(record_id, content_hash)

            record = {
                "record_id": record_id,
                "created_at": _utc_now_iso(),
                "source_type": clean_source_type,
                "topic": clean_topic,
                "confidence": confidence,
                "duration_min": duration_min,
                "importance": importance,
                "file_name": str(file_name or "")[:120],
                "content_hash": content_hash,
                "block_hash": block_hash,
                "payload": encrypted_payload,
            }

            records.append(record)
            records = records[-MAX_RECORDS:]
            _write_json(RECORDS_PATH, records)
            _record_access_event("write", source)

            _log_security_event(
                "memory_write",
                True,
                reason="memory_twin_record_saved",
                metadata={
                    "record_id": record_id,
                    "topic": clean_topic,
                    "source_type": clean_source_type,
                    "importance": importance,
                    "on_chain": bool(block_hash),
                },
            )

            return {
                "ok": True,
                "record_id": record_id,
                "topic": clean_topic,
                "summary": summary,
                "on_chain": bool(block_hash),
                "message": "Memory Twin me entry securely save ho gayi.",
            }
        except Exception as exc:
            _log_security_event(
                "memory_write",
                False,
                reason="memory_twin_record_error",
                metadata={"error": str(exc)},
            )
            return {
                "ok": False,
                "message": f"Memory save failed: {exc}",
            }


def _extract_document_text(file_suffix: str, raw_bytes: bytes) -> str:
    suffix = str(file_suffix or "").lower()

    text_extensions = {
        ".txt",
        ".md",
        ".json",
        ".csv",
        ".py",
        ".js",
        ".html",
        ".css",
        ".sql",
        ".log",
    }

    if suffix in text_extensions:
        for encoding in ("utf-8", "utf-16", "latin-1"):
            try:
                return raw_bytes.decode(encoding)
            except Exception:
                continue
        return ""

    if suffix == ".pdf" and PdfReader is not None:
        try:
            reader = PdfReader(io.BytesIO(raw_bytes))
            pages = []
            for page in reader.pages[:6]:
                pages.append(page.extract_text() or "")
            return "\n".join(pages).strip()
        except Exception:
            return ""

    return ""


def _decode_data_payload(data_payload: str) -> bytes:
    payload = str(data_payload or "").strip()
    if payload.startswith("data:") and "," in payload:
        payload = payload.split(",", 1)[1]
    return base64.b64decode(payload, validate=False)


def ingest_upload(
    file_name: str,
    data_payload: str,
    topic: str = "",
    confidence: int = 3,
    importance: int = 7,
    duration_min: int = 20,
    source: str = "ui_upload",
) -> Dict[str, Any]:
    with _STORAGE_LOCK:
        try:
            _ensure_storage()
            safe_name = _sanitize_filename(file_name)
            raw_bytes = _decode_data_payload(data_payload)
            if not raw_bytes:
                return {"ok": False, "message": "Uploaded file payload is empty."}

            extension = Path(safe_name).suffix.lower()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            stored_name = f"{timestamp}_{safe_name}"
            stored_path = UPLOADS_DIR / stored_name
            stored_path.write_bytes(raw_bytes)

            extracted_text = _extract_document_text(extension, raw_bytes)

            image_extensions = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
            source_type = "image" if extension in image_extensions else "document"

            if not extracted_text:
                if source_type == "image":
                    extracted_text = (
                        f"Image uploaded: {safe_name}. Visual concept capture added. "
                        "User can append detailed notes for better recall."
                    )
                else:
                    extracted_text = (
                        f"Document uploaded: {safe_name}. Raw parsing unavailable, "
                        "so metadata entry created for manual revision tagging."
                    )

            resolved_topic = _safe_topic(topic or Path(safe_name).stem.replace("_", " "))

            result = add_study_record(
                topic=resolved_topic,
                content=extracted_text,
                source_type=source_type,
                confidence=confidence,
                duration_min=duration_min,
                importance=importance,
                file_name=stored_name,
                source=source,
            )

            if result.get("ok"):
                result["stored_file"] = str(stored_path)

            return result
        except Exception as exc:
            return {
                "ok": False,
                "message": f"Upload ingest failed: {exc}",
            }


def _parse_timestamp(value: str) -> datetime:
    text = str(value or "").replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _topic_metrics(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    metrics: Dict[str, Dict[str, Any]] = {}
    for record in records:
        topic = _safe_topic(record.get("topic", "General"))
        stats = metrics.setdefault(
            topic,
            {
                "topic": topic,
                "sessions": 0,
                "confidence_total": 0,
                "duration_total": 0,
                "last_studied": "",
            },
        )
        stats["sessions"] += 1
        stats["confidence_total"] += _normalize_confidence(record.get("confidence", 3))
        stats["duration_total"] += _normalize_duration(record.get("duration_min", 20))

        current_last = _parse_timestamp(stats.get("last_studied") or "1970-01-01T00:00:00+00:00")
        new_time = _parse_timestamp(record.get("created_at", ""))
        if new_time >= current_last:
            stats["last_studied"] = str(record.get("created_at", ""))

    return metrics


def _topic_strength_score(stats: Dict[str, Any], now_dt: datetime) -> float:
    sessions = int(stats.get("sessions", 0))
    if sessions <= 0:
        return 0.0

    avg_conf = float(stats.get("confidence_total", 0)) / max(1, sessions)
    total_duration = int(stats.get("duration_total", 0))
    last_studied = _parse_timestamp(stats.get("last_studied", ""))
    days_since = max(0.0, (now_dt - last_studied).total_seconds() / 86400.0)

    confidence_score = (avg_conf / 5.0) * 60.0
    frequency_score = min(25.0, sessions * 4.5)
    duration_bonus = min(15.0, (total_duration / 180.0) * 15.0)
    recency_penalty = min(20.0, max(0.0, days_since - 2.0) * 3.0)

    score = max(0.0, min(100.0, confidence_score + frequency_score + duration_bonus - recency_penalty))
    return round(score, 1)


def _history_entries(records: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for record in records[:limit]:
        payload = _decrypt_payload(record.get("payload", ""))
        summary = str(payload.get("summary", "")).strip()
        items.append(
            {
                "topic": _safe_topic(record.get("topic", "General")),
                "time": str(record.get("created_at", "")),
                "summary": summary or "No summary available.",
                "confidence": _normalize_confidence(record.get("confidence", 3)),
                "source_type": str(record.get("source_type", "text")),
            }
        )
    return items


def _build_revision_plan(weak_topics: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not weak_topics:
        return [
            {
                "topic": "All tracked topics",
                "priority": "low",
                "task": "Light revision maintain karo: 20 min recap + 5 min recall.",
                "when": "Next 24 hours",
            }
        ]

    plan: List[Dict[str, Any]] = []
    for index, weak_topic in enumerate(weak_topics[:4], start=1):
        topic = weak_topic.get("topic", "Unknown")
        score = float(weak_topic.get("score", 0.0))
        priority = "high" if score < 35 else "medium"
        day_offset = 0 if index <= 2 else 1
        when_label = "Tonight" if day_offset == 0 else "Tomorrow"
        plan.append(
            {
                "topic": topic,
                "priority": priority,
                "task": "25 min concept review + 10 min active recall + 5 MCQ check.",
                "when": when_label,
            }
        )

    return plan


def _security_alerts(limit: int = 8) -> List[Dict[str, Any]]:
    logs = _get_recent_security_logs(limit=limit)
    alerts: List[Dict[str, Any]] = []
    for item in logs:
        if item.get("success") and str(item.get("event_type", "")) not in {
            "memory_access_anomaly",
            "intrusion",
            "panic_mode",
        }:
            continue

        alerts.append(
            {
                "time": item.get("created_at", ""),
                "event": item.get("event_type", ""),
                "reason": item.get("reason", ""),
                "success": bool(item.get("success", False)),
            }
        )

    if not alerts:
        alerts.append(
            {
                "time": _utc_now_iso(),
                "event": "secure_state",
                "reason": "No recent critical security alerts.",
                "success": True,
            }
        )

    return alerts[:6]


def get_dashboard(max_history: int = 8) -> Dict[str, Any]:
    with _STORAGE_LOCK:
        _ensure_storage()
        _record_access_event("read", "dashboard")

        records = _read_json(RECORDS_PATH, [])
        if not isinstance(records, list):
            records = []

        records.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)

        metrics = _topic_metrics(records)
        now_dt = datetime.now(timezone.utc)

        strong_topics: List[Dict[str, Any]] = []
        weak_topics: List[Dict[str, Any]] = []
        for _topic, stats in metrics.items():
            sessions = int(stats.get("sessions", 0))
            avg_conf = round(float(stats.get("confidence_total", 0)) / max(1, sessions), 2)
            score = _topic_strength_score(stats, now_dt)

            summary = {
                "topic": stats.get("topic", "Unknown"),
                "score": score,
                "sessions": sessions,
                "avg_confidence": avg_conf,
                "duration_total": int(stats.get("duration_total", 0)),
                "last_studied": stats.get("last_studied", ""),
            }

            if score >= 70 and sessions >= 2:
                strong_topics.append(summary)
            elif score < 45 or avg_conf <= 2.8:
                weak_topics.append(summary)

        strong_topics.sort(key=lambda item: item["score"], reverse=True)
        weak_topics.sort(key=lambda item: item["score"])

        history = _history_entries(records, limit=max_history)
        revision_plan = _build_revision_plan(weak_topics)
        alerts = _security_alerts(limit=10)
        integrity = _verify_integrity_internal(log_event=False)

        return {
            "ok": True,
            "generated_at": _utc_now_iso(),
            "totals": {
                "records": len(records),
                "topics": len(metrics),
                "on_chain_records": sum(1 for item in records if item.get("block_hash")),
                "integrity_blocks": integrity.get("total_blocks", 0),
            },
            "strong_topics": strong_topics[:6],
            "weak_topics": weak_topics[:6],
            "study_history": history,
            "revision_plan": revision_plan,
            "alerts": alerts,
            "integrity": integrity,
        }


def parse_quick_add_command(query: str) -> Dict[str, Any]:
    raw = str(query or "").strip()
    lowered = raw.lower()
    markers = [
        "memory add",
        "study add",
        "add study",
        "add memory",
        "note add",
    ]

    tail = raw
    for marker in markers:
        index = lowered.find(marker)
        if index >= 0:
            tail = raw[index + len(marker) :].strip(" :-")
            break

    if not tail:
        return {}

    confidence_match = re.search(r"(?:confidence|conf)\s*[:=]?\s*([1-5])", tail, flags=re.IGNORECASE)
    duration_match = re.search(
        r"(?:duration|min|minutes)\s*[:=]?\s*(\d{1,3})",
        tail,
        flags=re.IGNORECASE,
    )
    confidence = int(confidence_match.group(1)) if confidence_match else 3
    duration = int(duration_match.group(1)) if duration_match else 20

    tail = re.sub(r"(?:confidence|conf)\s*[:=]?\s*[1-5]", "", tail, flags=re.IGNORECASE)
    tail = re.sub(
        r"(?:duration|min|minutes)\s*[:=]?\s*\d{1,3}",
        "",
        tail,
        flags=re.IGNORECASE,
    )
    tail = re.sub(r"\s+", " ", tail).strip(" |:-")

    topic = "General"
    content = ""
    if "::" in tail:
        topic, content = [part.strip() for part in tail.split("::", 1)]
    elif "|" in tail:
        topic, content = [part.strip() for part in tail.split("|", 1)]
    elif ":" in tail:
        topic, content = [part.strip() for part in tail.split(":", 1)]
    else:
        words = tail.split()
        if len(words) >= 6:
            topic = " ".join(words[:3])
            content = " ".join(words[3:])
        else:
            content = tail

    if not content:
        return {}

    return {
        "topic": _safe_topic(topic),
        "content": content,
        "confidence": _normalize_confidence(confidence),
        "duration_min": _normalize_duration(duration),
    }


def voice_history_reply() -> str:
    dashboard = get_dashboard(max_history=3)
    history = dashboard.get("study_history", [])
    if not history:
        return "Abhi tak koi study memory save nahi hui. 'memory add topic :: notes' bolo." 

    snippets = []
    for item in history[:3]:
        topic = item.get("topic", "topic")
        confidence = item.get("confidence", 3)
        snippets.append(f"{topic} confidence {confidence}")
    return "Recent study snapshot: " + ", ".join(snippets) + "."


def voice_weak_topics_reply() -> str:
    dashboard = get_dashboard(max_history=5)
    weak = dashboard.get("weak_topics", [])
    if not weak:
        return "Nice, abhi koi major weak topic detect nahi hua. Revision momentum maintain rakho."

    top = weak[:3]
    parts = [f"{item.get('topic')} score {item.get('score')}" for item in top]
    return "Weak areas identified: " + ", ".join(parts) + "."


def voice_strong_topics_reply() -> str:
    dashboard = get_dashboard(max_history=5)
    strong = dashboard.get("strong_topics", [])
    if not strong:
        return "Strong topics abhi build phase me hain. Thoda aur focused revision karo."

    top = strong[:3]
    parts = [f"{item.get('topic')} score {item.get('score')}" for item in top]
    return "Strong topics: " + ", ".join(parts) + "."


def voice_revision_reply() -> str:
    dashboard = get_dashboard(max_history=6)
    plan = dashboard.get("revision_plan", [])
    if not plan:
        return "Revision plan abhi generate nahi ho paya. Pehle kuch study entries save karo."

    top = plan[:3]
    parts = [f"{item.get('topic')} {item.get('when')}" for item in top]
    return "Personal revision plan ready: " + ", ".join(parts) + "."


def voice_integrity_reply() -> str:
    result = verify_integrity()
    if result.get("is_valid"):
        return "Memory ledger verified. Koi tampering detect nahi hui."

    issue_count = len(result.get("issues", []))
    return f"Warning: memory integrity mismatch detect hui. Total issues {issue_count}."

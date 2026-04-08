"""
Local Activity Logger for ZARIS AI
Records file operations and scan results for user insights.
No sensitive tracking - all data stays local.
"""

import json
import os
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


ACTIVITY_LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "activity_log.json")
MAX_LOG_ENTRIES = 1000
MAX_DAYS_HISTORY = 30


@dataclass
class ActivityEntry:
    timestamp: str
    activity_type: str
    category: str
    message: str
    metadata: dict


class ActivityLogger:
    def __init__(self, log_file: str = None):
        self.log_file = Path(log_file or ACTIVITY_LOG_FILE)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._logs: list[dict] = []
        self._load_logs()

    def _load_logs(self):
        if self.log_file.exists():
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    self._logs = json.load(f)
                    self._cleanup_old_logs()
            except Exception:
                self._logs = []

    def _save_logs(self):
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self._logs[-MAX_LOG_ENTRIES:], f, indent=2)
        except Exception:
            pass

    def _cleanup_old_logs(self):
        cutoff = datetime.now() - timedelta(days=MAX_DAYS_HISTORY)
        cutoff_str = cutoff.isoformat()
        self._logs = [log for log in self._logs if log.get("timestamp", "") >= cutoff_str]

    def log(self, activity_type: str, category: str, message: str, metadata: dict = None):
        entry = ActivityEntry(
            timestamp=datetime.now().isoformat(),
            activity_type=activity_type,
            category=category,
            message=message,
            metadata=metadata or {}
        )
        self._logs.append(asdict(entry))
        self._cleanup_old_logs()
        self._save_logs()

    def log_file_added(self, file_path: str, size_mb: float = 0, source: str = "user"):
        self.log(
            activity_type="file_added",
            category="files",
            message=f"File added: {Path(file_path).name}",
            metadata={"path": file_path, "size_mb": size_mb, "source": source}
        )

    def log_file_deleted(self, file_path: str, size_mb: float = 0, reason: str = "user"):
        self.log(
            activity_type="file_deleted",
            category="files",
            message=f"File deleted: {Path(file_path).name}",
            metadata={"path": file_path, "size_mb": size_mb, "reason": reason}
        )

    def log_scan_result(self, folder: str, total_files: int, duplicates: int, 
                        suspicious: int, unused: int, scan_time: float):
        self.log(
            activity_type="scan_completed",
            category="scans",
            message=f"Scanned {total_files} files in {scan_time:.1f}s",
            metadata={
                "folder": folder,
                "total_files": total_files,
                "duplicates": duplicates,
                "suspicious": suspicious,
                "unused": unused,
                "scan_time": round(scan_time, 2)
            }
        )

    def log_risky_file(self, file_path: str, risk_type: str, size_mb: float):
        self.log(
            activity_type="risky_file",
            category="security",
            message=f"Risky file found: {Path(file_path).name}",
            metadata={"path": file_path, "risk_type": risk_type, "size_mb": size_mb}
        )

    def log_duplicate_found(self, file_path: str, duplicate_count: int, wasted_mb: float):
        self.log(
            activity_type="duplicate",
            category="cleanup",
            message=f"Duplicate found: {Path(file_path).name}",
            metadata={"path": file_path, "count": duplicate_count, "wasted_mb": wasted_mb}
        )

    def log_cleanup(self, files_removed: int, space_freed_mb: float):
        self.log(
            activity_type="cleanup",
            category="cleanup",
            message=f"Cleaned up {files_removed} files",
            metadata={"files_removed": files_removed, "space_freed_mb": space_freed_mb}
        )

    def get_today_stats(self) -> dict:
        today = datetime.now().date().isoformat()
        today_logs = [log for log in self._logs if log.get("timestamp", "").startswith(today)]
        
        stats = {
            "files_added": 0,
            "files_deleted": 0,
            "scans_completed": 0,
            "risky_files": 0,
            "duplicates_found": 0,
            "total_files_scanned": 0,
            "scan_time_total": 0.0,
        }
        
        for log in today_logs:
            activity_type = log.get("activity_type", "")
            metadata = log.get("metadata", {})
            
            if activity_type == "file_added":
                stats["files_added"] += 1
            elif activity_type == "file_deleted":
                stats["files_deleted"] += 1
            elif activity_type == "scan_completed":
                stats["scans_completed"] += 1
                stats["total_files_scanned"] += metadata.get("total_files", 0)
                stats["scan_time_total"] += metadata.get("scan_time", 0)
            elif activity_type == "risky_file":
                stats["risky_files"] += 1
            elif activity_type == "duplicate":
                stats["duplicates_found"] += 1
        
        return stats

    def get_recent_activities(self, limit: int = 10) -> list[dict]:
        return self._logs[-limit:][::-1]

    def get_weekly_summary(self) -> dict:
        week_ago = datetime.now() - timedelta(days=7)
        week_ago_str = week_ago.isoformat()
        week_logs = [log for log in self._logs if log.get("timestamp", "") >= week_ago_str]
        
        daily_stats = defaultdict(lambda: {
            "files_added": 0, "files_deleted": 0, "scans": 0, "risky": 0
        })
        
        for log in week_logs:
            date = log.get("timestamp", "")[:10]
            activity_type = log.get("activity_type", "")
            
            if activity_type == "file_added":
                daily_stats[date]["files_added"] += 1
            elif activity_type == "file_deleted":
                daily_stats[date]["files_deleted"] += 1
            elif activity_type == "scan_completed":
                daily_stats[date]["scans"] += 1
            elif activity_type == "risky_file":
                daily_stats[date]["risky"] += 1
        
        return dict(daily_stats)

    def get_insight_message(self) -> str:
        stats = self.get_today_stats()
        messages = []
        
        if stats["risky_files"] > 0:
            messages.append(f"{stats['risky_files']} risky file{'s' if stats['risky_files'] > 1 else ''} detected today")
        
        if stats["duplicates_found"] > 0:
            messages.append(f"{stats['duplicates_found']} duplicate{'s' if stats['duplicates_found'] > 1 else ''} found")
        
        if stats["scans_completed"] > 0:
            messages.append(f"{stats['scans_completed']} scan{'s' if stats['scans_completed'] > 1 else ''} completed")
        
        if stats["files_deleted"] > 0:
            messages.append(f"{stats['files_deleted']} file{'s' if stats['files_deleted'] > 1 else ''} deleted")
        
        if not messages:
            return "No significant activity today."
        
        return ". ".join(messages) + "."

    def get_activity_breakdown(self) -> dict:
        category_counts = defaultdict(int)
        for log in self._logs:
            category = log.get("category", "other")
            category_counts[category] += 1
        
        return dict(category_counts)

    def clear_old_logs(self, days: int = None):
        if days is None:
            days = MAX_DAYS_HISTORY
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.isoformat()
        original_count = len(self._logs)
        self._logs = [log for log in self._logs if log.get("timestamp", "") >= cutoff_str]
        removed = original_count - len(self._logs)
        self._save_logs()
        return removed


_activity_logger: Optional[ActivityLogger] = None


def get_activity_logger() -> ActivityLogger:
    global _activity_logger
    if _activity_logger is None:
        _activity_logger = ActivityLogger()
    return _activity_logger
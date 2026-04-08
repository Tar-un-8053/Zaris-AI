"""
Simple Alert System for JARVIS
Notifies users about risky files, duplicates, and provides daily summaries.
"""

import json
import os
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List
from enum import Enum


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    timestamp: str
    severity: str
    title: str
    message: str
    category: str
    action_suggested: str
    dismissed: bool = False


class AlertSystem:
    ALERTS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "alerts.json")
    CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "security_data", "config.json")
    MAX_ALERTS = 50
    ALERT_COOLDOWN_HOURS = 2
    
    def __init__(self):
        self._alerts: List[dict] = []
        self._telegram_enabled = True
        self._load_alerts()
        self._load_config()
    
    def _load_alerts(self):
        Path(self.ALERTS_FILE).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(self.ALERTS_FILE):
            try:
                with open(self.ALERTS_FILE, "r", encoding="utf-8") as f:
                    self._alerts = json.load(f)
            except Exception:
                self._alerts = []
    
    def _load_config(self):
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    alerts_config = config.get("alerts", {})
                    telegram_config = alerts_config.get("telegram", {})
                    self._telegram_enabled = telegram_config.get("enabled", True)
                    self._telegram_token = telegram_config.get("bot_token", "")
                    self._telegram_chat_id = telegram_config.get("chat_id", "")
            except Exception:
                self._telegram_enabled = True
    
    def _save_alerts(self):
        try:
            with open(self.ALERTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self._alerts[-self.MAX_ALERTS:], f, indent=2)
        except Exception:
            pass
    
    def _can_alert(self, category: str) -> bool:
        """Check if we can send alert (cooldown to prevent spam)."""
        now = datetime.now()
        for alert in reversed(self._alerts[-20:]):
            if alert.get("category") == category:
                try:
                    alert_time = datetime.fromisoformat(alert.get("timestamp", ""))
                    if now - alert_time < timedelta(hours=self.ALERT_COOLDOWN_HOURS):
                        return False
                except Exception:
                    pass
        return True
    
    def create_alert(
        self,
        severity: AlertSeverity,
        title: str,
        message: str,
        category: str,
        action_suggested: str = ""
    ) -> Alert:
        """Create a new alert."""
        alert = Alert(
            timestamp=datetime.now().isoformat(),
            severity=severity.value,
            title=title,
            message=message,
            category=category,
            action_suggested=action_suggested,
            dismissed=False
        )
        
        self._alerts.append(asdict(alert))
        self._cleanup_old_alerts()
        self._save_alerts()
        
        return alert
    
    def send_telegram_notification(self, alert: Alert) -> bool:
        """Send alert to Telegram."""
        if not self._telegram_enabled:
            return False
        
        if not self._telegram_token or not self._telegram_chat_id:
            return False
        
        try:
            import urllib.request
            import urllib.parse
            
            # Format message based on severity
            severity_emoji = {
                "critical": "CRITICAL",
                "warning": "WARNING",
                "info": "INFO"
            }
            
            severity_prefix = severity_emoji.get(alert.severity, "INFO")
            
            # Build message - avoid special characters that break Telegram Markdown
            title = alert.title.replace('*', '').replace('_', '').replace('`', '')
            message = alert.message.replace('*', '').replace('_', '').replace('`', '')
            
            text = f"[{severity_prefix}] {title}\n\n{message}"
            if alert.action_suggested:
                action = alert.action_suggested.replace('*', '').replace('_', '')
                text += f"\n\nSuggestion: {action}"
            text += f"\n\nTime: {datetime.now().strftime('%H:%M')}"
            
            # Send to Telegram
            url = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
            payload = urllib.parse.urlencode({
                "chat_id": self._telegram_chat_id,
                "text": text
            }).encode("utf-8")
            
            request = urllib.request.Request(url, data=payload)
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            
            return True
        except Exception as e:
            print(f"Telegram alert failed: {e}")
            return False
    
    def notify(self, alert: Alert) -> bool:
        """Send alert via all enabled channels (Telegram)."""
        # Always save to local alerts
        self._alerts.append(asdict(alert))
        self._cleanup_old_alerts()
        self._save_alerts()
        
        # Send to Telegram for critical/warning
        if alert.severity in ["critical", "warning"]:
            return self.send_telegram_notification(alert)
        
        return True
    
    def _cleanup_old_alerts(self):
        """Remove alerts older than 7 days."""
        cutoff = datetime.now() - timedelta(days=7)
        self._alerts = [
            a for a in self._alerts
            if self._is_alert_newer_than(a, cutoff)
        ]
    
    def _is_alert_newer_than(self, alert: dict, cutoff: datetime) -> bool:
        try:
            alert_time = datetime.fromisoformat(alert.get("timestamp", ""))
            return alert_time > cutoff
        except Exception:
            return True
    
    def alert_risky_file(self, file_name: str, risk_type: str, risk_score: int) -> Optional[Alert]:
        """Alert about a risky file detected and send to Telegram."""
        if not self._can_alert("risky_file"):
            return None
        
        if risk_score >= 80:
            severity = AlertSeverity.CRITICAL
            action = "Delete or quarantine the file immediately"
        elif risk_score >= 50:
            severity = AlertSeverity.WARNING
            action = "Review file before opening"
        else:
            severity = AlertSeverity.INFO
            action = "Verify file source"
        
        alert = Alert(
            timestamp=datetime.now().isoformat(),
            severity=severity.value,
            title=f"Risky File: {file_name}",
            message=f"Detected {risk_type} with risk score {risk_score}/100",
            category="risky_file",
            action_suggested=action
        )
        
        self.notify(alert)
        return alert
    
    def alert_duplicates_found(self, count: int, wasted_mb: float) -> Optional[Alert]:
        """Alert about duplicate files and send to Telegram."""
        if count < 3:
            return None
        
        if not self._can_alert("duplicates"):
            return None
        
        severity = AlertSeverity.INFO
        if wasted_mb > 1000:
            severity = AlertSeverity.WARNING
        
        alert = Alert(
            timestamp=datetime.now().isoformat(),
            severity=severity.value,
            title=f"Duplicate Files Found",
            message=f"{count} duplicate sets found, wasting {wasted_mb:.1f}MB",
            category="duplicates",
            action_suggested="Say 'show duplicates' to review"
        )
        
        self.notify(alert)
        return alert
    
    def alert_unused_files(self, count: int, wasted_mb: float) -> Optional[Alert]:
        """Alert about unused files and send to Telegram."""
        if count < 5:
            return None
        
        if not self._can_alert("unused_files"):
            return None
        
        severity = AlertSeverity.INFO
        if wasted_mb > 5000:
            severity = AlertSeverity.WARNING
        
        alert = Alert(
            timestamp=datetime.now().isoformat(),
            severity=severity.value,
            title=f"Unused Files Detected",
            message=f"{count} files unused for 90+ days, using {wasted_mb:.1f}MB",
            category="unused_files",
            action_suggested="Say 'show unused' to review"
        )
        
        self.notify(alert)
        return alert
    
    def alert_scan_complete(self, files_scanned: int, issues_found: int) -> Optional[Alert]:
        """Alert about completed scan."""
        if issues_found == 0:
            return None
        
        if not self._can_alert("scan_complete"):
            return None
        
        return self.create_alert(
            severity=AlertSeverity.INFO,
            title="Scan Complete",
            message=f"Scanned {files_scanned} files, found {issues_found} issues",
            category="scan",
            action_suggested="Say 'show duplicates' or 'show unused' for details"
        )
    
    def get_pending_alerts(self, limit: int = 5) -> List[dict]:
        """Get unread alerts."""
        pending = [a for a in self._alerts if not a.get("dismissed", False)]
        return pending[-limit:][::-1]
    
    def dismiss_alert(self, index: int):
        """Dismiss an alert."""
        if 0 <= index < len(self._alerts):
            self._alerts[index]["dismissed"] = True
            self._save_alerts()
    
    def dismiss_all(self):
        """Dismiss all alerts."""
        for alert in self._alerts:
            alert["dismissed"] = True
        self._save_alerts()
    
    def get_daily_summary(self) -> dict:
        """Generate a daily summary of activity."""
        from backend.activity_logger import get_activity_logger
        
        logger = get_activity_logger()
        stats = logger.get_today_stats()
        
        pending_alerts = self.get_pending_alerts(limit=10)
        
        critical_alerts = len([a for a in pending_alerts if a.get("severity") == "critical"])
        warning_alerts = len([a for a in pending_alerts if a.get("severity") == "warning"])
        
        summary = {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "files_scanned": stats.get("total_files_scanned", 0),
            "scans_completed": stats.get("scans_completed", 0),
            "risky_files": stats.get("risky_files", 0),
            "duplicates_found": stats.get("duplicates_found", 0),
            "files_deleted": stats.get("files_deleted", 0),
            "pending_alerts": len(pending_alerts),
            "critical_alerts": critical_alerts,
            "warning_alerts": warning_alerts,
        }
        
        return summary
    
    def format_daily_summary(self) -> str:
        """Format daily summary for voice output."""
        summary = self.get_daily_summary()
        
        parts = [f"Daily summary for {summary['date']}."]
        
        if summary["files_scanned"] > 0:
            parts.append(f"Scanned {summary['files_scanned']} files.")
        
        if summary["risky_files"] > 0:
            parts.append(f"Detected {summary['risky_files']} risky file{'s' if summary['risky_files'] > 1 else ''}.")
        
        if summary["duplicates_found"] > 0:
            parts.append(f"Found {summary['duplicates_found']} duplicate sets.")
        
        if summary["files_deleted"] > 0:
            parts.append(f"Deleted {summary['files_deleted']} file{'s' if summary['files_deleted'] > 1 else ''}.")
        
        if summary["critical_alerts"] > 0:
            parts.append(f"Attention: {summary['critical_alerts']} critical alert{'s' if summary['critical_alerts'] > 1 else ''} pending.")
        elif summary["warning_alerts"] > 0:
            parts.append(f"{summary['warning_alerts']} warning{'s' if summary['warning_alerts'] > 1 else ''} pending.")
        
        if summary["files_scanned"] == 0 and summary["pending_alerts"] == 0:
            parts.append("No activity detected. System running smoothly.")
        
        # Add suggestions
        suggestions = []
        if summary["risky_files"] > 0:
            suggestions.append("Review risky files")
        if summary["duplicates_found"] > 5:
            suggestions.append("Clean up duplicates")
        if summary["pending_alerts"] > 3:
            suggestions.append("Check pending alerts")
        
        if suggestions:
            parts.append(f"Suggestions: {', '.join(suggestions[:3])}.")
        
        return " ".join(parts)
    
    def format_pending_alerts(self, limit: int = 3) -> str:
        """Format pending alerts for voice output."""
        alerts = self.get_pending_alerts(limit=limit)
        
        if not alerts:
            return "No pending alerts."
        
        if len(alerts) == 1:
            alert = alerts[0]
            return f"Alert: {alert['title']}. {alert['message']}"
        
        parts = [f"You have {len(alerts)} pending alert{'s' if len(alerts) > 1 else ''}:"]
        
        for alert in alerts[:3]:
            severity = alert.get("severity", "info")
            if severity == "critical":
                parts.append(f"Critical: {alert['title']}")
            elif severity == "warning":
                parts.append(f"Warning: {alert['title']}")
            else:
                parts.append(f"{alert['title']}")
        
        return " ".join(parts)


_alert_system: Optional[AlertSystem] = None


def get_alert_system() -> AlertSystem:
    global _alert_system
    if _alert_system is None:
        _alert_system = AlertSystem()
    return _alert_system


def create_risky_file_alert(file_name: str, risk_type: str, risk_score: int) -> Optional[Alert]:
    """Convenience function for risky file alerts."""
    return get_alert_system().alert_risky_file(file_name, risk_type, risk_score)


def create_duplicate_alert(count: int, wasted_mb: float) -> Optional[Alert]:
    """Convenience function for duplicate alerts."""
    return get_alert_system().alert_duplicates_found(count, wasted_mb)


def create_unused_alert(count: int, wasted_mb: float) -> Optional[Alert]:
    """Convenience function for unused file alerts."""
    return get_alert_system().alert_unused_files(count, wasted_mb)


def get_daily_briefing() -> str:
    """Get daily briefing message."""
    return get_alert_system().format_daily_summary()


def get_alert_briefing() -> str:
    """Get pending alerts briefing."""
    return get_alert_system().format_pending_alerts()


def send_security_alert(event_type: str, details: dict) -> bool:
    """Send security alert directly to Telegram."""
    alert_system = get_alert_system()
    
    # Determine severity based on event type
    critical_events = ["unauthorized_access", "rat_detected", "malware_detected", "panic_mode"]
    warning_events = ["unknown_face", "multiple_failures", "usb_connected"]
    
    if event_type in critical_events:
        severity = AlertSeverity.CRITICAL
    elif event_type in warning_events:
        severity = AlertSeverity.WARNING
    else:
        severity = AlertSeverity.INFO
    
    # Build message
    emojis = {
        "unauthorized_access": "🔓",
        "rat_detected": "🐀",
        "malware_detected": "🦠",
        "unknown_face": "👤",
        "multiple_failures": "⚠️",
        "usb_connected": "🔌",
        "file_deleted": "🗑️",
        "suspicious_file": "⚠️",
    }
    
    emoji = emojis.get(event_type, "⚠️")
    title = f"{emoji} {event_type.replace('_', ' ').title()}"
    
    message_parts = []
    for key, value in details.items():
        message_parts.append(f"{key}: {value}")
    
    message = "\n".join(message_parts) if message_parts else f"{event_type} detected"
    
    alert = Alert(
        timestamp=datetime.now().isoformat(),
        severity=severity.value,
        title=title,
        message=message,
        category=event_type,
        action_suggested="Check security status"
    )
    
    return alert_system.notify(alert)


def test_telegram_alert() -> bool:
    """Test Telegram connection by sending a test alert."""
    alert_system = get_alert_system()
    
    test_alert = Alert(
        timestamp=datetime.now().isoformat(),
        severity="info",
        title="🔔 Test Alert",
        message="ZARIS AI Telegram alerts are working!",
        category="test",
        action_suggested="This is a test message"
    )
    
    return alert_system.send_telegram_notification(test_alert)
import datetime as dt
import json
import os
import platform
import shutil
from pathlib import Path

from backend.security.storage import REPORTS_DIR, ensure_security_storage, get_threat_score, log_security_event
from backend.folder_scanner import FileInfo, FolderScanner, ScanResult, format_scan_result, format_summary, get_scanner
from backend.activity_logger import get_activity_logger
from backend.threat_detection import analyze_threat, get_threat_alert, should_block_file, check_file_before_action
from backend.alert_system import get_alert_system, create_risky_file_alert, create_duplicate_alert, create_unused_alert
from backend.system_monitor import get_system_monitor

ZARIS_HELP_TEXT = (
    "Zaris AI commands: scan <folder>, check file <path>, delete file <path>, "
    "show duplicates, show unused, daily summary, show alerts, "
    "test alert, telegram on/off, activity today, system status, "
    "show disk, show memory, show processes, show graph, help."
)

MAX_SCAN_FILES = max(50, int(os.getenv("ZARIS_SCAN_MAX_FILES", os.getenv("JARVIS_SCAN_MAX_FILES", "500"))))
MAX_SCAN_DEPTH = max(1, int(os.getenv("ZARIS_SCAN_MAX_DEPTH", os.getenv("JARVIS_SCAN_MAX_DEPTH", "4"))))
SCAN_LOOKBACK_HOURS = max(1, int(os.getenv("ZARIS_SCAN_LOOKBACK_HOURS", os.getenv("JARVIS_SCAN_LOOKBACK_HOURS", "240"))))
LATEST_SCAN_PATH = os.path.join(REPORTS_DIR, "zaris_download_scan_latest.json")

_HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".js",
    ".vbs",
    ".jar",
}

_MEDIUM_RISK_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".lnk",
}

_SAFE_LOOKING_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "jpg",
    "jpeg",
    "png",
    "txt",
    "xls",
    "xlsx",
}

_CORE_COMMAND_ALIASES = {
    "scan downloads": [
        "scan downloads",
        "scan my downloads",
        "check downloads",
        "download scan",
        "scan download folder",
    ],
    "show risky files": [
        "show risky files",
        "risky files",
        "show suspicious files",
        "list risky files",
        "show threats",
    ],
    "system status": [
        "system status",
        "zaris status",
        "jarvis status",
        "security status",
        "status report",
    ],
    "last scan summary": [
        "last scan summary",
        "last scan",
        "scan summary",
        "download scan summary",
    ],
    "scan folders": [
        "scan folders",
        "scan monitored folders",
        "folder scan",
        "scan my folders",
    ],
    "show duplicates": [
        "show duplicates",
        "duplicates",
        "duplicate files",
        "find duplicates",
        "show duplicate files",
        "duplicate file names",
        "duplicate file paths",
        "duplicates list",
        "list duplicates",
        "duplicate files list",
        "show duplicate names",
        "dup files",
        "dupes",
        "duplicates files",
        "duplicates file names",
        "duplicate path",
        "duplicate paths",
        "duplicate file path",
        "duplicate files name",
    ],
    "show unused": [
        "show unused",
        "unused files",
        "old files",
        "show old files",
        "list unused files",
        "unused file names",
        "old file names",
        "list old files",
        "unused files list",
    ],
    "folder scan status": [
        "folder scan status",
        "folder status",
        "monitored folders",
        "scan status",
    ],
    "activity today": [
        "activity today",
        "today activity",
        "activity summary",
        "today summary",
        "daily summary",
        "activity stats",
    ],
    "activity log": [
        "activity log",
        "recent activity",
        "show activity",
        "activity history",
        "recent logs",
    ],
    "delete file": [
        "delete file",
        "delete this file",
        "remove file",
        "erase file",
        "delete",
        "remove this file",
    ],
    "check file": [
        "check file",
        "check this file",
        "scan file",
        "analyze file",
        "is file safe",
        "file safe",
        "is this file safe",
        "check if safe",
    ],
    "daily summary": [
        "daily summary",
        "today summary",
        "daily briefing",
        "daily report",
        "activity today",
    ],
    "system status": [
        "system status",
        "system info",
        "computer status",
        "pc status",
        "system health",
        "cpu usage",
        "ram usage",
        "disk space",
        "memory usage",
    ],
    "show disk": [
        "show disk",
        "disk space",
        "disk usage",
        "storage",
        "show storage",
        "drive space",
    ],
    "show memory": [
        "show memory",
        "memory usage",
        "ram info",
        "memory info",
    ],
    "show processes": [
        "show processes",
        "top processes",
        "running processes",
        "process list",
    ],
    "show graph": [
        "show graph",
        "show system graph",
        "system graph",
        "show monitor",
        "system monitor",
        "open monitor",
        "show dashboard",
        "open dashboard",
    ],
    "show alerts": [
        "show alerts",
        "pending alerts",
        "alerts",
        "any alerts",
        "check alerts",
    ],
    "test alert": [
        "test alert",
        "test telegram",
        "send test alert",
        "test notification",
    ],
    "telegram on": [
        "telegram on",
        "telegram alert on",
        "phone alert on",
        "enable telegram",
    ],
    "telegram off": [
        "telegram off",
        "telegram alert off",
        "phone alert off",
        "disable telegram",
    ],
"zaris help": [
        "help",
        "zaris help",
        "help zaris",
        "jarvis help",
        "help jarvis",
        "commands",
        "zaris commands",
        "jarvis commands",
        "hello",
        "helo",
        "security",
        "alert",
        "अलर्ट",
        "सिक्योरिटी",
        "हेलो",
        "हेल्प",
    ],
}


def _normalize_text(text):
    return " ".join(str(text or "").strip().lower().split())


def normalize_core_command(query):
    normalized = _normalize_text(query)
    if not normalized:
        return ""

    # Handle "scan <path>" type commands - remove "folder path" if present
    if normalized.startswith("scan folders "):
        potential_path = normalized[13:].strip()
        if potential_path and (len(potential_path) > 2):
            return "scan path"
    if normalized.startswith("scan folder "):
        potential_path = normalized[12:].strip()
        if potential_path and (len(potential_path) > 2):
            return "scan path"
    if normalized.startswith("scan "):
        potential_path = normalized[5:].strip()
        potential_path = potential_path.replace("folder path", "").replace("folder", "").strip()
        if potential_path and (len(potential_path) > 2):
            return "scan path"
    
    if normalized.startswith("check folder "):
        return "scan path"
    
    if normalized.startswith("check "):
        potential_path = normalized[6:].strip()
        potential_path = potential_path.replace("file path", "").replace("folder path", "").strip()
        if potential_path and (len(potential_path) > 2):
            return "check file"

    if normalized.startswith("add folder "):
        return "add folder"
    if normalized.startswith("remove folder "):
        return "remove folder"
    
    # Handle "delete file <path>" type commands
    if normalized.startswith("delete folder "):
        return "delete folder"
    if normalized.startswith("delete file "):
        return "delete file"
    if normalized.startswith("delete "):
        potential_file = normalized[7:].strip()
        if potential_file and len(potential_file) > 2:
            return "delete file"
    if normalized.startswith("remove folder "):
        return "delete folder"
    if normalized.startswith("remove file "):
        return "delete file"
    if normalized.startswith("erase "):
        potential_file = normalized[6:].strip()
        if potential_file and len(potential_file) > 2:
            return "delete file"
    
    # Handle "check file <path>" type commands
    if normalized.startswith("check files "):
        return "check file"
    if normalized.startswith("check file "):
        return "check file"
    if normalized.startswith("scan files "):
        return "check file"
    if normalized.startswith("scan file "):
        return "check file"
    if normalized.startswith("analyze file "):
        return "check file"
    if normalized.startswith("is file safe"):
        return "check file"
    if normalized.startswith("check if "):
        return "check file"
    if normalized.startswith("test telegram"):
        return "test alert"
    if normalized.startswith("send test"):
        return "test alert"

    for canonical, aliases in _CORE_COMMAND_ALIASES.items():
        if normalized == canonical:
            return canonical
        for alias in aliases:
            alias_text = _normalize_text(alias)
            if not alias_text:
                continue
            if normalized == alias_text:
                return canonical
            # Keep partial matching for phrase aliases only. Single-word aliases
            # are exact-match only to avoid accidental rewrites like
            # "security mode on" -> "jarvis help".
            if " " in alias_text and alias_text in normalized:
                return canonical

    return ""


def _downloads_dir():
    home = Path(os.path.expanduser("~"))
    downloads = home / "Downloads"
    
    # Check OneDrive Downloads fallback
    if not downloads.exists():
        onedrive_downloads = home / "OneDrive" / "Downloads"
        if onedrive_downloads.exists():
            return onedrive_downloads
    
    # Try common Windows locations
    common_paths = [
        Path(os.environ.get("USERPROFILE", "")) / "Downloads",
        Path("C:/Users") / os.environ.get("USERNAME", "") / "Downloads",
        Path.home() / "Downloads",
    ]
    
    for path in common_paths:
        if path.exists():
            return path
    
    return downloads


def _iter_recent_files(root_dir, max_files, max_depth, lookback_hours):
    if not root_dir.exists() or not root_dir.is_dir():
        return []

    now_epoch = dt.datetime.now().timestamp()
    lookback_seconds = float(lookback_hours) * 3600.0
    base_depth = len(root_dir.parts)
    candidates = []

    for current_dir, child_dirs, child_files in os.walk(root_dir):
        current_depth = len(Path(current_dir).parts) - base_depth
        if current_depth >= max_depth:
            child_dirs[:] = []

        for file_name in child_files:
            path = Path(current_dir) / file_name
            try:
                modified_at = path.stat().st_mtime
            except Exception:
                continue

            if now_epoch - modified_at > lookback_seconds:
                continue

            candidates.append(path)
            if len(candidates) >= max_files:
                return candidates

    return candidates


def _score_file_risk(path_obj):
    name_lower = path_obj.name.lower()
    ext = path_obj.suffix.lower()
    reasons = []
    score = 0

    if ext in _HIGH_RISK_EXTENSIONS:
        reasons.append("executable_or_script")
        score += 75
    elif ext in _MEDIUM_RISK_EXTENSIONS:
        reasons.append("archive_or_shortcut")
        score += 40

    name_parts = name_lower.split(".")
    if len(name_parts) >= 3:
        second_last = name_parts[-2]
        last = f".{name_parts[-1]}"
        if second_last in _SAFE_LOOKING_EXTENSIONS and last in _HIGH_RISK_EXTENSIONS:
            reasons.append("double_extension_disguise")
            score += 35

    try:
        size_mb = path_obj.stat().st_size / (1024 * 1024)
    except Exception:
        size_mb = 0.0

    if size_mb > 120 and ext in (_HIGH_RISK_EXTENSIONS | _MEDIUM_RISK_EXTENSIONS):
        reasons.append("large_payload")
        score += 10

    if score < 40:
        return None

    risk_level = "high" if score >= 70 else "medium"
    return {
        "name": path_obj.name,
        "path": str(path_obj),
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
    }


def _write_latest_scan(report_obj):
    ensure_security_storage()
    with open(LATEST_SCAN_PATH, "w", encoding="utf-8") as handle:
        json.dump(report_obj, handle, ensure_ascii=False, indent=2)


def get_latest_scan_report():
    ensure_security_storage()
    if not os.path.exists(LATEST_SCAN_PATH):
        return None

    try:
        with open(LATEST_SCAN_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def scan_downloads():
    ensure_security_storage()
    downloads_dir = _downloads_dir()

    if not downloads_dir.exists():
        report = {
            "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "downloads_dir": str(downloads_dir),
            "error": "downloads_directory_missing",
            "scanned_files": 0,
            "risky_files_count": 0,
            "risky_files": [],
        }
        _write_latest_scan(report)
        log_security_event(
            "downloads_scan",
            False,
            reason="downloads_directory_missing",
            metadata={"downloads_dir": str(downloads_dir)},
        )
        return report

    files = _iter_recent_files(downloads_dir, MAX_SCAN_FILES, MAX_SCAN_DEPTH, SCAN_LOOKBACK_HOURS)

    risky_files = []
    for file_path in files:
        risk_obj = _score_file_risk(file_path)
        if risk_obj:
            risky_files.append(risk_obj)

    risky_files.sort(key=lambda item: item.get("risk_score", 0), reverse=True)

    report = {
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "downloads_dir": str(downloads_dir),
        "lookback_hours": SCAN_LOOKBACK_HOURS,
        "scanned_files": len(files),
        "risky_files_count": len(risky_files),
        "risky_files": risky_files,
    }

    _write_latest_scan(report)
    log_security_event(
        "downloads_scan",
        True,
        reason="downloads_scan_completed",
        metadata={
            "scanned_files": len(files),
            "risky_files_count": len(risky_files),
            "lookback_hours": SCAN_LOOKBACK_HOURS,
        },
    )
    return report


def build_scan_reply(report_obj):
    if not report_obj:
        return "Scan failed. Try again."

    if report_obj.get("error") == "downloads_directory_missing":
        return "Downloads folder nahi mila."

    scanned = int(report_obj.get("scanned_files", 0))
    risky = int(report_obj.get("risky_files_count", 0))

    if risky <= 0:
        return f"Scan complete. {scanned} files checked. No risky files found."

    return f"Scan complete. {scanned} files checked, {risky} risky found. Say show risky files."


def build_risky_files_reply(limit=5):
    report = get_latest_scan_report()
    if not report:
        return "No scan report yet. Say scan downloads first."

    risky_files = report.get("risky_files", []) or []
    if not risky_files:
        return "Last scan clean tha. Koi risky file nahi mili."

    top_items = risky_files[: max(1, int(limit))]
    labels = [f"{item.get('name', 'unknown')} {item.get('risk_level', 'medium')}" for item in top_items]
    return "Top risky files: " + ", ".join(labels) + "."


def build_last_scan_summary_reply():
    report = get_latest_scan_report()
    if not report:
        return "No scan report available. Say scan downloads."

    if report.get("error"):
        return "Last scan complete nahi hua. Scan downloads dubara bolo."

    scanned = int(report.get("scanned_files", 0))
    risky = int(report.get("risky_files_count", 0))
    at = report.get("generated_at", "")
    return f"Last scan {at}. Checked {scanned} files and found {risky} risky."


def build_system_status_reply():
    monitor = get_system_monitor()
    try:
        return monitor.format_stats()
    except Exception:
        threat_score = get_threat_score()
        return f"System online on {platform.node()}. Threat score {threat_score}."


def build_disk_reply():
    monitor = get_system_monitor()
    drives = monitor.get_all_drives()
    if not drives:
        return "Unable to get disk information."
    lines = []
    for drive in drives:
        lines.append(
            f"{drive['drive']} {drive['used_gb']:.1f}/{drive['total_gb']:.1f} GB ({drive['percent']}% used)"
        )
    return ". ".join(lines)


def build_memory_reply():
    monitor = get_system_monitor()
    ram = monitor.get_ram_usage()
    return f"RAM: {ram['used_gb']:.1f} of {ram['total_gb']:.1f} GB used ({ram['percent']}%). {ram['available_gb']:.1f} GB available."


def build_processes_reply():
    monitor = get_system_monitor()
    processes = monitor.get_top_processes(5)
    if not processes:
        return "Unable to get process information."
    lines = [f"Top {len(processes)} memory users:"]
    for proc in processes:
        lines.append(f"{proc.name}: {proc.memory_mb:.0f} MB")
    return ". ".join(lines)


def build_folder_status_reply():
    scanner = get_scanner()
    folders = scanner.get_monitored_folders()
    if not folders:
        return "No folders monitored. Say 'add folder <path>' to add one."
    result = scanner.get_last_result()
    if result:
        summary = format_summary(result)
        return (
            f"Monitoring {len(folders)} folders. Last scan: {result.total_files} files, "
            f"{result.total_size_mb:.1f}MB, {len(result.duplicates)} duplicates, "
            f"{len(result.suspicious_files)} suspicious."
        )
    return f"Monitoring {len(folders)} folders. No scan yet. Say 'scan folders'."


def build_duplicates_reply():
    scanner = get_scanner()
    result = scanner.get_last_result()
    if not result:
        return "No scan data. Say 'scan folders' first."
    if not result.duplicates:
        return "No duplicate files found."
    lines = [f"Found {len(result.duplicates)} duplicate sets:"]
    for dup in result.duplicates[:5]:
        name = Path(dup['files'][0]).name if dup['files'] else "unknown"
        lines.append(f"{dup['count']} copies of {dup['size_mb']}MB. File: {name[:30]}. Wasted: {dup['wasted_mb']}MB")
    total_wasted = sum(d['wasted_mb'] for d in result.duplicates)
    lines.append(f"Total wasted: {total_wasted:.1f}MB")
    return " ".join(lines)


def build_unused_reply():
    scanner = get_scanner()
    result = scanner.get_last_result()
    if not result:
        return "No scan data. Say 'scan folders' first."
    if not result.unused_files:
        return "No unused files found."
    lines = [f"Found {len(result.unused_files)} unused files (90+ days):"]
    for f in result.unused_files[:5]:
        name = Path(f['path']).name
        lines.append(f"{f['size_mb']}MB, {f['days_unused']} days: {name}")
    total_unused = sum(f['size_mb'] for f in result.unused_files)
    lines.append(f"Total unused: {total_unused:.1f}MB")
    return " ".join(lines)


def build_activity_today_reply():
    logger = get_activity_logger()
    stats = logger.get_today_stats()
    insight = logger.get_insight_message()
    
    lines = [f"Today's activity: {insight}"]
    lines.append(f"Files scanned: {stats['total_files_scanned']}")
    lines.append(f"Scans completed: {stats['scans_completed']}")
    if stats['risky_files'] > 0:
        lines.append(f"Risky files: {stats['risky_files']}")
    if stats['duplicates_found'] > 0:
        lines.append(f"Duplicates found: {stats['duplicates_found']}")
    return " ".join(lines)


def build_activity_log_reply():
    logger = get_activity_logger()
    activities = logger.get_recent_activities(limit=5)
    
    if not activities:
        return "No recent activity logged."
    
    lines = ["Recent activity:"]
    for activity in activities:
        timestamp = activity.get('timestamp', '')[:16]
        activity_type = activity.get('activity_type', 'unknown')
        message = activity.get('message', '')
        lines.append(f"{timestamp}: {activity_type} - {message}")
    
    return " ".join(lines)


def build_daily_summary_reply():
    from backend.alert_system import get_alert_system
    alert_system = get_alert_system()
    return alert_system.format_daily_summary()


def build_alerts_reply():
    from backend.alert_system import get_alert_system
    alert_system = get_alert_system()
    return alert_system.format_pending_alerts()


def create_scan_alerts(result):
    """Create alerts based on scan results."""
    if result.duplicates:
        total_wasted = sum(d['wasted_mb'] for d in result.duplicates)
        create_duplicate_alert(len(result.duplicates), total_wasted)
    
    if result.unused_files:
        total_unused = sum(f['size_mb'] for f in result.unused_files)
        create_unused_alert(len(result.unused_files), total_unused)
    
    if result.suspicious_files:
        for f in result.suspicious_files[:3]:
            create_risky_file_alert(
                Path(f['path']).name,
                f['type'],
                80  # High risk score for suspicious files
            )


def log_file_deletion(file_path: str, size_mb: float = 0, reason: str = "user"):
    """Log when a file is deleted through the app and send Telegram alert."""
    logger = get_activity_logger()
    logger.log_file_deleted(file_path=file_path, size_mb=size_mb, reason=reason)
    
    # Send Telegram notification for file deletion
    from backend.alert_system import get_alert_system, Alert
    from datetime import datetime
    
    alert_system = get_alert_system()
    
    file_name = Path(file_path).name
    
    deletion_alert = Alert(
        timestamp=datetime.now().isoformat(),
        severity="info",
        title="File Deleted",
        message=f"{file_name} ({size_mb:.1f}MB) moved to recycle bin",
        category="file_deleted",
        action_suggested="Check recycle bin to restore if needed"
    )
    
    alert_system.send_telegram_notification(deletion_alert)


def log_file_addition(file_path: str, size_mb: float = 0, source: str = "user"):
    """Log when a file is added."""
    logger = get_activity_logger()
    logger.log_file_added(file_path=file_path, size_mb=size_mb, source=source)


def send_security_alert(event_type: str, details: dict) -> bool:
    """Send security alert to Telegram for unauthorized access, RAT detection, etc."""
    from backend.alert_system import send_security_alert as _send_alert
    return _send_alert(event_type, details)


# Protected locations - never delete from these
PROTECTED_PATHS = [
    "windows",
    "program files",
    "program files (x86)",
    "system32",
    "syswow64",
    "appdata",
    ".git",
    ".venv",
    "venv",
    "env",
]

def delete_file(file_path: str) -> dict:
    """Delete a file and log the action."""
    import os
    import send2trash
    
    logger = get_activity_logger()
    path = Path(file_path.strip('"\''))
    
    # Safety check 1: Path must exist
    if not path.exists():
        return {"success": False, "error": f"File not found: {file_path}"}
    
    # Safety check 2: Must be a file, not a directory
    if path.is_dir():
        return {"success": False, "error": f"Not a file (it's a folder): {file_path}. Say 'delete folder' instead."}
    
    # Safety check 3: Check for protected paths
    path_lower = str(path).lower()
    for protected in PROTECTED_PATHS:
        if protected in path_lower:
            return {"success": False, "error": f"Cannot delete from protected location: {protected}"}
    
    # Safety check 4: Don't delete system files
    system_files = ["ntdll.dll", "kernel32.dll", "system", "explorer.exe"]
    if path.name.lower() in system_files:
        return {"success": False, "error": "Cannot delete system files"}
    
    # Safety check 5: Analyze threat before deleting
    threat = analyze_threat(str(path))
    threat_warning = ""
    if threat.is_rat:
        threat_warning = f"WARNING: This file appears to be a RAT! {threat.warnings[0] if threat.warnings else ''}"
        logger.log_risky_file(str(path), "rat", threat.risk_score)
    elif threat.is_malware:
        threat_warning = f"ALERT: This file appears to be MALWARE! {threat.warnings[0] if threat.warnings else ''}"
        logger.log_risky_file(str(path), "malware", threat.risk_score)
    elif threat.risk_level == "high":
        threat_warning = f"High risk file detected. {threat.warnings[0] if threat.warnings else ''}"
        logger.log_risky_file(str(path), "high_risk", threat.risk_score)
    
    try:
        # Get file size before deletion
        file_size = path.stat().st_size
        size_mb = file_size / (1024 * 1024)
        
        # Move to recycle bin instead of permanent delete
        send2trash.send2trash(str(path))
        
        # Log the deletion
        logger.log_file_deleted(file_path=str(path), size_mb=size_mb, reason="user")
        
        result = {
            "success": True,
            "message": f"Moved to recycle bin: {path.name}",
            "size_mb": round(size_mb, 2)
        }
        
        if threat_warning:
            result["warning"] = threat_warning
        
        return result
    except Exception as e:
        return {"success": False, "error": f"Failed to delete: {str(e)}"}


def delete_folder(folder_path: str) -> dict:
    """Delete a folder and log the action."""
    import os
    import send2trash
    
    logger = get_activity_logger()
    
    # Clean up the path
    import re as _re
    folder_path = folder_path.strip('"\'').strip()
    if not _re.search(r'^[a-zA-Z]:[\\/]', folder_path):
        drive_match = _re.match(r'^([a-zA-Z])["\s]?(.*)$', folder_path)
        if drive_match and len(folder_path) > 1:
            drive_letter = drive_match.group(1)
            rest_path = drive_match.group(2).lstrip('"\' ')
            folder_path = f"{drive_letter}:\\{rest_path}"
    
    path = Path(folder_path)
    
    # Safety check 1: Path must exist
    if not path.exists():
        return {"success": False, "error": f"Folder not found: {folder_path}"}
    
    # Safety check 2: Must be a directory
    if not path.is_dir():
        return {"success": False, "error": f"Not a folder (it's a file): {folder_path}. Say 'delete file' instead."}
    
    # Safety check 3: Check for protected paths
    path_lower = str(path).lower()
    for protected in PROTECTED_PATHS:
        if protected in path_lower:
            return {"success": False, "error": f"Cannot delete from protected location: {protected}"}
    
    # Safety check 4: Don't delete system folders
    system_folders = ["windows", "system32", "program files", "appdata", "program files (x86)"]
    if path.name.lower() in system_folders:
        return {"success": False, "error": f"Cannot delete system folder: {path.name}"}
    
    # Safety check 5: Don't delete root drives
    if len(path.parts) <= 2:
        return {"success": False, "error": "Cannot delete root drive or top-level folders"}
    
    try:
        # Count files and folders inside
        file_count = 0
        folder_count = 0
        total_size = 0
        
        for item in path.rglob('*'):
            if item.is_file():
                file_count += 1
                try:
                    total_size += item.stat().st_size
                except:
                    pass
            elif item.is_dir():
                folder_count += 1
        
        size_mb = total_size / (1024 * 1024)
        
        # Move to recycle bin
        send2trash.send2trash(str(path))
        
        # Log the deletion
        logger.log_file_deleted(file_path=str(path), size_mb=size_mb, reason="user_folder")
        
        return {
            "success": True,
            "message": f"Moved to recycle bin: {path.name}",
            "files_deleted": file_count,
            "folders_deleted": folder_count,
            "size_mb": round(size_mb, 2),
            "warning": f"Deleted {file_count} files and {folder_count} subfolders ({size_mb:.1f}MB)"
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to delete folder: {str(e)}"}


def find_and_delete_folder(folder_name_or_path: str) -> dict:
    """Find a folder by name or path and delete it."""
    from pathlib import Path
    import os
    
    # Clean up the path
    import re as _re
    folder_name_or_path = folder_name_or_path.strip('"\'').strip()
    if not _re.search(r'^[a-zA-Z]:[\\/]', folder_name_or_path):
        drive_match = _re.match(r'^([a-zA-Z])["\s]?(.*)$', folder_name_or_path)
        if drive_match and len(folder_name_or_path) > 1:
            drive_letter = drive_match.group(1)
            rest_path = drive_match.group(2).lstrip('"\' ')
            folder_name_or_path = f"{drive_letter}:\\{rest_path}"
    
    potential_path = Path(folder_name_or_path)
    
    # If it's a full path
    if potential_path.exists() and potential_path.is_dir():
        return delete_folder(str(potential_path))
    
    # If it's just a folder name, search in common locations
    search_locations = [
        Path.home() / "Downloads",
        Path.home() / "Desktop",
        Path.home() / "Documents",
        Path.home() / "OneDrive" / "Desktop",
        Path.home() / "OneDrive" / "Documents",
    ]
    
    for location in search_locations:
        if not location.exists():
            continue
        for root, dirs, files in os.walk(location):
            for dir_name in dirs:
                if dir_name.lower() == folder_name_or_path.lower():
                    found_path = Path(root) / dir_name
                    return delete_folder(str(found_path))
                # Partial match
                if folder_name_or_path.lower() in dir_name.lower():
                    found_path = Path(root) / dir_name
                    result = delete_folder(str(found_path))
                    if result["success"]:
                        return result
    
    return {"success": False, "error": f"Folder not found: {folder_name_or_path}"}


def find_and_delete_file(file_name_or_path: str) -> dict:
    """Find a file by name or path and delete it."""
    from pathlib import Path
    import os
    
    logger = get_activity_logger()
    
    # If it's a full path
    potential_path = Path(file_name_or_path.strip('"\''))
    
    if potential_path.exists():
        return delete_file(str(potential_path))
    
    # If it's just a filename, search in common locations
    search_locations = [
        Path.home() / "Downloads",
        Path.home() / "Desktop",
        Path.home() / "Documents",
        Path.home() / "OneDrive" / "Desktop",
        Path.home() / "OneDrive" / "Documents",
    ]
    
    for location in search_locations:
        if not location.exists():
            continue
        for root, dirs, files in os.walk(location):
            for file in files:
                if file.lower() == file_name_or_path.lower():
                    found_path = Path(root) / file
                    return delete_file(str(found_path))
                # Partial match
                if file_name_or_path.lower() in file.lower():
                    found_path = Path(root) / file
                    return delete_file(str(found_path))
    
    return {"success": False, "error": f"File not found: {file_name_or_path}"}


def check_file_threat(file_path: str) -> dict:
    """Check if a file is harmful/RAT and return alert info."""
    import re as _re
    
    # Clean up the path
    file_path = file_path.strip('"\'').strip()
    
    # Fix malformed paths only if needed (don't double-fix valid paths)
    if not _re.search(r'^[a-zA-Z]:[\\/]', file_path):
        drive_match = _re.match(r'^([a-zA-Z])["\s]?(.*)$', file_path)
        if drive_match and len(file_path) > 1:
            drive_letter = drive_match.group(1)
            rest_path = drive_match.group(2).lstrip('"\' ')
            file_path = f"{drive_letter}:\\{rest_path}"
    
    path = Path(file_path)
    
    if not path.exists():
        # Try to find in common locations
        search_locations = [
            Path.home() / "Downloads",
            Path.home() / "Desktop",
            Path.home() / "Documents",
        ]
        for location in search_locations:
            if not location.exists():
                continue
            for root, dirs, files in os.walk(location):
                for file in files:
                    if file.lower() == path.name.lower():
                        path = Path(root) / file
                        break
    
    if not path.exists():
        return {
            "found": False,
            "message": f"File not found: {file_path}",
            "threat": None
        }
    
    # Analyze the threat
    result = check_file_before_action(str(path), action="check")
    threat = result["threat"]
    
    # Build response message
    if threat.is_safe:
        message = f"File '{threat.file_name}' is SAFE. No threats detected."
    elif threat.is_rat:
        message = f"WARNING: '{threat.file_name}' appears to be a RAT (Remote Access Trojan)! "
        message += f"Risk score: {threat.risk_score}/100. "
        message += f"Threats: {', '.join(threat.warnings[:3])}. "
        message += "Recommendation: DELETE this file immediately!"
    elif threat.is_malware:
        message = f"ALERT: '{threat.file_name}' appears to be MALWARE! "
        message += f"Risk score: {threat.risk_score}/100. "
        message += f"Threats: {', '.join(threat.warnings[:3])}. "
        message += "Recommendation: DELETE this file!"
    elif threat.risk_level == "high":
        message = f"High risk file: '{threat.file_name}'. "
        message += f"Risk score: {threat.risk_score}/100. "
        message += f"Threats: {', '.join(threat.warnings[:2])}. "
        message += "Scan with antivirus before opening."
    elif threat.risk_level == "medium":
        message = f"Medium risk file: '{threat.file_name}'. "
        message += f"Risk score: {threat.risk_score}/100. "
        message += f"Warnings: {', '.join(threat.warnings[:2])}. "
        message += "Verify source before opening."
    else:
        message = f"Low risk file: '{threat.file_name}'. "
        message += f"Risk score: {threat.risk_score}/100. "
        message += f"Warnings: {', '.join(threat.warnings[:2]) if threat.warnings else 'none'}."
    
    return {
        "found": True,
        "message": message,
        "threat": threat,
        "risk_level": threat.risk_level,
        "is_rat": threat.is_rat,
        "is_malware": threat.is_malware,
        "should_block": should_block_file(threat),
        "file_name": threat.file_name,
        "file_path": str(path)
    }
    
    return {"success": False, "error": f"File not found: {file_name_or_path}"}


def scan_folder_path(folder_path: str):
    """Scan a specific folder path and return detailed summary."""
    scanner = get_scanner()
    logger = get_activity_logger()
    
    # Clean up the path
    folder_path = folder_path.strip('"\'').strip()
    
    # Fix malformed paths only if needed
    import re as _re
    if not _re.search(r'^[a-zA-Z]:[\\/]', folder_path):
        drive_match = _re.match(r'^([a-zA-Z])["\s]?(.*)$', folder_path)
        if drive_match and len(folder_path) > 1:
            drive_letter = drive_match.group(1)
            rest_path = drive_match.group(2).lstrip('"\' ')
            folder_path = f"{drive_letter}:\\{rest_path}"

    path = Path(folder_path)
    
    if not path.exists():
        return f"Folder nahi mila: {folder_path}"
    
    if not path.is_dir():
        return f"Yeh folder nahi hai (file hai): {folder_path}"
    
    # Get list of all items in the folder
    try:
        all_items = list(path.iterdir())
        files = [f for f in all_items if f.is_file()]
        folders = [f for f in all_items if f.is_dir()]
    except PermissionError:
        return f"Permission denied. Folder access nahi ho raha: {folder_path}"
    except Exception as e:
        return f"Folder read error: {e}"
    
    # Get total size
    total_size = sum(f.stat().st_size for f in files if f.exists())
    total_size_mb = total_size / (1024 * 1024)
    
    # Run the detailed scanner
    result = scanner.scan_now([str(path)])
    
    # Log the scan result
    logger.log_scan_result(
        folder=str(path),
        total_files=result.total_files,
        duplicates=len(result.duplicates),
        suspicious=len(result.suspicious_files),
        unused=len(result.unused_files),
        scan_time=result.scan_duration_sec
    )
    
    # Build detailed response
    response_lines = [
        f"{'='*60}",
        f"FOLDER SCAN: {path.name}",
        f"{'='*60}",
        f"Path: {str(path)}",
        f"Files: {len(files)} | Folders: {len(folders)} | Total: {total_size_mb:.2f} MB",
        "",
    ]
    
    # ===== ALL FILES LIST =====
    if files:
        response_lines.append(f"{'='*60}")
        response_lines.append("ALL FILES IN FOLDER:")
        response_lines.append(f"{'='*60}")
        
        # Sort files by size (largest first)
        files_sorted = sorted(files, key=lambda f: f.stat().st_size, reverse=True)
        
        for i, f in enumerate(files_sorted, 1):
            try:
                size = f.stat().st_size
                if size > 1024 * 1024:
                    size_str = f"{size/(1024*1024):.1f}MB"
                elif size > 1024:
                    size_str = f"{size/1024:.1f}KB"
                else:
                    size_str = f"{size}B"
                
                # Check if suspicious
                is_suspicious = f.suffix.lower() in {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".msi"}
                flag = "⚠️" if is_suspicious else " "
                response_lines.append(f"{i:3}. {flag} {f.name} ({size_str})")
            except:
                response_lines.append(f"{i:3}. {f.name}")
        
        response_lines.append("")
    
    # ===== SUSPICIOUS FILES WITH REASONS =====
    if result.suspicious_files:
        response_lines.append(f"{'='*60}")
        response_lines.append("⚠️ THREAT DETECTION - SUSPICIOUS FILES:")
        response_lines.append(f"{'='*60}")
        response_lines.append(f"Total suspicious: {len(result.suspicious_files)}")
        response_lines.append("")
        
        for f in result.suspicious_files:
            name = Path(f['path']).name
            size = f.get('size_mb', 0)
            ext = f.get('type', 'unknown')
            warnings = f.get('warnings', [])
            
            response_lines.append(f"File: {name}")
            response_lines.append(f"  Size: {size}MB | Type: {ext}")
            response_lines.append(f"  Threats: {', '.join(warnings) if warnings else 'Executable file'}")
            
            # Detailed threat explanation
            if ".exe" in ext or ".msi" in ext:
                response_lines.append(f"  ⚠️  WARNING: Executable file - can run code on your system")
            if ".bat" in ext or ".cmd" in ext:
                response_lines.append(f"  ⚠️  WARNING: Batch script - can execute commands")
            if ".ps1" in ext:
                response_lines.append(f"  ⚠️  WARNING: PowerShell script - powerful automation")
            if ".vbs" in ext:
                response_lines.append(f"  ⚠️  WARNING: VBScript - can execute malicious code")
            if ".jar" in ext:
                response_lines.append(f"  ⚠️  WARNING: Java archive - verify source before running")
            
            # Check for double extension
            name_parts = name.lower().split('.')
            if len(name_parts) >= 3:
                second_last = name_parts[-2]
                last_ext = f".{name_parts[-1]}"
                if second_last in {"pdf", "doc", "jpg", "png", "txt", "zip"} and last_ext in {".exe", ".bat", ".cmd", ".scr"}:
                    response_lines.append(f"  🚨 CRITICAL: Double extension detected - LIKELY MALWARE!")
            
            response_lines.append("")
        
        response_lines.append("RECOMMENDATION: Scan these files with antivirus before opening.")
        response_lines.append("")
    
    # ===== DUPLICATES =====
    if result.duplicates:
        response_lines.append(f"{'='*60}")
        response_lines.append("DUPLICATE FILES (Same content, multiple copies):")
        response_lines.append(f"{'='*60}")
        response_lines.append(f"Duplicate sets: {len(result.duplicates)}")
        
        total_wasted = sum(d['wasted_mb'] for d in result.duplicates)
        response_lines.append(f"Wasted space: {total_wasted:.1f}MB")
        response_lines.append("")
        
        for dup in result.duplicates:
            count = dup['count']
            size_mb = dup['size_mb']
            wasted = dup['wasted_mb']
            files = dup['files']
            
            response_lines.append(f"  {count} copies × {size_mb}MB = {wasted}MB wasted")
            response_lines.append(f"  Files:")
            for fp in files:
                response_lines.append(f"    - {Path(fp).name}")
            response_lines.append("")
    
    # ===== UNUSED FILES =====
    if result.unused_files:
        response_lines.append(f"{'='*60}")
        response_lines.append("UNUSED FILES (Not accessed in 90+ days):")
        response_lines.append(f"{'='*60}")
        response_lines.append(f"Total unused: {len(result.unused_files)} files")
        
        total_unused_mb = sum(f['size_mb'] for f in result.unused_files)
        response_lines.append(f"Space: {total_unused_mb:.1f}MB")
        response_lines.append("")
        
        for f in result.unused_files[:10]:
            response_lines.append(f"  - {Path(f['path']).name} ({f['size_mb']}MB, {f['days_unused']} days)")
        
        if len(result.unused_files) > 10:
            response_lines.append(f"  ... and {len(result.unused_files) - 10} more")
        response_lines.append("")
    
    # ===== SUBFOLDERS =====
    if folders:
        response_lines.append(f"{'='*60}")
        response_lines.append("SUBFOLDERS:")
        response_lines.append(f"{'='*60}")
        for folder in sorted(folders, key=lambda f: f.name.lower()):
            try:
                sub_files = len([f for f in folder.iterdir() if f.is_file()])
                sub_folders = len([f for f in folder.iterdir() if f.is_dir()])
                response_lines.append(f"  📁 {folder.name}/ ({sub_files} files, {sub_folders} folders)")
            except:
                response_lines.append(f"  📁 {folder.name}/ (access denied)")
        response_lines.append("")
    
    # ===== SUMMARY =====
    response_lines.append(f"{'='*60}")
    response_lines.append("SCAN SUMMARY:")
    response_lines.append(f"{'='*60}")
    
    if result.suspicious_files:
        response_lines.append(f"⚠️  THREATS FOUND: {len(result.suspicious_files)} suspicious files")
        response_lines.append("ACTION: Review suspicious files above. Delete if unknown.")
    else:
        response_lines.append("✅ NO THREATS: All files appear safe")
    
    if result.duplicates:
        response_lines.append(f"📦 DUPLICATES: {len(result.duplicates)} sets, {total_wasted:.1f}MB wasted")
        response_lines.append("ACTION: Consider deleting duplicates to save space")
    
    if result.unused_files:
        response_lines.append(f"🗑️ UNUSED: {len(result.unused_files)} old files, {total_unused_mb:.1f}MB")
        response_lines.append("ACTION: Delete old unused files if not needed")
    
    response_lines.append(f"{'='*60}")
    
    return "\n".join(response_lines)


def execute_folder_command(command_text, original_query=""):
    scanner = get_scanner()
    
    if command_text == "check file":
        file_identifier = original_query.lower() if original_query else ""
        # Remove command keywords - order matters (longer phrases first)
        removal_words = ["check files", "check file path", "check file s", "check file", "check s",
                         "scan files", "scan file ", "analyze file ", "is file safe ", "check if safe "]
        for word in removal_words:
            if file_identifier.startswith(word):
                file_identifier = file_identifier[len(word):]
                break
        file_identifier = file_identifier.strip()
        # Remove quotes and stray 's'
        file_identifier = file_identifier.strip('"\'').strip()
        
        if not file_identifier:
            return "Please specify a file. Say 'check file filename' or 'is file safe C colon path'."
        
        result = check_file_threat(file_identifier)
        
        if not result["found"]:
            return result["message"]
        
        return result["message"]
    
    if command_text == "delete file":
        file_identifier = original_query.lower() if original_query else ""
        file_identifier = file_identifier.replace("delete file ", "").replace("delete ", "")
        file_identifier = file_identifier.replace("remove file ", "").replace("remove ", "")
        file_identifier = file_identifier.replace("erase ", "").strip()
        file_identifier = file_identifier.strip('"\'').strip()
        
        if not file_identifier:
            return "Please specify a file. Say 'delete file filename' or 'delete C colon path to file'."
        
        # First check if file is harmful
        check_result = check_file_threat(file_identifier)
        if check_result["found"] and check_result.get("should_block"):
            threat_info = check_result.get("threat")
            warnings = check_result.get("warnings", [])
            warning_msg = warnings[0] if warnings else "Harmful file detected"
            return f"BLOCKED: This file is potentially harmful! {warning_msg}. Say 'delete file' again if you still want to delete it."
        
        result = find_and_delete_file(file_identifier)
        if result["success"]:
            msg = f"{result['message']} Size: {result['size_mb']}MB"
            if "warning" in result:
                msg = f"WARNING: {result['warning']}. {msg}"
            return msg
        return result["error"]
    
    if command_text == "delete folder":
        folder_identifier = original_query.lower() if original_query else ""
        # Remove command keywords
        removal_words = ["delete folders", "delete folder path", "delete folder", "delete"]
        for word in removal_words:
            if folder_identifier.startswith(word):
                folder_identifier = folder_identifier[len(word):]
                break
        folder_identifier = folder_identifier.replace("remove folder ", "").replace("remove ", "").strip()
        folder_identifier = folder_identifier.strip('"\'').strip()
        
        if not folder_identifier:
            return "Please specify a folder. Say 'delete folder foldername' or 'delete folder C colon path'."
        
        # Show what's inside before deleting (preview)
        import re as _re
        folder_path = folder_identifier
        if not _re.search(r'^[a-zA-Z]:[\\/]', folder_path):
            drive_match = _re.match(r'^([a-zA-Z])["\s]?(.*)$', folder_path)
            if drive_match and len(folder_path) > 1:
                drive_letter = drive_match.group(1)
                rest_path = drive_match.group(2).lstrip('"\' ')
                folder_path = f"{drive_letter}:\\{rest_path}"
        
        path = Path(folder_path)
        
        # Check if it exists
        if not path.exists():
            # Try searching in common locations
            search_locations = [
                Path.home() / "Downloads",
                Path.home() / "Desktop",
                Path.home() / "Documents",
            ]
            found = False
            for location in search_locations:
                if not location.exists():
                    continue
                for root, dirs, files in os.walk(location):
                    for dir_name in dirs:
                        if folder_identifier.lower() in dir_name.lower():
                            path = Path(root) / dir_name
                            found = True
                            break
                    if found:
                        break
                if found:
                    break
            
            if not found:
                return f"Folder not found: {folder_identifier}"
        
        if path.is_file():
            return f"This is a file, not a folder. Say 'delete file {folder_identifier}' instead."
        
        # Count contents
        try:
            file_count = sum(1 for _ in path.rglob('*') if _.is_file())
            folder_count = sum(1 for _ in path.rglob('*') if _.is_dir())
            total_size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
            size_mb = total_size / (1024 * 1024)
            
            # Warning for large folders
            if file_count > 100 or size_mb > 500:
                warning = f"WARNING: This folder contains {file_count} files and {folder_count} subfolders ({size_mb:.1f}MB). "
                warning += "Say 'delete folder' again to confirm deletion."
                return warning
            
            result = delete_folder(str(path))
            if result["success"]:
                return f"Folder deleted! {result['warning']}. Moved to recycle bin."
            return result["error"]
            
        except Exception as e:
            return f"Error scanning folder: {e}"
    
    if command_text == "scan path":
        folder_path = original_query.lower() if original_query else ""
        # Remove command keywords - order matters (longer phrases first)
        removal_words = ["scan folder path", "scan folders", "scan folder s", "scan folder", 
                         "scan file path", "scan s", "scan"]
        for word in removal_words:
            if folder_path.startswith(word):
                folder_path = folder_path[len(word):]
                break
        folder_path = folder_path.strip()
        # Remove quotes
        folder_path = folder_path.strip('"\'').strip()
        
        if not folder_path:
            return "Please specify a folder path. Say 'scan C colon Users Downloads'."
        return scan_folder_path(folder_path)
    
    if command_text.startswith("add folder "):
        folder_path = original_query.replace("add folder", "").strip() if original_query else ""
        if not folder_path and "add folder " in command_text:
            folder_path = command_text.replace("add folder", "").strip()
        folder_path = folder_path.strip('"\'')
        result = scanner.add_folder(folder_path)
        if result["success"]:
            return f"Added folder: {folder_path}"
        return result["error"]
    
    if command_text.startswith("remove folder "):
        folder_path = original_query.replace("remove folder", "").strip() if original_query else ""
        if not folder_path and "remove folder " in command_text:
            folder_path = command_text.replace("remove folder", "").strip()
        folder_path = folder_path.strip('"\'')
        result = scanner.remove_folder(folder_path)
        if result["success"]:
            return f"Removed folder: {folder_path}"
        return result["error"]
    
    if command_text == "scan folders":
        if not scanner.get_monitored_folders():
            default_folders = [str(Path.home() / "Downloads")]
            scanner.add_folder(default_folders[0])
        result = scanner.scan_now()
        summary = format_summary(result)
        return (
            f"Scanned {result.total_files} files in {result.scan_duration_sec}s. "
            f"{len(result.duplicates)} duplicates, {len(result.suspicious_files)} suspicious, "
            f"{len(result.unused_files)} unused files."
        )
    
    if command_text == "show duplicates":
        return build_duplicates_reply()
    
    if command_text == "show unused":
        return build_unused_reply()
    
    if command_text == "folder scan status":
        return build_folder_status_reply()
    
    if command_text == "activity today":
        return build_activity_today_reply()
    
    if command_text == "activity log":
        return build_activity_log_reply()
    
    if command_text == "daily summary":
        return build_daily_summary_reply()
    
    if command_text == "show alerts":
        return build_alerts_reply()
    
    if command_text == "test alert":
        from backend.alert_system import test_telegram_alert
        success = test_telegram_alert()
        if success:
            return "Test alert sent to Telegram. Check your phone!"
        return "Failed to send test alert. Check Telegram configuration."
    
    if command_text == "telegram on":
        from backend.alert_system import get_alert_system
        alert_system = get_alert_system()
        alert_system._telegram_enabled = True
        return "Telegram alerts enabled. You will receive phone notifications for critical and warning alerts."
    
    if command_text == "telegram off":
        from backend.alert_system import get_alert_system
        alert_system = get_alert_system()
        alert_system._telegram_enabled = False
        return "Telegram alerts disabled. Alerts will only be stored locally."
    
    return None


def execute_core_command(command_text, original_query=""):
    folder_result = execute_folder_command(command_text, original_query)
    if folder_result:
        return folder_result
    
    if command_text == "scan downloads":
        return build_scan_reply(scan_downloads())

    if command_text == "show risky files":
        return build_risky_files_reply()

    if command_text == "system status":
        return build_system_status_reply()

    if command_text == "show disk":
        return build_disk_reply()

    if command_text == "show memory":
        return build_memory_reply()

    if command_text == "show processes":
        return build_processes_reply()

    if command_text == "show graph":
        return "[SHOW_SYSTEM_MONITOR]"

    if command_text == "last scan summary":
        return build_last_scan_summary_reply()

    if command_text == "activity today":
        return build_activity_today_reply()

    if command_text == "activity log":
        return build_activity_log_reply()

    if command_text == "daily summary":
        return build_daily_summary_reply()

    if command_text == "show alerts":
        return build_alerts_reply()

    if command_text == "test alert":
        from backend.alert_system import test_telegram_alert
        success = test_telegram_alert()
        if success:
            return "Test alert sent to Telegram. Check your phone!"
        return "Failed to send test alert. Check Telegram configuration."

    if command_text == "telegram on":
        from backend.alert_system import get_alert_system
        alert_system = get_alert_system()
        alert_system._telegram_enabled = True
        return "Telegram alerts enabled. You will receive phone notifications for critical and warning alerts."

    if command_text == "telegram off":
        from backend.alert_system import get_alert_system
        alert_system = get_alert_system()
        alert_system._telegram_enabled = False
        return "Telegram alerts disabled. Alerts will only be stored locally."

    if command_text in {"zaris help", "jarvis help"}:
        return ZARIS_HELP_TEXT

    return "Command not supported in Zaris AI core mode. Say help."

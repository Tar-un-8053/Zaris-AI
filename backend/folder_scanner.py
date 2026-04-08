"""
Lightweight folder scanner for ZARIS AI.
Features:
- Periodic scanning of selected folders
- Duplicate file detection
- Unused file detection (based on access time)
- Suspicious file type highlighting
- Resource-efficient operation
"""

import hashlib
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".pif", ".com", ".hta", ".wsf", ".dll", ".sys",
}

MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".mp3", ".flac", ".wav",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".raw", ".cr2",
}

SKIP_FOLDERS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", ".cache",
    "AppData", "Program Files", "Program Files (x86)", "Windows",
    "$RECYCLE.BIN", "System Volume Information", ".vscode", ".idea",
}

LARGE_FILE_THRESHOLD_MB = 100
HASH_CHUNK_SIZE = 65536
UNUSED_DAYS_THRESHOLD = 90
MAX_HASH_SIZE_MB = 50


@dataclass
class FileInfo:
    path: str
    name: str
    size: int
    extension: str
    modified_time: float
    accessed_time: float
    hash_prefix: str = ""
    is_suspicious: bool = False
    warnings: list = field(default_factory=list)


@dataclass
class ScanResult:
    timestamp: str
    folders_scanned: list
    total_files: int
    total_size_mb: float
    duplicates: list
    unused_files: list
    suspicious_files: list
    large_files: list
    scan_duration_sec: float


class FolderScanner:
    def __init__(self, max_cpu_percent: float = 30, quick_mode: bool = True):
        self.monitored_folders: list[str] = []
        self.scan_interval_sec: int = 3600
        self._running = False
        self._scanner_thread: Optional[threading.Thread] = None
        self._last_scan_result: Optional[ScanResult] = None
        self._max_cpu_percent = max_cpu_percent
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._quick_mode = quick_mode

    def add_folder(self, folder_path: str) -> dict:
        path = Path(folder_path)
        if not path.exists():
            return {"success": False, "error": f"Folder not found: {folder_path}"}
        if not path.is_dir():
            return {"success": False, "error": f"Not a folder: {folder_path}"}
        if str(path) in self.monitored_folders:
            return {"success": False, "error": "Already monitored"}
        self.monitored_folders.append(str(path))
        return {"success": True, "message": f"Added: {folder_path}"}

    def remove_folder(self, folder_path: str) -> dict:
        if folder_path in self.monitored_folders:
            self.monitored_folders.remove(folder_path)
            return {"success": True, "message": f"Removed: {folder_path}"}
        return {"success": False, "error": "Folder not in monitored list"}

    def set_scan_interval(self, minutes: int) -> dict:
        if minutes < 5:
            return {"success": False, "error": "Minimum 5 minutes"}
        self.scan_interval_sec = minutes * 60
        return {"success": True, "message": f"Interval set to {minutes} minutes"}

    def start_periodic_scan(self):
        if self._running:
            return {"success": False, "error": "Already running"}
        self._running = True
        self._scanner_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._scanner_thread.start()
        return {"success": True, "message": "Periodic scan started"}

    def stop_periodic_scan(self):
        self._running = False
        if self._scanner_thread:
            self._scanner_thread.join(timeout=5)
        return {"success": True, "message": "Periodic scan stopped"}

    def _throttle_cpu(self):
        time.sleep(0.01)

    def _should_skip(self, path: Path) -> bool:
        for part in path.parts:
            if part.lower() in {f.lower() for f in SKIP_FOLDERS}:
                return True
        return False

    def _compute_hash(self, file_path: Path) -> str:
        try:
            file_size = file_path.stat().st_size
            max_size = MAX_HASH_SIZE_MB * 1024 * 1024
            if file_size > max_size:
                return f"LARGE:{file_size:x}"[:16]
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                first_chunk = f.read(HASH_CHUNK_SIZE)
                hasher.update(first_chunk)
                if file_size > HASH_CHUNK_SIZE * 10:
                    f.seek(file_size - HASH_CHUNK_SIZE)
                    last_chunk = f.read(HASH_CHUNK_SIZE)
                    hasher.update(last_chunk)
                elif file_size > HASH_CHUNK_SIZE:
                    f.seek(HASH_CHUNK_SIZE)
                    while chunk := f.read(HASH_CHUNK_SIZE):
                        hasher.update(chunk)
                        self._throttle_cpu()
            return hasher.hexdigest()[:16]
        except Exception:
            return ""

    def _get_file_info(self, file_path: Path) -> Optional[FileInfo]:
        try:
            stat = file_path.stat()
            ext = file_path.suffix.lower()
            info = FileInfo(
                path=str(file_path),
                name=file_path.name,
                size=stat.st_size,
                extension=ext,
                modified_time=stat.st_mtime,
                accessed_time=stat.st_atime,
                is_suspicious=ext in SUSPICIOUS_EXTENSIONS,
                warnings=[],
            )
            if info.is_suspicious:
                info.warnings.append(f"Suspicious type: {ext}")
            return info
        except Exception:
            return None

    def _find_duplicates(self, files: list[FileInfo]) -> list[dict]:
        size_groups: dict[int, list[FileInfo]] = defaultdict(list)
        for f in files:
            if f.size > 0:
                size_groups[f.size].append(f)

        duplicates = []
        for size, group in size_groups.items():
            if len(group) < 2:
                continue

            if self._quick_mode:
                wasted_mb = (size * (len(group) - 1)) / (1024 * 1024)
                duplicates.append({
                    "hash": "QUICK:" + str(size),
                    "size_mb": round(size / (1024 * 1024), 2),
                    "count": len(group),
                    "wasted_mb": round(wasted_mb, 2),
                    "files": [f.path for f in group[:5]],
                })
            else:
                hash_groups: dict[str, list[FileInfo]] = defaultdict(list)
                for f in group:
                    f.hash_prefix = self._compute_hash(Path(f.path))
                    if f.hash_prefix:
                        hash_groups[f.hash_prefix].append(f)

                for hash_val, dup_group in hash_groups.items():
                    if len(dup_group) >= 2:
                        wasted_mb = (size * (len(dup_group) - 1)) / (1024 * 1024)
                        duplicates.append({
                            "hash": hash_val,
                            "size_mb": round(size / (1024 * 1024), 2),
                            "count": len(dup_group),
                            "wasted_mb": round(wasted_mb, 2),
                            "files": [f.path for f in dup_group[:5]],
                        })
        return sorted(duplicates, key=lambda x: x["wasted_mb"], reverse=True)[:10]

    def _find_unused_files(self, files: list[FileInfo], days: int = UNUSED_DAYS_THRESHOLD) -> list[dict]:
        threshold = time.time() - (days * 86400)
        unused = []
        for f in files:
            if f.accessed_time < threshold and f.size > 1024:
                days_unused = int((time.time() - f.accessed_time) / 86400)
                unused.append({
                    "path": f.path,
                    "size_mb": round(f.size / (1024 * 1024), 2),
                    "days_unused": days_unused,
                    "last_accessed": datetime.fromtimestamp(f.accessed_time).strftime("%Y-%m-%d"),
                    "extension": f.extension,
                })
        return sorted(unused, key=lambda x: x["size_mb"], reverse=True)[:20]

    def _find_large_files(self, files: list[FileInfo], threshold_mb: float = LARGE_FILE_THRESHOLD_MB) -> list[dict]:
        threshold_bytes = threshold_mb * 1024 * 1024
        large = []
        for f in files:
            if f.size > threshold_bytes:
                large.append({
                    "path": f.path,
                    "size_mb": round(f.size / (1024 * 1024), 2),
                    "extension": f.extension,
                    "modified": datetime.fromtimestamp(f.modified_time).strftime("%Y-%m-%d"),
                })
        return sorted(large, key=lambda x: x["size_mb"], reverse=True)[:20]

    def scan_now(self, folder_paths: Optional[list[str]] = None) -> ScanResult:
        start_time = time.time()
        folders = folder_paths or self.monitored_folders

        if not folders:
            return ScanResult(
                timestamp=datetime.now().isoformat(),
                folders_scanned=[],
                total_files=0,
                total_size_mb=0,
                duplicates=[],
                unused_files=[],
                suspicious_files=[],
                large_files=[],
                scan_duration_sec=0,
            )

        all_files: list[FileInfo] = []
        suspicious_files = []

        for folder in folders:
            folder_path = Path(folder)
            if not folder_path.exists():
                continue
            for root, dirs, files in os.walk(folder_path):
                dirs[:] = [d for d in dirs if not self._should_skip(Path(root) / d)]
                for filename in files:
                    file_path = Path(root) / filename
                    if self._should_skip(file_path):
                        continue
                    info = self._get_file_info(file_path)
                    if info:
                        all_files.append(info)
                        if info.is_suspicious:
                            suspicious_files.append({
                                "path": info.path,
                                "type": info.extension,
                                "size_mb": round(info.size / (1024 * 1024), 2),
                                "warnings": info.warnings,
                            })

        total_size = sum(f.size for f in all_files)
        duplicates = self._find_duplicates(all_files)
        unused_files = self._find_unused_files(all_files)
        large_files = self._find_large_files(all_files)

        scan_duration = time.time() - start_time
        self._last_scan_result = ScanResult(
            timestamp=datetime.now().isoformat(),
            folders_scanned=folders,
            total_files=len(all_files),
            total_size_mb=round(total_size / (1024 * 1024), 2),
            duplicates=duplicates,
            unused_files=unused_files,
            suspicious_files=suspicious_files[:20],
            large_files=large_files,
            scan_duration_sec=round(scan_duration, 2),
        )
        return self._last_scan_result

    def _scan_loop(self):
        while self._running:
            for folder in self.monitored_folders:
                if not self._running:
                    break
                self.scan_now([folder])
            for _ in range(self.scan_interval_sec):
                if not self._running:
                    break
                time.sleep(1)

    def get_last_result(self) -> Optional[ScanResult]:
        return self._last_scan_result

    def get_monitored_folders(self) -> list[str]:
        return self.monitored_folders.copy()


def format_scan_result(result: ScanResult) -> str:
    lines = [
        f"Scan Results ({result.timestamp})",
        "=" * 50,
        f"Folders: {len(result.folders_scanned)}",
        f"Total Files: {result.total_files:,}",
        f"Total Size: {result.total_size_mb:,.2f} MB",
        f"Scan Time: {result.scan_duration_sec}s",
        "",
    ]

    if result.duplicates:
        lines.append("DUPLICATE FILES:")
        lines.append("-" * 30)
        for dup in result.duplicates[:5]:
            lines.append(f"  {dup['count']} copies x {dup['size_mb']}MB = {dup['wasted_mb']}MB wasted")
            lines.append(f"    {dup['files'][0]}")
        total_wasted = sum(d['wasted_mb'] for d in result.duplicates)
        lines.append(f"  Total wasted: {total_wasted:.2f}MB")
        lines.append("")

    if result.unused_files:
        lines.append("UNUSED FILES (>90 days):")
        lines.append("-" * 30)
        for f in result.unused_files[:5]:
            lines.append(f"  {f['size_mb']}MB - {f['days_unused']} days unused - {Path(f['path']).name}")
        total_unused = sum(f['size_mb'] for f in result.unused_files)
        lines.append(f"  Total unused space: {total_unused:.2f}MB")
        lines.append("")

    if result.suspicious_files:
        lines.append("SUSPICIOUS FILES:")
        lines.append("-" * 30)
        for f in result.suspicious_files[:5]:
            lines.append(f"  {f['type']} - {Path(f['path']).name} ({f['size_mb']}MB)")
        lines.append("")

    if result.large_files:
        lines.append("LARGE FILES (>100MB):")
        lines.append("-" * 30)
        for f in result.large_files[:5]:
            lines.append(f"  {f['size_mb']}MB - {Path(f['path']).name}")

    if not any([result.duplicates, result.unused_files, result.suspicious_files, result.large_files]):
        lines.append("No issues found. System clean.")

    return "\n".join(lines)


def format_summary(result: ScanResult) -> dict:
    return {
        "files": result.total_files,
        "size_mb": result.total_size_mb,
        "duplicates": len(result.duplicates),
        "wasted_mb": sum(d['wasted_mb'] for d in result.duplicates),
        "unused_count": len(result.unused_files),
        "unused_mb": sum(f['size_mb'] for f in result.unused_files),
        "suspicious_count": len(result.suspicious_files),
        "large_files_count": len(result.large_files),
        "scan_time_sec": result.scan_duration_sec,
    }


_scanner_instance: Optional[FolderScanner] = None


def get_scanner() -> FolderScanner:
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = FolderScanner()
    return _scanner_instance
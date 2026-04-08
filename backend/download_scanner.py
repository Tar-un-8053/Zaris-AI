import os
import threading
import time
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

from backend.security.zaris_core import check_file_threat
from backend.security.storage import log_security_event

_download_scanner = None
_watch_threads = []
_OBSERVERS = []
_MONITORED_FOLDERS = []
_FOLDERS_CONFIG_FILE = Path(__file__).parent.parent / "security_data" / "scan_folders.json"


def _load_monitored_folders():
    global _MONITORED_FOLDERS
    
    try:
        if _FOLDERS_CONFIG_FILE.exists():
            data = json.loads(_FOLDERS_CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                _MONITORED_FOLDERS = [Path(p) for p in data if Path(p).exists()]
                return
    except Exception:
        pass
    
    _MONITORED_FOLDERS = get_download_folders()


def _save_monitored_folders():
    global _MONITORED_FOLDERS
    
    try:
        _FOLDERS_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _FOLDERS_CONFIG_FILE.write_text(
            json.dumps([str(p) for p in _MONITORED_FOLDERS], indent=2),
            encoding="utf-8"
        )
    except Exception as e:
        print(f"Failed to save folders config: {e}")


def get_monitored_folders():
    global _MONITORED_FOLDERS
    if not _MONITORED_FOLDERS:
        _load_monitored_folders()
    return [str(p) for p in _MONITORED_FOLDERS]


def add_monitored_folder(folder_path):
    global _MONITORED_FOLDERS, _download_scanner
    
    folder = Path(folder_path)
    
    if not folder.exists() or not folder.is_dir():
        return {"success": False, "error": "Folder does not exist"}
    
    if folder in _MONITORED_FOLDERS:
        return {"success": False, "error": "Folder already being monitored"}
    
    _MONITORED_FOLDERS.append(folder)
    _save_monitored_folders()
    
    if _download_scanner:
        try:
            handler = DownloadFileHandler(callback=_download_scanner._callback)
            _download_scanner.schedule(handler, str(folder), recursive=False)
            print(f"Added folder to monitor: {folder}")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    log_security_event(
        "system_history",
        True,
        reason="scan_folder_added",
        metadata={"folder": str(folder)}
    )
    
    return {"success": True, "message": f"Folder added: {folder}"}


def remove_monitored_folder(folder_path):
    global _MONITORED_FOLDERS
    
    folder = Path(folder_path)
    
    if folder in _MONITORED_FOLDERS:
        _MONITORED_FOLDERS.remove(folder)
        _save_monitored_folders()
        
        log_security_event(
            "system_history",
            True,
            reason="scan_folder_removed",
            metadata={"folder": str(folder)}
        )
        
        return {"success": True, "message": f"Folder removed: {folder}"}
    
    return {"success": False, "error": "Folder not in monitored list"}


class DownloadFileHandler(FileSystemEventHandler):
    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self._recently_scanned = set()
        self._scan_lock = threading.Lock()
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        if self._should_scan(file_path):
            self._scan_file(file_path)
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        if self._should_scan(file_path, is_modify=True):
            self._scan_file(file_path)
    
    def _should_scan(self, file_path, is_modify=False):
        ext = Path(file_path).suffix.lower()
        skip_extensions = {
            ".tmp", ".temp", ".part", ".crdownload", ".download",
            ".partial", ".bak", ".swp", ".DS_Store", "Thumbs.db",
            ".lock", ".pid"
        }
        
        if ext in skip_extensions:
            return False
        
        file_name = Path(file_path).name.lower()
        skip_patterns = ["~", ".tmp", "tmp", "temp", ".lock"]
        if any(p in file_name for p in skip_patterns):
            return False
        
        with self._scan_lock:
            if file_path in self._recently_scanned:
                return False
            self._recently_scanned.add(file_path)
        
        return True
    
    def _scan_file(self, file_path):
        try:
            time.sleep(0.5)
            
            if not Path(file_path).exists():
                return
            
            try:
                size = Path(file_path).stat().st_size
                if size < 100:
                    return
            except Exception:
                return
            
            log_security_event(
                "download_scan",
                True,
                reason="file_detected",
                metadata={"file": file_path}
            )
            
            result = check_file_threat(file_path)
            
            if result.get("found") and result.get("should_block"):
                threat = result.get("threat")
                threat_info = {
                    "file_path": file_path,
                    "file_name": result.get("file_name", Path(file_path).name),
                    "is_rat": result.get("is_rat", False),
                    "is_malware": result.get("is_malware", False),
                    "risk_level": result.get("risk_level", "unknown"),
                    "risk_score": threat.risk_score if threat else 0,
                    "warnings": threat.warnings if threat else []
                }
                
                log_security_event(
                    "threat_detected",
                    True,
                    reason="harmful_file_downloaded",
                    metadata={
                        "file": file_path,
                        "risk_level": threat_info["risk_level"],
                        "is_rat": threat_info["is_rat"],
                        "is_malware": threat_info["is_malware"],
                    }
                )
                
                if self.callback:
                    self.callback(threat_info)
            
        except Exception as e:
            print(f"Download scan error for {file_path}: {e}")
        
        finally:
            with self._scan_lock:
                self._recently_scanned.discard(file_path)


def get_download_folders():
    folders = []
    
    home = Path.home()
    
    download_folders = [
        home / "Downloads",
        Path(os.environ.get("USERPROFILE", home)) / "Downloads",
    ]
    
    desktop_folders = [
        home / "Desktop",
        Path(os.environ.get("USERPROFILE", home)) / "Desktop",
    ]
    
    for folder in download_folders:
        if folder.exists() and folder.is_dir():
            if folder not in folders:
                folders.append(folder)
    
    for folder in desktop_folders:
        if folder.exists() and folder.is_dir():
            if folder not in folders:
                folders.append(folder)
    
    return folders


def start_download_scanner(threat_callback=None):
    global _download_scanner, _OBSERVERS
    
    if _download_scanner is not None:
        return _download_scanner
    
    _load_monitored_folders()
    
    folders = _MONITORED_FOLDERS if _MONITORED_FOLDERS else get_download_folders()
    
    if not folders:
        print("No download folders found to monitor")
        return None
    
    handler = DownloadFileHandler(callback=threat_callback)
    
    observer = Observer()
    _OBSERVERS.append(observer)
    
    observer._callback = threat_callback
    
    for folder in folders:
        try:
            observer.schedule(handler, str(folder), recursive=False)
            print(f"Monitoring: {folder}")
        except Exception as e:
            print(f"Failed to monitor {folder}: {e}")
    
    observer.start()
    _download_scanner = observer
    
    log_security_event(
        "system_history",
        True,
        reason="download_scanner_started",
        metadata={"folders": [str(f) for f in folders]}
    )
    
    return observer


def stop_download_scanner():
    global _download_scanner, _OBSERVERS
    
    for observer in _OBSERVERS:
        try:
            observer.stop()
            observer.join(timeout=2)
        except Exception:
            pass
    
    _OBSERVERS = []
    _download_scanner = None
    
    log_security_event(
        "system_history",
        True,
        reason="download_scanner_stopped"
    )


def is_download_scanner_running():
    global _download_scanner
    return _download_scanner is not None
"""
System Monitor for ZARIS AI
Real-time system stats: CPU, RAM, Disk, Processes, Health Score
"""

import json
import os
import platform
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict
import shutil


HISTORY_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "system_history.json")
HISTORY_MAX_HOURS = 24
HISTORY_INTERVAL_SEC = 60


@dataclass
class SystemStats:
    timestamp: str
    cpu_percent: float
    ram_percent: float
    ram_used_gb: float
    ram_total_gb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    cpu_temp: float
    processes_count: int
    uptime_hours: float
    network_down_mb: float
    network_up_mb: float


@dataclass
class ProcessInfo:
    name: str
    pid: int
    cpu_percent: float
    memory_mb: float


@dataclass
class StorageBreakdown:
    category: str
    size_gb: float
    percent: float
    file_count: int


class SystemMonitor:
    def __init__(self):
        self._history: List[dict] = []
        self._last_network_down = 0.0
        self._last_network_up = 0.0
        self._last_network_time = time.time()
        self._load_history()

    def _load_history(self):
        Path(HISTORY_FILE).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    self._history = json.load(f)
            except Exception:
                self._history = []

    def _save_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self._history[-1000:], f, indent=2)
        except Exception:
            pass

    def get_cpu_usage(self) -> float:
        """Get CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.5)
        except Exception:
            try:
                if platform.system() == "Windows":
                    output = subprocess.check_output(
                        ["wmic", "cpu", "get", "loadpercentage"],
                        creationflags=subprocess.CREATE_NO_WINDOW
                    ).decode()
                    for line in output.strip().split("\n"):
                        line = line.strip()
                        if line and line.isdigit():
                            return float(line)
                return 0.0
            except Exception:
                return 0.0

    def get_ram_usage(self) -> Dict:
        """Get RAM usage details."""
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                "percent": mem.percent,
                "used_gb": round(mem.used / (1024**3), 2),
                "total_gb": round(mem.total / (1024**3), 2),
                "available_gb": round(mem.available / (1024**3), 2),
            }
        except Exception:
            try:
                if platform.system() == "Windows":
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    c_ulonglong = ctypes.c_ulonglong
                    
                    class MEMORYSTATUSEX(ctypes.Structure):
                        _fields_ = [
                            ("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", c_ulonglong),
                            ("ullAvailPhys", c_ulonglong),
                        ]
                    
                    stat = MEMORYSTATUSEX()
                    stat.dwLength = ctypes.sizeof(stat)
                    kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                    
                    total_gb = round(stat.ullTotalPhys / (1024**3), 2)
                    used_gb = round((stat.ullTotalPhys - stat.ullAvailPhys) / (1024**3), 2)
                    
                    return {
                        "percent": stat.dwMemoryLoad,
                        "used_gb": used_gb,
                        "total_gb": total_gb,
                        "available_gb": round(stat.ullAvailPhys / (1024**3), 2),
                    }
                return {"percent": 0, "used_gb": 0, "total_gb": 0, "available_gb": 0}
            except Exception:
                return {"percent": 0, "used_gb": 0, "total_gb": 0, "available_gb": 0}

    def get_disk_usage(self, drive: str = None) -> Dict:
        """Get disk usage for a drive."""
        if drive is None:
            drive = os.environ.get("SystemDrive", "C:\\")
            if not drive.endswith("\\"):
                drive += "\\"
        
        try:
            usage = shutil.disk_usage(drive)
            total_gb = round(usage.total / (1024**3), 2)
            used_gb = round(usage.used / (1024**3), 2)
            free_gb = round(usage.free / (1024**3), 2)
            percent = round((usage.used / usage.total) * 100, 1)
            
            return {
                "drive": drive,
                "percent": percent,
                "used_gb": used_gb,
                "total_gb": total_gb,
                "free_gb": free_gb,
            }
        except Exception:
            return {"drive": drive, "percent": 0, "used_gb": 0, "total_gb": 0, "free_gb": 0}

    def get_all_drives(self) -> List[Dict]:
        """Get usage for all drives."""
        drives = []
        if platform.system() == "Windows":
            for letter in "CDEFGH":
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(self.get_disk_usage(drive))
        else:
            drives.append(self.get_disk_usage("/"))
        return drives

    def get_cpu_temperature(self) -> float:
        """Get CPU temperature if available."""
        try:
            import psutil
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        if entry.current:
                            return round(entry.current, 1)
        except Exception:
            pass
        
        try:
            if platform.system() == "Windows":
                import wmi
                c = wmi.WMI()
                for temp in c.Win32_TemperatureProbe():
                    if temp.CurrentReading:
                        return round(temp.CurrentReading / 10, 1)
        except Exception:
            pass
        
        return 0.0

    def get_top_processes(self, limit: int = 5) -> List[ProcessInfo]:
        """Get top processes by memory usage."""
        processes = []
        
        try:
            import psutil
            for proc in psutil.process_iter(['name', 'pid', 'memory_info', 'cpu_percent']):
                try:
                    pinfo = proc.info
                    if pinfo['memory_info']:
                        processes.append(ProcessInfo(
                            name=pinfo['name'] or "Unknown",
                            pid=pinfo['pid'],
                            cpu_percent=proc.cpu_percent() if proc.cpu_percent() else 0,
                            memory_mb=round(pinfo['memory_info'].rss / (1024**2), 1)
                        ))
                except Exception:
                    continue
            
            processes.sort(key=lambda x: x.memory_mb, reverse=True)
            return processes[:limit]
        except Exception:
            pass
        
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    ["tasklist", "/fo", "csv"],
                    creationflags=subprocess.CREATE_NO_WINDOW
                ).decode()
                
                lines = output.strip().split("\n")[1:]
                for line in lines[:20]:
                    parts = line.replace('"', '').split(",")
                    if len(parts) >= 5:
                        try:
                            name = parts[0]
                            pid = int(parts[1])
                            mem_str = parts[4].replace(" K", "").replace(",", "")
                            mem_kb = float(mem_str)
                            processes.append(ProcessInfo(
                                name=name,
                                pid=pid,
                                cpu_percent=0,
                                memory_mb=round(mem_kb / 1024, 1)
                            ))
                        except Exception:
                            continue
                
                processes.sort(key=lambda x: x.memory_mb, reverse=True)
                return processes[:limit]
        except Exception:
            pass
        
        return []

    def get_process_count(self) -> int:
        """Get total number of running processes."""
        try:
            import psutil
            return len(psutil.pids())
        except Exception:
            try:
                if platform.system() == "Windows":
                    output = subprocess.check_output(
                        ["tasklist", "/fo", "csv"],
                        creationflags=subprocess.CREATE_NO_WINDOW
                    ).decode()
                    return len([l for l in output.strip().split("\n") if l])
            except Exception:
                return 0

    def get_uptime(self) -> float:
        """Get system uptime in hours."""
        try:
            import psutil
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            return round(uptime_seconds / 3600, 1)
        except Exception:
            try:
                if platform.system() == "Windows":
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    uptime_ms = kernel32.GetTickCount64()
                    return round((uptime_ms / 1000) / 3600, 1)
            except Exception:
                return 0.0

    def get_network_speed(self) -> Dict:
        """Get network download/upload speeds."""
        try:
            import psutil
            net = psutil.net_io_counters()
            current_time = time.time()
            current_down = net.bytes_recv / (1024**2)
            current_up = net.bytes_sent / (1024**2)
            
            time_diff = current_time - self._last_network_time
            if time_diff > 0:
                down_speed = (current_down - self._last_network_down) / time_diff
                up_speed = (current_up - self._last_network_up) / time_diff
            else:
                down_speed = 0
                up_speed = 0
            
            self._last_network_down = current_down
            self._last_network_up = current_up
            self._last_network_time = current_time
            
            return {
                "download_mbps": round(down_speed, 2),
                "upload_mbps": round(up_speed, 2),
                "total_down_mb": round(current_down, 1),
                "total_up_mb": round(current_up, 1),
            }
        except Exception:
            return {"download_mbps": 0, "upload_mbps": 0, "total_down_mb": 0, "total_up_mb": 0}

    def get_storage_breakdown(self, folder: str = None) -> List[StorageBreakdown]:
        """Get storage breakdown by file type/category."""
        if folder is None:
            folder = str(Path.home())
        
        categories = {
            "Videos": {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm"},
            "Images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp"},
            "Documents": {".pdf", ".doc", ".docx", ".txt", ".xls", ".xlsx", ".ppt", ".pptx"},
            "Music": {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"},
            "Archives": {".zip", ".rar", ".7z", ".tar", ".gz"},
            "Programs": {".exe", ".msi", ".app", ".dmg"},
            "Code": {".py", ".js", ".html", ".css", ".java", ".cpp", ".c"},
            "Other": set(),
        }
        
        sizes = defaultdict(lambda: {"size": 0, "count": 0})
        
        try:
            for root, dirs, files in os.walk(folder):
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
                
                for file in files:
                    try:
                        filepath = os.path.join(root, file)
                        size = os.path.getsize(filepath)
                        ext = os.path.splitext(file)[1].lower()
                        
                        found = False
                        for category, extensions in categories.items():
                            if ext in extensions:
                                sizes[category]["size"] += size
                                sizes[category]["count"] += 1
                                found = True
                                break
                        
                        if not found:
                            sizes["Other"]["size"] += size
                            sizes["Other"]["count"] += 1
                    except Exception:
                        continue
        except Exception:
            pass
        
        result = []
        total_size = sum(s["size"] for s in sizes.values()) or 1
        
        for category, data in sizes.items():
            if data["count"] > 0:
                result.append(StorageBreakdown(
                    category=category,
                    size_gb=round(data["size"] / (1024**3), 2),
                    percent=round((data["size"] / total_size) * 100, 1),
                    file_count=data["count"]
                ))
        
        result.sort(key=lambda x: x.size_gb, reverse=True)
        return result

    def calculate_health_score(self) -> Dict:
        """Calculate overall system health score (0-100)."""
        cpu = self.get_cpu_usage()
        ram = self.get_ram_usage()
        disk = self.get_disk_usage()
        
        cpu_score = max(0, 100 - cpu)
        ram_score = max(0, 100 - ram["percent"])
        disk_score = max(0, 100 - disk["percent"])
        
        temp = self.get_cpu_temperature()
        temp_score = max(0, 100 - max(0, temp - 40))
        
        overall = round((cpu_score * 0.3 + ram_score * 0.3 + disk_score * 0.2 + temp_score * 0.2), 1)
        
        warnings = []
        if cpu > 90:
            warnings.append("High CPU usage")
        if ram["percent"] > 90:
            warnings.append("Low RAM available")
        if disk["percent"] > 90:
            warnings.append("Disk nearly full")
        if temp > 80:
            warnings.append("High CPU temperature")
        
        return {
            "overall_score": overall,
            "cpu_score": round(cpu_score, 1),
            "ram_score": round(ram_score, 1),
            "disk_score": round(disk_score, 1),
            "temp_score": round(temp_score, 1),
            "warnings": warnings,
        }

    def get_full_stats(self) -> SystemStats:
        """Get all system stats in one call."""
        cpu = self.get_cpu_usage()
        ram = self.get_ram_usage()
        disk = self.get_disk_usage()
        
        return SystemStats(
            timestamp=datetime.now().isoformat(),
            cpu_percent=cpu,
            ram_percent=ram["percent"],
            ram_used_gb=ram["used_gb"],
            ram_total_gb=ram["total_gb"],
            disk_percent=disk["percent"],
            disk_used_gb=disk["used_gb"],
            disk_total_gb=disk["total_gb"],
            cpu_temp=self.get_cpu_temperature(),
            processes_count=self.get_process_count(),
            uptime_hours=self.get_uptime(),
            network_down_mb=0,
            network_up_mb=0,
        )

    def record_history(self):
        """Record current stats to history."""
        stats = self.get_full_stats()
        net = self.get_network_speed()
        
        entry = {
            "timestamp": stats.timestamp,
            "cpu": stats.cpu_percent,
            "ram": stats.ram_percent,
            "disk": stats.disk_percent,
            "temp": stats.cpu_temp,
            "net_down": net["download_mbps"],
            "net_up": net["upload_mbps"],
        }
        
        self._history.append(entry)
        
        cutoff = datetime.now() - timedelta(hours=HISTORY_MAX_HOURS)
        self._history = [
            h for h in self._history
            if datetime.fromisoformat(h["timestamp"]) > cutoff
        ]
        
        self._save_history()

    def get_history(self, hours: int = 1) -> List[Dict]:
        """Get history for the last N hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [
            h for h in self._history
            if datetime.fromisoformat(h["timestamp"]) > cutoff
        ]

    def format_stats(self) -> str:
        """Format current stats for voice output."""
        cpu = self.get_cpu_usage()
        ram = self.get_ram_usage()
        disk = self.get_disk_usage()
        health = self.calculate_health_score()
        
        parts = [
            f"CPU usage: {cpu:.1f}%",
            f"RAM: {ram['used_gb']:.1f} of {ram['total_gb']:.1f} GB ({ram['percent']}%)",
            f"Disk: {disk['used_gb']:.1f} of {disk['total_gb']:.1f} GB ({disk['percent']}%)",
            f"Health score: {health['overall_score']} out of 100",
        ]
        
        if health["warnings"]:
            parts.append(f"Warning: {', '.join(health['warnings'])}")
        
        return ". ".join(parts)

    def format_disk_breakdown(self) -> str:
        """Format storage breakdown for voice."""
        breakdown = self.get_storage_breakdown()
        
        if not breakdown:
            return "Unable to analyze storage."
        
        lines = [f"Storage breakdown:"]
        for item in breakdown[:5]:
            lines.append(f"{item.category}: {item.size_gb:.1f} GB ({item.percent}%)")
        
        return ". ".join(lines)

    def format_top_processes(self) -> str:
        """Format top processes for voice."""
        processes = self.get_top_processes(5)
        
        if not processes:
            return "Unable to get process information."
        
        lines = ["Top memory users:"]
        for proc in processes:
            lines.append(f"{proc.name}: {proc.memory_mb:.0f} MB")
        
        return ". ".join(lines)


_monitor_instance: Optional[SystemMonitor] = None


def get_system_monitor() -> SystemMonitor:
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = SystemMonitor()
    return _monitor_instance
import hashlib
import os
from pathlib import Path

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".pif", ".com", ".hta", ".wsf",
}

SAFE_SYSTEM_FILES = {
    "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe", "powershell.exe",
    "explorer.exe", "winlogon.exe", "csrss.exe", "svchost.exe", "lsass.exe",
    "services.exe", "wininit.exe", "dwm.exe", "taskmgr.exe", "regedit.exe",
    "mmc.exe", "wordpad.exe", "write.exe", "control.exe", "mstsc.exe",
}

SUSPICIOUS_PATTERNS = [
    "password", "crack", "keygen", "patch", "warez", "hack",
    "trojan", "malware", "virus", "worm", "rat ", "backdoor",
    "crypt", "ransom", "keylog", "steal", "inject",
]

def scan_file(file_path):
    if not os.path.exists(file_path):
        return {"error": "File not found", "path": file_path}
    
    path = Path(file_path)
    ext = path.suffix.lower()
    name_lower = path.name.lower()
    
    result = {
        "path": str(path),
        "name": path.name,
        "extension": ext,
        "risk_level": "safe",
        "risk_score": 0,
        "warnings": [],
        "file_size_mb": 0,
        "file_hash": "",
        "is_system_file": False,
    }
    
    try:
        size = path.stat().st_size
        result["file_size_mb"] = round(size / (1024 * 1024), 2)
        
        if size < 100 * 1024 * 1024:
            try:
                with open(path, "rb") as f:
                    content = f.read()
                    result["file_hash"] = hashlib.sha256(content).hexdigest()[:16]
            except Exception:
                pass
    except Exception:
        pass
    
    if name_lower in SAFE_SYSTEM_FILES:
        result["is_system_file"] = True
        result["risk_level"] = "safe"
        result["risk_score"] = 0
        result["warnings"] = ["Known Windows system file"]
        return result
    
    if ext in SUSPICIOUS_EXTENSIONS:
        result["risk_level"] = "high"
        result["risk_score"] = 80
        result["warnings"].append(f"Executable file: {ext}")
    
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in name_lower:
            result["risk_score"] = max(result["risk_score"], 40)
            result["warnings"].append(f"Suspicious name pattern: '{pattern}'")
    
    name_parts = name_lower.split(".")
    if len(name_parts) >= 3:
        second_last = name_parts[-2].lower()
        if second_last in {"pdf", "doc", "jpg", "png", "txt", "zip"} and ext in SUSPICIOUS_EXTENSIONS:
            result["risk_level"] = "critical"
            result["risk_score"] = 95
            result["warnings"].append("Double extension detected (likely malware)")
    
    if result["risk_score"] >= 80:
        result["risk_level"] = "critical"
    elif result["risk_score"] >= 50:
        result["risk_level"] = "high"
    elif result["risk_score"] >= 20:
        result["risk_level"] = "medium"
    else:
        result["risk_level"] = "safe"
    
    return result


def build_scan_reply(scan_result):
    if scan_result.get("error"):
        return f"Error: {scan_result['error']}"
    
    name = scan_result["name"]
    risk = scan_result["risk_level"]
    score = scan_result["risk_score"]
    size = scan_result["file_size_mb"]
    warnings = scan_result["warnings"]
    is_system = scan_result.get("is_system_file", False)
    
    if is_system:
        return f"File '{name}' is a known Windows system file. Safe to keep. Size: {size}MB."
    
    if risk == "safe":
        return f"File '{name}' looks safe. Size: {size}MB. No threats detected."
    
    if risk == "critical":
        reply = f"CRITICAL ALERT: '{name}' is likely MALWARE!"
    elif risk == "high":
        reply = f"WARNING: '{name}' is suspicious. Be careful!"
    else:
        reply = f"Caution: '{name}' has some warnings."
    
    reply += f" Risk score: {score}/100. Size: {size}MB."
    
    if warnings:
        reply += f" Issues: {', '.join(warnings[:3])}."
    
    if risk in {"critical", "high"}:
        reply += " Recommend scanning with antivirus before opening."
    
    return reply
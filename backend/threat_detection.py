"""
Threat Detection and Alert System for ZARIS AI
Detects harmful files, RATs, malware patterns and alerts user.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


RAT_INDICATORS = {
    "names": [
        "rat", "remote", "backdoor", "nJRAT", "njrat", "darkcomet", "dark comet",
        "poisonivy", "poison ivy", "teamviewer", "anydesk", "vnc", "remote desktop",
        "logmein", "ammyy", "laplink", "radmin", "dameware", "bomgar",
        "spy", "keylog", "stealer", "grabber", "clipper", "miner",
    ],
    "extensions": {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".jar"},
    "suspicious_combos": [
        ("remote", "admin"),
        ("backdoor", "access"),
        ("password", "steal"),
        ("keylog", "capture"),
        ("screen", "capture"),
        ("webcam", "access"),
        ("file", "grabber"),
        ("crypto", "miner"),
    ]
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", 
    ".vbs", ".js", ".jar", ".msi", ".hta", ".wsf", ".dll",
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".iso", ".img", ".lnk",
}

SUSPICIOUS_PATTERNS = [
    "crack", "keygen", "patch", "warez", "hack", "pirate",
    "trojan", "malware", "virus", "worm", "backdoor",
    "rat", "remote access", "stealer", "keylog", "inject",
    "crypt", "ransom", "steal", "phish", "botnet",
    "c2", "command and control", "payload", "shell",
    "exploit", "vulnerability", "zero day", "0day",
]

KNOWN_SAFE_FILES = {
    "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe",
    "powershell.exe", "explorer.exe", "winlogon.exe",
    "csrss.exe", "svchost.exe", "lsass.exe", "services.exe",
    "wininit.exe", "dwm.exe", "taskmgr.exe", "regedit.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "code.exe",
    "python.exe", "pythonw.exe", "pip.exe",
    "git.exe", "node.exe", "npm.exe",
    "java.exe", "javaw.exe",
}


@dataclass
class ThreatAnalysis:
    file_path: str
    file_name: str
    extension: str
    risk_level: str
    risk_score: int
    threat_type: str
    warnings: list
    recommendations: list
    is_rat: bool
    is_malware: bool
    is_safe: bool


def analyze_threat(file_path: str) -> ThreatAnalysis:
    """Analyze a file for potential threats."""
    path = Path(file_path)
    
    if not path.exists():
        return ThreatAnalysis(
            file_path=file_path,
            file_name=path.name,
            extension="",
            risk_level="unknown",
            risk_score=0,
            threat_type="file_not_found",
            warnings=["File not found"],
            recommendations=["Check if file exists"],
            is_rat=False,
            is_malware=False,
            is_safe=False
        )
    
    ext = path.suffix.lower()
    name_lower = path.name.lower()
    name_without_ext = path.stem.lower()
    
    risk_score = 0
    warnings = []
    threat_type = "unknown"
    is_rat = False
    is_malware = False
    recommendations = []
    
    # Check if known safe file
    if name_lower in KNOWN_SAFE_FILES:
        return ThreatAnalysis(
            file_path=str(path),
            file_name=path.name,
            extension=ext,
            risk_level="safe",
            risk_score=0,
            threat_type="known_safe",
            warnings=["Known safe system file"],
            recommendations=["File is safe to keep"],
            is_rat=False,
            is_malware=False,
            is_safe=True
        )
    
    # Check for RAT indicators
    for indicator in RAT_INDICATORS["names"]:
        if indicator in name_lower or indicator in name_without_ext:
            is_rat = True
            risk_score += 50
            warnings.append(f"RAT indicator found: '{indicator}'")
            threat_type = "rat"
    
    # Check extension risk
    if ext in HIGH_RISK_EXTENSIONS:
        risk_score += 30
        warnings.append(f"High-risk extension: {ext}")
        if threat_type == "unknown":
            threat_type = "suspicious_executable"
    
    elif ext in MEDIUM_RISK_EXTENSIONS:
        risk_score += 15
        warnings.append(f"Medium-risk extension: {ext}")
    
    # Check suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in name_lower:
            risk_score += 25
            warnings.append(f"Suspicious pattern: '{pattern}'")
            if "rat" in pattern or "remote" in pattern:
                is_rat = True
            elif threat_type == "unknown":
                threat_type = "malware"
    
    # Check double extension (e.g., "file.pdf.exe")
    parts = name_lower.split(".")
    if len(parts) >= 3:
        second_last = parts[-2] if len(parts) >= 2 else ""
        safe_ends = {"pdf", "doc", "jpg", "png", "txt", "mp3", "mp4", "zip"}
        if second_last in safe_ends and ext in HIGH_RISK_EXTENSIONS:
            risk_score += 40
            warnings.append("Double extension detected - likely malware")
            threat_type = "malware"
            is_malware = True
    
    # Check suspicious combinations
    name_combined = name_lower.replace("_", " ").replace("-", " ")
    for word1, word2 in RAT_INDICATORS["suspicious_combos"]:
        if word1 in name_combined and word2 in name_combined:
            is_rat = True
            risk_score += 35
            warnings.append(f"Suspicious combination: '{word1}' + '{word2}'")
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = "critical"
        threat_type = "malware" if not is_rat else "rat"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    elif risk_score >= 20:
        risk_level = "low"
    else:
        risk_level = "safe"
        threat_type = "potentially_unwanted"
    
    # Generate recommendations
    if risk_level in ["critical", "high"]:
        recommendations.append("DELETE this file immediately")
        recommendations.append("Run antivirus scan")
        recommendations.append("Check for similar files")
    elif risk_level == "medium":
        recommendations.append("Scan with antivirus before opening")
        recommendations.append("Do not run without verification")
    elif risk_level == "low":
        recommendations.append("Verify file source before running")
    
    is_safe = risk_level == "safe"
    is_malware = risk_level in ["critical", "high"] and not is_rat
    
    return ThreatAnalysis(
        file_path=str(path),
        file_name=path.name,
        extension=ext,
        risk_level=risk_level,
        risk_score=risk_score,
        threat_type=threat_type,
        warnings=warnings,
        recommendations=recommendations,
        is_rat=is_rat,
        is_malware=is_malware,
        is_safe=is_safe
    )


def get_threat_alert(threat: ThreatAnalysis) -> str:
    """Generate alert message for threat."""
    if threat.is_safe:
        return f"File '{threat.file_name}' appears safe."
    
    lines = []
    
    if threat.is_rat:
        lines.append("ALERT: This appears to be a RAT (Remote Access Trojan)!")
    elif threat.is_malware:
        lines.append("WARNING: This file appears to be MALWARE!")
    
    if threat.risk_level == "critical":
        lines.append(f"CRITICAL RISK - Score: {threat.risk_score}/100")
    elif threat.risk_level == "high":
        lines.append(f"HIGH RISK - Score: {threat.risk_score}/100")
    elif threat.risk_level == "medium":
        lines.append(f"MEDIUM RISK - Score: {threat.risk_score}/100")
    else:
        lines.append(f"LOW RISK - Score: {threat.risk_score}/100")
    
    if threat.warnings:
        lines.append(f"Threats detected: {'; '.join(threat.warnings[:3])}")
    
    if threat.recommendations:
        lines.append(f"Recommendation: {threat.recommendations[0]}")
    
    return " ".join(lines)


def should_block_file(threat: ThreatAnalysis) -> bool:
    """Determine if file should be blocked/deleted."""
    return threat.risk_level in ["critical", "high"] or threat.is_rat


def check_file_before_action(file_path: str, action: str = "open") -> dict:
    """Check file before any action and return alert info."""
    threat = analyze_threat(file_path)
    alert = get_threat_alert(threat)
    
    return {
        "should_proceed": not should_block_file(threat),
        "threat": threat,
        "alert": alert,
        "file_name": threat.file_name,
        "risk_level": threat.risk_level,
        "is_rat": threat.is_rat,
        "is_malware": threat.is_malware,
        "warnings": threat.warnings,
        "recommendations": threat.recommendations,
    }


def quick_threat_check(file_path: str) -> str:
    """Quick check for voice response."""
    threat = analyze_threat(file_path)
    
    if threat.is_safe:
        return "safe"
    
    if threat.is_rat:
        return "rat"
    
    if threat.is_malware:
        return "malware"
    
    if threat.risk_level == "high":
        return "high_risk"
    elif threat.risk_level == "medium":
        return "medium_risk"
    
    return "low_risk"


BLOCKED_FILES_REGISTRY = Path(__file__).parent.parent / "security_data" / "blocked_files.json"


def block_file_path(file_path) -> dict:
    """Block a file by adding it to the blocked registry and quarantining."""
    from pathlib import Path as _Path
    import json as _json
    import hashlib as _hashlib
    import shutil as _shutil
    import os as _os
    
    file_path = _Path(file_path)
    
    if not file_path.exists():
        return {"success": False, "error": "File not found"}
    
    try:
        BLOCKED_FILES_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    
    file_hash = _hashlib.md5(str(file_path).encode()).hexdigest()[:12]
    quarantine_dir = BLOCKED_FILES_REGISTRY.parent / "quarantine"
    
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    
    blocked_entry = {
        "original_path": str(file_path),
        "file_name": file_path.name,
        "blocked_at": str(_os.environ.get("ZARIS_BLOCKED_TIME", "")),
        "hash": file_hash,
    }
    
    blocked_files = []
    if BLOCKED_FILES_REGISTRY.exists():
        try:
            blocked_files = _json.loads(BLOCKED_FILES_REGISTRY.read_text(encoding="utf-8"))
            if not isinstance(blocked_files, list):
                blocked_files = []
        except Exception:
            blocked_files = []
    
    for existing in blocked_files:
        if existing.get("original_path") == str(file_path):
            return {"success": True, "message": "File already blocked", "already_blocked": True}
    
    quarantine_path = quarantine_dir / f"{file_path.stem}_{file_hash}{file_path.suffix}"
    
    try:
        _shutil.move(str(file_path), str(quarantine_path))
        blocked_entry["quarantine_path"] = str(quarantine_path)
        blocked_entry["status"] = "quarantined"
    except Exception as e:
        blocked_entry["quarantine_path"] = None
        blocked_entry["status"] = "registry_only"
        blocked_entry["quarantine_error"] = str(e)
    
    blocked_files.append(blocked_entry)
    
    try:
        BLOCKED_FILES_REGISTRY.write_text(_json.dumps(blocked_files, indent=2), encoding="utf-8")
    except Exception as e:
        return {"success": False, "error": f"Failed to save registry: {e}"}
    
    return {
        "success": True,
        "message": f"File blocked and moved to quarantine: {file_path.name}",
        "quarantine_path": str(quarantine_path) if "quarantine_path" in blocked_entry else None,
    }
import datetime as dt
import os
import platform
import socket
import subprocess
import time

from backend.security.storage import DECOY_DIR, EVIDENCE_DIR, ensure_security_storage

try:
    import cv2
except Exception:
    cv2 = None

try:
    import numpy as np
except Exception:
    np = None

try:
    import pyautogui
except Exception:
    pyautogui = None

try:
    import psutil
except Exception:
    psutil = None


def _timestamp():
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def capture_screenshot(prefix="screen"):
    ensure_security_storage()
    if pyautogui is None:
        return None, "pyautogui unavailable"

    path = os.path.join(EVIDENCE_DIR, f"{prefix}_{_timestamp()}.png")
    try:
        image = pyautogui.screenshot()
        image.save(path)
        return path, "screenshot_saved"
    except Exception as exc:
        return None, f"screenshot_failed:{exc}"


def capture_screenshot_burst(prefix="screen_burst", count=3):
    saved = []
    for index in range(max(1, count)):
        path, _message = capture_screenshot(prefix=f"{prefix}_{index + 1}")
        if path:
            saved.append(path)
    return saved


def capture_screen_recording(prefix="screen_record", duration_sec=4, fps=4):
    ensure_security_storage()
    if pyautogui is None or cv2 is None or np is None:
        return None, "screen_recording_unavailable"

    duration_sec = max(1.5, float(duration_sec))
    fps = max(1, int(fps))
    frame_interval = 1.0 / fps

    try:
        first_frame = pyautogui.screenshot()
    except Exception as exc:
        return None, f"screen_recording_failed:{exc}"

    frame_array = cv2.cvtColor(np.array(first_frame), cv2.COLOR_RGB2BGR)
    height, width = frame_array.shape[:2]
    path = os.path.join(EVIDENCE_DIR, f"{prefix}_{_timestamp()}.avi")

    codecs = ("XVID", "MJPG")
    writer = None
    for codec in codecs:
        candidate = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*codec), fps, (width, height))
        if candidate.isOpened():
            writer = candidate
            break
        candidate.release()

    if writer is None:
        return None, "screen_recording_writer_failed"

    deadline = time.time() + duration_sec
    next_frame_at = time.time()

    try:
        while time.time() < deadline:
            image = pyautogui.screenshot()
            frame = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            if frame.shape[1] != width or frame.shape[0] != height:
                frame = cv2.resize(frame, (width, height))
            writer.write(frame)

            next_frame_at += frame_interval
            sleep_for = next_frame_at - time.time()
            if sleep_for > 0:
                time.sleep(sleep_for)
    finally:
        writer.release()

    return path, "screen_recording_saved"


def collect_system_snapshot():
    snapshot = {
        "hostname": platform.node(),
        "platform": platform.platform(),
    }

    try:
        snapshot["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        snapshot["local_ip"] = ""

    if psutil is not None:
        try:
            snapshot["boot_time"] = dt.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            snapshot["boot_time"] = ""
        try:
            snapshot["users"] = [user.name for user in psutil.users()]
        except Exception:
            snapshot["users"] = []
        try:
            snapshot["battery_percent"] = psutil.sensors_battery().percent if psutil.sensors_battery() else None
        except Exception:
            snapshot["battery_percent"] = None

    return snapshot


def write_forensic_summary(reason, extra=None):
    ensure_security_storage()
    path = os.path.join(EVIDENCE_DIR, f"forensic_{_timestamp()}.txt")
    snapshot = collect_system_snapshot()

    lines = [
        "SENTINEL FORENSIC SUMMARY",
        f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Reason: {reason}",
        "",
        "System Snapshot:",
    ]

    for key, value in snapshot.items():
        lines.append(f"{key}: {value}")

    if extra:
        lines.append("")
        lines.append("Extra Metadata:")
        for key, value in extra.items():
            lines.append(f"{key}: {value}")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    return path


def prepare_decoy_workspace():
    ensure_security_storage()
    os.makedirs(DECOY_DIR, exist_ok=True)

    fake_files = {
        "Passwords_DO_NOT_OPEN.txt": "Demo decoy file.\nReal credentials yahan store nahi hote.\n",
        "Banking_Backup.txt": "Fake archive for intruder confusion.\nNo real banking data here.\n",
        "Personal_Documents.txt": "This is a decoy workspace created by Sentinel Cyber Guard.\n",
    }

    for filename, content in fake_files.items():
        path = os.path.join(DECOY_DIR, filename)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)

    readme_path = os.path.join(DECOY_DIR, "README_DECOY.txt")
    with open(readme_path, "w", encoding="utf-8") as handle:
        handle.write(
            "Sentinel Decoy Mode\n"
            "This folder is safe to demo and intentionally contains fake bait documents.\n"
        )

    return DECOY_DIR


def open_decoy_workspace():
    folder = prepare_decoy_workspace()
    try:
        os.startfile(folder)
        return True, folder
    except Exception:
        try:
            subprocess.Popen(["explorer", folder])
            return True, folder
        except Exception as exc:
            return False, f"{folder} ({exc})"

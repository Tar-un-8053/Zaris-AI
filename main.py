import base64
import io
import os
import socket
import sys
import threading
import webbrowser as _wb

import eel

from backend.command import (
    mark_frontend_speech_complete,
    mark_frontend_speech_started,
    speak,
    takecommand,
    transcribe_audio,
)
from backend.face_rec import register_face
from backend.feature import handle_query, start_hotword, startup_greeting
from backend.memory_twin import add_study_record, get_dashboard, ingest_upload, verify_integrity
from backend.security import start_cyber_security_services, verify_owner_identity
from backend.security.storage import log_security_event
from backend.download_scanner import start_download_scanner, stop_download_scanner, get_monitored_folders, add_monitored_folder, remove_monitored_folder

_INSTANCE_LOCK_SOCKET = None


for _stream_name in ("stdout", "stderr"):
    _stream = getattr(sys, _stream_name, None)
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _acquire_single_instance_lock():
    global _INSTANCE_LOCK_SOCKET

    if _INSTANCE_LOCK_SOCKET is not None:
        return True

    try:
        lock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lock_socket.bind(("127.0.0.1", 48765))
        _INSTANCE_LOCK_SOCKET = lock_socket
        return True
    except OSError:
        print("Sentinel already running. Duplicate instance block kar diya.")
        return False


@eel.expose
def ui_init():
    log_security_event("ui_history", True, reason="ui_initialized", metadata={"surface": "eel"})
    
    # Check if startup face scan is enabled (default: enabled)
    import os
    startup_scan_enabled = os.getenv("ZARIS_STARTUP_FACE_SCAN", os.getenv("JARVIS_STARTUP_FACE_SCAN", "1")).strip().lower() not in {"0", "false", "no"}
    
    if startup_scan_enabled:
        startup_face_scan()
    else:
        startup_greeting()


def startup_face_scan():
    """Face scan on startup for owner verification."""
    from backend.face_rec import get_face_status, recognize_face
    
    is_ready, status_msg = get_face_status()
    
    if not is_ready:
        print(f"Face scan skipped: {status_msg}")
        startup_greeting()
        return
    
    print("\n" + "=" * 50)
    print("OWNER VERIFICATION - Face Scan")
    print("Camera ki taraf dekho...")
    print("=" * 50)
    
    speak("Owner verification start. Please look at the camera.")
    
    face_name, confidence = recognize_face(timeout=8, show_window=True)
    
    if face_name:
        print(f"Face recognized: {face_name} (confidence: {confidence:.1f})")
        log_security_event("auth_attempt", True, reason="startup_face_verified", face_name=face_name, face_confidence=confidence)
        speak(f"Welcome back {face_name}. Security system online.")
        startup_greeting()
    else:
        print("Face not recognized.")
        log_security_event("auth_attempt", False, reason="startup_face_not_recognized")
        speak("Face not recognized. Press the face button to enroll or continue.")
        startup_greeting()


@eel.expose
def reportSpeechStarted(speech_id):
    mark_frontend_speech_started(speech_id)


@eel.expose
def reportSpeechDone(speech_id):
    mark_frontend_speech_complete(speech_id)


@eel.expose
def micButtonPressed():
    print("\nMic button pressed")
    log_security_event("ui_history", True, reason="mic_button_pressed", metadata={"surface": "frontend"})

    import backend.feature as feat

    feat._wake_active = False
    query = takecommand()

    if query:
        print(f"Security input: {query}")
        log_security_event(
            "input_history",
            True,
            reason="mic_button_input_received",
            voice_text=query,
            metadata={"source": "mic_button"},
        )

        def _run_single_command():
            try:
                handle_query(query, source="mic_button")
            finally:
                feat._wake_active = True

        threading.Thread(target=_run_single_command, daemon=True).start()
        return query

    print("No voice command captured")
    log_security_event("input_history", True, reason="mic_button_no_input", metadata={"source": "mic_button"})
    feat._wake_active = True
    return None


@eel.expose
def submitSecurityCommand(text):
    def _run():
        if text and text.strip():
            print(f"\nConsole command: {text}")
            log_security_event(
                "input_history",
                True,
                reason="console_command_received",
                voice_text=text.strip(),
                metadata={"source": "command_console"},
            )
            handle_query(text.strip(), source="command_console")

    threading.Thread(target=_run, daemon=True).start()


@eel.expose
def processPhoneAudio(audio_base64, mime_type="audio/webm"):
    """Process audio from phone browser and return transcript."""
    import time
    import backend.feature as feat
    from backend.command import recognizer
    
    print(f"\nPhone audio received: {mime_type}")
    log_security_event("ui_history", True, reason="phone_audio_received", metadata={"mime_type": mime_type})
    
    start_time = time.time()
    
    try:
        audio_bytes = base64.b64decode(audio_base64)
        print(f"Audio size: {len(audio_bytes)} bytes")
        wav_audio = _convert_to_wav(audio_bytes, mime_type)
        
        if wav_audio is None:
            print("Failed to convert audio to WAV")
            return {"text": None, "latency": int((time.time() - start_time) * 1000), "error": "conversion_failed"}
        
        import speech_recognition as sr
        audio_data = sr.AudioData(wav_audio, sample_rate=16000, sample_width=2)
        
        transcript = transcribe_audio(audio_data, languages=["hi-IN", "en-IN", "en-US"], lowercase=True, verbose=True)
        
        latency = int((time.time() - start_time) * 1000)
        
        if transcript:
            print(f"Phone transcript ({latency}ms): {transcript}")
            log_security_event(
                "input_history",
                True,
                reason="phone_audio_transcribed",
                voice_text=transcript,
                metadata={"source": "phone_mic", "latency_ms": latency},
            )
            
            def _run_command():
                try:
                    feat._wake_active = False
                    handle_query(transcript, source="phone_mic")
                finally:
                    feat._wake_active = True
            
            threading.Thread(target=_run_command, daemon=True).start()
            return {"text": transcript, "latency": latency}
        
        print("Phone audio: no transcript")
        return {"text": None, "latency": latency}
        
    except Exception as e:
        print(f"Phone audio error: {e}")
        return {"text": None, "latency": int((time.time() - start_time) * 1000), "error": str(e)}


def _convert_to_wav(audio_bytes, mime_type):
    """Convert audio bytes to WAV format for speech recognition."""
    import subprocess
    import tempfile
    import os
    
    try:
        # Try pydub with imageio-ffmpeg
        try:
            from pydub import AudioSegment
            import imageio_ffmpeg
            
            ffmpeg_path = imageio_ffmpeg.get_ffmpeg_exe()
            AudioSegment.converter = ffmpeg_path
            
            audio = AudioSegment.from_file(io.BytesIO(audio_bytes), format="webm")
            audio = audio.set_frame_rate(16000)
            audio = audio.set_channels(1)
            
            wav_buffer = io.BytesIO()
            audio.export(wav_buffer, format="wav")
            return wav_buffer.getvalue()
        except ImportError:
            pass
        except Exception as pydub_err:
            print(f"Pydub conversion failed: {pydub_err}")
        
        # Fallback: Use ffmpeg directly with imageio-ffmpeg
        try:
            import imageio_ffmpeg
            ffmpeg_path = imageio_ffmpeg.get_ffmpeg_exe()
            
            with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as in_file:
                in_file.write(audio_bytes)
                in_path = in_file.name
            
            out_path = in_path.replace(".webm", ".wav")
            
            subprocess.run(
                [ffmpeg_path, "-y", "-i", in_path, "-ar", "16000", "-ac", "1", out_path],
                capture_output=True,
                check=True
            )
            with open(out_path, "rb") as f:
                wav_data = f.read()
            return wav_data
        except ImportError:
            print("imageio-ffmpeg not available")
        except Exception as ffmpeg_err:
            print(f"FFmpeg conversion failed: {ffmpeg_err}")
        finally:
            if 'in_path' in locals() and os.path.exists(in_path):
                os.unlink(in_path)
            if 'out_path' in locals() and os.path.exists(out_path):
                os.unlink(out_path)
                
    except Exception as e:
        print(f"Audio conversion error: {e}")
        return None


@eel.expose
def registerFace(name):
    def _run():
        log_security_event(
            "ui_history",
            True,
            reason="face_enrollment_requested",
            metadata={"requested_name": name},
        )
        speak(f"Theek hai {name}, owner face enrollment start kar raha hoon. Camera ki taraf dekho.")
        _success, message = register_face(name, num_samples=30)
        log_security_event(
            "ui_history",
            bool(_success),
            reason="face_enrollment_completed" if _success else "face_enrollment_failed",
            face_name=name,
            metadata={"message": message},
        )
        speak(message)

    threading.Thread(target=_run, daemon=True).start()


@eel.expose
def recognizeFace():
    def _run():
        log_security_event(
            "ui_history",
            True,
            reason="owner_verification_requested",
            metadata={"mode": "voice_and_face"},
        )
        success, message = verify_owner_identity(action_label="ui_owner_verification")
        log_security_event(
            "ui_history",
            bool(success),
            reason="owner_verification_passed" if success else "owner_verification_failed",
            metadata={"mode": "voice_and_face", "message": message},
        )

    threading.Thread(target=_run, daemon=True).start()


@eel.expose
def getMemoryTwinDashboard():
    log_security_event(
        "ui_history",
        True,
        reason="memory_dashboard_requested",
        metadata={"surface": "frontend"},
    )
    return get_dashboard()


@eel.expose
def addMemoryTwinEntry(
    topic,
    content,
    source_type="text",
    confidence=3,
    duration_min=20,
    importance=7,
):
    log_security_event(
        "ui_history",
        True,
        reason="memory_entry_add_requested",
        metadata={
            "surface": "frontend",
            "source_type": str(source_type or "text"),
            "topic": str(topic or "")[:80],
        },
    )
    return add_study_record(
        topic=topic,
        content=content,
        source_type=source_type,
        confidence=confidence,
        duration_min=duration_min,
        importance=importance,
        source="frontend",
    )


@eel.expose
def ingestMemoryTwinUpload(
    file_name,
    data_payload,
    topic="",
    confidence=3,
    importance=7,
    duration_min=20,
):
    log_security_event(
        "ui_history",
        True,
        reason="memory_upload_requested",
        metadata={
            "surface": "frontend",
            "file_name": str(file_name or "")[:120],
        },
    )
    return ingest_upload(
        file_name=file_name,
        data_payload=data_payload,
        topic=topic,
        confidence=confidence,
        importance=importance,
        duration_min=duration_min,
        source="frontend_upload",
    )


@eel.expose
def verifyMemoryTwinIntegrity():
    log_security_event(
        "ui_history",
        True,
        reason="memory_integrity_verify_requested",
        metadata={"surface": "frontend"},
    )
    return verify_integrity()


@eel.expose
def checkFileForThreat(file_path):
    from backend.security.zaris_core import check_file_threat
    try:
        result = check_file_threat(file_path)
        log_security_event(
            "ui_history",
            True,
            reason="threat_check",
            metadata={"file": file_path, "result": result.get("message", "")[:100]},
        )
        return result
    except Exception as e:
        log_security_event(
            "ui_history",
            False,
            reason="threat_check_error",
            metadata={"file": file_path, "error": str(e)},
        )
        return {"found": False, "message": f"Error checking file: {e}", "should_show_popup": False}


@eel.expose
def handleThreatAction(action, file_path):
    from backend.security.zaris_core import find_and_delete_file
    from backend.threat_detection import block_file_path
    from pathlib import Path
    
    log_security_event(
        "ui_history",
        True,
        reason=f"threat_action_{action}",
        metadata={"file": file_path},
    )
    
    if action == "delete":
        try:
            result = find_and_delete_file(file_path)
            if result.get("success"):
                log_security_event(
                    "ui_history",
                    True,
                    reason="threat_file_deleted",
                    metadata={"file": file_path},
                )
                return {"success": True, "message": f"File deleted: {file_path}"}
            else:
                return {"success": False, "error": result.get("error", "Delete failed")}
        except Exception as e:
            log_security_event(
                "ui_history",
                False,
                reason="threat_delete_error",
                metadata={"file": file_path, "error": str(e)},
            )
            return {"success": False, "error": str(e)}
    
    elif action == "block":
        try:
            block_file_path(Path(file_path))
            log_security_event(
                "ui_history",
                True,
                reason="threat_file_blocked",
                metadata={"file": file_path},
            )
            return {"success": True, "message": f"File blocked: {file_path}"}
        except Exception as e:
            log_security_event(
                "ui_history",
                False,
                reason="threat_block_error",
                metadata={"file": file_path, "error": str(e)},
            )
            return {"success": False, "error": str(e)}
    
    elif action == "ignore":
        return {"success": True, "message": "Threat ignored"}
    
    return {"success": False, "error": "Unknown action"}


@eel.expose
def getSystemStats():
    from backend.system_monitor import get_system_monitor
    monitor = get_system_monitor()
    
    try:
        cpu = monitor.get_cpu_usage()
        ram = monitor.get_ram_usage()
        drives = monitor.get_all_drives()
        health = monitor.calculate_health_score()
        processes = monitor.get_top_processes(5)
        
        return {
            "success": True,
            "cpu": {"percent": cpu},
            "ram": ram,
            "drives": drives,
            "health": health,
            "processes": [
                {"name": p.name, "pid": p.pid, "memory_mb": p.memory_mb, "cpu_percent": p.cpu_percent}
                for p in processes
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@eel.expose
def getScanFolders():
    try:
        folders = get_monitored_folders()
        return {"success": True, "folders": folders}
    except Exception as e:
        return {"success": False, "error": str(e)}


@eel.expose
def addScanFolder(folder_path):
    try:
        result = add_monitored_folder(folder_path)
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


@eel.expose
def removeScanFolder(folder_path):
    try:
        result = remove_monitored_folder(folder_path)
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def start():
    if not _acquire_single_instance_lock():
        return

    eel.init("frontend")

    start_cyber_security_services()
    start_hotword()
    
    # Start download scanner
    try:
        start_download_scanner(threat_callback=_on_download_threat_detected)
        print("Download scanner started. Monitoring for harmful files.")
    except Exception as e:
        print(f"Download scanner failed to start: {e}")
    
    log_security_event("system_history", True, reason="application_started")

    local_ip = _get_local_ip()
    port = 8001

    print("\n====================================")
    print(f"ZARIS AI running at: http://localhost:{port}")
    print(f"Phone access: http://{local_ip}:{port}")
    print("====================================\n")

    threading.Timer(1.5, lambda: _wb.open(f"http://localhost:{port}/index.html")).start()

    eel.start(
        "index.html",
        size=(1000, 800),
        host="0.0.0.0",
        port=port,
        mode=None,
        block=True,
        close_callback=_on_browser_close,
    )


def _on_browser_close(*args):
    print("Browser band hua, security service background me chalti rahegi.")
    try:
        stop_download_scanner()
    except Exception:
        pass


def _on_download_threat_detected(threat_info):
    print(f"THREAT DETECTED in download: {threat_info.get('file_name', 'Unknown')}")
    try:
        eel.showThreatAlert(threat_info)
    except Exception as e:
        print(f"Failed to show threat alert: {e}")


if __name__ == "__main__":
    start()

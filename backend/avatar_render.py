import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
ASSETS_DIR = FRONTEND_DIR / "assets"
AVATAR_DIR = ASSETS_DIR / "avatar"
GENERATED_DIR = ASSETS_DIR / "generated" / "avatar"
DEFAULT_AVATAR = AVATAR_DIR / "jarvis-avatar.mp4"


def _resolve_path(value):
    if not value:
        return None
    return Path(value).expanduser().resolve()


def _frontend_url_for(path):
    path = Path(path).resolve()
    rel_path = path.relative_to(FRONTEND_DIR.resolve())
    version = int(path.stat().st_mtime) if path.exists() else int(time.time())
    return f"./{rel_path.as_posix()}?v={version}"


def get_base_avatar_path():
    configured = _resolve_path(os.getenv("AVATAR_SOURCE_PATH"))
    if configured and configured.exists():
        return configured
    return DEFAULT_AVATAR


def get_base_avatar_url():
    avatar_path = get_base_avatar_path()
    if avatar_path.exists():
        return _frontend_url_for(avatar_path)
    return "./assets/avatar/jarvis-avatar.mp4"


def get_exact_render_status():
    inference = _resolve_path(os.getenv("WAV2LIP_INFERENCE"))
    checkpoint = _resolve_path(os.getenv("WAV2LIP_CHECKPOINT"))
    avatar_path = get_base_avatar_path()

    reasons = []
    if not avatar_path.exists():
        reasons.append("avatar source missing")
    if inference is None:
        reasons.append("WAV2LIP_INFERENCE not set")
    elif not inference.exists():
        reasons.append("inference script missing")
    if checkpoint is None:
        reasons.append("WAV2LIP_CHECKPOINT not set")
    elif not checkpoint.exists():
        reasons.append("checkpoint missing")

    return {
        "enabled": not reasons,
        "reason": "; ".join(reasons) if reasons else "ready",
        "inference": str(inference) if inference else "",
        "checkpoint": str(checkpoint) if checkpoint else "",
        "avatar": str(avatar_path),
    }


def _ensure_generated_dir():
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)


def _cleanup_generated_assets(max_files=30):
    _ensure_generated_dir()
    files = sorted(
        GENERATED_DIR.glob("*"),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    )
    for stale in files[max_files:]:
        try:
            stale.unlink()
        except Exception:
            pass


def persist_audio_for_render(source_audio, speech_id):
    _ensure_generated_dir()
    target = GENERATED_DIR / f"{speech_id}.mp3"
    shutil.copy2(source_audio, target)
    _cleanup_generated_assets()
    return str(target), _frontend_url_for(target)


def _notify_exact_ready(speech_id, output_path):
    try:
        import eel

        eel.exactAvatarReady(
            speech_id,
            _frontend_url_for(output_path),
            {
                "renderer": "wav2lip",
                "baseAvatar": get_base_avatar_url(),
            },
        )
    except Exception as exc:
        print(f"Exact avatar notify failed: {exc}")


def _render_exact_avatar_job(speech_id, audio_path):
    status = get_exact_render_status()
    if not status["enabled"]:
        print(f"Exact avatar render skipped: {status['reason']}")
        return

    inference = Path(status["inference"])
    checkpoint = Path(status["checkpoint"])
    avatar_path = Path(status["avatar"])
    output_path = GENERATED_DIR / f"{speech_id}-exact.mp4"
    workdir = _resolve_path(os.getenv("WAV2LIP_WORKDIR")) or inference.parent
    python_exec = os.getenv("WAV2LIP_PYTHON") or sys.executable
    extra_args = shlex.split(os.getenv("WAV2LIP_ARGS", ""))

    command = [
        python_exec,
        str(inference),
        "--checkpoint_path",
        str(checkpoint),
        "--face",
        str(avatar_path),
        "--audio",
        str(audio_path),
        "--outfile",
        str(output_path),
        *extra_args,
    ]

    started = time.time()
    try:
        result = subprocess.run(
            command,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        print(f"Exact avatar render failed to start: {exc}")
        return

    if result.returncode != 0 or not output_path.exists():
        stderr_tail = (result.stderr or "").strip()[-800:]
        print(f"Exact avatar render failed: {stderr_tail or result.returncode}")
        return

    print(f"Exact avatar ready in {time.time() - started:.2f}s -> {output_path.name}")
    _notify_exact_ready(speech_id, output_path)


def start_exact_avatar_render(speech_id, audio_path):
    status = get_exact_render_status()
    if not status["enabled"]:
        return False

    thread = threading.Thread(
        target=_render_exact_avatar_job,
        args=(speech_id, audio_path),
        daemon=True,
    )
    thread.start()
    return True

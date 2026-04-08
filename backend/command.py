# backend/command.py

import asyncio
import hashlib
import importlib.util
import os
import threading
import time
import uuid

from typing import Iterable, Optional

import edge_tts
import eel
import pygame
import speech_recognition as sr

from backend.avatar_render import (
    get_base_avatar_url,
    get_exact_render_status,
    persist_audio_for_render,
    start_exact_avatar_render,
)
from backend.config import ASSISTANT_DISPLAY_NAME, normalize_assistant_text

mic_active = False
last_spoken_at = 0.0
is_speaking = False
last_spoken_text = ""
_speak_lock = threading.Lock()
_speech_state_lock = threading.Lock()
_last_ambient_adjust = 0
_frontend_speech_started = {}
_frontend_speech_done = {}
_active_speech_id = None
_mic_capture_lock = threading.Lock()
_cancel_requested = False
_cancel_lock = threading.Lock()


def request_cancel():
    global _cancel_requested
    with _cancel_lock:
        _cancel_requested = True


def clear_cancel():
    global _cancel_requested
    with _cancel_lock:
        _cancel_requested = False


def is_cancel_requested():
    with _cancel_lock:
        return _cancel_requested

VOICE = "hi-IN-MadhurNeural"
VOICE_PITCH = "+12Hz"
VOICE_RATE = "+28%"
AMBIENT_REFRESH_SEC = 10
SPEECH_WAIT_POLL_SEC = 0.08
SPEECH_WAIT_MAX_SEC = 8.0
TTS_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "security_data", "tts_cache")
FAST_BROWSER_TTS = os.getenv("SENTINEL_FAST_BROWSER_TTS", "0").strip().lower() not in {"0", "false", "no"}
ULTRA_FAST_MODE = os.getenv("SENTINEL_ULTRA_FAST", "1").strip().lower() not in {"0", "false", "no"}
FRONTEND_SPEECH_START_GRACE_SEC = 0.25 if ULTRA_FAST_MODE else 0.75
FRONTEND_SPEECH_MAX_SEC = 11.0 if ULTRA_FAST_MODE else 14.0

if not pygame.mixer.get_init():
    pygame.mixer.init(frequency=44100, size=-16, channels=2)

recognizer = sr.Recognizer()
recognizer.pause_threshold = 0.8
recognizer.energy_threshold = 150
recognizer.dynamic_energy_threshold = True
recognizer.dynamic_energy_adjustment_damping = 0.2
recognizer.dynamic_energy_ratio = 1.8
recognizer.non_speaking_duration = 0.3
recognizer.phrase_threshold = 0.3
recognizer.operation_timeout = 8
DEFAULT_RECOGNITION_LANGUAGES = ("hi-IN", "en-IN", "en-US")
SPEECH_RECOGNITION_MODE = os.getenv("SENTINEL_SPEECH_MODE", "online").strip().lower()
ALLOW_ONLINE_STT_FALLBACK = os.getenv("SENTINEL_ALLOW_ONLINE_STT", "1").strip().lower() not in {
    "0",
    "false",
    "no",
}
LOCAL_STT_ENGINE_ORDER = tuple(
    engine.strip().lower()
    for engine in os.getenv("SENTINEL_LOCAL_STT_ENGINES", "vosk,sphinx").split(",")
    if engine.strip()
)
_OFFLINE_STT_WARNING_SHOWN = False
_LOCAL_STT_UNAVAILABLE_ENGINES = set()
_LOCAL_STT_SKIPPED_ENGINES_LOGGED = set()
SPHINX_KEYWORD_MODE = os.getenv("SENTINEL_SPHINX_KEYWORDS", "1").strip().lower() not in {
    "0",
    "false",
    "no",
}
SPHINX_KEYWORD_ENTRIES = [
    ("jarvis", 1e-20),
    ("scan downloads", 1e-20),
    ("show risky files", 1e-20),
    ("system status", 1e-20),
    ("last scan summary", 1e-20),
    ("help", 1e-20),
]

_NOISE_TOKENS = {
    "a",
    "an",
    "and",
    "hmm",
    "huh",
    "oh",
    "ok",
    "okay",
    "the",
    "uh",
    "um",
    "erroor",
    "error",
    "erro",
}


def _is_local_engine_dependency_available(engine):
    if engine == "vosk":
        return importlib.util.find_spec("vosk") is not None

    if engine == "sphinx":
        return importlib.util.find_spec("pocketsphinx") is not None

    return False


def _active_local_stt_engines(verbose=True):
    engines = []
    for engine in LOCAL_STT_ENGINE_ORDER:
        normalized_engine = str(engine or "").strip().lower()
        if not normalized_engine:
            continue

        if normalized_engine in _LOCAL_STT_UNAVAILABLE_ENGINES:
            continue

        if _is_local_engine_dependency_available(normalized_engine):
            engines.append(normalized_engine)
            continue

        if verbose and normalized_engine not in _LOCAL_STT_SKIPPED_ENGINES_LOGGED:
            _LOCAL_STT_SKIPPED_ENGINES_LOGGED.add(normalized_engine)
            print(f"Local STT engine '{normalized_engine}' not installed, skipping.")
        _LOCAL_STT_UNAVAILABLE_ENGINES.add(normalized_engine)

    return engines


def _new_tts_loop():
    loop = asyncio.new_event_loop()
    return loop


def _speak_with_pyttsx3(text):
    try:
        import pyttsx3

        engine = pyttsx3.init()
        try:
            engine.setProperty("rate", 185)
        except Exception:
            pass
        engine.say(text)
        engine.runAndWait()
        try:
            engine.stop()
        except Exception:
            pass
        return True
    except Exception as exc:
        print(f"Offline TTS fallback failed: {exc}")
        return False


def _ensure_tts_cache_dir():
    os.makedirs(TTS_CACHE_DIR, exist_ok=True)


def _build_cached_audio_path(text):
    _ensure_tts_cache_dir()
    cache_key = hashlib.sha1(
        f"{VOICE}|{VOICE_PITCH}|{VOICE_RATE}|{normalize_assistant_text(text)}".encode("utf-8")
    ).hexdigest()
    return os.path.join(TTS_CACHE_DIR, f"{cache_key}.mp3")


def _generate_edge_tts_audio(text, output_path):
    async def _speak():
        communicate = edge_tts.Communicate(
            text=text,
            voice=VOICE,
            pitch=VOICE_PITCH,
            rate=VOICE_RATE,
        )
        await communicate.save(output_path)

    loop = _new_tts_loop()
    try:
        loop.run_until_complete(asyncio.wait_for(_speak(), timeout=15.0))
    except asyncio.TimeoutError:
        raise TimeoutError("TTS generation timed out after 15 seconds")
    finally:
        loop.close()


def _notify_speaking_started(text, speech_id, exact_status):
    try:
        payload = {
            "speechId": speech_id,
            "baseVideoUrl": get_base_avatar_url(),
            "exactRenderEnabled": exact_status["enabled"],
            "exactRenderReason": exact_status["reason"],
            "browserSpeechEnabled": FAST_BROWSER_TTS,
        }
        if FAST_BROWSER_TTS:
            eel.startSpeakingUI(text, payload)
        else:
            eel.renderSecurityResponse(text, payload)
    except Exception:
        pass


def _notify_speaking_stopped(speech_id):
    try:
        if FAST_BROWSER_TTS:
            eel.stopSpeakingUI(speech_id)
        else:
            eel.finishSecurityResponse(speech_id)
    except Exception:
        pass


def _stop_audio_playback():
    try:
        pygame.mixer.music.stop()
    except Exception:
        pass
    try:
        pygame.mixer.music.unload()
    except Exception:
        pass


def _start_exact_avatar_render_async(audio_file, speech_id):
    def _run():
        try:
            render_audio_path, _ = persist_audio_for_render(audio_file, speech_id)
            start_exact_avatar_render(speech_id, render_audio_path)
        except Exception as exc:
            print(f"Exact avatar prep failed: {exc}")

    threading.Thread(target=_run, daemon=True).start()


def _prepare_frontend_speech_track(speech_id):
    started_event = threading.Event()
    done_event = threading.Event()
    with _speech_state_lock:
        _frontend_speech_started[speech_id] = started_event
        _frontend_speech_done[speech_id] = done_event
    return started_event, done_event


def _clear_frontend_speech_track(speech_id):
    with _speech_state_lock:
        _frontend_speech_started.pop(speech_id, None)
        _frontend_speech_done.pop(speech_id, None)


def mark_frontend_speech_started(speech_id):
    if not speech_id:
        return
    with _speech_state_lock:
        event = _frontend_speech_started.get(speech_id)
    if event:
        event.set()


def mark_frontend_speech_complete(speech_id):
    if not speech_id:
        return
    with _speech_state_lock:
        event = _frontend_speech_done.get(speech_id)
    if event:
        event.set()


def _estimate_speech_duration(text):
    word_count = max(1, len(str(text or "").split()))
    estimate = 0.26 * word_count + 1.1
    return max(2.2, min(FRONTEND_SPEECH_MAX_SEC, estimate))


def interrupt_current_speech():
    global _active_speech_id

    speech_id = _active_speech_id
    if speech_id:
        mark_frontend_speech_complete(speech_id)
    _stop_audio_playback()

    try:
        eel.forceFrontendSpeechStop(speech_id or "")
    except Exception:
        pass

    return bool(speech_id or is_speaking)


def _maybe_adjust_for_noise(source):
    global _last_ambient_adjust

    now = time.time()
    if now - _last_ambient_adjust < AMBIENT_REFRESH_SEC:
        return

    recognizer.adjust_for_ambient_noise(source, duration=0.12)
    _last_ambient_adjust = now


def _normalize_local_stt_result(result_obj):
    def _collapse_repeated_phrase(words):
        total_words = len(words)
        if total_words < 2:
            return words

        max_phrase_len = min(4, total_words // 2)
        for phrase_len in range(1, max_phrase_len + 1):
            phrase = words[:phrase_len]
            match_count = 1
            for i in range(phrase_len, total_words, phrase_len):
                chunk = words[i:i + phrase_len]
                if chunk == phrase:
                    match_count += 1
                else:
                    break
            if match_count >= 2:
                return phrase

        return words

    def _collapse_adjacent_duplicate_words(words):
        if not words:
            return words

        collapsed = [words[0]]
        for word in words[1:]:
            if word.lower() != collapsed[-1].lower():
                collapsed.append(word)
        return collapsed

    if isinstance(result_obj, dict):
        text = str(result_obj.get("text", "")).strip()
    else:
        text = str(result_obj or "").strip()

    if not text:
        return ""

    words = [word for word in text.split() if word]
    words = _collapse_repeated_phrase(words)
    words = _collapse_adjacent_duplicate_words(words)
    return " ".join(words).strip()


def _is_likely_noise_transcript(text):
    if not text:
        return True

    tokens = [token.strip(" .,!?:;\"'`()[]{}") for token in str(text).split()]
    tokens = [token for token in tokens if token]
    if not tokens:
        return True

    lowered = [token.lower() for token in tokens]
    if len(lowered) == 1 and lowered[0] in _NOISE_TOKENS:
        return True

    if all(token in _NOISE_TOKENS for token in lowered):
        return True

    unique_words = set(lowered)
    total_words = len(lowered)
    if total_words >= 4:
        unique_ratio = len(unique_words) / total_words
        if unique_ratio < 0.35:
            return True

    return False


def _recognize_with_local_engine(audio, engine):
    if engine == "vosk":
        try:
            return recognizer.recognize_vosk(audio)
        except TypeError:
            # Older/newer SpeechRecognition builds may differ in args.
            return recognizer.recognize_vosk(audio, show_all=False)

    if engine == "sphinx":
        return recognizer.recognize_sphinx(audio, language="en-US")

    return ""


def transcribe_audio_local(audio, lowercase=True, engines: Optional[Iterable[str]] = None, verbose=True):
    if audio is None:
        return None

    selected_engines = list(engines or _active_local_stt_engines(verbose=verbose))
    for engine in selected_engines:
        normalized_engine = str(engine or "").strip().lower()
        if not normalized_engine:
            continue

        if normalized_engine in _LOCAL_STT_UNAVAILABLE_ENGINES:
            continue

        try:
            result_text = _normalize_local_stt_result(_recognize_with_local_engine(audio, normalized_engine))
            if result_text:
                if _is_likely_noise_transcript(result_text):
                    continue
                if verbose:
                    print(f"User ({normalized_engine}):", result_text)
                return result_text.lower() if lowercase else result_text
        except sr.UnknownValueError:
            continue
        except Exception as exc:
            # Engine unavailable/errors are expected on some setups; try next local engine.
            _LOCAL_STT_UNAVAILABLE_ENGINES.add(normalized_engine)
            if verbose and normalized_engine not in _LOCAL_STT_SKIPPED_ENGINES_LOGGED:
                _LOCAL_STT_SKIPPED_ENGINES_LOGGED.add(normalized_engine)
                print(f"Local STT engine '{normalized_engine}' unavailable: {exc}")

    return None


def capture_audio_with_lock(
    recognizer_obj,
    timeout,
    phrase_time_limit,
    adjust_callback=None,
    lock_timeout=1.0,
):
    acquired = _mic_capture_lock.acquire(timeout=max(0.05, float(lock_timeout)))
    if not acquired:
        return None, "busy"

    try:
        with sr.Microphone() as source:
            if adjust_callback:
                adjust_callback(source)
            audio = recognizer_obj.listen(
                source,
                timeout=timeout,
                phrase_time_limit=phrase_time_limit,
            )
            return audio, ""
    except sr.WaitTimeoutError:
        return None, "timeout"
    except Exception as exc:
        return None, str(exc)
    finally:
        _mic_capture_lock.release()


def transcribe_audio(audio, languages=None, lowercase=True, verbose=True):
    global _OFFLINE_STT_WARNING_SHOWN

    if audio is None:
        return None

    prefers_offline = SPEECH_RECOGNITION_MODE in {"offline", "local", "auto"}
    allows_online = SPEECH_RECOGNITION_MODE in {"online", "google"} or ALLOW_ONLINE_STT_FALLBACK

    if prefers_offline:
        local_query = transcribe_audio_local(audio, lowercase=lowercase, verbose=verbose)
        if local_query:
            return local_query

        if not allows_online and not _OFFLINE_STT_WARNING_SHOWN and verbose:
            _OFFLINE_STT_WARNING_SHOWN = True
            print("Offline STT unavailable. Install local engine support (vosk model or pocketsphinx).")

    if not allows_online:
        if verbose:
            print("Samajh nahi aaya")
        return None

    for language in languages or DEFAULT_RECOGNITION_LANGUAGES:
        try:
            query = _normalize_local_stt_result(recognizer.recognize_google(audio, language=language))
            if _is_likely_noise_transcript(query):
                continue
            if verbose:
                print(f"User ({language}):", query)
            return query.lower() if lowercase else query
        except sr.UnknownValueError:
            continue
        except sr.RequestError as exc:
            if verbose:
                print(f"Google API error ({language}): {exc}")
        except Exception as exc:
            if verbose:
                print(f"Speech transcription error ({language}): {exc}")

    if verbose:
        print("Samajh nahi aaya")
    return None


def listen_for_command_audio(
    timeout=3.8,
    phrase_time_limit=4.5,
    languages=None,
    lowercase=True,
):
    if ULTRA_FAST_MODE and is_speaking:
        interrupt_current_speech()
        time.sleep(0.08)

    waited_sec = 0.0
    while is_speaking and waited_sec < SPEECH_WAIT_MAX_SEC:
        time.sleep(SPEECH_WAIT_POLL_SEC)
        waited_sec += SPEECH_WAIT_POLL_SEC

    if is_speaking:
        print("Speech abhi chal rahi hai, mic capture skip kiya.")
        return None, None

    print("Sun raha hoon...")
    audio, capture_error = capture_audio_with_lock(
        recognizer,
        timeout=timeout,
        phrase_time_limit=phrase_time_limit,
        adjust_callback=_maybe_adjust_for_noise,
    )

    if capture_error == "busy":
        print("Mic busy hai, capture skip kiya.")
        return None, None

    if capture_error == "timeout":
        print("Timeout - kuch suna nahi")
        return None, None

    if capture_error:
        print(f"Mic error: {capture_error}")
        return None, None

    print("Mic ready - bol!")
    print("Audio capture done")

    return transcribe_audio(audio, languages=languages, lowercase=lowercase), audio


def speak(text):
    global is_speaking, last_spoken_text, last_spoken_at, _active_speech_id

    text = normalize_assistant_text(text)
    if not text or not text.strip():
        return

    if not _speak_lock.acquire(blocking=False):
        print("speak() already running, skipping:", text[:40])
        return

    speech_id = None

    try:
        if is_speaking:
            return

        is_speaking = True
        last_spoken_text = text
        last_spoken_at = time.time()
        speech_id = uuid.uuid4().hex
        _active_speech_id = speech_id
        exact_status = get_exact_render_status()
        print(f"{ASSISTANT_DISPLAY_NAME}:", text)

        if FAST_BROWSER_TTS:
            started_event, done_event = _prepare_frontend_speech_track(speech_id)
            _notify_speaking_started(text, speech_id, exact_status)

            if started_event.wait(timeout=FRONTEND_SPEECH_START_GRACE_SEC):
                done_event.wait(timeout=_estimate_speech_duration(text))
                return

        audio_file = _build_cached_audio_path(text)
        audio_ready = os.path.exists(audio_file)
        try:
            if not audio_ready:
                _generate_edge_tts_audio(text, audio_file)
                audio_ready = os.path.exists(audio_file)
        except (TimeoutError, Exception) as exc:
            print(f"TTS error: {exc}")
            audio_ready = False
            
        if not audio_ready:
            print("Using offline TTS fallback (pyttsx3)")
            _notify_speaking_started(text, speech_id, exact_status)
            _speak_with_pyttsx3(text)
            return

        if exact_status["enabled"] and not ULTRA_FAST_MODE:
            _start_exact_avatar_render_async(audio_file, speech_id)

        try:
            pygame.mixer.music.load(audio_file)
            _notify_speaking_started(text, speech_id, exact_status)
            pygame.mixer.music.play()

            while pygame.mixer.music.get_busy():
                time.sleep(0.04)

            pygame.mixer.music.stop()
            try:
                pygame.mixer.music.unload()
            except Exception:
                pass
        except Exception as exc:
            print(f"Audio playback error: {exc}")
            try:
                pygame.mixer.music.stop()
                pygame.mixer.music.unload()
            except Exception:
                pass
            _notify_speaking_started(text, speech_id, exact_status)
            _speak_with_pyttsx3(text)

    except Exception as exc:
        print(f"speak() critical error: {exc}")

    finally:
        is_speaking = False
        _active_speech_id = None
        _speak_lock.release()
        _clear_frontend_speech_track(speech_id)
        _notify_speaking_stopped(speech_id)
        time.sleep(0.3)


def takecommand(timeout=5.0, phrase_time_limit=8.0, languages=None, lowercase=True):
    global mic_active
    query, _audio = listen_for_command_audio(
        timeout=timeout,
        phrase_time_limit=phrase_time_limit,
        languages=languages,
        lowercase=lowercase,
    )
    return query

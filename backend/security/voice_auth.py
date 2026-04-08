import audioop
import io
import statistics
import wave
from array import array


def _to_pcm_frames(audio_data):
    if audio_data is None:
        return b"", 16000, 2

    wav_bytes = audio_data.get_wav_data(convert_rate=16000, convert_width=2)
    with wave.open(io.BytesIO(wav_bytes), "rb") as handle:
        sample_rate = handle.getframerate()
        sample_width = handle.getsampwidth()
        channels = handle.getnchannels()
        frames = handle.readframes(handle.getnframes())

    if channels > 1:
        frames = audioop.tomono(frames, sample_width, 0.5, 0.5)

    return frames, sample_rate, sample_width


def _chunk_metrics(chunk, sample_width):
    if not chunk:
        return 0.0, 0.0, 0.0

    usable = len(chunk) - (len(chunk) % sample_width)
    if usable <= 0:
        return 0.0, 0.0, 0.0

    chunk = chunk[:usable]
    samples = array("h")
    samples.frombytes(chunk)

    if len(samples) < 3:
        return float(audioop.rms(chunk, sample_width)), 0.0, 0.0

    crossings = 0
    deltas = []
    previous = samples[0]
    for sample in samples[1:]:
        if (sample >= 0 > previous) or (sample < 0 <= previous):
            crossings += 1
        deltas.append(abs(sample - previous))
        previous = sample

    zcr = crossings / max(1, len(samples) - 1)
    mean_delta = sum(deltas) / max(1, len(deltas))
    rms = float(audioop.rms(chunk, sample_width))
    return rms, zcr, mean_delta


def create_voiceprint(audio_data, transcript=""):
    frames, sample_rate, sample_width = _to_pcm_frames(audio_data)
    if not frames:
        return {}

    chunk_size = max(sample_width * 320, sample_rate * sample_width // 20)
    rms_values = []
    zcr_values = []
    delta_values = []

    for index in range(0, len(frames), chunk_size):
        chunk = frames[index : index + chunk_size]
        rms, zcr, mean_delta = _chunk_metrics(chunk, sample_width)
        if rms <= 0:
            continue
        rms_values.append(rms)
        zcr_values.append(zcr)
        delta_values.append(mean_delta)

    if not rms_values:
        return {}

    duration = len(frames) / float(sample_rate * sample_width)
    return {
        "feature_version": 1,
        "transcript": str(transcript or "").strip().lower(),
        "duration": round(duration, 4),
        "mean_rms": round(statistics.fmean(rms_values), 4),
        "std_rms": round(statistics.pstdev(rms_values) if len(rms_values) > 1 else 0.0, 4),
        "mean_zcr": round(statistics.fmean(zcr_values), 6),
        "std_zcr": round(statistics.pstdev(zcr_values) if len(zcr_values) > 1 else 0.0, 6),
        "mean_delta": round(statistics.fmean(delta_values), 4),
    }


def compare_voiceprints(reference, live, threshold=0.63):
    if not reference or not live:
        return False, 0.0, "Voiceprint sample unavailable."

    weights = (
        ("duration", 0.12, 0.85),
        ("mean_rms", 0.20, 110.0),
        ("std_rms", 0.14, 80.0),
        ("mean_zcr", 0.20, 0.04),
        ("std_zcr", 0.14, 0.02),
        ("mean_delta", 0.20, 450.0),
    )

    weighted_distance = 0.0
    total_weight = 0.0

    for key, weight, floor in weights:
        ref_value = float(reference.get(key, 0.0))
        live_value = float(live.get(key, 0.0))
        scale = max(abs(ref_value) * 0.5, floor)
        component = min(2.0, abs(live_value - ref_value) / scale)
        weighted_distance += component * weight
        total_weight += weight

    if total_weight <= 0:
        return False, 0.0, "Voiceprint comparison failed."

    score = max(0.0, 1.0 - (weighted_distance / total_weight))
    matched = score >= threshold
    reason = "Voiceprint matched." if matched else "Voiceprint mismatch."
    return matched, round(score, 4), reason

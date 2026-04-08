// phone_mic.js - Phone microphone capture for ZARIS AI
// Uses MediaRecorder API to capture audio from phone browser

const PhoneMic = (function () {
  let mediaRecorder = null;
  let audioChunks = [];
  let stream = null;
  let isRecording = false;
  let silenceDetector = null;
  let silenceTimeout = null;
  let audioContext = null;
  let analyser = null;
  let onStartCallback = null;
  let onStopCallback = null;
  let onErrorCallback = null;

  const MAX_RECORDING_TIME = 10000; // 10 seconds max
  const SILENCE_THRESHOLD = 0.02; // Audio level threshold
  const SILENCE_DURATION = 1500; // 1.5 seconds of silence to stop

  async function checkMicPermission() {
    try {
      const result = await navigator.permissions.query({ name: "microphone" });
      return result.state;
    } catch {
      return "unknown";
    }
  }

  async function requestMicAccess() {
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          sampleRate: 16000,
          channelCount: 1,
        },
      });
      return true;
    } catch (err) {
      console.error("Mic access denied:", err);
      if (onErrorCallback) {
        if (err.name === "NotAllowedError") {
          onErrorCallback("Microphone permission denied. Please allow mic access.");
        } else if (err.name === "NotFoundError") {
          onErrorCallback("No microphone found on this device.");
        } else {
          onErrorCallback("Failed to access microphone: " + err.message);
        }
      }
      return false;
    }
  }

  function setupSilenceDetection() {
    if (!stream) return;

    audioContext = new (window.AudioContext || window.webkitAudioContext)();
    analyser = audioContext.createAnalyser();
    const source = audioContext.createMediaStreamSource(stream);
    source.connect(analyser);
    analyser.fftSize = 256;

    const dataArray = new Uint8Array(analyser.frequencyBinCount);
    let silenceStart = null;

    silenceDetector = setInterval(() => {
      if (!isRecording) {
        clearInterval(silenceDetector);
        return;
      }

      analyser.getByteFrequencyData(dataArray);
      const average = dataArray.reduce((a, b) => a + b) / dataArray.length;
      const normalizedLevel = average / 255;

      if (normalizedLevel < SILENCE_THRESHOLD) {
        if (!silenceStart) {
          silenceStart = Date.now();
        } else if (Date.now() - silenceStart > SILENCE_DURATION) {
          console.log("Silence detected, stopping recording");
          stopRecording();
        }
      } else {
        silenceStart = null;
      }
    }, 100);
  }

  function getSupportedMimeType() {
    const types = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg"];
    for (const type of types) {
      if (MediaRecorder.isTypeSupported(type)) {
        return type;
      }
    }
    return "audio/webm";
  }

  async function startRecording() {
    if (isRecording) return false;

    if (!stream) {
      const granted = await requestMicAccess();
      if (!granted) return false;
    }

    audioChunks = [];
    const mimeType = getSupportedMimeType();

    try {
      mediaRecorder = new MediaRecorder(stream, { mimeType });
    } catch {
      mediaRecorder = new MediaRecorder(stream);
    }

    mediaRecorder.ondataavailable = (event) => {
      if (event.data.size > 0) {
        audioChunks.push(event.data);
      }
    };

    mediaRecorder.onstop = async () => {
      if (audioChunks.length === 0) {
        if (onStopCallback) onStopCallback(null);
        return;
      }

      const audioBlob = new Blob(audioChunks, { type: mimeType });
      await processAudio(audioBlob);
    };

    mediaRecorder.onerror = (event) => {
      console.error("MediaRecorder error:", event);
      if (onErrorCallback) onErrorCallback("Recording error: " + event.error);
      isRecording = false;
    };

    mediaRecorder.start(100);
    isRecording = true;

    setupSilenceDetection();

    setTimeout(() => {
      if (isRecording) {
        console.log("Max recording time reached");
        stopRecording();
      }
    }, MAX_RECORDING_TIME);

    if (onStartCallback) onStartCallback();
    return true;
  }

  function stopRecording() {
    if (!isRecording || !mediaRecorder) return;

    isRecording = false;

    if (silenceDetector) {
      clearInterval(silenceDetector);
      silenceDetector = null;
    }

    if (mediaRecorder.state !== "inactive") {
      mediaRecorder.stop();
    }
  }

  async function processAudio(audioBlob) {
    try {
      const arrayBuffer = await audioBlob.arrayBuffer();
      const base64Audio = arrayBufferToBase64(arrayBuffer);
      const mimeType = audioBlob.type || "audio/webm";

      if (typeof window.eel !== "undefined") {
        const result = await window.eel.processPhoneAudio(base64Audio, mimeType)();
        if (onStopCallback) onStopCallback(result);
      } else {
        console.error("EEL not available");
        if (onErrorCallback) onErrorCallback("Backend connection not available");
        if (onStopCallback) onStopCallback(null);
      }
    } catch (err) {
      console.error("Error processing audio:", err);
      if (onErrorCallback) onErrorCallback("Failed to process audio");
      if (onStopCallback) onStopCallback(null);
    }
  }

  function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function cleanup() {
    stopRecording();
    if (stream) {
      stream.getTracks().forEach((track) => track.stop());
      stream = null;
    }
    if (audioContext) {
      audioContext.close();
      audioContext = null;
    }
  }

  return {
    start: startRecording,
    stop: stopRecording,
    isActive: () => isRecording,
    cleanup: cleanup,
    onStart: (callback) => {
      onStartCallback = callback;
    },
    onStop: (callback) => {
      onStopCallback = callback;
    },
    onError: (callback) => {
      onErrorCallback = callback;
    },
    checkPermission: checkMicPermission,
  };
})();

// Auto-cleanup on page unload
window.addEventListener("beforeunload", () => {
  PhoneMic.cleanup();
});
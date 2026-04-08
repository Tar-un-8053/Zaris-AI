let siriWave = null;
let siriWrapper = null;
let currentBrowserUtterance = null;
let currentBrowserSpeechId = null;
const CHAT_HISTORY_LIMIT = 22;

function appendChatMessage(prefix, text, role = "system") {
  const cleanText = String(text || "").trim();
  if (!cleanText) return;

  const display = document.getElementById("consoleDisplay");
  if (!display) return;

  const seedLine = document.getElementById("consoleLine");
  if (seedLine) seedLine.remove();

  const lastLine = display.lastElementChild;
  if (
    lastLine &&
    lastLine instanceof HTMLElement &&
    lastLine.dataset.role === role &&
    lastLine.dataset.message === cleanText
  ) {
    return;
  }

  const line = document.createElement("div");
  line.className = `chat-line ${role}`;
  line.dataset.role = role;
  line.dataset.message = cleanText;

  const label = document.createElement("span");
  label.className = "chat-prefix";
  label.textContent = prefix;

  const content = document.createElement("span");
  content.className = "chat-text";
  content.textContent = cleanText;

  line.appendChild(label);
  line.appendChild(content);
  display.appendChild(line);

  while (display.children.length > CHAT_HISTORY_LIMIT) {
    display.removeChild(display.firstElementChild);
  }

  display.classList.add("active");
  display.scrollTop = display.scrollHeight;
}

function showUserFeed(text) {
  appendChatMessage("YOU", text, "user");
}

function showAssistantFeed(text) {
  appendChatMessage("ZARIS AI", text, "assistant");
}

window.pushUserMessage = showUserFeed;

function getBrowserSpeech() {
  if (typeof window === "undefined") return null;
  return window.speechSynthesis || null;
}

function pickBrowserVoice() {
  const synth = getBrowserSpeech();
  if (!synth || !synth.getVoices) return null;

  const voices = synth.getVoices() || [];
  if (!voices.length) return null;

  const malePatterns = [
    /male/i,
    /madhur/i,
    /ravi/i,
    /david/i,
    /guy/i,
    /mark/i,
    /ryan/i,
    /arthur/i,
    /daniel/i,
    /george/i,
    /prabhat/i,
  ];
  const preferredLocales = ["hi-IN", "en-IN", "en-US"];
  for (const locale of preferredLocales) {
    const exactMale = voices.find((voice) => {
      const tag = `${voice.name || ""} ${voice.voiceURI || ""}`;
      return (voice.lang || "").toLowerCase() === locale.toLowerCase() && malePatterns.some((pattern) => pattern.test(tag));
    });
    if (exactMale) return exactMale;
  }

  for (const locale of preferredLocales) {
    const exact = voices.find((voice) => (voice.lang || "").toLowerCase() === locale.toLowerCase());
    if (exact) return exact;
  }

  const partialMale = voices.find((voice) => {
    const tag = `${voice.lang || ""} ${voice.name || ""} ${voice.voiceURI || ""}`;
    return /hi|india/i.test(tag) && malePatterns.some((pattern) => pattern.test(tag));
  });
  if (partialMale) return partialMale;

  const partial = voices.find((voice) => /hi|india/i.test(`${voice.lang || ""} ${voice.name || ""}`));
  return partial || voices[0] || null;
}

function stopBrowserSpeech(notifyBackend = false) {
  const synth = getBrowserSpeech();
  if (!synth) return;

  const speechId = currentBrowserSpeechId;
  currentBrowserUtterance = null;
  currentBrowserSpeechId = null;
  synth.cancel();

  if (notifyBackend && speechId && window.eel) {
    window.eel.reportSpeechDone(speechId)();
  }
}

function startBrowserSpeech(text, meta) {
  const synth = getBrowserSpeech();
  if (!synth || !text || typeof SpeechSynthesisUtterance === "undefined") {
    return false;
  }

  stopBrowserSpeech(false);

  const utterance = new SpeechSynthesisUtterance(text);
  const voice = pickBrowserVoice();
  const speechId = (meta && meta.speechId) || "";

  if (voice) utterance.voice = voice;
  utterance.lang = (voice && voice.lang) || "hi-IN";
  utterance.rate = 1.32;
  utterance.pitch = 0.96;
  utterance.volume = 1.0;

  currentBrowserUtterance = utterance;
  currentBrowserSpeechId = speechId;

  if (window.eel && speechId) {
    window.eel.reportSpeechStarted(speechId)();
  }

  utterance.onstart = () => {
  };

  utterance.onend = () => {
    const completedSpeechId = currentBrowserSpeechId || speechId;
    currentBrowserUtterance = null;
    currentBrowserSpeechId = null;
    if (window.eel && completedSpeechId) {
      window.eel.reportSpeechDone(completedSpeechId)();
    }
  };

  utterance.onerror = () => {
    const completedSpeechId = currentBrowserSpeechId || speechId;
    currentBrowserUtterance = null;
    currentBrowserSpeechId = null;
    if (window.eel && completedSpeechId) {
      window.eel.reportSpeechDone(completedSpeechId)();
    }
  };

  synth.speak(utterance);
  return true;
}

function applyStatus(text, color, mode) {
  $("#statusText").text(text).css("color", color);

  const $dot = $("#statusDot");
  $dot.removeClass("standby listening");

  if (mode === "listening") {
    $dot.addClass("listening");
    $dot.css("background", color).css("box-shadow", `0 0 12px ${color}`);
    return;
  }

  $dot.addClass("standby");
  $dot.css("background", color).css("box-shadow", `0 0 8px ${color}`);
}

function setStandbyState() {
  applyStatus("MIC ARMED", "#ffaa00", "standby");
  $("#commandInput").attr("placeholder", "Security console command type karein...");
}

$(document).ready(function () {
  stopBrowserSpeech(false);
  siriWrapper = $("#SiriWave");

  siriWave = new SiriWave({
    container: document.getElementById("siri-container"),
    width: Math.min(window.innerWidth * 0.55, 600),
    height: 100,
    style: "ios9",
    amplitude: 0,
    autostart: false,
    color: "#00f0ff"
  });

  siriWrapper.hide();
  setStandbyState();

  const synth = getBrowserSpeech();
  if (synth && typeof synth.onvoiceschanged !== "undefined") {
    synth.onvoiceschanged = () => {
      pickBrowserVoice();
    };
  }
});

function startMicUI() {
  $("#robotCore").addClass("listening");
  applyStatus("VOICE LISTEN", "#00f0ff", "listening");
  $("#MicBtn").addClass("active");
  showConsoleFeed("Voice command sun raha hoon...");

  if (siriWrapper) siriWrapper.fadeIn(200);
  if (siriWave) {
    siriWave.start();
    siriWave.setAmplitude(0.6);
  }
}

function stopMicUI() {
  $("#robotCore").removeClass("listening");
  $("#MicBtn").removeClass("active");
  setStandbyState();

  if (siriWave) {
    siriWave.setAmplitude(0);
    siriWave.stop();
  }
  if (siriWrapper) siriWrapper.fadeOut(200);
}

function showConsoleFeed(text) {
  appendChatMessage("SYS", text, "system");
}

window.showConsoleFeed = showConsoleFeed;

eel.expose(startSpeakingUI);
function startSpeakingUI(text, meta) {
  $("#robotCore").addClass("speaking");
  if (window.startAvatarHybridSpeech) window.startAvatarHybridSpeech(text || "", meta || {});

  applyStatus("ALERT VOICE", "#00ff88", "listening");
  if (text) showAssistantFeed(text);
  if ((meta && meta.browserSpeechEnabled) !== false) {
    const started = startBrowserSpeech(text || "", meta || {});
    if (!started) {
      const speechId = (meta && meta.speechId) || "";
      if (speechId && window.eel) {
        window.eel.reportSpeechDone(speechId)();
      }
    }
  }

  if (siriWrapper) siriWrapper.fadeIn(150);
  if (siriWave) {
    siriWave.start();
    siriWave.setAmplitude(0.8);
  }
}

eel.expose(renderSecurityResponse);
function renderSecurityResponse(text, meta) {
  if (text && text.includes("[SHOW_SYSTEM_MONITOR]")) {
    if (window.showSystemMonitor) {
      window.showSystemMonitor();
    }
    text = text.replace("[SHOW_SYSTEM_MONITOR]", "").trim() || "System monitor opened.";
  }

  $("#robotCore").addClass("speaking");
  if (window.startAvatarHybridSpeech) window.startAvatarHybridSpeech(text || "", meta || {});

  applyStatus("ALERT VOICE", "#00ff88", "listening");
  if (text) showAssistantFeed(text);

  if (siriWrapper) siriWrapper.fadeIn(120);
  if (siriWave) {
    siriWave.start();
    siriWave.setAmplitude(0.65);
  }
}

eel.expose(stopSpeakingUI);
function stopSpeakingUI(speechId) {
  $("#robotCore").removeClass("speaking");
  if (window.stopAvatarHybridSpeech) window.stopAvatarHybridSpeech(speechId || null);
  stopBrowserSpeech(false);
  setStandbyState();

  if (siriWave) {
    siriWave.setAmplitude(0);
    siriWave.stop();
  }
  if (siriWrapper) siriWrapper.fadeOut(200);
}

eel.expose(finishSecurityResponse);
function finishSecurityResponse(speechId) {
  $("#robotCore").removeClass("speaking");
  if (window.stopAvatarHybridSpeech) window.stopAvatarHybridSpeech(speechId || null);
  setStandbyState();

  if (siriWave) {
    siriWave.setAmplitude(0);
    siriWave.stop();
  }
  if (siriWrapper) siriWrapper.fadeOut(120);
}

eel.expose(forceFrontendSpeechStop);
function forceFrontendSpeechStop(_speechId) {
  stopBrowserSpeech(false);
  $("#robotCore").removeClass("speaking");
  if (window.stopAvatarHybridSpeech) window.stopAvatarHybridSpeech(_speechId || null);
  setStandbyState();

  if (siriWave) {
    siriWave.setAmplitude(0);
    siriWave.stop();
  }
  if (siriWrapper) siriWrapper.fadeOut(120);
}

eel.expose(exactAvatarReady);
function exactAvatarReady(speechId, videoUrl, meta) {
  if (window.handleExactAvatarReady) {
    window.handleExactAvatarReady(speechId, videoUrl, meta || {});
  }
}

eel.expose(wakeWordDetected);
function wakeWordDetected() {
  $("#robotCore").addClass("listening");
  applyStatus("WAKE TRIGGER", "#ff6666", "listening");
  $("#MicBtn").addClass("active");
  showConsoleFeed("Wake phrase detect ho gayi. Security console active.");

  if (siriWrapper) siriWrapper.fadeIn(100);
  if (siriWave) {
    siriWave.start();
    siriWave.setAmplitude(0.9);
  }
}

eel.expose(wakeWordMicStart);
function wakeWordMicStart(directCmd) {
  $("#robotCore").addClass("listening");
  $("#MicBtn").addClass("active");

  if (directCmd) {
    applyStatus("COMMAND PARSE", "#00ff88", "listening");
    showUserFeed(directCmd);
    $("#commandInput").val(directCmd);
  } else {
    applyStatus("VOICE LISTEN", "#00f0ff", "listening");
    showConsoleFeed("Security command bolo...");
    $("#commandInput").val("");
    $("#commandInput").attr("placeholder", "Security command sun raha hoon...");
  }

  if (siriWrapper) siriWrapper.fadeIn(150);
  if (siriWave) {
    siriWave.start();
    siriWave.setAmplitude(0.7);
  }
}

eel.expose(wakeWordMicStop);
function wakeWordMicStop(resultText) {
  if (resultText) {
    $("#commandInput").val(resultText);
  } else {
    showConsoleFeed("Command clear nahi mila.");
    $("#commandInput").val("");
    $("#commandInput").attr("placeholder", "Dobara try karein...");
  }

  $("#robotCore").removeClass("listening");
  $("#MicBtn").removeClass("active");
  setStandbyState();

  if (siriWave) {
    siriWave.setAmplitude(0);
    siriWave.stop();
  }
  if (siriWrapper) siriWrapper.fadeOut(200);
}

eel.expose(conversationListening);
function conversationListening() {
  $("#robotCore").addClass("listening");
  $("#MicBtn").addClass("active");
  applyStatus("COMMAND LOOP", "#00ffcc", "listening");
  showConsoleFeed("Next security command bolo. 'bye' ya 'stop' se standby.");

  if (siriWrapper) siriWrapper.fadeIn(150);
  if (siriWave) {
    siriWave.start();
    siriWave.setAmplitude(0.4);
  }
}

eel.expose(conversationEnded);
function conversationEnded() {
  $("#robotCore").removeClass("listening speaking");
  $("#MicBtn").removeClass("active");
  setStandbyState();

  if (siriWave) {
    siriWave.setAmplitude(0);
    siriWave.stop();
  }
  if (siriWrapper) siriWrapper.fadeOut(200);
}

function initCinematicBoot() {
  const body = document.body;
  if (!body) return;

  window.requestAnimationFrame(() => {
    window.setTimeout(() => {
      body.classList.add("app-ready");
    }, 90);
  });
}

function initTelemetryMotion() {
  const core = document.getElementById("robotCore");
  const labels = [
    document.getElementById("telemetryPrimary"),
    document.getElementById("telemetrySecondary"),
    document.getElementById("telemetryTertiary"),
    document.getElementById("telemetryQuaternary"),
  ];

  if (!core || labels.some((label) => !label)) return;

  const telemetryStates = {
    idle: ["THREAT 00", "AUDIO READY", "VISION READY", "LOCK STANDBY"],
    listening: ["VOICE LIVE", "COMMAND PARSE", "AUTH CHECK", "SCAN ACTIVE"],
    speaking: ["ALERT VOICE", "ACTION ROUTE", "IDS LIVE", "LOW LATENCY"],
  };

  let targetX = 0;
  let targetY = 0;
  let currentX = 0;
  let currentY = 0;

  function applyTelemetryState() {
    let state = "idle";

    if (core.classList.contains("speaking")) {
      state = "speaking";
    } else if (core.classList.contains("listening")) {
      state = "listening";
    }

    telemetryStates[state].forEach((text, index) => {
      if (labels[index].textContent !== text) {
        labels[index].textContent = text;
      }
    });
  }

  core.addEventListener("pointermove", (event) => {
    const rect = core.getBoundingClientRect();
    const x = (event.clientX - (rect.left + rect.width / 2)) / rect.width;
    const y = (event.clientY - (rect.top + rect.height / 2)) / rect.height;

    targetX = x;
    targetY = y;
  });

  core.addEventListener("pointerleave", () => {
    targetX = 0;
    targetY = 0;
  });

  if (typeof MutationObserver !== "undefined") {
    const observer = new MutationObserver(applyTelemetryState);
    observer.observe(core, { attributes: true, attributeFilter: ["class"] });
  }

  applyTelemetryState();

  function animateTelemetry(time) {
    const idleX = Math.sin(time * 0.0011) * 6;
    const idleY = Math.cos(time * 0.00145) * 4;

    currentX += (targetX - currentX) * 0.06;
    currentY += (targetY - currentY) * 0.06;

    const shiftX = currentX * 18 + idleX;
    const shiftY = currentY * 10 + idleY;

    core.style.setProperty("--hud-shift-x", `${shiftX.toFixed(2)}px`);
    core.style.setProperty("--hud-shift-y", `${shiftY.toFixed(2)}px`);
    core.style.setProperty("--hud-shift-x-negative", `${(-shiftX).toFixed(2)}px`);
    core.style.setProperty("--hud-shift-y-negative", `${(-shiftY).toFixed(2)}px`);

    window.requestAnimationFrame(animateTelemetry);
  }

  window.requestAnimationFrame(animateTelemetry);
}

(function initCinematicLayer() {
  const start = () => {
    initCinematicBoot();
    initTelemetryMotion();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();

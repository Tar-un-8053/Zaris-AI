$(document).ready(function () {
  let listening = false;
  const MIC_ALWAYS_ON = false;
  let backendNoticeAt = 0;
  let usePhoneMic = false;

  // Detect if on mobile device
  function isMobileDevice() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ||
           (window.innerWidth <= 768 && 'ontouchstart' in window);
  }

  // Initialize phone mic if on mobile
  if (isMobileDevice() && typeof PhoneMic !== "undefined") {
    usePhoneMic = true;
    console.log("Mobile device detected, using phone mic");
    
    PhoneMic.onStart(function() {
      listening = true;
      startMicUI();
      $("#MicBtn").addClass("recording");
      $("#commandInput").val("");
      $("#commandInput").attr("placeholder", "Boliye... sun raha hoon");
    });
    
    PhoneMic.onStop(function(result) {
      listening = false;
      stopMicUI();
      $("#MicBtn").removeClass("recording");
      
      if (result && result.text) {
        if (typeof window.pushUserMessage === "function") {
          window.pushUserMessage(result.text);
        }
        $("#commandInput").val(result.text);
        $("#commandInput").attr("placeholder", "Security console command type karein...");
        
        if (result.latency) {
          const latencyNode = document.getElementById("latencyVal");
          if (latencyNode) latencyNode.textContent = `${result.latency}ms`;
        }
      } else {
        $("#commandInput").val("");
        $("#commandInput").attr("placeholder", "Command samajh nahi aaya, phir se boliye...");
      }
    });
    
    PhoneMic.onError(function(message) {
      listening = false;
      stopMicUI();
      $("#MicBtn").removeClass("recording");
      showConsoleFeed(message || "Mic error");
    });
  }

  function hasBackend() {
    return typeof window.eel !== "undefined";
  }

  function backendSocketState() {
    if (!hasBackend()) return "missing";
    const socket = window.eel._websocket;
    if (!socket || typeof socket.readyState !== "number") return "initializing";
    if (typeof WebSocket !== "undefined") {
      if (socket.readyState === WebSocket.OPEN) return "open";
      if (socket.readyState === WebSocket.CONNECTING) return "connecting";
      if (socket.readyState === WebSocket.CLOSING) return "closing";
      if (socket.readyState === WebSocket.CLOSED) return "closed";
    }
    return "unknown";
  }

  function isBackendReady() {
    return hasBackend() && backendSocketState() === "open";
  }

  function showBackendUnavailable(context = "") {
    const state = backendSocketState();
    const scope = context ? ` (${context})` : "";
    console.warn(`Backend unavailable${scope}. socket=${state}`);
    const now = Date.now();
    if (now - backendNoticeAt > 5000) {
      showConsoleFeed("Backend reconnect ho raha hai. 2 sec baad retry karo.");
      backendNoticeAt = now;
    }
  }

  function isClosedSocketError(err) {
    const message = String(err || "");
    return message.includes("WebSocket is already in CLOSING or CLOSED state");
  }

  // Phone mic recording cycle
  async function runPhoneMicCycle() {
    if (listening) return;
    
    if (!isBackendReady()) {
      showBackendUnavailable("phone-mic");
      return;
    }
    
    const started = await PhoneMic.start();
    if (!started) {
      showConsoleFeed("Mic access nahi mila. Permission check karo.");
    }
  }

  // Backend mic recording cycle (for desktop)
  async function runBackendMicCycle() {
    if (listening) return;
    listening = true;

    startMicUI();
    $("#commandInput").val("");
    $("#commandInput").attr("placeholder", "Voice command sun raha hoon...");

    const startTime = Date.now();

    try {
      if (!isBackendReady()) {
        showBackendUnavailable("mic");
        return;
      }

      const text = await window.eel.micButtonPressed()();
      const latency = Date.now() - startTime;
      const latencyNode = document.getElementById("latencyVal");
      if (latencyNode) latencyNode.textContent = `${latency}ms`;

      if (text) {
        if (typeof window.pushUserMessage === "function") {
          window.pushUserMessage(text);
        }
        $("#commandInput").val(text);
        $("#commandInput").attr("placeholder", "Security console command type karein...");
      } else {
        $("#commandInput").val("");
        $("#commandInput").attr("placeholder", "Command clear nahi aaya, phir se try karein...");
      }
    } catch (err) {
      console.error("EEL error:", err);
      showConsoleFeed("Security engine me temporary issue aaya.");
    } finally {
      listening = false;

      if (MIC_ALWAYS_ON) {
        setTimeout(runBackendMicCycle, 150);
      } else {
        stopMicUI();
      }
    }
  }

  async function runMicCaptureCycle() {
    if (usePhoneMic) {
      return runPhoneMicCycle();
    }
    return runBackendMicCycle();
  }

  $("#MicBtn").on("click", async function () {
    runMicCaptureCycle();
  });

  if (MIC_ALWAYS_ON && !usePhoneMic) {
    runMicCaptureCycle();
  }

  $("#ConsoleBtn").on("click", function () {
    $("#commandInput").focus();
    showConsoleFeed("Try: security mode on, unlock system, show intruder log, panic mode");
  });

  $("#TerminateBtn").on("click", function () {
    if (!isBackendReady()) {
      showBackendUnavailable("terminate");
      return;
    }
    showConsoleFeed("Command cancel kar raha hoon...");
    window.eel.submitSecurityCommand("terminate")();
  });

  const $modal = $("#faceModal");
  const $nameInput = $("#faceNameInput");

  $("#FaceBtn").on("click", function () {
    $modal.removeClass("hidden");
    $nameInput.addClass("hidden");
    $("#faceName").val("");
  });

  $("#faceCloseBtn").on("click", function () {
    $modal.addClass("hidden");
  });

  $modal.on("click", function (e) {
    if (e.target === this) $modal.addClass("hidden");
  });

  $("#faceRegisterBtn").on("click", function () {
    $nameInput.removeClass("hidden");
    $("#faceName").focus();
  });

  $("#faceStartBtn").on("click", function () {
    const name = $("#faceName").val().trim();
    if (!name) {
      alert("Owner name likho.");
      return;
    }
    if (!isBackendReady()) {
      showBackendUnavailable("face-enroll");
      return;
    }

    $modal.addClass("hidden");
    showConsoleFeed("Owner face enrollment start. Camera ki taraf dekho.");
    window.eel.registerFace(name)();
  });

  $("#faceName").on("keypress", function (e) {
    if (e.key === "Enter") $("#faceStartBtn").click();
  });

  $("#faceRecognizeBtn").on("click", function () {
    if (!isBackendReady()) {
      showBackendUnavailable("owner-verify");
      return;
    }

    $modal.addClass("hidden");
    showConsoleFeed("Owner verification start...");
    window.eel.recognizeFace()();
  });

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function renderList(targetId, items, renderItem) {
    const target = document.getElementById(targetId);
    if (!target) return;
    if (!Array.isArray(items) || !items.length) {
      target.innerHTML = '<div class="memory-item"><small>No data yet.</small></div>';
      return;
    }
    target.innerHTML = items.map(renderItem).join("");
  }

  function setIntegrityBadge(integrity) {
    const badge = document.getElementById("memoryIntegrityBadge");
    if (!badge) return;
    const valid = Boolean(integrity && integrity.is_valid);
    badge.textContent = valid ? "Integrity OK" : "Integrity Alert";
    badge.style.borderColor = valid ? "rgba(0,255,170,0.45)" : "rgba(255,128,128,0.55)";
    badge.style.color = valid ? "#a8ffe6" : "#ffd0d0";
  }

  async function refreshMemoryTwinDashboard() {
    if (!isBackendReady()) return;
    try {
      const data = await window.eel.getMemoryTwinDashboard()();
      if (!data || data.ok === false) return;

      const totals = data.totals || {};
      const setText = (id, value) => {
        const node = document.getElementById(id);
        if (node) node.textContent = value;
      };

      setText("kpiRecords", String(totals.records || 0));
      setText("kpiTopics", String(totals.topics || 0));
      setText("kpiOnChain", String(totals.on_chain_records || 0));
      setText("kpiBlocks", String(totals.integrity_blocks || 0));

      renderList("weakTopicsList", data.weak_topics || [], (item) => {
        return (
          '<div class="memory-item">' +
          `<strong>${esc(item.topic)}</strong>` +
          `<small>Score ${esc(item.score)} | Sessions ${esc(item.sessions)} | Conf ${esc(item.avg_confidence)}</small>` +
          "</div>"
        );
      });

      renderList("strongTopicsList", data.strong_topics || [], (item) => {
        return (
          '<div class="memory-item">' +
          `<strong>${esc(item.topic)}</strong>` +
          `<small>Score ${esc(item.score)} | Sessions ${esc(item.sessions)} | Conf ${esc(item.avg_confidence)}</small>` +
          "</div>"
        );
      });

      renderList("studyHistoryList", data.study_history || [], (item) => {
        return (
          '<div class="memory-item">' +
          `<strong>${esc(item.topic)} (${esc(item.source_type)})</strong>` +
          `<small>${esc(item.summary)}</small>` +
          "</div>"
        );
      });

      renderList("revisionPlanList", data.revision_plan || [], (item) => {
        return (
          '<div class="memory-item">' +
          `<strong>${esc(item.topic)} - ${esc(item.when)}</strong>` +
          `<small>${esc(item.task)}</small>` +
          "</div>"
        );
      });

      renderList("securityAlertsList", data.alerts || [], (item) => {
        return (
          '<div class="memory-item">' +
          `<strong>${esc(item.event)}</strong>` +
          `<small>${esc(item.reason)} (${esc(item.time)})</small>` +
          "</div>"
        );
      });

      setIntegrityBadge(data.integrity || {});
    } catch (err) {
      if (isClosedSocketError(err)) return;
      console.error("Memory Twin refresh error:", err);
    }
  }

  function readFileAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = (error) => reject(error);
      reader.readAsDataURL(file);
    });
  }

  async function saveMemoryNote() {
    if (!isBackendReady()) {
      showBackendUnavailable("memory-save");
      return;
    }

    const topic = $("#memoryTopicInput").val().trim();
    const note = $("#memoryNoteInput").val().trim();
    const confidence = Number($("#memoryConfidenceInput").val() || 3);
    const duration = Number($("#memoryDurationInput").val() || 20);

    if (!note) {
      showConsoleFeed("Memory note empty hai. Pehle study points likho.");
      return;
    }

    try {
      const result = await window.eel.addMemoryTwinEntry(topic, note, "text", confidence, duration, 8)();
      showConsoleFeed((result && result.message) || "Memory entry save request sent.");
      $("#memoryNoteInput").val("");
      refreshMemoryTwinDashboard();
    } catch (err) {
      if (isClosedSocketError(err)) {
        showBackendUnavailable("memory-save");
        return;
      }
      console.error("Memory save error:", err);
      showConsoleFeed("Memory save me issue aaya.");
    }
  }

  async function uploadMemoryFile() {
    if (!isBackendReady()) {
      showBackendUnavailable("memory-upload");
      return;
    }

    const input = document.getElementById("memoryFileInput");
    if (!input || !input.files || !input.files.length) {
      showConsoleFeed("Upload ke liye file select karo.");
      return;
    }

    const file = input.files[0];
    if (file.size > 5 * 1024 * 1024) {
      showConsoleFeed("File size 5MB se kam rakho for smooth demo.");
      return;
    }

    const topic = $("#memoryTopicInput").val().trim();
    const confidence = Number($("#memoryConfidenceInput").val() || 3);
    const duration = Number($("#memoryDurationInput").val() || 20);

    try {
      const payload = await readFileAsDataURL(file);
      const result = await window.eel.ingestMemoryTwinUpload(file.name, payload, topic, confidence, 7, duration)();
      showConsoleFeed((result && result.message) || "Upload process initiated.");
      input.value = "";
      refreshMemoryTwinDashboard();
    } catch (err) {
      if (isClosedSocketError(err)) {
        showBackendUnavailable("memory-upload");
        return;
      }
      console.error("Memory upload error:", err);
      showConsoleFeed("File ingest failed.");
    }
  }

  async function verifyMemoryLedger() {
    if (!isBackendReady()) {
      showBackendUnavailable("memory-verify");
      return;
    }

    try {
      const result = await window.eel.verifyMemoryTwinIntegrity()();
      if (result && result.is_valid) {
        showConsoleFeed("Memory ledger verified. No tampering detected.");
      } else {
        const issueCount = (result && result.issues && result.issues.length) || 0;
        showConsoleFeed(`Integrity warning: ${issueCount} issue(s) found.`);
      }
      refreshMemoryTwinDashboard();
    } catch (err) {
      if (isClosedSocketError(err)) {
        showBackendUnavailable("memory-verify");
        return;
      }
      console.error("Integrity verify error:", err);
      showConsoleFeed("Integrity verify failed.");
    }
  }

  $("#memoryRefreshBtn").on("click", refreshMemoryTwinDashboard);
  $("#memorySaveBtn").on("click", saveMemoryNote);
  $("#memoryUploadBtn").on("click", uploadMemoryFile);
  $("#memoryVerifyBtn").on("click", verifyMemoryLedger);

  setTimeout(refreshMemoryTwinDashboard, 1200);
  setInterval(refreshMemoryTwinDashboard, 45000);

  // ================= THREAT ALERT POPUP =================
  let currentThreatFile = null;

  window.showThreatAlert = function(threatInfo) {
    currentThreatFile = threatInfo.file_path;
    
    const fileName = threatInfo.file_name || threatInfo.file_path?.split(/[\\/]/).pop() || "Unknown";
    const threatType = threatInfo.is_rat ? "RAT (Remote Access Trojan)" :
                       threatInfo.is_malware ? "MALWARE" :
                       threatInfo.risk_level?.toUpperCase() || "UNKNOWN";
    const riskScore = threatInfo.risk_score || threatInfo.threat?.risk_score || 0;
    const warnings = threatInfo.warnings || threatInfo.threat?.warnings || [];
    
    $("#threatFileName").text(fileName);
    $("#threatType").text(threatType);
    $("#threatScore").text(riskScore + "/100");
    
    if (threatInfo.file_path) {
      $("#threatPath").text(threatInfo.file_path);
      $("#threatPathRow").removeClass("hidden");
    } else {
      $("#threatPathRow").addClass("hidden");
    }
    
    if (warnings.length > 0) {
      const warningsHtml = warnings.slice(0, 5).map(w => `<div>• ${w}</div>`).join("");
      $("#threatWarnings").html(warningsHtml);
    } else {
      $("#threatWarnings").html("<div>No specific warnings available</div>");
    }
    
    $("#threatAlertModal").removeClass("hidden");
  };

  window.hideThreatAlert = function() {
    $("#threatAlertModal").addClass("hidden");
    currentThreatFile = null;
  };

  $("#threatCloseBtn").on("click", function() {
    hideThreatAlert();
  });

  $("#threatIgnoreBtn").on("click", function() {
    hideThreatAlert();
    showConsoleFeed("Threat ignored. Use with caution.");
  });

  $("#threatBlockBtn").on("click", async function() {
    if (!currentThreatFile) {
      hideThreatAlert();
      return;
    }
    
    if (!hasBackend()) {
      showBackendUnavailable("threat-block");
      return;
    }
    
    showConsoleFeed("File block kar raha hoon...");
    
    try {
      const result = await window.eel.handleThreatAction("block", currentThreatFile)();
      if (result.success) {
        showConsoleFeed(result.message || "File blocked successfully.");
        hideThreatAlert();
      } else {
        showConsoleFeed("Block failed: " + (result.error || "Unknown error"));
      }
    } catch (err) {
      if (isClosedSocketError(err)) {
        showBackendUnavailable("threat-block");
        return;
      }
      console.error("Block error:", err);
      showConsoleFeed("Block failed. Backend error.");
    }
  });

  $("#threatDeleteBtn").on("click", async function() {
    if (!currentThreatFile) {
      hideThreatAlert();
      return;
    }
    
    if (!hasBackend()) {
      showBackendUnavailable("threat-delete");
      return;
    }
    
    if (!confirm("Are you sure you want to DELETE this threat file?\n\n" + currentThreatFile)) {
      return;
    }
    
    showConsoleFeed("File delete kar raha hoon...");
    
    try {
      const result = await window.eel.handleThreatAction("delete", currentThreatFile)();
      if (result.success) {
        showConsoleFeed(result.message || "File deleted successfully.");
        hideThreatAlert();
      } else {
        showConsoleFeed("Delete failed: " + (result.error || "Unknown error"));
      }
    } catch (err) {
      if (isClosedSocketError(err)) {
        showBackendUnavailable("threat-delete");
        return;
      }
      console.error("Delete error:", err);
      showConsoleFeed("Delete failed. Backend error.");
    }
  });

  window.checkFileAndShowAlert = async function(filePath) {
    if (!hasBackend()) {
      showBackendUnavailable("file-check");
      return false;
    }
    
    try {
      const result = await window.eel.checkFileForThreat(filePath)();
      
      if (result.found && result.should_block) {
        const threatInfo = {
          file_path: filePath,
          file_name: result.file_name,
          is_rat: result.is_rat,
          is_malware: result.is_malware,
          risk_level: result.risk_level,
          risk_score: result.threat?.risk_score || 0,
          warnings: result.threat?.warnings || []
        };
        showThreatAlert(threatInfo);
        return true;
      }
      
      return false;
    } catch (err) {
      console.error("File check error:", err);
      return false;
    }
  };

  // ================= FOLDER MANAGER =================
  async function loadFolderList() {
    if (!hasBackend()) {
      showBackendUnavailable("folder-list");
      return;
    }
    
    try {
      const result = await window.eel.getScanFolders()();
      if (result.success && result.folders) {
        const folderList = $("#folderList");
        folderList.empty();
        
        result.folders.forEach(folder => {
          const folderItem = $("<div class='folder-item'>")
            .html(`
              <span class='folder-item-path'>${folder}</span>
              <button class='folder-item-remove' data-folder='${folder}'>
                <i class='bi bi-x-circle'>×
              </button>
            `);
          folderList.append(folderItem);
        });
        
        $(".folder-item-remove").on("click", async function() {
          const folderPath = $(this).data("folder");
          await removeFolderFromList(folderPath);
        });
      }
    } catch (err) {
      console.error("Load folders error:", err);
    }
  }

  async function addFolderToList(folderPath) {
    if (!hasBackend()) {
      showBackendUnavailable("folder-add");
      return;
    }
    
    if (!folderPath || folderPath.trim() === "") {
      showConsoleFeed("Folder path likho.");
      return;
    }
    
    showConsoleFeed("Folder add kar raha hoon...");
    
    try {
      const result = await window.eel.addScanFolder(folderPath.trim())();
      if (result.success) {
        showConsoleFeed(result.message || "Folder added successfully.");
        loadFolderList();
      } else {
        showConsoleFeed("Error: " + (result.error || "Failed to add folder."));
      }
    } catch (err) {
      if (isClosedSocketError(err)) {
        showBackendUnavailable("folder-add");
        return;
      }
      console.error("Add folder error:", err);
      showConsoleFeed("Backend error. Folder add nahi ho paya.");
    }
  }

  async function removeFolderFromList(folderPath) {
    if (!hasBackend()) {
      showBackendUnavailable("folder-remove");
      return;
    }
    
    try {
      const result = await window.eel.removeScanFolder(folderPath)();
      if (result.success) {
        showConsoleFeed(result.message || "Folder removed.");
        loadFolderList();
      } else {
        showConsoleFeed("Error: " + (result.error || "Failed to remove folder."));
      }
    } catch (err) {
      console.error("Remove folder error:", err);
    }
  }

  const $folderModal = $("#folderModal");

  $("#FolderBtn").on("click", function() {
    $folderModal.removeClass("hidden");
    loadFolderList();
  });

  $("#folderCloseBtn, #folderModalCloseBtn").on("click", function() {
    $folderModal.addClass("hidden");
  });

  $folderModal.on("click", function(e) {
    if (e.target === this) $folderModal.addClass("hidden");
  });

  $("#folderAddBtn").on("click", async function() {
    const folderPath = $("#folderInput").val();
    await addFolderToList(folderPath);
    $("#folderInput").val("");
  });

  $("#folderInput").on("keypress", function(e) {
    if (e.key === "Enter") {
      const folderPath = $(this).val();
      addFolderToList(folderPath);
      $(this).val("");
    }
  });
});

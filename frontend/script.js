function initCanvasScene() {
  const canvas = document.getElementById("canvasOne");
  const core = document.getElementById("robotCore");
  if (!canvas || !core) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  let size = 320;
  let center = size / 2;
  let particles = [];

  function buildParticles(nextSize) {
    const count = Math.max(54, Math.round(nextSize / 5));
    const minRadius = nextSize * 0.16;
    const maxRadius = nextSize * 0.41;

    return Array.from({ length: count }, (_, index) => ({
      angle: (Math.PI * 2 * index) / count,
      radius: minRadius + Math.random() * (maxRadius - minRadius),
      speed: 0.0018 + Math.random() * 0.0036,
      size: 1 + Math.random() * Math.max(1.6, nextSize * 0.006),
      alpha: 0.16 + Math.random() * 0.32,
      drift: 0.35 + Math.random() * 1.3,
    }));
  }

  function resizeScene() {
    size = Math.max(240, Math.round(Math.min(core.clientWidth, core.clientHeight) * 0.9));
    center = size / 2;
    canvas.width = size;
    canvas.height = size;
    particles = buildParticles(size);
  }

  resizeScene();
  window.addEventListener("resize", resizeScene);

  function draw(time) {
    ctx.clearRect(0, 0, size, size);

    particles.forEach((particle, index) => {
      particle.angle += particle.speed;

      const pulse = Math.sin(time * 0.0015 + index) * particle.drift;
      const x = center + Math.cos(particle.angle) * (particle.radius + pulse);
      const y = center + Math.sin(particle.angle * 1.05) * (particle.radius * 0.72 + pulse);

      ctx.beginPath();
      ctx.fillStyle = `rgba(68, 217, 255, ${particle.alpha})`;
      ctx.arc(x, y, particle.size, 0, Math.PI * 2);
      ctx.fill();
    });

    requestAnimationFrame(draw);
  }

  requestAnimationFrame(draw);
}

function initAvatarMotion() {
  const core = document.getElementById("robotCore");
  const avatar = document.getElementById("avatarHolo");
  if (!core || !avatar) return;

  let targetX = 0;
  let targetY = 0;
  let currentX = 0;
  let currentY = 0;

  core.addEventListener("pointermove", (event) => {
    const rect = core.getBoundingClientRect();
    const nx = (event.clientX - (rect.left + rect.width / 2)) / rect.width;
    const ny = (event.clientY - (rect.top + rect.height / 2)) / rect.height;

    targetX = nx * 10;
    targetY = ny * 10;
  });

  core.addEventListener("pointerleave", () => {
    targetX = 0;
    targetY = 0;
  });

  function animate(time) {
    const idleX = Math.sin(time * 0.0011) * 1.8;
    const idleY = Math.cos(time * 0.0014) * 1.4;

    currentX += (targetX - currentX) * 0.08;
    currentY += (targetY - currentY) * 0.08;

    avatar.style.setProperty("--drift-x", `${(currentX * 0.35 + idleX).toFixed(2)}px`);
    avatar.style.setProperty("--drift-y", `${(currentY * 0.35 + idleY).toFixed(2)}px`);
    avatar.style.setProperty("--tilt-x", `${(-currentX * 0.12).toFixed(2)}deg`);
    avatar.style.setProperty("--tilt-y", `${(currentY * 0.08).toFixed(2)}deg`);

    requestAnimationFrame(animate);
  }

  requestAnimationFrame(animate);
}

function initAvatarVideo() {
  const video = document.getElementById("avatarVideo");
  const imgCore = document.getElementById("imgCore");
  const shell = document.querySelector(".avatar-video-shell");
  if (!video || !imgCore || !shell) return;

  const videos = [video];
  const sourceTag = video.querySelector("source");
  const playbackState = {
    activeSpeechId: null,
    speechStartedAt: 0,
    revertTimer: null,
    baseSrc: (sourceTag && sourceTag.getAttribute("src")) || "./assets/avatar/zaris-avatar.mp4",
    currentSrc: "",
    usingExact: false,
  };

  video.muted = true;
  video.defaultMuted = true;
  video.loop = true;
  video.playsInline = true;

  const playVideo = (item) => {
    if (!item) return;
    const playPromise = item.play();
    if (playPromise && typeof playPromise.catch === "function") {
      playPromise.catch(() => {});
    }
  };

  const seekVideo = (item, seconds) => {
    if (!item || !Number.isFinite(seconds)) return;

    try {
      const safeMax = item.duration && Number.isFinite(item.duration)
        ? Math.max(0, item.duration - 0.06)
        : seconds;
      item.currentTime = Math.max(0, Math.min(seconds, safeMax));
    } catch (error) {
      // Ignore transient seek errors while metadata is still settling.
    }
  };

  const applySourceToVideo = (item, src, seekTo = 0) => {
    if (!item) return;

    const finalize = () => {
      seekVideo(item, seekTo);
      playVideo(item);
    };

    if (item.dataset.avatarSrc === src) {
      finalize();
      return;
    }

    let handled = false;
    const onReady = () => {
      if (handled) return;
      handled = true;
      finalize();
    };

    item.dataset.avatarSrc = src;
    item.addEventListener("loadedmetadata", onReady, { once: true });
    item.addEventListener("canplay", onReady, { once: true });
    item.src = src;
    item.load();
  };

  const applyAvatarSource = (src, options = {}) => {
    const { exact = false, seekTo = 0 } = options;
    const nextSrc = src || playbackState.baseSrc;

    playbackState.currentSrc = nextSrc;
    playbackState.usingExact = exact;

    shell.classList.toggle("avatar-exact-active", exact);
    imgCore.classList.toggle("avatar-exact-active", exact);

    videos.forEach((item) => applySourceToVideo(item, nextSrc, seekTo));
  };

  const tryPlay = () => {
    videos.forEach((item) => {
      playVideo(item);
    });
  };

  const markReady = () => {
    imgCore.classList.add("avatar-video-ready");
  };

  const markFallback = () => {
    imgCore.classList.remove("avatar-video-ready");
  };

  video.addEventListener("loadeddata", markReady);
  video.addEventListener("canplay", markReady);
  video.addEventListener("error", markFallback);

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") tryPlay();
  });

  window.addEventListener("pointerdown", tryPlay, { once: true });
  window.addEventListener("keydown", tryPlay, { once: true });

  window.startAvatarHybridSpeech = (text = "", meta = {}) => {
    if (playbackState.revertTimer) {
      clearTimeout(playbackState.revertTimer);
      playbackState.revertTimer = null;
    }

    playbackState.activeSpeechId = meta.speechId || null;
    playbackState.speechStartedAt = performance.now();
    playbackState.baseSrc = meta.baseVideoUrl || playbackState.baseSrc;

    applyAvatarSource(playbackState.baseSrc, { exact: false, seekTo: 0 });
  };

  window.stopAvatarHybridSpeech = (speechId) => {
    if (speechId && playbackState.activeSpeechId && speechId !== playbackState.activeSpeechId) {
      return;
    }

    playbackState.activeSpeechId = null;

    if (playbackState.revertTimer) {
      clearTimeout(playbackState.revertTimer);
    }

    playbackState.revertTimer = window.setTimeout(() => {
      applyAvatarSource(playbackState.baseSrc, { exact: false, seekTo: 0 });
      playbackState.revertTimer = null;
    }, 180);
  };

  window.handleExactAvatarReady = (speechId, videoUrl) => {
    if (!speechId || speechId !== playbackState.activeSpeechId) return;
    if (!videoUrl) return;

    const elapsed = Math.max(0, (performance.now() - playbackState.speechStartedAt) / 1000);
    applyAvatarSource(videoUrl, { exact: true, seekTo: elapsed });
  };

  applyAvatarSource(playbackState.baseSrc, { exact: false, seekTo: 0 });
  tryPlay();
}

window.addEventListener("load", () => {
  initCanvasScene();
  initAvatarMotion();
  initAvatarVideo();
});

window.showSystemMonitor = function() {
  const panel = document.getElementById('systemMonitorPanel');
  if (panel) {
    panel.classList.remove('hidden');
    refreshSystemStats();
  }
};

window.hideSystemMonitor = function() {
  const panel = document.getElementById('systemMonitorPanel');
  if (panel) {
    panel.classList.add('hidden');
  }
};

window.refreshSystemStats = async function() {
  try {
    const data = await window.eel.getSystemStats()();
    
    if (!data.success) {
      console.error('System stats error:', data.error);
      return;
    }

    const cpu = data.cpu.percent;
    const ram = data.ram;
    const drives = data.drives;
    const health = data.health;
    const processes = data.processes;

    document.getElementById('cpuBar').style.width = cpu + '%';
    document.getElementById('cpuValue').textContent = cpu.toFixed(1) + '%';
    
    document.getElementById('ramBar').style.width = ram.percent + '%';
    document.getElementById('ramValue').textContent = ram.percent.toFixed(1) + '%';
    
    if (drives && drives.length > 0) {
      const disk = drives[0];
      document.getElementById('diskBar').style.width = disk.percent + '%';
      document.getElementById('diskValue').textContent = disk.percent.toFixed(1) + '%';
    }

    document.getElementById('healthScore').textContent = health.overall_score.toFixed(0) + '/100';
    
    document.getElementById('ramUsed').textContent = ram.used_gb.toFixed(1) + ' GB';
    document.getElementById('ramTotal').textContent = ram.total_gb.toFixed(1) + ' GB';
    document.getElementById('ramAvailable').textContent = ram.available_gb.toFixed(1) + ' GB';

    let drivesHtml = '';
    for (const drive of drives) {
      const barColor = drive.percent > 90 ? '#f44336' : drive.percent > 70 ? '#ff9800' : '#44d9ff';
      drivesHtml += `<div class="list-item drive-item">
        <span class="drive-name">${drive.drive}</span>
        <span class="drive-size">${drive.used_gb.toFixed(1)}/${drive.total_gb.toFixed(1)} GB</span>
        <div class="mini-bar"><div style="width:${drive.percent}%;background:${barColor}"></div></div>
      </div>`;
    }
    document.getElementById('drivesList').innerHTML = drivesHtml;

    let procHtml = '';
    for (const proc of processes) {
      procHtml += `<div class="list-item process-item">
        <span class="proc-name">${proc.name}</span>
        <span class="proc-mem">${proc.memory_mb.toFixed(0)} MB</span>
      </div>`;
    }
    document.getElementById('processesList').innerHTML = procHtml;

    let warnHtml = '';
    if (health.warnings && health.warnings.length > 0) {
      for (const w of health.warnings) {
        warnHtml += `<div class="warning-item">${w}</div>`;
      }
    } else {
      warnHtml = '<div class="ok-item">All systems normal</div>';
    }
    document.getElementById('warningsList').innerHTML = warnHtml;

  } catch (e) {
    console.error('Failed to get system stats:', e);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const closeBtn = document.getElementById('monitorCloseBtn');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => window.hideSystemMonitor());
  }
  
  const refreshBtn = document.getElementById('monitorRefreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => window.refreshSystemStats());
  }
});

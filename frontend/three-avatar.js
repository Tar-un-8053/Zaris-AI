(function () {
  function initThreeAvatar() {
    const container = document.getElementById("threeAvatarLayer");
    const core = document.getElementById("robotCore");

    if (!container || !core || !window.THREE) return;
    if (container.dataset.initialized === "true") return;

    const THREE = window.THREE;

    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({
        alpha: true,
        antialias: true,
        powerPreference: "high-performance",
      });
    } catch (error) {
      console.warn("Three avatar could not start:", error);
      return;
    }

    container.dataset.initialized = "true";
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    if ("outputColorSpace" in renderer && THREE.SRGBColorSpace) {
      renderer.outputColorSpace = THREE.SRGBColorSpace;
    }

    const canvas = renderer.domElement;
    canvas.className = "three-avatar-canvas";
    container.appendChild(canvas);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 100);
    camera.position.set(0, 0, 5.35);

    const stage = new THREE.Group();
    scene.add(stage);

    const haloGroup = new THREE.Group();
    const latticeGroup = new THREE.Group();
    const particleGroup = new THREE.Group();
    stage.add(haloGroup);
    stage.add(latticeGroup);
    stage.add(particleGroup);

    const states = {
      idle: {
        primary: new THREE.Color(0x67ebff),
        secondary: new THREE.Color(0x296fff),
        particles: new THREE.Color(0x9af7ff),
        speed: 1,
        shellOpacity: 0.18,
        knotOpacity: 0.26,
        ringOpacity: 0.18,
        particleOpacity: 0.58,
      },
      listening: {
        primary: new THREE.Color(0x93f6ff),
        secondary: new THREE.Color(0x26c7ff),
        particles: new THREE.Color(0xcfffff),
        speed: 1.45,
        shellOpacity: 0.24,
        knotOpacity: 0.34,
        ringOpacity: 0.24,
        particleOpacity: 0.76,
      },
      speaking: {
        primary: new THREE.Color(0x9bffd6),
        secondary: new THREE.Color(0x00f0b5),
        particles: new THREE.Color(0xdffff2),
        speed: 2.1,
        shellOpacity: 0.3,
        knotOpacity: 0.42,
        ringOpacity: 0.3,
        particleOpacity: 0.86,
      },
    };

    const shellMaterial = new THREE.MeshBasicMaterial({
      color: states.idle.primary.clone(),
      wireframe: true,
      transparent: true,
      opacity: states.idle.shellOpacity,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const knotMaterial = new THREE.MeshBasicMaterial({
      color: states.idle.secondary.clone(),
      wireframe: true,
      transparent: true,
      opacity: states.idle.knotOpacity,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const ringMaterialA = new THREE.MeshBasicMaterial({
      color: states.idle.primary.clone(),
      transparent: true,
      opacity: states.idle.ringOpacity,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const ringMaterialB = new THREE.MeshBasicMaterial({
      color: states.idle.secondary.clone(),
      transparent: true,
      opacity: states.idle.ringOpacity * 0.9,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const ringMaterialC = new THREE.MeshBasicMaterial({
      color: states.idle.primary.clone(),
      transparent: true,
      opacity: states.idle.ringOpacity * 0.72,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const diskMaterial = new THREE.MeshBasicMaterial({
      color: states.idle.primary.clone(),
      transparent: true,
      opacity: 0.1,
      side: THREE.DoubleSide,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });

    const outerShell = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1.04, 1),
      shellMaterial
    );
    outerShell.rotation.set(0.55, 0.2, -0.25);
    latticeGroup.add(outerShell);

    const coreKnot = new THREE.Mesh(
      new THREE.TorusKnotGeometry(0.66, 0.15, 180, 22),
      knotMaterial
    );
    latticeGroup.add(coreKnot);

    const outerRing = new THREE.Mesh(
      new THREE.TorusGeometry(1.44, 0.026, 12, 164),
      ringMaterialA
    );
    outerRing.rotation.set(0.3, 0, 0);
    haloGroup.add(outerRing);

    const midRing = new THREE.Mesh(
      new THREE.TorusGeometry(1.14, 0.024, 10, 148),
      ringMaterialB
    );
    midRing.rotation.set(1.05, 0.24, 0.5);
    haloGroup.add(midRing);

    const innerRing = new THREE.Mesh(
      new THREE.TorusGeometry(0.92, 0.022, 10, 132),
      ringMaterialC
    );
    innerRing.rotation.set(0.2, 1.05, 0.3);
    haloGroup.add(innerRing);

    const scanDisk = new THREE.Mesh(
      new THREE.RingGeometry(0.86, 1.72, 96),
      diskMaterial
    );
    scanDisk.rotation.set(Math.PI / 2.7, 0, 0);
    scanDisk.position.y = -0.15;
    stage.add(scanDisk);

    const particleCount = 720;
    const positions = new Float32Array(particleCount * 3);
    for (let index = 0; index < particleCount; index += 1) {
      const radius = 1.15 + Math.random() * 1.35;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);

      positions[index * 3] = radius * Math.sin(phi) * Math.cos(theta);
      positions[index * 3 + 1] = radius * Math.cos(phi) * 0.82;
      positions[index * 3 + 2] = radius * Math.sin(phi) * Math.sin(theta);
    }

    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute(
      "position",
      new THREE.BufferAttribute(positions, 3)
    );

    const particleMaterial = new THREE.PointsMaterial({
      color: states.idle.particles.clone(),
      size: 0.028,
      transparent: true,
      opacity: states.idle.particleOpacity,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      sizeAttenuation: true,
    });

    const particleCloud = new THREE.Points(particleGeometry, particleMaterial);
    particleGroup.add(particleCloud);

    const rimLight = new THREE.PointLight(0x76f0ff, 2.2, 8);
    rimLight.position.set(1.8, 1.6, 2.8);
    scene.add(rimLight);

    const fillLight = new THREE.PointLight(0x1f69ff, 1.2, 7);
    fillLight.position.set(-2.1, -1.2, 2.4);
    scene.add(fillLight);

    const currentPrimary = states.idle.primary.clone();
    const currentSecondary = states.idle.secondary.clone();
    const currentParticles = states.idle.particles.clone();

    let activeState = "idle";
    let currentSpeed = states.idle.speed;

    const pointer = {
      targetX: 0,
      targetY: 0,
      currentX: 0,
      currentY: 0,
    };

    function resizeRenderer() {
      const width = Math.max(container.clientWidth, 1);
      const height = Math.max(container.clientHeight, 1);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    }

    function syncState() {
      if (core.classList.contains("speaking")) {
        activeState = "speaking";
        return;
      }
      if (core.classList.contains("listening")) {
        activeState = "listening";
        return;
      }
      activeState = "idle";
    }

    core.addEventListener("pointermove", (event) => {
      const rect = core.getBoundingClientRect();
      pointer.targetX =
        ((event.clientX - (rect.left + rect.width / 2)) / rect.width) * 0.72;
      pointer.targetY =
        ((event.clientY - (rect.top + rect.height / 2)) / rect.height) * 0.48;
    });

    core.addEventListener("pointerleave", () => {
      pointer.targetX = 0;
      pointer.targetY = 0;
    });

    const classObserver = new MutationObserver(syncState);
    classObserver.observe(core, { attributes: true, attributeFilter: ["class"] });

    if (typeof ResizeObserver !== "undefined") {
      const resizeObserver = new ResizeObserver(resizeRenderer);
      resizeObserver.observe(container);
    }

    window.addEventListener("resize", resizeRenderer);
    resizeRenderer();
    syncState();

    container.classList.add("three-avatar-ready");

    function animateFrame(time) {
      const seconds = time * 0.001;
      const target = states[activeState];

      currentPrimary.lerp(target.primary, 0.055);
      currentSecondary.lerp(target.secondary, 0.055);
      currentParticles.lerp(target.particles, 0.055);
      currentSpeed += (target.speed - currentSpeed) * 0.045;

      shellMaterial.color.copy(currentPrimary);
      knotMaterial.color.copy(currentSecondary);
      ringMaterialA.color.copy(currentPrimary);
      ringMaterialB.color.copy(currentSecondary);
      ringMaterialC.color.copy(currentPrimary).lerp(currentSecondary, 0.28);
      diskMaterial.color.copy(currentPrimary);
      particleMaterial.color.copy(currentParticles);

      shellMaterial.opacity +=
        (target.shellOpacity - shellMaterial.opacity) * 0.06;
      knotMaterial.opacity +=
        (target.knotOpacity - knotMaterial.opacity) * 0.06;
      ringMaterialA.opacity +=
        (target.ringOpacity - ringMaterialA.opacity) * 0.06;
      ringMaterialB.opacity +=
        (target.ringOpacity * 0.9 - ringMaterialB.opacity) * 0.06;
      ringMaterialC.opacity +=
        (target.ringOpacity * 0.72 - ringMaterialC.opacity) * 0.06;
      particleMaterial.opacity +=
        (target.particleOpacity - particleMaterial.opacity) * 0.06;
      diskMaterial.opacity +=
        (target.ringOpacity * 0.5 - diskMaterial.opacity) * 0.06;

      pointer.currentX += (pointer.targetX - pointer.currentX) * 0.04;
      pointer.currentY += (pointer.targetY - pointer.currentY) * 0.04;

      const pulse =
        1 + Math.sin(seconds * (1.15 + currentSpeed * 0.18)) * 0.045;
      const knotPulse =
        1 + Math.sin(seconds * (1.8 + currentSpeed * 0.26) + 0.6) * 0.06;

      stage.position.x = pointer.currentX * 0.42;
      stage.position.y = -0.06 - pointer.currentY * 0.32;
      stage.rotation.x = -0.22 + pointer.currentY * 0.34;
      stage.rotation.z = pointer.currentX * 0.16;
      stage.rotation.y += 0.0024 * currentSpeed;

      outerShell.rotation.x += 0.0022 * currentSpeed;
      outerShell.rotation.y -= 0.0018 * currentSpeed;
      outerShell.scale.setScalar(0.98 * pulse);

      coreKnot.rotation.x += 0.0056 * currentSpeed;
      coreKnot.rotation.y += 0.0048 * currentSpeed;
      coreKnot.scale.setScalar(knotPulse);

      outerRing.rotation.z += 0.0042 * currentSpeed;
      midRing.rotation.x += 0.0052 * currentSpeed;
      midRing.rotation.z -= 0.0026 * currentSpeed;
      innerRing.rotation.y -= 0.0038 * currentSpeed;
      scanDisk.rotation.z += 0.0028 * currentSpeed;

      particleCloud.rotation.y += 0.0009 * currentSpeed;
      particleCloud.rotation.x = Math.sin(seconds * 0.4) * 0.16;

      rimLight.color.copy(currentPrimary);
      fillLight.color.copy(currentSecondary);
      rimLight.intensity +=
        ((activeState === "speaking" ? 3.2 : 2.2) - rimLight.intensity) * 0.05;
      fillLight.intensity +=
        ((activeState === "speaking" ? 1.8 : 1.2) - fillLight.intensity) * 0.05;

      camera.position.x =
        Math.sin(seconds * 0.32) * 0.14 + pointer.currentX * 0.14;
      camera.position.y =
        Math.cos(seconds * 0.24) * 0.12 + pointer.currentY * 0.1;
      camera.lookAt(0, 0, 0);

      renderer.render(scene, camera);
      window.requestAnimationFrame(animateFrame);
    }

    window.requestAnimationFrame(animateFrame);
  }

  window.addEventListener("load", initThreeAvatar);
})();

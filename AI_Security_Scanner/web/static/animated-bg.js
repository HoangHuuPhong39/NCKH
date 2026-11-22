/**
 * Persistent AnimatedBackground Controller
 * - Mounted ONCE at the root app shell (#animated-background) outside tab/route views.
 * - Controls the full-screen 3D Cyber Circuit Board video (#bg-cyber-video) + canvas circuit pulses (#bg-particles-canvas).
 * - Respects prefers-reduced-motion: reduce (pauses video & stops animation loop).
 * - Pauses automatically when browser tab is hidden (visibilitychange) to save CPU/GPU.
 */
(function () {
  'use strict';

  function initAnimatedBackground() {
    const root = document.getElementById('animated-background');
    const video = document.getElementById('bg-cyber-video');
    const canvas = document.getElementById('bg-particles-canvas');
    if (!root) return;

    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    let isReducedMotion = reducedMotionQuery.matches;
    let isTabHidden = document.hidden;
    let videoReady = false;

    function syncVideoPlayback() {
      if (!video) return;
      if (isReducedMotion || isTabHidden) {
        try {
          video.pause();
        } catch (e) {}
      } else {
        const playPromise = video.play();
        if (playPromise && typeof playPromise.catch === 'function') {
          playPromise.catch(() => {
            videoReady = false;
          });
        }
      }
    }

    if (video) {
      video.muted = true;
      video.playsInline = true;
      video.addEventListener('playing', () => {
        videoReady = true;
      });
      video.addEventListener('error', () => {
        videoReady = false;
      });
      syncVideoPlayback();
    }

    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let dpr = 1;
    let rafId = null;
    let lastFrameTime = 0;
    const FRAME_INTERVAL = 1000 / 60; // Cap at ~60fps

    // 3D Perspective Circuit Traces (fallback & subtle complement to the 3D circuit video)
    const traces = [];
    const TRACE_COUNT = 26;

    function createTrace(randomY) {
      // Normalized lane from -1 (far left) to +1 (far right)
      const lane = (Math.random() - 0.5) * 2.2;
      const z = randomY ? Math.random() : 0.02 + Math.random() * 0.15;
      return {
        lane: lane,
        z: z, // 0 = horizon (top), 1 = foreground (bottom)
        speed: 0.0012 + Math.random() * 0.0018,
        length: 0.05 + Math.random() * 0.09,
        jogAt: 0.3 + Math.random() * 0.4,
        jogDir: (Math.random() > 0.5 ? 1 : -1) * (0.06 + Math.random() * 0.10),
        alpha: 0.25 + Math.random() * 0.45,
        width: 1.0 + Math.random() * 1.4
      };
    }

    function initTraces() {
      traces.length = 0;
      for (let i = 0; i < TRACE_COUNT; i++) {
        traces.push(createTrace(true));
      }
    }

    function resizeCanvas() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (traces.length === 0) initTraces();
      if (isReducedMotion) renderFrame(0, false);
    }

    function project3D(lane, z) {
      // Horizon sits near the top (y = 8% of height), expanding in perspective toward bottom
      const horizonY = height * 0.06;
      const clampedZ = Math.max(0.01, z);
      const perspective = Math.pow(clampedZ, 1.45);
      const y = horizonY + perspective * (height * 0.98);
      const spread = width * (0.14 + perspective * 0.78);
      const x = width * 0.5 + lane * spread;
      return { x, y, scale: 0.4 + perspective * 1.2 };
    }

    function renderFrame(timestamp, advance) {
      ctx.clearRect(0, 0, width, height);

      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      // When video is actively playing in dark mode, keep canvas overlay very subtle so the video is the star
      const opacityScale = (videoReady && !isLight) ? 0.28 : 0.85;
      const strokeRgb = isLight ? '2, 132, 199' : '14, 165, 233';
      const headRgb = isLight ? '14, 165, 233' : '56, 189, 248';

      for (let i = 0; i < traces.length; i++) {
        const t = traces[i];
        if (advance) {
          t.z += t.speed;
          if (t.z - t.length > 1.05) {
            traces[i] = createTrace(false);
            continue;
          }
        }

        const zHead = Math.min(1.08, t.z);
        const zTail = Math.max(0.02, t.z - t.length);
        if (zHead <= zTail) continue;

        const zMid = (zHead + zTail) * 0.5;
        const laneTail = t.lane;
        const laneHead = zHead > t.jogAt ? t.lane + t.jogDir : t.lane;

        const pTail = project3D(laneTail, zTail);
        const pMid = project3D(laneTail, zMid);
        const pHead = project3D(laneHead, zHead);

        const alpha = t.alpha * opacityScale * Math.min(1, zHead * 2.2) * Math.max(0.15, 1 - Math.max(0, zTail - 0.85) * 4);

        ctx.beginPath();
        ctx.moveTo(pTail.x, pTail.y);
        ctx.lineTo(pMid.x, pMid.y);
        ctx.lineTo(pHead.x, pHead.y);
        ctx.strokeStyle = `rgba(${strokeRgb}, ${alpha.toFixed(3)})`;
        ctx.lineWidth = t.width * pHead.scale * 0.65;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.stroke();

        // Glowing node at head of circuit trace
        ctx.beginPath();
        ctx.arc(pHead.x, pHead.y, Math.max(1.2, 1.8 * pHead.scale * 0.55), 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${headRgb}, ${Math.min(0.95, alpha * 1.6).toFixed(3)})`;
        ctx.fill();
      }
    }

    function loop(timestamp) {
      if (isTabHidden || isReducedMotion) {
        rafId = null;
        return;
      }
      if (timestamp - lastFrameTime >= FRAME_INTERVAL) {
        lastFrameTime = timestamp;
        renderFrame(timestamp, true);
      }
      rafId = window.requestAnimationFrame(loop);
    }

    function startLoop() {
      if (isReducedMotion || isTabHidden) {
        root.classList.add('is-paused');
        syncVideoPlayback();
        if (rafId) {
          window.cancelAnimationFrame(rafId);
          rafId = null;
        }
        renderFrame(0, false);
        return;
      }
      root.classList.remove('is-paused');
      syncVideoPlayback();
      if (!rafId) {
        lastFrameTime = performance.now();
        rafId = window.requestAnimationFrame(loop);
      }
    }

    function stopLoop() {
      root.classList.add('is-paused');
      syncVideoPlayback();
      if (rafId) {
        window.cancelAnimationFrame(rafId);
        rafId = null;
      }
    }

    resizeCanvas();
    startLoop();

    let resizeTimer = null;
    window.addEventListener('resize', () => {
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(resizeCanvas, 120);
    }, { passive: true });

    document.addEventListener('visibilitychange', () => {
      isTabHidden = document.hidden;
      if (isTabHidden) {
        stopLoop();
      } else {
        startLoop();
      }
    });

    const onMotionChange = (e) => {
      isReducedMotion = e.matches;
      if (isReducedMotion) {
        stopLoop();
        renderFrame(0, false);
      } else {
        startLoop();
      }
    };

    if (typeof reducedMotionQuery.addEventListener === 'function') {
      reducedMotionQuery.addEventListener('change', onMotionChange);
    } else if (typeof reducedMotionQuery.addListener === 'function') {
      reducedMotionQuery.addListener(onMotionChange);
    }

    // Re-render smoothly when theme attribute changes without resetting video or traces
    const themeObserver = new MutationObserver(() => {
      if (isReducedMotion || isTabHidden) {
        renderFrame(0, false);
      }
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme']
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAnimatedBackground, { once: true });
  } else {
    initAnimatedBackground();
  }
})();

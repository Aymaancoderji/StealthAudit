/**
 * StealthAudit Client SDK v1.0.0
 * Lightweight, non-blocking in-browser telemetry & bot detection agent.
 */
(function (global) {
  'use strict';

  if (global.StealthAudit) {
    return;
  }

  const DEFAULT_ENDPOINT = '/v1/telemetry';
  let cachedToken = null;
  let cachedAssessment = null;
  let inFlightPromise = null;
  let isInitialized = false;

  const config = {
    endpoint: DEFAULT_ENDPOINT,
    autoProtectForms: true,
    hiddenFieldName: '_stealthaudit_token',
    onReady: null,
    onBlock: null,
    onChallenge: null,
  };

  // Behavioral Dynamics Collector
  const behavioral = {
    mousePoints: [],
    keyEvents: [],
    scrollEvents: 0,
    hasUntrustedEvents: false,
    syntheticDetected: false,
  };

  function initBehavioralTracking() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;

    const onMouseMove = (e) => {
      if (e.isTrusted === false) behavioral.hasUntrustedEvents = true;
      if (behavioral.mousePoints.length < 60) {
        behavioral.mousePoints.push({
          x: e.clientX,
          y: e.clientY,
          t: performance.now(),
        });
      }
    };

    const onKeyDown = (e) => {
      if (e.isTrusted === false) behavioral.hasUntrustedEvents = true;
      if (behavioral.keyEvents.length < 50) {
        behavioral.keyEvents.push({
          type: 'down',
          key: e.key,
          t: performance.now(),
        });
      }
    };

    const onKeyUp = (e) => {
      if (e.isTrusted === false) behavioral.hasUntrustedEvents = true;
      if (behavioral.keyEvents.length < 50) {
        behavioral.keyEvents.push({
          type: 'up',
          key: e.key,
          t: performance.now(),
        });
      }
    };

    const onScroll = (e) => {
      if (e.isTrusted === false) behavioral.hasUntrustedEvents = true;
      behavioral.scrollEvents++;
    };

    const onPointer = (e) => {
      if (e.isTrusted === false) {
        behavioral.hasUntrustedEvents = true;
        behavioral.syntheticDetected = true;
      }
    };

    try {
      window.addEventListener('mousemove', onMouseMove, { passive: true });
      window.addEventListener('keydown', onKeyDown, { passive: true });
      window.addEventListener('keyup', onKeyUp, { passive: true });
      window.addEventListener('scroll', onScroll, { passive: true });
      window.addEventListener('pointerdown', onPointer, { passive: true });
      window.addEventListener('click', onPointer, { passive: true });
    } catch (err) {}
  }

  initBehavioralTracking();

  function getBehavioralMetrics() {
    const pts = behavioral.mousePoints;
    let straightLineRatio = 0;
    let trajectoryVariance = 0;

    if (pts.length >= 2) {
      let totalDistance = 0;
      const speeds = [];
      for (let i = 1; i < pts.length; i++) {
        const dx = pts[i].x - pts[i - 1].x;
        const dy = pts[i].y - pts[i - 1].y;
        const dt = Math.max(1, pts[i].t - pts[i - 1].t);
        const dist = Math.sqrt(dx * dx + dy * dy);
        totalDistance += dist;
        speeds.push(dist / dt);
      }
      const netDx = pts[pts.length - 1].x - pts[0].x;
      const netDy = pts[pts.length - 1].y - pts[0].y;
      const netDistance = Math.sqrt(netDx * netDx + netDy * netDy);
      if (totalDistance > 0) {
        straightLineRatio = Number((netDistance / totalDistance).toFixed(4));
      }
      if (speeds.length > 1) {
        const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
        const sumSq = speeds.reduce((acc, s) => acc + Math.pow(s - avgSpeed, 2), 0);
        trajectoryVariance = Number((sumSq / speeds.length).toFixed(4));
      }
    }

    const keyFlightTimes = [];
    const keys = behavioral.keyEvents.filter((k) => k.type === 'down');
    for (let i = 1; i < keys.length; i++) {
      keyFlightTimes.push(keys[i].t - keys[i - 1].t);
    }
    let keyFlightVariance = 0;
    if (keyFlightTimes.length > 1) {
      const avg = keyFlightTimes.reduce((a, b) => a + b, 0) / keyFlightTimes.length;
      const sumSq = keyFlightTimes.reduce((acc, k) => acc + Math.pow(k - avg, 2), 0);
      keyFlightVariance = Number((sumSq / keyFlightTimes.length).toFixed(4));
    }

    return {
      mouseMovementCount: pts.length,
      mouseTrajectoryVariance: trajectoryVariance,
      mouseStraightLineRatio: straightLineRatio,
      keyStrokeCount: keys.length,
      keyFlightVariance: keyFlightVariance,
      scrollEventCount: behavioral.scrollEvents,
      hasUntrustedEvents: behavioral.hasUntrustedEvents,
      syntheticEventDetected: behavioral.syntheticDetected,
    };
  }

  // Dynamic Proof-of-Work Challenge Solver
  async function solveProofOfWork(challenge) {
    if (!challenge || !challenge.prefix || !challenge.difficulty) {
      return null;
    }
    const { id, prefix, difficulty } = challenge;
    const target = '0'.repeat(difficulty);

    if (typeof Worker !== 'undefined' && typeof Blob !== 'undefined') {
      try {
        const workerScript = [
          'self.onmessage = async function(e) {',
          '  const { prefix, difficulty, target, maxIter } = e.data;',
          '  const enc = new TextEncoder();',
          '  for (let i = 0; i < maxIter; i++) {',
          '    const nonce = String(i);',
          '    const data = enc.encode(prefix + nonce);',
          '    const buf = await crypto.subtle.digest("SHA-256", data);',
          '    const arr = new Uint8Array(buf);',
          '    let hex = "";',
          '    for (let j = 0; j < Math.ceil(difficulty / 2); j++) {',
          '      hex += arr[j].toString(16).padStart(2, "0");',
          '    }',
          '    if (hex.startsWith(target)) {',
          '      self.postMessage({ nonce: nonce, found: true });',
          '      return;',
          '    }',
          '  }',
          '  self.postMessage({ found: false });',
          '};',
        ].join('\\n');

        const blob = new Blob([workerScript], { type: 'application/javascript' });
        const workerUrl = URL.createObjectURL(blob);
        const worker = new Worker(workerUrl);

        const sol = await new Promise((resolve) => {
          const timeout = setTimeout(() => {
            try { worker.terminate(); } catch (e) {}
            try { URL.revokeObjectURL(workerUrl); } catch (e) {}
            resolve(null);
          }, 5000);

          worker.onmessage = (e) => {
            clearTimeout(timeout);
            try { worker.terminate(); } catch (e) {}
            try { URL.revokeObjectURL(workerUrl); } catch (e) {}
            if (e.data && e.data.found) {
              resolve({ id: id, nonce: e.data.nonce });
            } else {
              resolve(null);
            }
          };
          worker.postMessage({ prefix: prefix, difficulty: difficulty, target: target, maxIter: 1000000 });
        });

        if (sol) return sol;
      } catch (err) {}
    }

    // Main thread fallback
    const enc = new TextEncoder();
    for (let i = 0; i < 500000; i++) {
      const nonce = String(i);
      const data = enc.encode(prefix + nonce);
      const buf = await crypto.subtle.digest('SHA-256', data);
      const arr = new Uint8Array(buf);
      let hex = '';
      for (let j = 0; j < Math.ceil(difficulty / 2); j++) {
        hex += arr[j].toString(16).padStart(2, '0');
      }
      if (hex.startsWith(target)) {
        return { id: id, nonce: nonce };
      }
    }
    return null;
  }

  async function sha256Hex(input) {
    try {
      const bytes = new TextEncoder().encode(input);
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    } catch (e) {
      return '';
    }
  }

  async function canvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 240;
      canvas.height = 60;
      const ctx = canvas.getContext('2d');
      if (!ctx) return null;
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 100, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('StealthAudit Client 1234 ,.!', 2, 15);
      ctx.strokeStyle = 'rgba(120,20,180,0.7)';
      ctx.beginPath();
      ctx.arc(60, 30, 20, 0, Math.PI * 2);
      ctx.stroke();
      const hash = await sha256Hex(canvas.toDataURL());
      return { hash };
    } catch (e) {
      return null;
    }
  }

  function webglFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = gl.getParameter(gl.VENDOR) || '';
      const renderer = gl.getParameter(gl.RENDERER) || '';
      const unmaskedVendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '';
      const unmaskedRenderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';
      const supportedExtensions = gl.getSupportedExtensions() || [];

      const shaderPrecision = {};
      const probes = [
        ['vertexHighFloat', gl.VERTEX_SHADER, gl.HIGH_FLOAT],
        ['vertexMediumFloat', gl.VERTEX_SHADER, gl.MEDIUM_FLOAT],
        ['fragmentHighFloat', gl.FRAGMENT_SHADER, gl.HIGH_FLOAT],
        ['fragmentMediumFloat', gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT],
      ];
      for (const [label, shaderType, precisionType] of probes) {
        const p = gl.getShaderPrecisionFormat(shaderType, precisionType);
        shaderPrecision[label] = p ? `range[${p.rangeMin},${p.rangeMax}] precision:${p.precision}` : '';
      }

      let webgl2Supported = false;
      try {
        const gl2 = canvas.getContext('webgl2');
        webgl2Supported = !!gl2;
      } catch (e) {}

      let webgpuSupported = false;
      try {
        webgpuSupported = typeof navigator !== 'undefined' && 'gpu' in navigator && !!navigator.gpu;
      } catch (e) {}

      return {
        vendor: String(vendor),
        renderer: String(renderer),
        unmaskedVendor: String(unmaskedVendor || ''),
        unmaskedRenderer: String(unmaskedRenderer || ''),
        supportedExtensions,
        shaderPrecision,
        webgl2Supported,
        webgpuSupported,
      };
    } catch (e) {
      return null;
    }
  }

  async function audioFingerprint() {
    try {
      const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!OfflineCtx) return null;

      const context = new OfflineCtx(1, 44100, 44100);
      const oscillator = context.createOscillator();
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;
      const compressor = context.createDynamicsCompressor();
      oscillator.connect(compressor);
      compressor.connect(context.destination);
      oscillator.start(0);

      const buffer = await context.startRendering();
      const data = buffer.getChannelData(0);
      let sum = 0;
      for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);

      const hash = await sha256Hex(sum.toString());
      return { hash };
    } catch (e) {
      return null;
    }
  }

  function scanAutomationArtifacts() {
    const knownNames = new Set([
      '__webdriver_evaluate', '__selenium_evaluate', '__webdriver_script_function',
      '__webdriver_script_func', '__webdriver_script_fn', '__fxdriver_evaluate',
      '__driver_unwrapped', '__webdriver_unwrapped', '__driver_evaluate',
      '__selenium_unwrapped', '__fxdriver_unwrapped', '__selenium_ide_recorder',
      'callselenium', '_selenium', '__nightmare', '__phantomas', 'callphantom',
      '_phantom', 'domautomation', 'domautomationcontroller',
      '__puppeteer_evaluation_script__', '__playwright_evaluation_script__',
    ]);
    const found = new Set();
    try {
      for (const name of Object.getOwnPropertyNames(window)) {
        const lower = name.toLowerCase();
        if (knownNames.has(lower) || /^\$?cdc_/i.test(name)) {
          found.add(name);
        }
      }
    } catch (e) {}
    try {
      for (const name of Object.getOwnPropertyNames(document)) {
        if (/^\$?cdc_/i.test(name)) found.add('document.' + name);
      }
    } catch (e) {}
    return Array.from(found);
  }

  function chromeObjectShape() {
    const present = !!window.chrome;
    return {
      loadTimes: present && typeof window.chrome.loadTimes === 'function',
      csi: present && typeof window.chrome.csi === 'function',
      app: present && typeof window.chrome.app === 'object' && window.chrome.app !== null,
    };
  }

  function webdriverDescriptorAnomaly() {
    try {
      const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      if ('webdriver' in navigator && !desc) return true;
      if (desc && desc.value !== undefined && typeof desc.get !== 'function') return true;
      return false;
    } catch (e) {
      return false;
    }
  }

  async function detectCDPRuntimeDomain() {
    try {
      let triggered = false;
      const probe = {};
      Object.defineProperty(probe, 'stealthaudit_probe', {
        enumerable: true,
        get() {
          triggered = true;
          return 0;
        },
      });
      console.debug(probe);
      await new Promise((resolve) => setTimeout(resolve, 25));
      return triggered;
    } catch (e) {
      return false;
    }
  }

  function testToStringIntegrity() {
    try {
      const fnToString = Function.prototype.toString;
      const s1 = fnToString.call(fnToString);
      const s2 = fnToString.call(fnToString.toString);
      const name = fnToString.name;
      const length = fnToString.length;

      const toStringOfToStringOk =
        s1.includes('[native code]') &&
        s2.includes('[native code]') &&
        s1.includes('toString') &&
        name === 'toString' &&
        length === 0;

      let descriptorAnomaly = false;
      const desc = Object.getOwnPropertyDescriptor(Function.prototype, 'toString');
      if (!desc || desc.enumerable !== false || desc.writable !== true || desc.configurable !== true) {
        descriptorAnomaly = true;
      }

      return { toStringOfToStringOk, descriptorAnomaly };
    } catch (e) {
      return { toStringOfToStringOk: false, descriptorAnomaly: true };
    }
  }

  function inspectErrorStack() {
    try {
      const err = new Error('stealthaudit_stack_probe');
      const stack = err.stack || '';
      const patterns = [
        '__puppeteer_evaluation_script__',
        '__playwright_evaluation_script__',
        'pptr:',
        'playwright/',
        'selenium-webdriver',
        'execute_async_script',
        'callphantom',
      ];
      const artifacts = [];
      const lower = stack.toLowerCase();
      for (const p of patterns) {
        if (lower.includes(p.toLowerCase())) {
          artifacts.push(p);
        }
      }
      if (/\$?cdc_[a-z0-9]+/i.test(stack)) {
        artifacts.push('cdc_stack_frame');
      }
      return {
        leak: artifacts.length > 0,
        artifacts,
      };
    } catch (e) {
      return { leak: false, artifacts: [] };
    }
  }

  // testProxyTraps detects if core browser objects or their prototypes are wrapped in Proxy
  function testProxyTraps() {
    try {
      if (typeof Proxy === 'undefined') return false;
      const targets = [navigator, screen];
      for (const t of targets) {
        try {
          const str = Object.prototype.toString.call(t);
          if (!str.startsWith('[object ')) {
            return true;
          }
        } catch (e) {
          return true;
        }
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  // testNativeGetters validates that prototype getters enforce native receiver checks
  function testNativeGetters() {
    try {
      if (typeof Navigator === 'undefined' || !Navigator.prototype) return false;
      const props = ['webdriver', 'plugins', 'languages', 'cookieEnabled'];
      for (const prop of props) {
        const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
        if (desc && typeof desc.get === 'function') {
          try {
            desc.get.call({});
            return true;
          } catch (err) {
            if (!(err instanceof TypeError)) {
              return true;
            }
          }
        }
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  async function workerProbe(windowUA, windowPlatform, windowConcurrency, windowWebdriver) {
    try {
      if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') {
        return { workerExecutionOk: false };
      }
      const workerCode = 'self.onmessage=function(){self.postMessage({userAgent:navigator.userAgent||\'\',platform:navigator.platform||\'\',hardwareConcurrency:navigator.hardwareConcurrency||0,webdriver:!!navigator.webdriver,deviceMemory:navigator.deviceMemory||0});};';
      const blob = new Blob([workerCode], { type: 'application/javascript' });
      const blobUrl = URL.createObjectURL(blob);
      const worker = new Worker(blobUrl);

      const result = await new Promise((resolve) => {
        const timer = setTimeout(() => {
          try { worker.terminate(); } catch (e) {}
          try { URL.revokeObjectURL(blobUrl); } catch (e) {}
          resolve(null);
        }, 500);

        worker.onmessage = (e) => {
          clearTimeout(timer);
          try { worker.terminate(); } catch (e) {}
          try { URL.revokeObjectURL(blobUrl); } catch (e) {}
          resolve(e.data);
        };

        worker.onerror = () => {
          clearTimeout(timer);
          try { worker.terminate(); } catch (e) {}
          try { URL.revokeObjectURL(blobUrl); } catch (e) {}
          resolve(null);
        };

        worker.postMessage('audit');
      });

      if (!result) {
        return { workerExecutionOk: false };
      }

      const workerWebdriverLeak = !!result.webdriver && !windowWebdriver;
      const workerUserAgentMismatch = !!(windowUA && result.userAgent && result.userAgent !== windowUA);
      const workerConcurrencyMismatch = !!(windowConcurrency > 0 && result.hardwareConcurrency > 0 && result.hardwareConcurrency !== windowConcurrency);
      const workerPlatformMismatch = !!(windowPlatform && result.platform && result.platform !== windowPlatform);

      return {
        workerExecutionOk: true,
        workerWebdriverLeak,
        workerUserAgentMismatch,
        workerConcurrencyMismatch,
        workerPlatformMismatch,
        workerUserAgent: result.userAgent || '',
        workerPlatform: result.platform || '',
      };
    } catch (e) {
      return { workerExecutionOk: false };
    }
  }

  async function runtimeFingerprint() {
    try {
      const webdriverFlag = !!navigator.webdriver;
      const functionToStringOk = Function.prototype.toString
        .call(Function.prototype.toString)
        .includes('[native code]');
      const hasChromeRuntime = !!(window.chrome && window.chrome.runtime);

      let permissionsAnomaly = false;
      try {
        if (navigator.permissions && navigator.permissions.query && typeof Notification !== 'undefined') {
          const status = await navigator.permissions.query({ name: 'notifications' });
          permissionsAnomaly = Notification.permission === 'denied' && status.state === 'prompt';
        }
      } catch (e) {}

      const workerSupport = typeof Worker !== 'undefined';
      const automationArtifacts = scanAutomationArtifacts();
      const chromeShape = chromeObjectShape();
      const webdriverDescriptorAnomalyFlag = webdriverDescriptorAnomaly();
      const cdpRuntimeDomainSuspected = await detectCDPRuntimeDomain();

      const toStringIntegrity = testToStringIntegrity();
      const stackInspection = inspectErrorStack();
      const workerResult = await workerProbe(
        navigator.userAgent || '',
        navigator.platform || '',
        navigator.hardwareConcurrency || 0,
        webdriverFlag
      );

      return {
        webdriverFlag,
        functionToStringOk,
        hasChromeRuntime,
        permissionsAnomaly,
        workerSupport,
        automationArtifacts,
        chromeLoadTimesPresent: chromeShape.loadTimes,
        chromeCsiPresent: chromeShape.csi,
        chromeAppPresent: chromeShape.app,
        webdriverDescriptorAnomaly: webdriverDescriptorAnomalyFlag,
        cdpRuntimeDomainSuspected,
        toStringOfToStringOk: toStringIntegrity.toStringOfToStringOk,
        toStringDescriptorAnomaly: toStringIntegrity.descriptorAnomaly,
        errorStackAutomationLeak: stackInspection.leak,
        errorStackArtifacts: stackInspection.artifacts,
        workerExecutionOk: !!workerResult.workerExecutionOk,
        workerWebdriverLeak: !!workerResult.workerWebdriverLeak,
        workerUserAgentMismatch: !!workerResult.workerUserAgentMismatch,
        workerConcurrencyMismatch: !!workerResult.workerConcurrencyMismatch,
        workerPlatformMismatch: !!workerResult.workerPlatformMismatch,
        workerUserAgent: workerResult.workerUserAgent || '',
        workerPlatform: workerResult.workerPlatform || '',
        proxyTrapDetected: testProxyTraps(),
        nativeGetterTampered: testNativeGetters(),
      };
    } catch (e) {
      return null;
    }
  }

  function enumerateFonts() {
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const candidates = [
      'Arial', 'Arial Black', 'Calibri', 'Cambria', 'Comic Sans MS',
      'Consolas', 'Courier New', 'Georgia', 'Helvetica', 'Impact',
      'Segoe UI', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana',
    ];

    const span = document.createElement('span');
    span.style.position = 'absolute';
    span.style.left = '-9999px';
    span.style.top = '-9999px';
    span.style.fontSize = testSize;
    span.textContent = testString;
    document.body.appendChild(span);

    const baseSizes = {};
    for (const base of baseFonts) {
      span.style.fontFamily = base;
      baseSizes[base] = { width: span.offsetWidth, height: span.offsetHeight };
    }

    const detected = [];
    for (const font of candidates) {
      let isDetected = false;
      for (const base of baseFonts) {
        span.style.fontFamily = `'${font}', ${base}`;
        const size = baseSizes[base];
        if (span.offsetWidth !== size.width || span.offsetHeight !== size.height) {
          isDetected = true;
          break;
        }
      }
      if (isDetected) detected.push(font);
    }

    document.body.removeChild(span);
    return detected;
  }

  async function deviceFingerprint() {
    try {
      let fonts = [];
      try {
        if (document.body) fonts = enumerateFonts();
      } catch (e) {}

      let mediaDeviceCount = 0;
      try {
        if (navigator.mediaDevices && typeof navigator.mediaDevices.enumerateDevices === 'function') {
          const devs = await navigator.mediaDevices.enumerateDevices();
          mediaDeviceCount = devs ? devs.length : 0;
        }
      } catch (e) {}

      let speechVoiceCount = 0;
      try {
        if (typeof window !== 'undefined' && window.speechSynthesis) {
          speechVoiceCount = window.speechSynthesis.getVoices().length;
        }
      } catch (e) {}

      let userAgentData = null;
      try {
        if (navigator.userAgentData) {
          const uad = navigator.userAgentData;
          let highEntropy = {};
          if (typeof uad.getHighEntropyValues === 'function') {
            try {
              highEntropy = await uad.getHighEntropyValues([
                'architecture',
                'bitness',
                'model',
                'platform',
                'platformVersion',
              ]);
            } catch (e) {}
          }
          userAgentData = {
            mobile: !!uad.mobile,
            platform: uad.platform || highEntropy.platform || '',
            architecture: highEntropy.architecture || '',
            bitness: highEntropy.bitness || '',
            model: highEntropy.model || '',
            platformVersion: highEntropy.platformVersion || '',
            brands: Array.isArray(uad.brands)
              ? uad.brands.map((b) => ({ brand: String(b.brand), version: String(b.version) }))
              : [],
          };
        }
      } catch (e) {}

      return {
        screenWidth: screen.width || 0,
        screenHeight: screen.height || 0,
        colorDepth: screen.colorDepth || 0,
        deviceMemory: navigator.deviceMemory || 0,
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        touchPoints: navigator.maxTouchPoints || 0,
        fonts,
        outerWidth: window.outerWidth || 0,
        outerHeight: window.outerHeight || 0,
        innerWidth: window.innerWidth || 0,
        innerHeight: window.innerHeight || 0,
        screenX: window.screenX !== undefined ? window.screenX : 0,
        screenY: window.screenY !== undefined ? window.screenY : 0,
        devicePixelRatio: window.devicePixelRatio || 1,
        mediaDeviceCount,
        speechVoiceCount,
        userAgentData,
      };
    } catch (e) {
      return null;
    }
  }

  async function collectFingerprint() {
    const [canvas, audio, runtime, device] = await Promise.all([
      canvasFingerprint(),
      audioFingerprint(),
      runtimeFingerprint(),
      deviceFingerprint(),
    ]);

    return {
      schemaVersion: '0.5.0',
      userAgent: navigator.userAgent || '',
      canvas,
      webgl: webglFingerprint(),
      audio,
      runtime,
      device,
      behavioral: getBehavioralMetrics(),
    };
  }

  async function sendTelemetry() {
    const fp = await collectFingerprint();
    const res = await fetch(config.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ fingerprint: fp }),
    });

    if (!res.ok) {
      throw new Error(`StealthAudit telemetry submission failed: ${res.status}`);
    }

    let data = await res.json();

    // If server issued a Proof-of-Work challenge, solve it silently in background!
    if (data.decision === 'challenge' && data.challenge) {
      if (typeof config.onChallenge === 'function') {
        config.onChallenge(data.challenge);
      }
      const solution = await solveProofOfWork(data.challenge);
      if (solution) {
        const solveRes = await fetch(config.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            fingerprint: fp,
            challenge: data.challenge,
            challengeSolution: solution,
          }),
        });
        if (solveRes.ok) {
          const solvedData = await solveRes.json();
          if (solvedData.token) {
            data = solvedData;
          }
        }
      }
    }

    cachedToken = data.token;
    cachedAssessment = data;

    // Attach to forms if configured
    if (config.autoProtectForms) {
      attachToForms(cachedToken);
    }

    if (typeof config.onReady === 'function') {
      config.onReady(data);
    }

    // Trigger custom window event
    try {
      const event = new CustomEvent('stealthaudit:ready', { detail: data });
      window.dispatchEvent(event);
    } catch (e) {}

    return cachedToken;
  }

  function attachToForms(token) {
    try {
      const forms = document.querySelectorAll('form');
      forms.forEach((form) => {
        let input = form.querySelector(`input[name="${config.hiddenFieldName}"]`);
        if (!input) {
          input = document.createElement('input');
          input.type = 'hidden';
          input.name = config.hiddenFieldName;
          form.appendChild(input);
        }
        input.value = token;
      });
    } catch (e) {}
  }

  // Public API
  const StealthAudit = {
    init: function (options) {
      if (options) {
        Object.assign(config, options);
      }
      isInitialized = true;
      this.execute();
      return this;
    },

    execute: function () {
      if (!inFlightPromise) {
        inFlightPromise = new Promise((resolve, reject) => {
          const run = () => {
            sendTelemetry()
              .then(resolve)
              .catch((err) => {
                inFlightPromise = null;
                reject(err);
              });
          };

          if ('requestIdleCallback' in window) {
            window.requestIdleCallback(run);
          } else {
            setTimeout(run, 0);
          }
        });
      }
      return inFlightPromise;
    },

    getToken: async function () {
      if (cachedToken) {
        return cachedToken;
      }
      return this.execute();
    },

    getAssessment: async function () {
      if (cachedAssessment) {
        return cachedAssessment;
      }
      await this.execute();
      return cachedAssessment;
    },

    getBehavioral: function () {
      return getBehavioralMetrics();
    },

    solveChallenge: async function (challenge) {
      return solveProofOfWork(challenge);
    },

    protectForm: function (form) {
      const el = typeof form === 'string' ? document.querySelector(form) : form;
      if (!el) return;
      if (cachedToken) {
        let input = el.querySelector(`input[name="${config.hiddenFieldName}"]`);
        if (!input) {
          input = document.createElement('input');
          input.type = 'hidden';
          input.name = config.hiddenFieldName;
          el.appendChild(input);
        }
        input.value = cachedToken;
      } else {
        this.getToken().then((token) => {
          this.protectForm(el);
        });
      }
    },

    renderBadge: function (containerSelector) {
      const el = typeof containerSelector === 'string' ? document.querySelector(containerSelector) : containerSelector;
      if (!el) return;
      el.innerHTML = `
        <div style="font-family:system-ui,-apple-system,sans-serif;font-size:12px;color:#6b7280;display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:6px;background:#f3f4f6;border:1px solid #e5e7eb;">
          <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;"></span>
          Protected by <strong>StealthAudit</strong>
        </div>
      `;
    },
  };

  global.StealthAudit = StealthAudit;

  // Auto-run if script was loaded with data-auto-run
  const currentScript = document.currentScript;
  if (currentScript) {
    const autoRun = currentScript.getAttribute('data-auto-run');
    const endpoint = currentScript.getAttribute('data-endpoint');
    if (endpoint) config.endpoint = endpoint;
    if (autoRun !== 'false') {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => StealthAudit.execute());
      } else {
        StealthAudit.execute();
      }
    }
  }
})(typeof window !== 'undefined' ? window : this);

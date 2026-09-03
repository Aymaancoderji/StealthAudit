// Standardized fingerprint audit script. Evaluated as a single expression
// in the target page (see pkg/collector/js_collector.go), returning a JSON
// object matching the Fingerprint struct in pkg/collector/collector.go.
//
// Hashes use SHA-256 via the native SubtleCrypto API rather than a
// hand-rolled MD5 implementation, since browsers don't expose MD5 natively
// and uniqueness (not cryptographic strength) is all that's needed here.
(async () => {
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
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 100, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('StealthAudit fingerprint 1234 ,.!', 2, 15);
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

      return {
        vendor: String(vendor),
        renderer: String(renderer),
        unmaskedVendor: String(unmaskedVendor || ''),
        unmaskedRenderer: String(unmaskedRenderer || ''),
        supportedExtensions,
        shaderPrecision,
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

  // scanAutomationArtifacts looks for global properties that WebDriver
  // implementations (ChromeDriver, Selenium, old PhantomJS, and various
  // automation shims) leave behind on window/document. Finding any of
  // these is an unambiguous automation signal — real browsers never
  // define them.
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
    } catch (e) {
      // ignore
    }
    try {
      for (const name of Object.getOwnPropertyNames(document)) {
        if (/^\$?cdc_/i.test(name)) found.add('document.' + name);
      }
    } catch (e) {
      // ignore
    }
    return Array.from(found);
  }

  // chromeObjectShape checks whether window.chrome, when present, has the
  // full shape a genuine Chrome runtime exposes (loadTimes/csi/app).
  // Stealth plugins that reconstruct window.chrome to hide headless mode
  // commonly ship an incomplete shim missing one or more of these.
  function chromeObjectShape() {
    const present = !!window.chrome;
    return {
      loadTimes: present && typeof window.chrome.loadTimes === 'function',
      csi: present && typeof window.chrome.csi === 'function',
      app: present && typeof window.chrome.app === 'object' && window.chrome.app !== null,
    };
  }

  // webdriverDescriptorAnomaly checks navigator.webdriver's property
  // descriptor rather than just its value. Stealth patches often delete
  // or replace the native getter on Navigator.prototype with a plain
  // value (or an own-property shadow), which is itself a tell distinct
  // from the webdriver flag's value.
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

  // detectCDPRuntimeDomain is a best-effort check for the DevTools
  // Protocol's Runtime domain being enabled, which Puppeteer and
  // Playwright both do by default to receive console output. When it's
  // active, logging an object generates a remote object preview that
  // reads the object's own enumerable properties (including getters)
  // even though nothing in the page itself ever accessed them. Not
  // 100% reliable across engine versions, so it's scored lower than the
  // artifact/descriptor checks above.
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
      await new Promise((resolve) => setTimeout(resolve, 30));
      return triggered;
    } catch (e) {
      return false;
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
          // Known headless-Chrome tell: Notification.permission reports
          // "denied" while the Permissions API still reports "prompt".
          permissionsAnomaly = Notification.permission === 'denied' && status.state === 'prompt';
        }
      } catch (e) {
        // ignore; leave permissionsAnomaly false
      }

      const workerSupport = typeof Worker !== 'undefined';

      const automationArtifacts = scanAutomationArtifacts();
      const chromeShape = chromeObjectShape();
      const webdriverDescriptorAnomalyFlag = webdriverDescriptorAnomaly();
      const cdpRuntimeDomainSuspected = await detectCDPRuntimeDomain();

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
      'Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria', 'Comic Sans MS',
      'Consolas', 'Courier New', 'Georgia', 'Helvetica', 'Impact', 'Lucida Console',
      'Lucida Sans Unicode', 'Microsoft Sans Serif', 'Palatino Linotype', 'Segoe Print',
      'Segoe Script', 'Segoe UI', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana',
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

  function deviceFingerprint() {
    try {
      let fonts = [];
      try {
        fonts = enumerateFonts();
      } catch (e) {
        fonts = [];
      }
      return {
        screenWidth: screen.width || 0,
        screenHeight: screen.height || 0,
        colorDepth: screen.colorDepth || 0,
        deviceMemory: navigator.deviceMemory || 0,
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        touchPoints: navigator.maxTouchPoints || 0,
        fonts,
      };
    } catch (e) {
      return null;
    }
  }

  const [canvas, audio, runtime] = await Promise.all([
    canvasFingerprint(),
    audioFingerprint(),
    runtimeFingerprint(),
  ]);

  return {
    schemaVersion: '0.3.0',
    userAgent: navigator.userAgent || '',
    canvas,
    webgl: webglFingerprint(),
    audio,
    runtime,
    device: deviceFingerprint(),
  };
})()

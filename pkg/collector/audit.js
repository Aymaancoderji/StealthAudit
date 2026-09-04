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

  // testToStringIntegrity validates Function.prototype.toString's
  // internal behavior, name, length, and property descriptor.
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

  // inspectErrorStack inspects new Error().stack for internal automation
  // runner evaluation traces or test framework artifacts.
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

  // workerProbe spawns an inline Web Worker via Blob to cross-validate
  // window-level telemetry against an isolated worker context.
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

  async function deviceFingerprint() {
    try {
      let fonts = [];
      try {
        fonts = enumerateFonts();
      } catch (e) {
        fonts = [];
      }

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

  const [canvas, audio, runtime, device] = await Promise.all([
    canvasFingerprint(),
    audioFingerprint(),
    runtimeFingerprint(),
    deviceFingerprint(),
  ]);

  return {
    schemaVersion: '0.4.0',
    userAgent: navigator.userAgent || '',
    canvas,
    webgl: webglFingerprint(),
    audio,
    runtime,
    device,
  };
})()

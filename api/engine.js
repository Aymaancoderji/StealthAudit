// Shared analysis engine, ML classifier, token signer, and challenge manager
const crypto = require('crypto');

const SECRET_KEY = Buffer.from(process.env.STEALTHAUDIT_SECRET_KEY || 'stealthaudit-secret-key-vercel-production-2026', 'utf-8');

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function computeVisitorID(fp) {
  if (!fp) return sha256Hex('unknown');
  const parts = [fp.userAgent || ''];
  if (fp.webgl) {
    parts.push(fp.webgl.unmaskedVendor || '', fp.webgl.unmaskedRenderer || '');
  }
  if (fp.canvas) {
    parts.push(fp.canvas.hash || '');
  }
  if (fp.audio) {
    parts.push(fp.audio.hash || '');
  }
  if (fp.device) {
    parts.push(
      String(fp.device.screenWidth ?? ''),
      String(fp.device.screenHeight ?? ''),
      String(fp.device.colorDepth ?? ''),
      String(fp.device.hardwareConcurrency ?? ''),
      String(fp.device.deviceMemory ?? ''),
      (fp.device.fonts || []).join(',')
    );
  }
  return sha256Hex(parts.join('|'));
}

const softwareRendererPatterns = [
  /swiftshader/i,
  /llvmpipe/i,
  /software rasterizer/i,
  /apple software renderer/i,
  /mesa.*(?:softpipe|llvmpipe)/i,
];

function isSoftwareRenderer(renderer) {
  if (!renderer) return false;
  return softwareRendererPatterns.some((p) => p.test(renderer));
}

function clientHintsPlatformMatches(ua, platform) {
  if (!platform || !ua) return true;
  const uaLower = ua.toLowerCase();
  const platLower = platform.toLowerCase();
  switch (platLower) {
    case 'windows':
      return uaLower.includes('windows');
    case 'macos':
    case 'mac os x':
      return uaLower.includes('macintosh') || uaLower.includes('mac os x');
    case 'linux':
      return uaLower.includes('linux') && !uaLower.includes('android');
    case 'android':
      return uaLower.includes('android');
    default:
      return true;
  }
}

function detectBrowserFamily(ua) {
  if (!ua) return 'unknown';
  const u = ua.toLowerCase();
  if (u.includes('firefox') && !u.includes('seamonkey')) return 'gecko';
  if (u.includes('safari') && !u.includes('chrome') && !u.includes('chromium') && !u.includes('android')) return 'webkit';
  if (u.includes('chrome') || u.includes('chromium') || u.includes('edg/')) return 'chromium';
  return 'unknown';
}

function scoreFingerprint(fp, netCapture, leakFindings) {
  const deductions = {
    js_runtime_integrity: 0,
    hardware_consistency: 0,
    tls_network_alignment: 0,
    session_isolation: 0,
  };
  const flags = [];

  const add = (category, code, severity, description) => {
    flags.push({ category, code, severity, description });
    deductions[category] += severity * 10.0;
  };

  const family = fp ? detectBrowserFamily(fp.userAgent) : 'unknown';

  if (fp && fp.runtime) {
    const rt = fp.runtime;
    if (rt.webdriverFlag) {
      add('js_runtime_integrity', 'webdriver_flag_true', 5, 'navigator.webdriver is true, an unambiguous automation signal real browsers never expose');
    }
    if (rt.functionToStringOk === false) {
      add('js_runtime_integrity', 'function_tostring_tampered', 4, 'Function.prototype.toString has been overridden, indicating an attempt to hide patched native functions');
    }
    if (rt.permissionsAnomaly) {
      add('js_runtime_integrity', 'permissions_api_anomaly', 3, 'Notification.permission and the Permissions API disagree, a known headless Chrome tell');
    }
    if (rt.workerSupport === false) {
      add('js_runtime_integrity', 'worker_unsupported', 2, 'Web Worker support is unexpectedly unavailable');
    }
    if (rt.automationArtifacts && rt.automationArtifacts.length > 0) {
      add('js_runtime_integrity', 'automation_artifacts_detected', 5, `WebDriver/automation-framework artifacts found on window/document (${rt.automationArtifacts.join(', ')})`);
    }
    if (rt.webdriverDescriptorAnomaly) {
      add('js_runtime_integrity', 'webdriver_descriptor_anomaly', 4, "navigator.webdriver's property descriptor doesn't match a native browser implementation");
    }
    if (rt.cdpRuntimeDomainSuspected) {
      add('js_runtime_integrity', 'cdp_runtime_domain_suspected', 3, 'Chrome DevTools Protocol Runtime domain preview signal detected via console timing');
    }
    if (rt.hasChromeRuntime && family === 'chromium' && (!rt.chromeLoadTimesPresent || !rt.chromeCsiPresent)) {
      add('js_runtime_integrity', 'chrome_object_shape_incomplete', 3, 'window.chrome is present but missing loadTimes/csi, consistent with partial stealth shims');
    }
    if (family === 'chromium' && !rt.hasChromeRuntime) {
      add('js_runtime_integrity', 'chrome_object_missing', 3, 'User-Agent claims Chromium but window.chrome.runtime is absent');
    }
    if (rt.workerWebdriverLeak) {
      add('js_runtime_integrity', 'worker_webdriver_leak', 5, 'navigator.webdriver is true in an isolated Web Worker despite being masked on window');
    }
    if (rt.workerUserAgentMismatch || rt.workerConcurrencyMismatch || rt.workerPlatformMismatch) {
      add('js_runtime_integrity', 'worker_environment_mismatch', 4, `Web Worker environment signals contradict window scope`);
    }
    if (rt.errorStackAutomationLeak) {
      add('js_runtime_integrity', 'error_stack_automation_leak', 5, `Error stack trace exposed automation runner frames or evaluation scripts (${(rt.errorStackArtifacts || []).join(', ')})`);
    }
    if (rt.toStringDescriptorAnomaly || rt.toStringOfToStringOk === false) {
      add('js_runtime_integrity', 'function_tostring_deep_tamper', 4, 'Function.prototype.toString failed deep integrity or descriptor checks');
    }
    if (rt.proxyTrapDetected) {
      add('js_runtime_integrity', 'proxy_trap_detected', 5, 'Core browser objects (navigator/screen) were detected to be wrapped in a JavaScript Proxy shim');
    }
    if (rt.nativeGetterTampered) {
      add('js_runtime_integrity', 'native_getter_tampered', 4, 'Native prototype getter invocation with an invalid receiver did not throw native engine TypeError');
    }
  }

  if (fp && fp.behavioral) {
    const beh = fp.behavioral;
    if (beh.hasUntrustedEvents || beh.syntheticEventDetected) {
      add('js_runtime_integrity', 'untrusted_synthetic_events', 5, 'Synthetic or untrusted DOM events (isTrusted=false) detected during interaction');
    }
    if (beh.mouseMovementCount > 5 && beh.mouseStraightLineRatio > 0.95) {
      add('js_runtime_integrity', 'linear_mouse_trajectory', 3, `Mouse movement trajectory is unnaturally straight (ratio=${beh.mouseStraightLineRatio.toFixed(2)})`);
    }
    if (beh.keyStrokeCount >= 4 && beh.keyFlightVariance < 2.0) {
      add('js_runtime_integrity', 'mechanical_keystroke_timing', 3, `Keystroke flight time variance is unnaturally low (variance=${beh.keyFlightVariance.toFixed(2)} ms)`);
    }
  }

  if (fp && fp.webgl) {
    if (isSoftwareRenderer(fp.webgl.unmaskedRenderer)) {
      add('hardware_consistency', 'software_gpu_renderer', 5, `WebGL reports a software rasterizer (${fp.webgl.unmaskedRenderer}) instead of real GPU hardware`);
    }
    if (family !== 'unknown' && fp.webgl.webgl2Supported === false) {
      add('hardware_consistency', 'webgl2_unsupported', 2, 'WebGL2 context unavailable on modern browser engine');
    }
  }

  if (fp && fp.canvas && !fp.canvas.hash) {
    add('hardware_consistency', 'canvas_fingerprint_blocked', 3, 'Canvas rendering produced no usable output');
  }
  if (fp && fp.audio && !fp.audio.hash) {
    add('hardware_consistency', 'audio_fingerprint_blocked', 3, 'Web Audio rendering produced no usable output');
  }

  if (fp && fp.device) {
    const dev = fp.device;
    if (dev.hardwareConcurrency <= 1) {
      add('hardware_consistency', 'low_core_count', 2, `hardwareConcurrency of ${dev.hardwareConcurrency} is unusually low`);
    }
    if ((dev.fonts || []).length < 3) {
      add('hardware_consistency', 'minimal_font_set', 2, `Only ${(dev.fonts || []).length} system fonts detected`);
    }
    if (family === 'chromium' && dev.deviceMemory === 0) {
      add('hardware_consistency', 'device_memory_missing_on_chromium', 2, 'Chrome always implements navigator.deviceMemory; value 0 suggests stripped runtime');
    }
    if ((dev.outerWidth === 0 && dev.outerHeight === 0) || (dev.outerWidth > 0 && dev.innerWidth > dev.outerWidth)) {
      add('hardware_consistency', 'headless_screen_geometry', 4, `Window geometry reports outer dimensions ${dev.outerWidth}x${dev.outerHeight}`);
    }
    if (dev.userAgentData && !clientHintsPlatformMatches(fp.userAgent, dev.userAgentData.platform)) {
      add('hardware_consistency', 'client_hints_platform_mismatch', 4, `navigator.userAgentData.platform (${dev.userAgentData.platform}) contradicts User-Agent`);
    }
    if (family === 'chromium' && dev.speechVoiceCount === 0 && fp.userAgent && (/windows/i.test(fp.userAgent) || /macintosh/i.test(fp.userAgent))) {
      add('hardware_consistency', 'speech_voices_empty', 2, 'Desktop Chromium reports 0 SpeechSynthesis voices');
    }
  }

  if (netCapture) {
    if (!netCapture.http2) {
      if (family !== 'unknown') {
        add('tls_network_alignment', 'http2_not_negotiated', 3, 'Browser did not negotiate HTTP/2 over TLS');
      }
    }
  }

  if (leakFindings && Array.isArray(leakFindings)) {
    for (const f of leakFindings) {
      if (f.leaked) {
        add('session_isolation', `leak_${f.kind}`, 4, f.detail || 'State leaked between isolated sessions');
      }
    }
  }

  const categoryScores = {};
  let total = 0;
  for (const cat of ['js_runtime_integrity', 'hardware_consistency', 'tls_network_alignment', 'session_isolation']) {
    let score = 100.0 - (deductions[cat] || 0);
    if (score < 0) score = 0;
    categoryScores[cat] = score;
    total += score;
  }

  return {
    stealthScore: total / 4,
    categoryScores,
    flags,
  };
}

const FeatureNames = [
  'webdriver_flag',
  'function_tostring_tampered',
  'permissions_api_anomaly',
  'missing_chrome_runtime',
  'worker_unsupported',
  'software_gpu_renderer',
  'canvas_fingerprint_blocked',
  'audio_fingerprint_blocked',
  'hardware_concurrency_norm',
  'font_count_norm',
  'device_memory_missing',
  'tls_ja3_missing',
  'http2_not_negotiated',
  'automation_artifacts_detected',
  'worker_context_leak',
  'error_stack_automation_leak',
  'headless_screen_geometry',
  'client_hints_platform_mismatch',
];

const Weights = [
  2.7489, 0.4858, 1.1101, 0.8172, 0.2208, 2.1468, 0.5642, 0.5067, -2.1014, -2.8281, 0.8848, 0.8708, 0.6217, 0.8757, 1.3449, 1.0286, 1.6515, 0.8999,
];

const Bias = -1.4007;

function b01(val) {
  return val ? 1 : 0;
}

function clip01(x) {
  if (x < 0) return 0;
  if (x > 1) return 1;
  return x;
}

function extractFeatureVector(fp, net) {
  const f = new Array(FeatureNames.length).fill(0);
  if (!fp) return f;

  if (fp.runtime) {
    const rt = fp.runtime;
    f[0] = b01(rt.webdriverFlag);
    f[1] = b01(!rt.functionToStringOk || rt.toStringOfToStringOk === false || rt.toStringDescriptorAnomaly);
    f[2] = b01(rt.permissionsAnomaly);
    f[3] = b01(!rt.hasChromeRuntime);
    f[4] = b01(rt.workerSupport === false);
    f[13] = b01(rt.automationArtifacts && rt.automationArtifacts.length > 0);
    f[14] = b01(rt.workerWebdriverLeak || rt.workerUserAgentMismatch || rt.workerPlatformMismatch);
    f[15] = b01(rt.errorStackAutomationLeak);
  }

  if (fp.webgl) {
    f[5] = b01(isSoftwareRenderer(fp.webgl.unmaskedRenderer));
  }

  f[6] = b01(!fp.canvas || !fp.canvas.hash);
  f[7] = b01(!fp.audio || !fp.audio.hash);

  if (fp.device) {
    const dev = fp.device;
    f[8] = clip01((dev.hardwareConcurrency || 1) / 16.0);
    f[9] = clip01(((dev.fonts || []).length) / 30.0);
    f[10] = b01(dev.deviceMemory === 0);
    f[16] = b01((dev.outerWidth === 0 && dev.outerHeight === 0) || (dev.outerWidth > 0 && dev.innerWidth > dev.outerWidth));
    f[17] = b01(dev.userAgentData && !clientHintsPlatformMatches(fp.userAgent, dev.userAgentData.platform));
  }

  f[11] = b01(!net || !net.tls || !net.tls.ja3);
  f[12] = b01(!net || !net.http2);

  return f;
}

function classifyFingerprint(fp, net) {
  const f = extractFeatureVector(fp, net);
  let dot = 0;
  const contributions = [];

  for (let i = 0; i < FeatureNames.length; i++) {
    const impact = f[i] * Weights[i];
    dot += impact;
    contributions.push({
      feature: FeatureNames[i],
      value: f[i],
      weight: Weights[i],
      impact: impact,
    });
  }

  const z = dot + Bias;
  const prob = 1 / (1 + Math.exp(-z));
  let verdict = 'uncertain';
  if (prob >= 0.65) verdict = 'likely_automated';
  else if (prob <= 0.35) verdict = 'likely_genuine';

  contributions.sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));

  return {
    probability: prob,
    verdict,
    contributions,
  };
}

function issueToken(claims, secretKey = SECRET_KEY) {
  const header = { alg: 'HS256', typ: 'SAT' };
  if (!claims.nonce) {
    claims.nonce = crypto.randomBytes(16).toString('hex');
  }
  const b64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
  const b64Claims = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const payload = `${b64Header}.${b64Claims}`;
  const sig = crypto.createHmac('sha256', secretKey).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(tokenStr, secretKey = SECRET_KEY) {
  if (!tokenStr || typeof tokenStr !== 'string') throw new Error('Token missing or invalid');
  const parts = tokenStr.split('.');
  if (parts.length !== 3) throw new Error('Invalid token structure');
  const [b64Header, b64Claims, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', secretKey).update(`${b64Header}.${b64Claims}`).digest('base64url');
  if (sig !== expectedSig) throw new Error('Signature mismatch');

  const claims = JSON.parse(Buffer.from(b64Claims, 'base64url').toString('utf-8'));
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && claims.exp < now) throw new Error('Token has expired');
  return claims;
}

function createChallenge(difficulty = 3, secretKey = SECRET_KEY) {
  const id = crypto.randomBytes(16).toString('hex');
  const prefix = crypto.randomBytes(16).toString('hex');
  const expiresAt = Math.floor(Date.now() / 1000) + 60;
  const payload = `${id}:${prefix}:${difficulty}:${expiresAt}`;
  const sig = crypto.createHmac('sha256', secretKey).update(payload).digest('hex');

  return {
    id,
    algorithm: 'sha256-hashcash',
    prefix,
    difficulty,
    expiresAt,
    signature: sig,
  };
}

function verifyChallengeSolution(challenge, solution, secretKey = SECRET_KEY) {
  if (!challenge || !solution || !solution.nonce) return false;
  if (challenge.expiresAt < Math.floor(Date.now() / 1000)) return false;

  const payload = `${challenge.id}:${challenge.prefix}:${challenge.difficulty}:${challenge.expiresAt}`;
  const expectedSig = crypto.createHmac('sha256', secretKey).update(payload).digest('hex');
  if (challenge.signature !== expectedSig) return false;

  const hash = crypto.createHash('sha256').update(challenge.prefix + solution.nonce).digest('hex');
  const target = '0'.repeat(challenge.difficulty);
  return hash.startsWith(target);
}

module.exports = {
  sha256Hex,
  computeVisitorID,
  scoreFingerprint,
  classifyFingerprint,
  issueToken,
  verifyToken,
  createChallenge,
  verifyChallengeSolution,
  SECRET_KEY,
};

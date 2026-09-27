const { scoreFingerprint, classifyFingerprint, computeVisitorID } = require('./engine');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const sampleFP = {
    schemaVersion: '0.5.0',
    userAgent: req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    canvas: { hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    audio: { hash: '35a92023a105220c3ef94640161421f148e6576ee2e176be510ad692994f7158' },
    webgl: {
      vendor: 'Google Inc. (NVIDIA)',
      renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0)',
      unmaskedVendor: 'NVIDIA Corporation',
      unmaskedRenderer: 'NVIDIA GeForce RTX 3080',
      webgl2Supported: true,
      webgpuSupported: true,
    },
    runtime: {
      webdriverFlag: false,
      functionToStringOk: true,
      hasChromeRuntime: true,
      permissionsAnomaly: false,
      workerSupport: true,
      chromeLoadTimesPresent: true,
      chromeCsiPresent: true,
    },
    device: {
      screenWidth: 1920,
      screenHeight: 1080,
      colorDepth: 24,
      deviceMemory: 8,
      hardwareConcurrency: 8,
      fonts: ['Arial', 'Courier New', 'Georgia', 'Times New Roman', 'Verdana'],
    },
  };

  const analysis = scoreFingerprint(sampleFP);
  const mlResult = classifyFingerprint(sampleFP);
  const visitorId = computeVisitorID(sampleFP);
  const nowIso = new Date().toISOString();

  res.setHeader('Content-Type', 'application/json');
  res.status(200).json({
    report: {
      fingerprint: sampleFP,
      analysis,
      ml: mlResult,
      generatedAt: nowIso,
    },
    visitor: {
      id: visitorId,
      shortId: visitorId.substring(0, 8).toUpperCase(),
      count: 1,
      isNew: false,
      firstSeen: nowIso,
      lastSeen: nowIso,
      visits: [nowIso],
    },
  });
};

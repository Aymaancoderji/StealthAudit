const { scoreFingerprint, classifyFingerprint, computeVisitorID } = require('./engine');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-StealthAudit-Token');
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'method not allowed' });
  }

  const fp = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
  const analysis = scoreFingerprint(fp);
  const mlResult = classifyFingerprint(fp);
  const visitorId = computeVisitorID(fp);
  const nowIso = new Date().toISOString();

  const report = {
    fingerprint: fp,
    analysis,
    ml: mlResult,
    generatedAt: nowIso,
  };

  const response = {
    report,
    visitor: {
      id: visitorId,
      shortId: visitorId.substring(0, 8).toUpperCase(),
      count: 1,
      isNew: true,
      firstSeen: nowIso,
      lastSeen: nowIso,
      visits: [nowIso],
    },
  };

  res.setHeader('Content-Type', 'application/json');
  res.status(200).json(response);
};

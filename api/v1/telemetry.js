const {
  scoreFingerprint,
  classifyFingerprint,
  computeVisitorID,
  issueToken,
  createChallenge,
  verifyChallengeSolution,
} = require('../engine');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-StealthAudit-Token');
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'method not allowed' });
  }

  const payload = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
  const fp = payload.fingerprint;
  if (!fp) {
    return res.status(400).json({ error: 'missing fingerprint data' });
  }

  const analysis = scoreFingerprint(fp);
  const mlResult = classifyFingerprint(fp);
  const visitorId = computeVisitorID(fp);

  const flagCodes = (analysis.flags || []).map((f) => f.code);

  let decision = 'allow';
  let isHardAutomation = false;

  if (fp.runtime) {
    const rt = fp.runtime;
    if (rt.webdriverFlag || (rt.automationArtifacts && rt.automationArtifacts.length > 0) || rt.workerWebdriverLeak || rt.errorStackAutomationLeak || rt.proxyTrapDetected) {
      isHardAutomation = true;
    }
  }
  if (fp.behavioral && fp.behavioral.hasUntrustedEvents) {
    isHardAutomation = true;
  }

  let issuedChallenge = null;
  let challengeVerified = false;

  if (isHardAutomation || mlResult.probability >= 0.85) {
    decision = 'block';
  } else if (mlResult.probability >= 0.40 || analysis.stealthScore < 50.0) {
    if (payload.challenge && payload.challengeSolution) {
      const valid = verifyChallengeSolution(payload.challenge, payload.challengeSolution);
      if (valid) {
        decision = 'allow';
        challengeVerified = true;
      } else {
        decision = 'challenge';
        issuedChallenge = createChallenge(3);
      }
    } else {
      decision = 'challenge';
      issuedChallenge = createChallenge(3);
    }
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const claims = {
    vid: visitorId,
    scr: analysis.stealthScore,
    bp: mlResult.probability,
    dec: decision,
    flg: flagCodes,
    chv: challengeVerified,
    iat: nowSec,
    exp: nowSec + 120,
  };

  const token = issueToken(claims);

  res.setHeader('Content-Type', 'application/json');
  res.status(200).json({
    token,
    decision,
    score: analysis.stealthScore,
    botProbability: mlResult.probability,
    verdict: mlResult.verdict,
    visitorId,
    flags: flagCodes,
    challenge: issuedChallenge,
    challengeVerified,
  });
};

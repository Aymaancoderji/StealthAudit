const { createChallenge, verifyChallengeSolution } = require('../engine');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'GET') {
    const ch = createChallenge(3);
    return res.status(200).json(ch);
  }

  if (req.method === 'POST') {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const valid = verifyChallengeSolution(body.challenge, body.solution);
    if (!valid) {
      return res.status(403).json({ valid: false, error: 'challenge verification failed' });
    }
    return res.status(200).json({ valid: true, verified: true });
  }

  return res.status(405).json({ error: 'method not allowed' });
};

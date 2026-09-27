const { verifyToken } = require('../engine');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'method not allowed' });
  }

  const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
  const token = body.token;
  res.setHeader('Content-Type', 'application/json');

  if (!token) {
    return res.status(400).json({ valid: false, error: 'missing token' });
  }

  try {
    const claims = verifyToken(token);
    return res.status(200).json({ valid: true, claims });
  } catch (err) {
    return res.status(403).json({ valid: false, error: err.message });
  }
};

const { verifyToken } = require('./engine');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-StealthAudit-Token');
  if (req.method === 'OPTIONS') return res.status(204).end();

  let token = req.headers['x-stealthaudit-token'];
  if (!token && req.body) {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    token = body._stealthaudit_token;
  }

  res.setHeader('Content-Type', 'application/json');
  if (!token) {
    return res.status(403).json({
      status: 'blocked',
      message: 'Access Denied: Missing StealthAudit security token.',
    });
  }

  try {
    const claims = verifyToken(token);
    if (claims.dec === 'block') {
      return res.status(403).json({
        status: 'blocked',
        message: 'Access Denied: Automated bot detected. Request rejected.',
        claims,
      });
    }

    return res.status(200).json({
      status: 'success',
      message: `Request Approved! Verified human visitor ${(claims.vid || '00000000').substring(0, 8)} (Stealth Score: ${(claims.scr || 0).toFixed(1)}, Bot Prob: ${((claims.bp || 0) * 100).toFixed(0)}%)`,
      claims,
    });
  } catch (err) {
    return res.status(403).json({
      status: 'blocked',
      message: `Access Denied: Token verification failed (${err.message}).`,
    });
  }
};

// middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'CLAVE_SECRETA';

function parseTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function authRequired(req, res, next) {
  const token = parseTokenFromHeader(req);
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Token inválido' });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const token = parseTokenFromHeader(req);
    if (!token) return res.status(401).json({ error: 'Token requerido' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      if (!allowedRoles.includes(decoded.role)) {
        return res.status(403).json({ error: 'Permiso denegado' });
      }
      next();
    } catch (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
  };
}

module.exports = { authRequired, requireRole };

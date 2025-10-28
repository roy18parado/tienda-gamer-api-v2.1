// middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'CLAVE_SECRETA';

// Lista de IPs permitidas para acceso público
const PUBLIC_IPS = ['TU.IP.PUBLICA.AQUI']; // ej: ['192.168.1.50', '200.100.50.25']

function parseTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function authRequired(req, res, next) {
  const token = parseTokenFromHeader(req);
  if (token) {
    // Si hay token, se valida normalmente
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      return next();
    } catch (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
  } else {
    // Si no hay token, permitimos solo si la IP está en PUBLIC_IPS
    const clientIp = req.ip || req.connection.remoteAddress;
    if (PUBLIC_IPS.includes(clientIp)) {
      req.user = { role: 'public' }; // rol genérico público
      return next();
    } else {
      return res.status(401).json({ error: 'Token requerido' });
    }
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const token = parseTokenFromHeader(req);
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        if (!allowedRoles.includes(decoded.role)) {
          return res.status(403).json({ error: 'Permiso denegado' });
        }
        return next();
      } catch (err) {
        return res.status(403).json({ error: 'Token inválido' });
      }
    } else {
      const clientIp = req.ip || req.connection.remoteAddress;
      if (PUBLIC_IPS.includes(clientIp)) {
        req.user = { role: 'public' };
        if (!allowedRoles.includes('public')) {
          return res.status(403).json({ error: 'Permiso denegado' });
        }
        return next();
      } else {
        return res.status(401).json({ error: 'Token requerido' });
      }
    }
  };
}

module.exports = { authRequired, requireRole };

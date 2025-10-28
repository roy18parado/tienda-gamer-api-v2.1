const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'CLAVE_SECRETA';

const PUBLIC_IPS = ['127.0.0.1', '::1']; // prueba localhost, agrega IPs reales luego

function parseTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function authRequired(req, res, next) {
  const token = parseTokenFromHeader(req);
  const clientIp = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  console.log('Cliente IP:', clientIp);

  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      return next();
    } catch (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
  } else if (PUBLIC_IPS.includes(clientIp)) {
    req.user = { role: 'public' };
    return next();
  } else {
    return res.status(401).json({ error: 'Token requerido' });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const token = parseTokenFromHeader(req);
    const clientIp = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;

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
    } else if (PUBLIC_IPS.includes(clientIp)) {
      req.user = { role: 'public' };
      if (!allowedRoles.includes('public')) {
        return res.status(403).json({ error: 'Permiso denegado' });
      }
      return next();
    } else {
      return res.status(401).json({ error: 'Token requerido' });
    }
  };
}

module.exports = { authRequired, requireRole };

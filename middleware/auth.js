// middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'CLAVE_SECRETA';

// Lista de IPs permitidas
const whitelist = [
  '45.232.149.130',
  '127.0.0.1',
  '::1',
  '45.232.149.146',
  '168.194.102.140',
  '34.82.242.193',
  '10.214.0.0/16'
];

// Función para verificar rangos CIDR
function cidrMatch(ip, cidr) {
  const [range, bits = '32'] = cidr.split('/');
  const ipNum = ipToLong(ip);
  const rangeNum = ipToLong(range);
  const mask = -1 << (32 - parseInt(bits));
  return (ipNum & mask) === (rangeNum & mask);
}

function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
}

function isWhitelisted(ip) {
  return whitelist.some(w => w === ip || (w.includes('/') && cidrMatch(ip, w)));
}

function parseTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

// Middleware authRequired actualizado
function authRequired(req, res, next) {
  const token = parseTokenFromHeader(req);
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress;

  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      return next();
    } catch (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
  }

  // Permitir acceso a IPs whitelist sin token
  if (isWhitelisted(clientIp)) {
    req.user = { role: 'public' };
    return next();
  }

  return res.status(401).json({ error: 'Token requerido' });
}

// Middleware requireRole actualizado
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const token = parseTokenFromHeader(req);
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress;

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
    }

    // Permitir acceso a IPs whitelist si 'public' está permitido
    if (isWhitelisted(clientIp)) {
      req.user = { role: 'public' };
      if (!allowedRoles.includes('public')) return res.status(403).json({ error: 'Permiso denegado' });
      return next();
    }

    return res.status(401).json({ error: 'Token requerido' });
  };
}

module.exports = { authRequired, requireRole };

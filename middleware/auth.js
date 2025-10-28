// middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'CLAVE_SECRETA';

// Lista de IPs permitidas
const whitelist = [
  '45.232.149.130',
  '127.0.0.1',       // IPv4 localhost
  '::1',             // IPv6 localhost
  '45.232.149.146',
  '168.194.102.140',
  '34.82.242.193',
  '10.214.0.0/16'
];

function parseTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

// Función para verificar si la IP está en la whitelist
function isWhitelisted(ip) {
  return whitelist.some(w => w === ip || (w.includes('/') && cidrMatch(ip, w)));
}

// Función simple para verificar rangos CIDR
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

function authRequired(req, res, next) {
  try {
    const token = parseTokenFromHeader(req);
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress;
    console.log('Cliente IP:', clientIp);

    if (token) {
      req.user = jwt.verify(token, JWT_SECRET);
      return next();
    } else if (isWhitelisted(clientIp)) {
      req.user = { role: 'public' };
      return next();
    } else {
      return res.status(401).json({ error: 'Token requerido' });
    }
  } catch (err) {
    console.error('Error en authRequired:', err);
    return res.status(500).json({ error: 'Error interno en auth' });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    try {
      const token = parseTokenFromHeader(req);
      const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || req.connection?.remoteAddress;

      if (token) {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        if (!allowedRoles.includes(decoded.role)) return res.status(403).json({ error: 'Permiso denegado' });
        return next();
      } else if (isWhitelisted(clientIp)) {
        req.user = { role: 'public' };
        if (!allowedRoles.includes('public')) return res.status(403).json({ error: 'Permiso denegado' });
        return next();
      } else {
        return res.status(401).json({ error: 'Token requerido' });
      }
    } catch (err) {
      console.error('Error en requireRole:', err);
      return res.status(500).json({ error: 'Error interno en auth' });
    }
  };
}

module.exports = { authRequired, requireRole };

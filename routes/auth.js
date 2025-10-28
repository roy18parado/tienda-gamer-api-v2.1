// middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'CLAVE_SECRETA';

// Lista de IPs permitidas para el público
const whitelist = [
  '45.232.149.130',
  '127.0.0.1',       // IPv4 localhost
  '::1',             // IPv6 localhost
  '45.232.149.146',
  '168.194.102.140',
  '34.82.242.193',
  '10.214.0.0/16'
];

// Función para verificar si una IP está permitida
function checkIP(req) {
  const clientIP = req.ip || req.connection.remoteAddress;
  return whitelist.some(ip => {
    if (ip.includes('/')) {
      // CIDR simple
      const [subnet, bits] = ip.split('/');
      const mask = ~(2 ** (32 - parseInt(bits)) - 1);
      const subnetInt = ipToInt(subnet) & mask;
      return (ipToInt(clientIP) & mask) === subnetInt;
    } else {
      return ip === clientIP;
    }
  });
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
}

// Parsear token
function parseTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

// Middleware principal
function authRequired(req, res, next) {
  const token = parseTokenFromHeader(req);

  // Si no hay token, solo permitir si IP está en whitelist
  if (!token) {
    if (checkIP(req)) return next(); 
    return res.status(401).json({ error: 'Token requerido' });
  }

  // Validar token
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Token inválido' });
  }
}

// Middleware de roles
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

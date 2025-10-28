// Archivo: middleware/auth.js
const jwt = require('jsonwebtoken');

// Usar variable de entorno con valor por defecto más seguro
const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_para_desarrollo_no_usar_en_produccion';

// Verificar que JWT_SECRET esté configurado en producción
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
    console.error('❌ CRÍTICO: JWT_SECRET no definida en producción');
    // No salir del proceso para permitir recuperación
}

function parseTokenFromHeader(req) {
    const auth = req.headers['authorization'] || '';
    return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function authRequired(req, res, next) {
    try {
        const token = parseTokenFromHeader(req);
        
        if (!token) {
            return res.status(401).json({ 
                error: 'Token de autenticación requerido',
                details: 'Incluye el token en el header: Authorization: Bearer <token>'
            });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        
        console.log(`🔐 Usuario autenticado: ${decoded.email || decoded.username} - Rol: ${decoded.role}`);
        next();
        
    } catch (err) {
        console.error('❌ Error en autenticación:', err.message);
        
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                error: 'Token expirado',
                details: 'El token ha caducado, inicia sesión nuevamente'
            });
        } else if (err.name === 'JsonWebTokenError') {
            return res.status(403).json({ 
                error: 'Token inválido',
                details: 'El token no es válido'
            });
        } else {
            return res.status(500).json({ 
                error: 'Error en autenticación',
                details: process.env.NODE_ENV === 'development' ? err.message : 'Error interno'
            });
        }
    }
}

function requireRole(...allowedRoles) {
    return (req, res, next) => {
        // Primero autenticar
        const tokenMiddleware = (req, res, next) => {
            const token = parseTokenFromHeader(req);
            if (!token) {
                return res.status(401).json({ 
                    error: 'Token requerido',
                    details: 'Se requiere autenticación para acceder a este recurso'
                });
            }
            try {
                req.user = jwt.verify(token, JWT_SECRET);
                next();
            } catch (err) {
                return res.status(403).json({ 
                    error: 'Token inválido o expirado',
                    details: 'Verifica tu token de autenticación'
                });
            }
        };

        // Ejecutar autenticación primero
        tokenMiddleware(req, res, (err) => {
            if (err) return next(err);
            
            // Luego verificar rol
            if (!req.user || !allowedRoles.includes(req.user.role)) {
                return res.status(403).json({ 
                    error: 'Permisos insuficientes',
                    details: `Se requiere uno de estos roles: ${allowedRoles.join(', ')}`,
                    userRole: req.user?.role,
                    allowedRoles: allowedRoles
                });
            }
            
            console.log(`✅ Acceso autorizado para rol: ${req.user.role} en ruta: ${req.path}`);
            next();
        });
    };
}

// Middleware opcional (para rutas que pueden ser públicas o privadas)
function optionalAuth(req, res, next) {
    const token = parseTokenFromHeader(req);
    if (token) {
        try {
            req.user = jwt.verify(token, JWT_SECRET);
            console.log(`🔐 Usuario identificado (opcional): ${req.user.email || req.user.username}`);
        } catch (err) {
            // Si el token es inválido, continuar sin usuario
            console.log('⚠️ Token opcional inválido, continuando como anónimo');
        }
    }
    next();
}

module.exports = { 
    authRequired, 
    requireRole, 
    optionalAuth,
    parseTokenFromHeader 
};

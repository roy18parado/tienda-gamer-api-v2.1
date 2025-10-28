// index.js (versión recomendada: CORS controlado + IP robusta)
const express = require('express');
const cors = require('cors');
const path = require('path');
const ipRangeCheck = require('ip-range-check');

const app = express();

// ===== TRUST PROXY - debe estar lo antes posible =====
app.set('trust proxy', 1); // confía en primer proxy (ej: render, heroku)

// ===== CONFIG - whitelist y allowed origins =====
const whitelist = [
  '45.232.149.130',
  '45.232.149.146',
  '168.194.102.140',
  '34.82.242.193',
  '10.214.0.0/16',
  '10.204.0.0/16'
];

// Orígenes permitidos (ajusta o usa process.env.ALLOWED_ORIGINS)
const allowedOrigins = [
  'http://45.232.149.130',
  'http://45.232.149.146'
];

// ===== CORS (función para manejo más fino) =====
const corsOptions = {
  origin: function (origin, callback) {
    // Si no hay origin (peticiones desde curl/postman o same-origin), aceptamos
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.warn(`🛑 CORS bloqueado: origen no permitido -> ${origin}`);
      return callback(new Error('CORS: Origen no permitido'), false);
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(express.json());
// Aplica CORS globalmente con las opciones definidas
app.use(cors(corsOptions));

// ===== Util: extraer IP real de petición =====
function extractClientIp(req) {
  // Revisa headers en orden: x-forwarded-for, x-real-ip
  const xff = req.headers['x-forwarded-for'] || req.headers['x-forwarded-for'.toLowerCase()];
  const xreal = req.headers['x-real-ip'] || req.headers['x-real-ip'.toLowerCase()];
  let ip = null;

  if (xff) {
    // x-forwarded-for puede contener "client, proxy1, proxy2"
    ip = xff.split(',')[0].trim();
  } else if (xreal) {
    ip = xreal.trim();
  } else if (req.ip) {
    ip = req.ip;
  } else if (req.connection && req.connection.remoteAddress) {
    ip = req.connection.remoteAddress;
  }

  if (!ip) return null;

  // Normalizar IPv4-mapped IPv6 -> '::ffff:45.232.149.130' => '45.232.149.130'
  ip = ip.replace(/^::ffff:/i, '');
  // si contiene zona (IPv6%eth0), eliminar parte %...
  ip = ip.split('%')[0];

  return ip;
}

// ===== Middleware de whitelist por IP (usarlo por ruta) =====
const ipWhitelistMiddleware = (req, res, next) => {
  try {
    if (req.method === 'OPTIONS') return next(); // preflights ya manejados por CORS

    const clientIp = extractClientIp(req);
    console.log(`🛡️ [IP CHECK] ${req.method} ${req.path} - x-forwarded-for: ${req.headers['x-forwarded-for'] || '-'} - req.ip: ${req.ip} - extraída: ${clientIp}`);

    if (!clientIp) {
      console.warn('⚠️ No se pudo extraer IP cliente.');
      return res.status(400).json({ error: 'No se pudo determinar la IP del cliente' });
    }

    if (ipRangeCheck(clientIp, whitelist)) {
      console.log(`✅ IP AUTORIZADA: ${clientIp}`);
      return next();
    } else {
      console.log(`❌ IP NO AUTORIZADA: ${clientIp}`);
      return res.status(403).json({
        error: `Acceso prohibido desde IP no autorizada: ${clientIp}`,
        ipRecibida: clientIp,
        ipsPermitidas: whitelist
      });
    }
  } catch (err) {
    console.error('❌ Error en middleware IP:', err);
    return res.status(500).json({ error: 'Error interno en validación de IP' });
  }
};

// ===== RUTAS =====
// Rutas públicas (por ejemplo, login)
const authRoutes = require('./routes/auth');
app.use('/', authRoutes);

// Ruta pública de estado
app.get('/', (req, res) => {
  res.json({ message: 'API funcionando', version: '1.0.0', timestamp: new Date().toISOString() });
});

// Rutas protegidas por IP (aplica middleware explicitamente)
const categoriasRoutes = require('./routes/categorias');
const productosRoutes = require('./routes/productos');
const imagenesRoutes = require('./routes/imagenes');
const usuariosRoutes = require('./routes/usuarios');

app.use('/categorias', ipWhitelistMiddleware, categoriasRoutes);
app.use('/productos', ipWhitelistMiddleware, productosRoutes);
app.use('/imagenes', ipWhitelistMiddleware, imagenesRoutes);
app.use('/usuarios', ipWhitelistMiddleware, usuariosRoutes);

// ===== SWAGGER (sin protección por IP para poder acceder a docs si quieres) =====
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: { title: 'API Tienda Gamer', version: '1.0.0' },
    servers: [{ url: process.env.SWAGGER_SERVER || 'https://tu-dominio.com' }],
    components: {
      securitySchemes: { BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } }
    }
  },
  apis: [path.join(__dirname, './routes/*.js')]
};
const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ===== Manejo de errores =====
app.use((err, req, res, next) => {
  console.error('❌ Error global:', err?.message || err);
  if (err && err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: 'Acceso CORS denegado', detalles: err.message });
  }
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ===== Arranque =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
  console.log(`🌐 Orígenes permitidos CORS: ${allowedOrigins.join(', ')}`);
  console.log(`📚 Docs en /api-docs`);
});

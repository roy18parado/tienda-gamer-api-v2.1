// Archivo: index.js - Versión final (IP + JWT + Render Compatible)
const express = require('express');
const cors = require('cors');
const path = require('path');
const ipRangeCheck = require('ip-range-check');

const app = express();
app.use(express.json());
app.set('trust proxy', 1); // 🔹 Importante para Render

// -------------------- CORS GLOBAL --------------------
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// -------------------- IP WHITELIST --------------------
const whitelist = [
  '45.232.149.130',  // Instituto 1
  '45.232.149.146',  // Instituto 2
  '168.194.102.140', // Casa
  '10.214.0.0/16',   // Red interna Render
  '10.204.0.0/16'    // Red interna Render
];

// ✅ Middleware de IP corregido para Render
const ipWhitelistMiddleware = (req, res, next) => {
  try {
    const forwardedFor = req.headers['x-forwarded-for'];
    const clientIp = forwardedFor
      ? forwardedFor.split(',')[0].trim()
      : req.connection.remoteAddress;

    const ipClean = clientIp.replace(/^::ffff:/, '');
    console.log(`🛡️ IP real detectada: ${ipClean}`);

    if (ipRangeCheck(ipClean, whitelist)) {
      console.log(`✅ IP AUTORIZADA: ${ipClean}`);
      next();
    } else {
      console.log(`❌ IP NO AUTORIZADA: ${ipClean}`);
      return res.status(403).json({
        error: `Acceso prohibido desde IP no autorizada`,
        ip: ipClean,
        permitido: whitelist
      });
    }
  } catch (err) {
    console.error('❌ Error en middleware de IP:', err);
    next(err);
  }
};

// -------------------- IMPORTAR RUTAS --------------------
const { authRequired, requireRole } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const categoriasRoutes = require('./routes/categorias');
const productosRoutes = require('./routes/productos');
const imagenesRoutes = require('./routes/imagenes');
const usuariosRoutes = require('./routes/usuarios');

// -------------------- RUTAS --------------------
// Rutas públicas
app.use('/', authRoutes);

app.get('/', (req, res) => {
  res.json({
    message: '🚀 API de Tienda Gamer funcionando correctamente',
    version: '1.0.0',
    status: 'active'
  });
});

// 🔒 Rutas protegidas (requieren IP autorizada + token válido)
app.use('/categorias', ipWhitelistMiddleware, authRequired, categoriasRoutes);
app.use('/productos', ipWhitelistMiddleware, authRequired, productosRoutes);
app.use('/imagenes', ipWhitelistMiddleware, authRequired, imagenesRoutes);
app.use('/usuarios', ipWhitelistMiddleware, requireRole('super'), usuariosRoutes);

// -------------------- SWAGGER --------------------
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Tienda Gamer',
      version: '1.0.0',
      description: 'Documentación técnica completa de la API.',
    },
    servers: [{ url: 'https://tienda-gamer-api-v2.onrender.com' }],
    components: {
      securitySchemes: {
        BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
      }
    }
  },
  apis: [path.join(__dirname, './routes/*.js')],
};
const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// -------------------- MANEJO DE ERRORES --------------------
app.use((err, req, res, next) => {
  console.error('❌ Error interno:', err.message || err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// -------------------- INICIO SERVIDOR --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
  console.log(`📚 Docs en /api-docs`);
});

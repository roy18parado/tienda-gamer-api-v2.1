// Archivo: index.js (Versión Final - CORS Global, IP por Ruta)

const express = require('express');
const cors = require('cors');
const path = require('path');
const ipRangeCheck = require('ip-range-check');

const app = express();
app.use(express.json()); // 1. Parsear JSON
app.set('trust proxy', 1); // 2. Confiar en proxy para req.ip

// --- CONFIGURACIÓN CORS GLOBAL (PRIMERO Y ÚNICO) ---
app.use(cors({
  origin: '*', // Permitir cualquier origen (incluyendo 'null')
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Métodos estándar
  allowedHeaders: ['Content-Type', 'Authorization'] // Cabeceras que usas
}));

// --- MIDDLEWARE DE SEGURIDAD DE IP (Definición) ---
// 4. Lista de IPs/Rangos Permitidos (ACTUALIZADA)
const whitelist = [
  '45.232.149.130', // Instituto 1
  '45.232.149.146', // Instituto 2
  '168.194.102.140', // Tu Casa
  '10.214.0.0/16',   // Rango Interno Render 1
  '10.204.0.0/16'    // Rango Interno Render 2
  // Quita 127.0.0.1 y ::1, no son necesarios en producción
];

// 5. Función Middleware para validar IP (SIN app.use global)
const ipWhitelistMiddleware = (req, res, next) => {
  // Las peticiones OPTIONS ya fueron manejadas por cors(), las saltamos
  if (req.method === 'OPTIONS') {
    return next();
  }

  const clientIp = req.ip;
  console.log(`🛡️ IP recibida para ${req.method} ${req.path}: ${clientIp}`);

  if (ipRangeCheck(clientIp, whitelist)) {
    console.log(`✅ IP AUTORIZADA: ${clientIp}`);
    next(); // IP OK, continuar
  } else {
    console.log(`❌ IP NO AUTORIZADA: ${clientIp}`);
    return res.status(403).json({
      error: `Acceso prohibido desde IP no autorizada: ${clientIp}`
    });
  }
};

// --- RUTAS ---
// Rutas Públicas (como /login, no necesitan filtro de IP)
const authRoutes = require('./routes/auth');
app.use('/', authRoutes); // Login es público

// Ruta raíz (pública)
app.get('/', (req, res) => {
  res.json({
    message: '🚀 API de Tienda Gamer funcionando correctamente',
    version: '1.0.0',
    /* ... resto de tu mensaje ... */
    status: 'active'
  });
});

// Rutas Protegidas por IP (Aplicamos el middleware ANTES de las rutas)
const categoriasRoutes = require('./routes/categorias');
const productosRoutes = require('./routes/productos');
const imagenesRoutes = require('./routes/imagenes');
const usuariosRoutes = require('./routes/usuarios');

// 6. Aplicar filtro IP SOLO a las rutas que lo necesiten
app.use('/categorias', ipWhitelistMiddleware, categoriasRoutes);
app.use('/productos', ipWhitelistMiddleware, productosRoutes);
app.use('/imagenes', ipWhitelistMiddleware, imagenesRoutes);
app.use('/usuarios', ipWhitelistMiddleware, usuariosRoutes);

// --- SWAGGER ---
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Tienda Gamer',
      version: '1.0.0',
      description: 'Documentación de la API.'
    },
    servers: [{ url: 'https://tienda-gamer-api-v2.onrender.com' }],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    }
  },
  apis: [path.join(__dirname, './routes/*.js')]
};

try {
  const swaggerSpec = swaggerJSDoc(swaggerOptions);
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  console.log("📚 Documentación Swagger configurada.");
} catch (yamlError) {
  console.error("❌ ERROR AL CONFIGURAR SWAGGER:", yamlError.message);
  app.use('/api-docs', (req, res) => {
    res.status(500).json({
      error: "Error al generar Swagger.",
      detalles: yamlError.message
    });
  });
}

// --- MANEJO DE ERRORES (Al final) ---
app.use((err, req, res, next) => {
  console.error('❌ Error interno:', err.message || err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// --- INICIO DEL SERVIDOR ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
  console.log('📚 Docs en /api-docs');
});

// --- CODIGO ANTERIOR FUNCIONAL DE IP ---
const allowedOrigins = [
  'http://45.232.149.130',
  'http://45.232.149.146'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log(`🛑 CORS bloqueado: origen no permitido -> ${origin}`);
      callback(new Error('CORS: Origen no permitido'));
    }
  },
  optionsSuccessStatus: 200,
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// Middleware para validar IP
app.use(ipWhitelistMiddleware);

// ✅ RUTAS PRINCIPALES - AGREGAR ESTO
app.get('/', (req, res) => {
  res.json({
    message: '🚀 API de Tienda Gamer funcionando correctamente',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      documentacion: '/api-docs',
      autenticacion: '/login, /register, /verify',
      categorias: '/categorias',
      productos: '/productos',
      imagenes: '/imagenes',
      usuarios: '/usuarios'
    },
    status: 'active'
  });
});

app.get('/info', (req, res) => {
  res.json({
    name: 'Tienda Gamer API',
    description: 'API REST para sistema de tienda gamer',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    serverTime: new Date().toISOString()
  });
});

app.get('/status', (req, res) => {
  res.json({
    status: 'OK',
    server: 'Running',
    timestamp: new Date().toISOString()
  });
});

// RUTAS DE LA API
app.use('/', authRoutes);
app.use('/categorias', categoriasRoutes);
app.use('/productos', productosRoutes);
app.use('/imagenes', imagenesRoutes);
app.use('/usuarios', usuariosRoutes);

// CONFIGURACIÓN DE SWAGGER (opcional)
const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error('❌ Error interno del servidor:', err.message);
  if (err.message.includes('CORS')) {
    return res.status(403).json({ error: 'Acceso CORS denegado', detalles: err.message });
  }
  res.status(500).json({
    error: 'Error interno del servidor',
    detalles: process.env.NODE_ENV === 'development' ? err.message : 'Contacta al administrador'
  });
});

// INICIO DEL SERVIDOR
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
  console.log(`🌐 Orígenes CORS permitidos: ${allowedOrigins.join(', ')}`);
  console.log(`📚 Documentación disponible en: http://localhost:${PORT}/api-docs`);
});

const express = require('express');
const cors = require('cors');
const path = require('path');
const ipRangeCheck = require('ip-range-check');

const app = express();
app.set('trust proxy', 1);

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

// Middleware CORS
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
const ipWhitelistMiddleware = (req, res, next) => {
  try {
    const forwardedFor = req.headers['x-forwarded-for'];
    const clientIp = forwardedFor ? forwardedFor.split(',')[0].trim() : req.ip;
    const ipClean = clientIp.replace(/::ffff:/, '');
    
    console.log(`🛡️ IP recibida: ${clientIp} ➜ Limpia: ${ipClean}`);

    if (ipRangeCheck(ipClean, whitelist)) {
      console.log(`✅ IP AUTORIZADA: ${ipClean}`);
      next();
    } else {
      console.log(`❌ IP NO AUTORIZADA: ${ipClean}`);
      return res.status(403).json({
        error: `Acceso prohibido desde IP no autorizada: ${ipClean}`,
        ipRecibida: ipClean,
        ipsPermitidas: whitelist
      });
    }
  } catch (error) {
    console.error('❌ Error en middleware de IP:', error);
    next();
  }
};

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
const authRoutes = require('./routes/auth');
const categoriasRoutes = require('./routes/categorias');
const productosRoutes = require('./routes/productos');
const imagenesRoutes = require('./routes/imagenes');
const usuariosRoutes = require('./routes/usuarios');

app.use('/', authRoutes);
app.use('/categorias', categoriasRoutes);
app.use('/productos', productosRoutes);
app.use('/imagenes', imagenesRoutes);
app.use('/usuarios', usuariosRoutes);

// CONFIGURACIÓN DE SWAGGER (opcional - si ya corregiste auth.js)
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
    },
  },
  apis: [path.join(__dirname, './routes/*.js')],
};
const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error('❌ Error interno del servidor:', err.message);
  
  if (err.message.includes('CORS')) {
    return res.status(403).json({ 
      error: 'Acceso CORS denegado',
      detalles: err.message 
    });
  }
  
  res.status(500).json({ 
    error: 'Error interno del servidor',
    detalles: process.env.NODE_ENV === 'development' ? err.message : 'Contacta al administrador'
  });
});

// INICIO DEL SERVIDOR
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
  console.log(`🌐 Orígenes CORS permitidos: ${allowedOrigins.join(', ')}`);
  console.log(`📚 Documentación disponible en: http://localhost:${PORT}/api-docs`);
});

// Archivo: index.js
const express = require('express');
const cors = require('cors');
const path = require('path');
const ipRangeCheck = require('ip-range-check');

// Importar middlewares de autenticación
const { authRequired, requireRole } = require('./middleware/auth');

const app = express();
app.use(express.json());
app.set('trust proxy', 1); // Confiar en proxy para X-Forwarded-For

// --- CONFIGURACIÓN SEGURA DE CORS ---
const allowedOrigins = [
    'http://45.232.149.130',
    'http://45.232.149.146',
    'https://tienda-gamer-api-v2.onrender.com',
    'http://localhost:3000',
    'http://localhost:5173' // Para Vite/React
];

const corsOptions = {
    origin: function (origin, callback) {
        // Permitir requests sin origen (Postman, curl, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.log(`🛑 CORS bloqueado: origen no permitido -> ${origin}`);
            callback(new Error('CORS: Origen no permitido'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// --- WHITELIST DE IPs ACTUALIZADA PARA RENDER ---
const whitelist = [
    '45.232.149.130',    // Instituto 1
    '45.232.149.146',    // Instituto 2  
    '168.194.102.140',   // Tu Casa
    '34.82.242.193',     // IP adicional del código anterior
    '10.0.0.0/8',        // Rango amplio para Render (incluye 10.17.x.x)
    '172.16.0.0/12',     // Rango interno adicional
    '127.0.0.1',         // Localhost
    '::1'                // IPv6 localhost
];

// --- MIDDLEWARE MEJORADO DE VALIDACIÓN DE IP ---
const ipWhitelistMiddleware = (req, res, next) => {
    // Saltar validación para preflight OPTIONS
    if (req.method === 'OPTIONS') {
        return next();
    }

    try {
        // Obtener IP real considerando proxies
        const forwardedFor = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        const clientIp = forwardedFor 
            ? forwardedFor.split(',')[0].trim() 
            : (realIp || req.ip || req.connection.remoteAddress);

        // Limpiar formato IPv6
        const ipClean = clientIp.replace(/::ffff:/g, '');
        const ipToCheck = ipClean === '::1' ? '127.0.0.1' : ipClean;

        console.log(`🛡️ IP recibida para ${req.method} ${req.path}: ${ipToCheck} (original: ${clientIp})`);

        if (ipRangeCheck(ipToCheck, whitelist)) {
            console.log(`✅ IP AUTORIZADA: ${ipToCheck}`);
            next();
        } else {
            console.log(`❌ IP NO AUTORIZADA: ${ipToCheck}`);
            console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
            return res.status(403).json({ 
                error: `Acceso prohibido desde IP no autorizada: ${ipToCheck}`,
                ipRecibida: ipToCheck,
                ipsPermitidas: whitelist
            });
        }
    } catch (error) {
        console.error('❌ Error en middleware de IP:', error);
        // En caso de error, permitir continuar para no bloquear la aplicación
        next();
    }
};

// --- RUTAS PÚBLICAS (sin filtro IP) ---
const authRoutes = require('./routes/auth');
app.use('/', authRoutes);

// Ruta raíz pública
app.get('/', (req, res) => {
    res.json({ 
        message: '🚀 API de Tienda Gamer funcionando correctamente',
        version: '1.0.0',
        status: 'active',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        endpoints: {
            documentacion: '/api-docs',
            autenticacion: '/login, /register, /verify',
            categorias: '/categorias',
            productos: '/productos',
            imagenes: '/imagenes',
            usuarios: '/usuarios'
        }
    });
});

// Ruta de health check (pública)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        server: 'Running', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

// Ruta pública de información
app.get('/info', (req, res) => {
    res.json({
        name: 'Tienda Gamer API',
        description: 'API REST para sistema de tienda gamer',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        serverTime: new Date().toISOString()
    });
});

// --- RUTAS PROTEGIDAS POR IP ---
const categoriasRoutes = require('./routes/categorias');
const productosRoutes = require('./routes/productos');
const imagenesRoutes = require('./routes/imagenes');
const usuariosRoutes = require('./routes/usuarios');

// Aplicar filtro IP + autenticación según necesidad
app.use('/categorias', ipWhitelistMiddleware, categoriasRoutes);
app.use('/productos', ipWhitelistMiddleware, productosRoutes);
app.use('/imagenes', ipWhitelistMiddleware, imagenesRoutes);
app.use('/usuarios', ipWhitelistMiddleware, usuariosRoutes);

// --- RUTAS DE EJEMPLO CON AUTENTICACIÓN JWT ---

// Ruta que requiere autenticación pero es pública en IP
app.get('/perfil', ipWhitelistMiddleware, authRequired, (req, res) => {
    res.json({ 
        message: 'Perfil del usuario',
        user: req.user,
        timestamp: new Date().toISOString()
    });
});

// Ruta que requiere rol de admin
app.get('/admin/dashboard', ipWhitelistMiddleware, requireRole('admin', 'superadmin'), (req, res) => {
    res.json({ 
        message: 'Panel de administración',
        user: req.user,
        stats: {
            usuarios: 150,
            productos: 45,
            ventas: 1200
        }
    });
});

// Ruta para usuarios normales
app.get('/usuario/dashboard', ipWhitelistMiddleware, requireRole('user', 'admin', 'superadmin'), (req, res) => {
    res.json({ 
        message: 'Dashboard de usuario',
        user: req.user,
        actividades: [
            'Último login: hoy',
            'Pedidos pendientes: 2',
            'Mensajes: 5'
        ]
    });
});

// --- CONFIGURACIÓN SWAGGER ---
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'API de Tienda Gamer - Documentación Segura',
            version: '1.0.0',
            description: 'API protegida con CORS, filtro de IPs y autenticación JWT',
        },
        servers: [{ 
            url: 'https://tienda-gamer-api-v2.onrender.com',
            description: 'Servidor de producción'
        }],
        components: {
            securitySchemes: {
                BearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        },
        security: [{
            BearerAuth: []
        }]
    },
    apis: [path.join(__dirname, './routes/*.js')],
};

try {
    const swaggerSpec = swaggerJSDoc(swaggerOptions);
    // Swagger público (puedes protegerlo si quieres)
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
        explorer: true,
        customCss: '.swagger-ui .topbar { display: none }',
        swaggerOptions: {
            persistAuthorization: true,
        }
    }));
    console.log("📚 Documentación Swagger configurada en /api-docs");
} catch (error) {
    console.error("❌ ERROR AL CONFIGURAR SWAGGER:", error.message);
    app.use('/api-docs', (req, res) => {
        res.status(500).json({ 
            error: "Error al generar documentación Swagger",
            detalles: process.env.NODE_ENV === 'development' ? error.message : 'Contacta al administrador'
        });
    });
}

// --- MANEJO DE ERRORES ---
app.use((err, req, res, next) => {
    console.error('❌ Error interno del servidor:', err.message);
    
    if (err.message.includes('CORS')) {
        return res.status(403).json({ 
            error: 'Acceso CORS denegado',
            details: 'Origen no permitido'
        });
    }
    
    res.status(500).json({ 
        error: 'Error interno del servidor',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Contacta al administrador'
    });
});

// Manejo de rutas no encontradas
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Ruta no encontrada',
        path: req.originalUrl,
        method: req.method,
        availableEndpoints: {
            public: ['/', '/health', '/info', '/api-docs', '/login', '/register'],
            protected: ['/perfil', '/admin/dashboard', '/usuario/dashboard', '/categorias', '/productos', '/imagenes', '/usuarios']
        }
    });
});

// --- INICIO DEL SERVIDOR ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
    console.log(`🌐 Orígenes CORS permitidos: ${allowedOrigins.join(', ')}`);
    console.log(`📚 Docs disponibles en: /api-docs`);
    console.log(`🏥 Health check en: /health`);
    console.log(`🔐 JWT Secret configurado: ${process.env.JWT_SECRET ? '✅' : '⚠️ Usando valor por defecto'}`);
});

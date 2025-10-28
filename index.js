const express = require('express');
const cors = require('cors');
const path = require('path');
const ipRangeCheck = require('ip-range-check');
const { authRequired, requireRole } = require('./middleware/auth');

const app = express();
app.use(express.json());
app.set('trust proxy', 1);

// --- CONFIGURACIÓN CORS ACTUALIZADA ---
const allowedOrigins = [
    'http://45.232.149.130',
    '45.232.149.130', // IP directa
    'http://45.232.149.146', 
    '45.232.149.146',
    'http://168.194.102.140',
    '168.194.102.140',
    'https://tienda-gamer-api-v2.onrender.com',
    'null' // Para archivos locales
];

const corsOptions = {
    origin: function (origin, callback) {
        // Permitir requests sin origen, null, o en la lista permitida
        if (!origin || origin === 'null' || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.log(`🛑 CORS bloqueado: origen no permitido -> ${origin}`);
            callback(new Error('CORS: Origen no permitido'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Origin', 'Accept'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// --- WHITELIST DE IPs ACTUALIZADA ---
const whitelist = [
    '45.232.149.130',
    '45.232.149.146',
    '168.194.102.140',
    '34.82.242.193',
    '10.214.0.0/16',
    '10.0.0.0/8',       // Rango más amplio para Render
    '127.0.0.1',
    '::1'
];

// --- MIDDLEWARE DE IP MEJORADO ---
const ipWhitelistMiddleware = (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    
    try {
        const forwardedFor = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        const clientIp = forwardedFor 
            ? forwardedFor.split(',')[0].trim() 
            : (realIp || req.ip || req.connection.remoteAddress);

        // Limpiar formato IPv6
        const ipClean = clientIp.replace(/::ffff:/g, '');
        const ipToCheck = ipClean === '::1' ? '127.0.0.1' : ipClean;

        console.log(`🛡️ IP recibida para ${req.method} ${req.path}: ${ipToCheck}`);

        if (ipRangeCheck(ipToCheck, whitelist)) {
            console.log(`✅ IP AUTORIZADA: ${ipToCheck}`);
            next();
        } else {
            console.log(`❌ IP NO AUTORIZADA: ${ipToCheck}`);
            return res.status(403).json({ 
                error: `Acceso prohibido desde IP no autorizada: ${ipToCheck}`,
                ipRecibida: ipToCheck,
                ipsPermitidas: whitelist
            });
        }
    } catch (error) {
        console.error('❌ Error en middleware de IP:', error);
        next();
    }
};

// --- RUTA PRINCIPAL (SOLO API INFO) ---
app.get('/', ipWhitelistMiddleware, (req, res) => {
    res.json({ 
        message: '🚀 API de Tienda Gamer funcionando correctamente',
        version: '1.0.0',
        status: 'active',
        timestamp: new Date().toISOString(),
        endpoints: {
            documentacion: '/api-docs',
            autenticacion: '/login, /register, /verify',
            categorias: '/categorias',
            productos: '/productos',
            imagenes: '/imagenes',
            usuarios: '/usuarios'
        },
        note: 'Esta es una API REST. Usa tu frontend desde una IP autorizada.'
    });
});

// --- RUTAS DE API (PROTEGIDAS POR IP) ---
const authRoutes = require('./routes/auth');
const categoriasRoutes = require('./routes/categorias');
const productosRoutes = require('./routes/productos');
const imagenesRoutes = require('./routes/imagenes');
const usuariosRoutes = require('./routes/usuarios');

// Rutas públicas (solo login/register - SIN filtro IP)
app.use('/', authRoutes);

// Rutas protegidas por IP
app.use('/categorias', ipWhitelistMiddleware, categoriasRoutes);
app.use('/productos', ipWhitelistMiddleware, productosRoutes);
app.use('/imagenes', ipWhitelistMiddleware, imagenesRoutes);
app.use('/usuarios', ipWhitelistMiddleware, usuariosRoutes);

// Health check (público)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        server: 'Running', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'production'
    });
});

// --- CONFIGURACIÓN SWAGGER ---
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'API de Tienda Gamer',
            version: '1.0.0',
            description: 'API protegida con filtro de IPs',
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
        }
    },
    apis: [path.join(__dirname, './routes/*.js')],
};

try {
    const swaggerSpec = swaggerJSDoc(swaggerOptions);
    // Swagger público (sin filtro IP para facilitar acceso)
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
    console.log("📚 Documentación Swagger configurada en /api-docs");
} catch (error) {
    console.error("❌ ERROR AL CONFIGURAR SWAGGER:", error.message);
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
        error: 'Error interno del servidor'
    });
});

// Ruta no encontrada
app.use('*', ipWhitelistMiddleware, (req, res) => {
    res.status(404).json({
        error: 'Ruta no encontrada',
        path: req.originalUrl,
        method: req.method
    });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor API corriendo en puerto ${PORT}`);
    console.log(`📋 IPs permitidas: ${whitelist.join(', ')}`);
    console.log(`🔐 Modo: Solo API REST`);
    console.log(`🌐 Frontend externo desde IPs autorizadas`);
});

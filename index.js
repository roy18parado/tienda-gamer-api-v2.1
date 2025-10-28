// Archivo: index.js (VERSIÓN COMPLETA CON FRONTEND)
const express = require('express');
const cors = require('cors');
const path = require('path');
const ipRangeCheck = require('ip-range-check');
const { authRequired, requireRole } = require('./middleware/auth');

const app = express();
app.use(express.json());
app.set('trust proxy', 1);

// --- SERVIR ARCHIVOS ESTÁTICOS (FRONTEND) ---
app.use(express.static(path.join(__dirname, 'public')));

// --- CONFIGURACIÓN CORS ACTUALIZADA ---
const allowedOrigins = [
    'http://45.232.149.130',
    'http://45.232.149.146', 
    'https://tienda-gamer-api-v2.onrender.com',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:8080',
    'null'
];

const corsOptions = {
    origin: function (origin, callback) {
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

// --- WHITELIST DE IPs (igual que antes) ---
const whitelist = [
    '45.232.149.130', '45.232.149.146', '168.194.102.140', '34.82.242.193',
    '10.0.0.0/8', '172.16.0.0/12', '127.0.0.1', '::1'
];

const ipWhitelistMiddleware = (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    try {
        const forwardedFor = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        const clientIp = forwardedFor ? forwardedFor.split(',')[0].trim() : (realIp || req.ip);
        const ipClean = clientIp.replace(/::ffff:/g, '');
        const ipToCheck = ipClean === '::1' ? '127.0.0.1' : ipClean;

        console.log(`🛡️ IP recibida para ${req.method} ${req.path}: ${ipToCheck}`);
        
        if (ipRangeCheck(ipToCheck, whitelist)) {
            next();
        } else {
            console.log(`❌ IP NO AUTORIZADA: ${ipToCheck}`);
            return res.status(403).json({ error: `Acceso prohibido desde IP no autorizada: ${ipToCheck}` });
        }
    } catch (error) {
        console.error('❌ Error en middleware de IP:', error);
        next();
    }
};

// --- RUTAS ---

// Ruta principal sirve el frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Ruta de health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', server: 'Running', timestamp: new Date().toISOString() });
});

// API Routes
const authRoutes = require('./routes/auth');
const categoriasRoutes = require('./routes/categorias');
const productosRoutes = require('./routes/productos');
const imagenesRoutes = require('./routes/imagenes');
const usuariosRoutes = require('./routes/usuarios');

app.use('/', authRoutes);
app.use('/categorias', ipWhitelistMiddleware, categoriasRoutes);
app.use('/productos', ipWhitelistMiddleware, productosRoutes);
app.use('/imagenes', ipWhitelistMiddleware, imagenesRoutes);
app.use('/usuarios', ipWhitelistMiddleware, usuariosRoutes);

// ... el resto de tu configuración (Swagger, manejo de errores, etc.)

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor completo corriendo en puerto ${PORT}`);
    console.log(`🌐 Frontend disponible en: https://tienda-gamer-api-v2.onrender.com`);
});

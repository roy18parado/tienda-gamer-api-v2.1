// index.js
const express = require('express');
const cors = require('cors');
const { authRequired, requireRole } = require('./middleware/auth');
require('dotenv').config();

const app = express();
app.use(express.json());

// Configuración CORS
const allowedOrigins = [
  'http://45.232.149.130',
  'http://45.232.149.146'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  }
}));

// Endpoints de prueba
app.get('/categorias', authRequired, (req, res) => {
  // Aquí tu lógica normal para enviar categorías
  res.json({ data: ['Acción', 'Aventura', 'Shooter'] });
});

app.get('/admin', requireRole('admin'), (req, res) => {
  res.json({ message: 'Solo admins pueden ver esto' });
});

// Puerto
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

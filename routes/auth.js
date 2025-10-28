// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'CLAVE_SECRETA';

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    console.log("🚫 Faltan campos");
    return res.status(400).json({ error: 'username y password requeridos' });
  }

  try {
    console.log("🧠 Intentando login de:", username);
    
    // 1️⃣ Buscar usuario en la BD
    const result = await db.query('SELECT * FROM usuarios WHERE username = $1', [username]);
    console.log("📦 Resultado query:", result.rows);

    if (result.rows.length === 0) {
      console.log("❌ Usuario no encontrado");
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const user = result.rows[0];

    // 2️⃣ Validar contraseña
    const passwordIsValid = await bcrypt.compare(password, user.password);
    console.log("🔑 Contraseña válida:", passwordIsValid);

    if (!passwordIsValid) {
      console.log("❌ Contraseña incorrecta");
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    // 3️⃣ Generar token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    console.log("✅ Login exitoso, token generado");
    res.json({ token, role: user.role });

  } catch (err) {
    console.error("💥 Error completo en /login:", err);
    res.status(500).json({ error: 'Error interno del servidor al intentar iniciar sesión.', detalle: err.message });
  }
});

module.exports = router;

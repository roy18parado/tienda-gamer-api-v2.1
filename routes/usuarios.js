const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { requireRole } = require('../middleware/auth');
const router = express.Router();

// POST /usuarios -> crea usuario (solo super)
router.post('/', requireRole('super'), async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role)
    return res.status(400).json({ error: 'Faltan campos' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO usuarios (username, password, role) VALUES ($1, $2, $3) RETURNING id',
      [username, hashed, role]
    );
    res.json({ id: result.rows[0].id, username, role });
  } catch (err) {
    if (err.code === '23505') // unique_violation
      return res.status(409).json({ error: 'Usuario ya existe' });
    res.status(500).json({ error: err.message });
  }
});

// GET /usuarios -> lista usuarios (solo super)
router.get('/', requireRole('super'), async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, username, role, creado_en FROM usuarios ORDER BY id DESC'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;

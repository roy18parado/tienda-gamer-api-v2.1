// routes/categorias.js
const express = require('express');
const db = require('../db');
const { requireRole } = require('../middleware/auth');
const router = express.Router();

// GET /categorias (público)
router.get('/', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM categorias ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /categorias (admin|super)
router.post('/', requireRole('admin', 'super'), async (req, res) => {
  const { nombre } = req.body;
  try {
    const result = await db.query(
      'INSERT INTO categorias (nombre) VALUES ($1) RETURNING id',
      [nombre]
    );
    res.json({ id: result.rows[0].id, nombre });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /categorias/:id (admin|super)
router.put('/:id', requireRole('admin', 'super'), async (req, res) => {
  const { id } = req.params;
  const { nombre } = req.body;
  try {
    await db.query('UPDATE categorias SET nombre = $1 WHERE id = $2', [nombre, id]);
    res.json({ id, nombre });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /categorias/:id (admin|super)
router.delete('/:id', requireRole('admin', 'super'), async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM categorias WHERE id = $1', [id]);
    res.json({ mensaje: 'Categoría eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;

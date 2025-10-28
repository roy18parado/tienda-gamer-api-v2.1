const express = require('express');
const db = require('../db');
const { requireRole } = require('../middleware/auth');
const router = express.Router();

// GET /imagenes/:producto_id (público)
router.get('/:producto_id', async (req, res) => {
  const { producto_id } = req.params;
  try {
    const result = await db.query(
      'SELECT id, url, producto_id FROM imagenes_productos WHERE producto_id = $1',
      [producto_id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /imagenes (admin|super)
router.post('/', requireRole('admin', 'super'), async (req, res) => {
  const { url, producto_id } = req.body;
  try {
    const result = await db.query(
      'INSERT INTO imagenes_productos (url, producto_id) VALUES ($1, $2) RETURNING id',
      [url, producto_id]
    );
    res.json({ id: result.rows[0].id, url, producto_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /imagenes/:id (admin|super)
router.delete('/:id', requireRole('admin', 'super'), async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM imagenes_productos WHERE id = $1', [id]);
    res.json({ mensaje: 'Imagen eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
